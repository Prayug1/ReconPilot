from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse
import ipaddress

from PySide6.QtCore import QObject, Signal

from utils.logger import ReconLogger
from utils.parser import save_results
from utils.reporter import generate_html_report
from utils.runtime import format_duration


# ── Standard result envelope ─────────────────────────────────────────────────

def make_result(module: str, status: str, data: Any = None, error: str = "") -> dict:
    """
    Standardised result envelope used by every module.
    status: "running" | "success" | "failed" | "skipped"
    """
    return {
        "module":    module,
        "status":    status,
        "data":      data or [],
        "error":     error,
        "timestamp": datetime.now().isoformat(),
    }


# ── Qt signals container ─────────────────────────────────────────────────────

class ManagerSignals(QObject):
    # (level, message)
    log          = Signal(str, str)
    # (module_name, status)   status: running|success|failed|skipped
    module_state = Signal(str, str)
    # (module_name, list_of_dicts_or_strings)
    result       = Signal(str, list)
    # () — everything done
    all_done     = Signal()
    # (title, message) — fatal scan error that should be shown to the user
    fatal_error  = Signal(str, str)
    # (module_name, int 0-100)
    progress     = Signal(str, int)


# Default scan order for optional modules. Live Host is compulsory and always
# runs first, so it is not included in this list.
DEFAULT_SCAN_ORDER: list[str] = [
    "headers", "waf", "whatweb",
    "sslcert", "dns", "subdomain",
    "http_probe", "nmap", "url_harvest",
    "js_collector", "js_secrets", "nuclei",
]

CTF_SCAN_ORDER: list[str] = [
    "headers", "waf", "whatweb",
    "sslcert", "dir_enum", "subdomain_fuzz",
    "nmap", "url_harvest", "js_collector",
    "js_secrets", "nuclei",
]


# ── ScanManager ──────────────────────────────────────────────────────────────

class ScanManager:
    """
    Orchestrates all reconnaissance modules for a single target.

    Usage
    -----
    mgr = ScanManager(target, output_dir, modules_enabled, signals)
    mgr.start()   # non-blocking — runs everything in threads
    mgr.stop()    # request graceful abort
    """

    MAX_WORKERS = 3          # parallel module threads
    MAX_RETRIES = 2          # HTTP-based modules only

    # No orchestrator-level module timeout. Every selected module is allowed to
    # run until it finishes naturally, or until the user presses Stop Scan.

    def __init__(
        self,
        target:   str,
        output_dir: str,
        modules:  dict[str, bool],   # {"nmap": True, "subdomain": False, ...}
        signals:  ManagerSignals,
        scan_order_mode: str = "default",
        custom_order: list[str] | None = None,
        scan_profile: str = "bug_bounty",
    ):
        self.target     = target
        self.output_dir = output_dir
        self.modules    = modules
        self.signals    = signals
        self.scan_profile = "ctf" if scan_profile == "ctf" else "bug_bounty"
        self.scan_order_mode = scan_order_mode if scan_order_mode in {"default", "custom"} else "default"
        self.custom_order = self._normalise_custom_order(
            custom_order or [],
            CTF_SCAN_ORDER if self.scan_profile == "ctf" else DEFAULT_SCAN_ORDER,
        )
        self._stop_evt  = threading.Event()
        self._results:  dict[str, Any] = {}
        self._module_stop_events: set[threading.Event] = set()
        self._module_stop_lock = threading.Lock()
        self._scan_started_monotonic: float | None = None
        self._scan_elapsed_s: float | None = None

        # Logger writes to the per-scan log file ONLY.
        # The UI is fed exclusively through signals.log so each event surfaces
        # to the console exactly once (no more greyed/colour duplicate pair).
        self.log = ReconLogger(target=target, log_callback=None)
        self._emit = signals.log.emit   # shorthand

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _say(self, level: str, msg: str) -> None:
        """Write to the log file AND surface to the UI console exactly once.

        Used by orchestrator-level status messages (Starting…, banners,
        completion / error / abort notices). Module-level streaming output
        goes through the `line_callback` path, which also emits exactly once.
        """
        getattr(self.log, level.lower(), self.log.info)(msg)
        self._emit(level.upper(), msg)

    # ── Public ───────────────────────────────────────────────────────────────

    def start(self):
        """Launch the orchestration thread (returns immediately)."""
        t = threading.Thread(target=self._run, daemon=True, name="ScanManager")
        t.start()

    @property
    def stopped(self) -> bool:
        return self._stop_evt.is_set()

    def stop(self):
        """Signal all running modules to abort and kill their subprocesses."""
        if self._stop_evt.is_set():
            return
        self._stop_evt.set()
        with self._module_stop_lock:
            active_stops = list(self._module_stop_events)
        for evt in active_stops:
            evt.set()
        self._say("WARNING", "⚠  Abort requested by user — stopping all active scans.")

    # ── Internal orchestration ────────────────────────────────────────────────

    def _run(self):
        self._scan_started_monotonic = time.perf_counter()
        self._scan_elapsed_s = None

        self._say("INFO", f"{'─'*64}")
        self._say("INFO", f"  ReconPilot  |  Target: {self.target}")
        self._say("INFO", f"  Output dir : {self.output_dir}")
        self._say("INFO", f"{'─'*64}")

        # ── Compulsory Phase 0: Live host check.
        # This always runs first and cannot be disabled from the UI. If the
        # target is not reachable, all other modules are skipped so we do not
        # waste time running dependent scans against a dead host.
        live_data = []
        if not self._stop_evt.is_set():
            live_data = self._run_module("live_host") or []

        if not self._stop_evt.is_set() and not self._live_host_is_alive(live_data):
            msg = (
                "Target appears unreachable. ReconPilot stopped the scan to avoid "
                "running dependent modules against an unreachable host."
            )
            self._say("ERROR", f"✘  {msg}")
            self.signals.fatal_error.emit("Target unreachable", msg)
            self._stop_evt.set()

        if not self._stop_evt.is_set():
            if self.scan_profile == "ctf":
                if self.scan_order_mode == "custom":
                    self._run_ctf_order()
                else:
                    self._run_ctf_default_order()
            elif self.scan_order_mode == "custom":
                self._run_custom_order()
            else:
                self._run_default_order()

        # ── Save consolidated JSON and generate report only after all selected
        # scan phases complete successfully.
        if not self._stop_evt.is_set():
            if self._scan_started_monotonic is not None:
                self._scan_elapsed_s = max(0.0, time.perf_counter() - self._scan_started_monotonic)
                self._say("INFO", f"Observed scan runtime: {format_duration(self._scan_elapsed_s)}")
            self._save_all()
            self._generate_report()

        if self._stop_evt.is_set():
            self._say("WARNING", "⏹  Scan stopped. Active modules were cancelled.")
        else:
            self._say("INFO", "✔  All modules finished.")
        self.signals.all_done.emit()

    @staticmethod
    def _live_host_is_alive(data: Any) -> bool:
        """Return True only when the live-host module reported ALIVE."""
        if not isinstance(data, list) or not data:
            return False
        for row in data:
            if isinstance(row, dict) and str(row.get("status", "")).upper() == "ALIVE":
                return True
        return False

    @staticmethod
    def _normalise_custom_order(order: list[str], allowed_order: list[str]) -> list[str]:
        """Return the user-selected order only, restricted to the active mode."""
        allowed = set(allowed_order)
        seen: set[str] = set()
        cleaned: list[str] = []
        for mod in order:
            if mod in allowed and mod not in seen:
                cleaned.append(mod)
                seen.add(mod)
        return cleaned


    def _run_ctf_order(self) -> None:
        """Run the user-ordered Controlled Environment / CTF workflow.

        Live Host already ran. Users can drag CTF modules into any order in the
        UI. Before web-dependent modules run, ReconPilot prepares
        ctf_web_targets.txt from available Nmap results or safe URL/domain
        fallbacks. For IP targets, keeping Nmap before web modules is still the
        best order because Nmap discovers the web ports.
        """
        selected = [m for m in self.custom_order if self.modules.get(m)]
        if not selected or self._stop_evt.is_set():
            return

        self._say("INFO", f"[CTF Mode] ▶  Running {len(selected)} selected module(s) in the user-defined order.")
        web_targets_built = False
        web_dependent = {"dir_enum", "subdomain_fuzz", "url_harvest", "js_collector", "nuclei"}

        for idx, mod in enumerate(selected, 1):
            if self._stop_evt.is_set():
                break

            if mod in web_dependent and not web_targets_built:
                self._build_ctf_web_targets()
                web_targets_built = True

            self._say("INFO", f"[CTF Mode] ▶  {idx}/{len(selected)}: {mod}")
            self._run_module(mod)

            if mod == "nmap":
                self._build_ctf_web_targets()
                web_targets_built = True

    @staticmethod
    def _host_from_target(target: str) -> tuple[str, str, int | None]:
        raw = (target or "").strip()
        if "://" in raw:
            parsed = urlparse(raw)
        else:
            parsed = urlparse("//" + raw)
        host = (parsed.hostname or raw.split("/")[0].split(":")[0]).strip("[]")
        scheme = parsed.scheme or ""
        return host, scheme, parsed.port

    @staticmethod
    def _is_ip_host(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _run_ctf_default_order(self) -> None:
        """Run the built-in Controlled / CTF phased workflow.

        Live Host has already run. The default CTF workflow excludes HTTP Probe
        and DNS Enum, uses active local crawling for URL Harvest, and keeps
        dependency-sensitive steps ordered so later modules can consume files
        written by earlier modules.
        """
        # Phase 1: quick web fingerprinting.
        self._run_parallel_phase(
            "CTF Phase 1",
            ["headers", "waf", "whatweb"],
        )

        # Phase 2: TLS metadata, directory enumeration, and vhost/subdomain
        # brute force. Directory Enumeration needs URL seeds, so build safe
        # fallback web targets first. If Nmap has not run yet, raw IP targets
        # fall back to http://IP and https://IP; domain/URL targets keep their
        # supplied scheme when available.
        if (self.modules.get("dir_enum") or self.modules.get("subdomain_fuzz")) and not self._stop_evt.is_set():
            self._build_ctf_web_targets()
        self._run_parallel_phase(
            "CTF Phase 2",
            ["sslcert", "dir_enum", "subdomain_fuzz"],
        )

        # Phase 3: Nmap first, then rebuild CTF web targets from discovered web
        # ports before URL Harvest and JS Collector. URL Harvest in CTF mode is
        # active crawling only, so HTTP Probe is not required.
        phase3 = [m for m in ["nmap", "url_harvest", "js_collector"] if self.modules.get(m)]
        if phase3 and not self._stop_evt.is_set():
            self._say("INFO", f"[CTF Phase 3] ▶  Running: {', '.join(phase3)}")

        if self.modules.get("nmap") and not self._stop_evt.is_set():
            self._run_module("nmap")

        if not self._stop_evt.is_set():
            self._build_ctf_web_targets()

        if self.modules.get("url_harvest") and not self._stop_evt.is_set():
            self._run_module("url_harvest")

        if self.modules.get("js_collector") and not self._stop_evt.is_set():
            self._run_module("js_collector")

        # Phase 4: scan downloaded JavaScript first, then run Nuclei against
        # the prepared/discovered CTF web targets.
        phase4 = [m for m in ["js_secrets", "nuclei"] if self.modules.get(m)]
        if phase4 and not self._stop_evt.is_set():
            self._say("INFO", f"[CTF Phase 4] ▶  Running: {', '.join(phase4)}")

        if self.modules.get("js_secrets") and not self._stop_evt.is_set():
            self._run_module("js_secrets")

        if self.modules.get("nuclei") and not self._stop_evt.is_set():
            self._run_module("nuclei")

    def _build_ctf_web_targets(self) -> list[dict]:
        """Create output/<target>/ctf_web_targets.txt from Nmap web ports."""
        host, input_scheme, input_port = self._host_from_target(self.target)
        ports = self._results.get("nmap", []) or []
        targets: list[str] = []
        seen: set[str] = set()

        def add(url: str) -> None:
            url = url.rstrip("/")
            if url and url not in seen:
                seen.add(url)
                targets.append(url)

        for row in ports:
            if not isinstance(row, dict):
                continue
            port_s = str(row.get("port", "")).strip()
            if not port_s.isdigit():
                continue
            port = int(port_s)
            service = str(row.get("service", "")).lower()
            product = str(row.get("product", "")).lower()
            tunnel = str(row.get("tunnel", "")).lower()
            looks_web = (
                "http" in service
                or "http" in product
                or port in {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443, 5000, 3000}
            )
            if not looks_web:
                continue
            scheme = "https" if service == "https" or tunnel == "ssl" or port in {443, 8443, 9443} else "http"
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            add(f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}")

        # If the user supplied an explicit URL and Nmap did not identify a web
        # port, still allow the downstream CTF web modules to use that URL.
        if not targets and input_scheme in {"http", "https"}:
            add(self.target)
        elif not targets and self._is_ip_host(host):
            # In the requested CTF default workflow Directory Enumeration runs
            # before Nmap. For raw IP lab targets, start with the common web
            # schemes so DirEnum/URL Harvest still have something
            # useful to test; after Nmap finishes this list is rebuilt with any
            # discovered web ports.
            add(f"http://{host}")
            add(f"https://{host}")
        elif not targets and not self._is_ip_host(host):
            # Domain/hostname fallback for CTF labs where nmap is filtered but
            # a normal web vhost may still exist.
            add(f"https://{host}")
            add(f"http://{host}")

        rows = [{"url": u, "status": "LIVE"} for u in targets]
        self._results["ctf_web_targets"] = rows

        out_file = Path(self.output_dir) / "ctf_web_targets.txt"
        try:
            out_file.write_text("\n".join(targets) + ("\n" if targets else ""), encoding="utf-8")
        except Exception as exc:
            self._say("WARNING", f"[CTF Mode] Could not save web target list: {exc}")

        if targets:
            self._say("INFO", f"[CTF Mode] ✔  {len(targets)} web target(s) prepared → {out_file}")
            for u in targets[:20]:
                self._say("INFO", f"[CTF Mode]   • {u}")
            if len(targets) > 20:
                self._say("INFO", f"[CTF Mode]   … {len(targets) - 20} more")
        else:
            self._say("WARNING", "[CTF Mode] No web ports/URLs were found; web modules may return no results.")
        return rows

    def _ctf_probe_rows(self) -> list[dict]:
        """HTTP-like rows for JS Collector in CTF mode."""
        rows = list(self._results.get("ctf_web_targets", []) or [])
        for r in self._results.get("dir_enum", []) or []:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            status = str(r.get("status", ""))
            if not url:
                continue
            codes = [int(x) for x in __import__('re').findall(r"\d{3}", status)]
            if not codes or any(200 <= c < 400 for c in codes):
                rows.append({"url": url, "status": status or "LIVE"})
        seen: set[str] = set()
        out: list[dict] = []
        for row in rows:
            u = row.get("url")
            if u and u not in seen:
                seen.add(u)
                out.append(row)
        return out

    def _run_default_order(self) -> None:
        """Run the built-in phased scan order."""
        # ── Phase 1: HTTP-facing fingerprinting modules.
        self._run_parallel_phase(
            "Phase 1",
            ["headers", "waf", "whatweb"],
        )

        # ── Phase 2: certificate, DNS, and subdomain discovery.
        self._run_parallel_phase(
            "Phase 2",
            ["sslcert", "dns", "subdomain"],
        )

        # ── Phase 3: live web discovery, port scan, and URL harvesting.
        self._run_parallel_phase(
            "Phase 3",
            ["http_probe", "nmap", "url_harvest"],
        )

        # ── Phase 4: JavaScript pipeline and Nuclei.
        # JS Collector consumes HTTP Probe live URLs and direct .js URLs from
        # URL Harvest. JS Secrets then scans the downloaded JS files. Nuclei
        # remains on the main target only in Bug Bounty mode.
        if self.modules.get("js_collector") and not self._stop_evt.is_set():
            self._run_module("js_collector")

        if self.modules.get("js_secrets") and not self._stop_evt.is_set():
            self._run_module("js_secrets")

        if self.modules.get("nuclei") and not self._stop_evt.is_set():
            self._run_module("nuclei")

    def _run_custom_order(self) -> None:
        """Run selected modules one-by-one in the user's custom order."""
        selected = [m for m in self.custom_order if self.modules.get(m)]
        if not selected or self._stop_evt.is_set():
            return

        self._say("INFO", f"[Custom Order] ▶  Running {len(selected)} selected module(s) one-by-one.")
        for idx, mod in enumerate(selected, 1):
            if self._stop_evt.is_set():
                break
            self._say("INFO", f"[Custom Order] ▶  {idx}/{len(selected)}: {mod}")
            self._run_module(mod)

    def _run_parallel_phase(self, phase_name: str, module_names: list[str]) -> None:
        """Run selected modules from a phase with the manager worker limit."""
        phase = [m for m in module_names if self.modules.get(m)]
        if not phase or self._stop_evt.is_set():
            return

        self._say("INFO", f"[{phase_name}] ▶  Running: {', '.join(phase)}")
        pool = ThreadPoolExecutor(max_workers=self.MAX_WORKERS)
        futs = {pool.submit(self._run_module, m): m for m in phase}
        try:
            while futs and not self._stop_evt.is_set():
                for fut in list(futs):
                    if fut.done():
                        mod = futs.pop(fut)
                        try:
                            fut.result()
                        except Exception as exc:
                            self._say("ERROR", f"[{mod}] Unhandled exception: {exc}")
                if futs and not self._stop_evt.is_set():
                    time.sleep(0.1)
        finally:
            if self._stop_evt.is_set():
                for fut in futs:
                    fut.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
            else:
                pool.shutdown(wait=True)

    def _run_module(self, module_name: str):
        """Import and execute a single module with timeout + retry logic."""
        if self._stop_evt.is_set():
            self.signals.module_state.emit(module_name, "skipped")
            return []

        self.signals.module_state.emit(module_name, "running")
        self._say("INFO", f"[{module_name}] Starting …")

        # Per-module cancellation token. Set when the orchestrator gives up on
        # this module (timeout or user abort). Modules that accept it can
        # terminate their subprocess; either way, any further UI emissions
        # from this module are dropped on the floor.
        mod_stop = threading.Event()
        with self._module_stop_lock:
            self._module_stop_events.add(mod_stop)

        # Each per-module callback writes to BOTH the UI console AND the
        # per-scan log file, so scan.log is a complete transcript of
        # everything the user sees in the live console — including
        # per-item streaming output like JS-file URLs, per-target probe
        # lines, per-nuclei finding, etc.
        def line_cb(msg: str):
            if mod_stop.is_set():
                return
            self.log.info(msg)            # → scan.log
            self._emit("INFO", msg)       # → UI console

        prog_cb    = lambda pct: None if mod_stop.is_set() else self.signals.progress.emit(module_name, pct)

        done_event = threading.Event()
        result_box: list[Any] = []   # mutable container for thread result

        def done_cb(data):
            result_box.append(data)
            done_event.set()

        try:
            self._dispatch(module_name, line_cb, prog_cb, done_cb, mod_stop)
        except Exception as exc:
            mod_stop.set()
            with self._module_stop_lock:
                self._module_stop_events.discard(mod_stop)
            self._say("ERROR", f"[{module_name}] Dispatch error: {exc}")
            self.signals.module_state.emit(module_name, "failed")
            self._results[module_name] = []
            return []

        try:
            # Wait indefinitely until the module calls done_callback, unless the
            # user presses Stop Scan. This deliberately removes hard module
            # ceilings so long-running tools such as waybackurls, gau, gospider,
            # nuclei, wafw00f, and WhatWeb can finish naturally.
            while True:
                if done_event.wait(timeout=0.1):
                    break
                if self._stop_evt.is_set():
                    mod_stop.set()
                    self.signals.module_state.emit(module_name, "skipped")
                    self._results[module_name] = []
                    return []

            if self._stop_evt.is_set() or mod_stop.is_set():
                self.signals.module_state.emit(module_name, "skipped")
                self._results[module_name] = []
                return []

            data = result_box[0] if result_box else []
            self._results[module_name] = data
            self.signals.result.emit(module_name, data if isinstance(data, list) else [])
            self.signals.module_state.emit(module_name, "success")
            self.signals.progress.emit(module_name, 100)
            return data
        finally:
            mod_stop.set()
            with self._module_stop_lock:
                self._module_stop_events.discard(mod_stop)

    def _dispatch(self, module_name: str, line_cb, prog_cb, done_cb,
                  mod_stop: threading.Event | None = None):
        """Route module_name to the correct module function.

        ``mod_stop`` is a per-module cancellation event. Modules that accept it
        can use it to terminate any subprocess they spawned; modules that don't
        accept it simply ignore the argument (the orchestrator already gates
        their UI callbacks).
        """
        t  = self.target
        od = self.output_dir

        if module_name == "nmap":
            from modules.nmap_scan import run_nmap
            run_nmap(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop,
                     ctf_mode=(self.scan_profile == "ctf"))

        elif module_name == "subdomain":
            from modules.subdomain_scan import run_subdomain_scan
            run_subdomain_scan(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "headers":
            from modules.http_headers import run_header_check
            run_header_check(t, od, self.log, line_cb, done_cb,
                             retries=self.MAX_RETRIES, stop_evt=mod_stop)

        elif module_name == "live_host":
            from modules.live_host import run_live_host_check
            run_live_host_check(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "http_probe":
            from modules.http_probe import run_http_probe
            if self.scan_profile == "ctf":
                # Probe CTF web targets and any hostnames discovered by ffuf.
                subs = []
                for row in self._results.get("ctf_web_targets", []) or []:
                    if isinstance(row, dict) and row.get("url"):
                        subs.append(row.get("url"))
                for row in self._results.get("subdomain_fuzz", []) or []:
                    if isinstance(row, dict):
                        subs.append(row.get("host") or row.get("url") or "")
            else:
                subs = self._results.get("subdomain", [])
            run_http_probe(t, subs, od, self.log, line_cb, done_cb, prog_cb,
                           retries=self.MAX_RETRIES, stop_evt=mod_stop)

        elif module_name == "js_collector":
            from modules.js_collector import run_js_collector
            probe_data = self._ctf_probe_rows() if self.scan_profile == "ctf" else self._results.get("http_probe", [])
            run_js_collector(t, probe_data, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "waf":
            from modules.waf_scan import run_waf_scan
            run_waf_scan(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "whatweb":
            from modules.whatweb_scan import run_whatweb_scan
            run_whatweb_scan(t, od, self.log, line_cb, done_cb,
                             stop_evt=mod_stop)

        elif module_name == "sslcert":
            from modules.ssl_cert import run_ssl_cert
            run_ssl_cert(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "dns":
            from modules.dns_enum import run_dns_enum
            run_dns_enum(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "url_harvest":
            from modules.url_harvest import run_url_harvest
            ctf_targets = [r.get("url") for r in self._results.get("ctf_web_targets", []) if isinstance(r, dict) and r.get("url")] if self.scan_profile == "ctf" else None
            run_url_harvest(t, od, self.log, line_cb, done_cb,
                            stop_evt=mod_stop, ctf_mode=(self.scan_profile == "ctf"),
                            target_urls=ctf_targets)

        elif module_name == "js_secrets":
            from modules.js_secrets import run_js_secrets
            run_js_secrets(t, od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "nuclei":
            from modules.nuclei_scan import run_nuclei_scan
            target_urls = [r.get("url") for r in self._results.get("ctf_web_targets", []) if isinstance(r, dict) and r.get("url")] if self.scan_profile == "ctf" else None
            run_nuclei_scan(t, od, self.log, line_cb, done_cb, prog_cb,
                            stop_evt=mod_stop, target_urls=target_urls)

        elif module_name == "dir_enum":
            from modules.dir_enum import run_dir_enum
            run_dir_enum(t, self._results.get("ctf_web_targets", []), od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        elif module_name == "subdomain_fuzz":
            from modules.subdomain_fuzz import run_subdomain_fuzz
            run_subdomain_fuzz(t, self._results.get("ctf_web_targets", []), od, self.log, line_cb, done_cb, stop_evt=mod_stop)

        else:
            raise ValueError(f"Unknown module: {module_name}")

    # ── Persistence & reporting ───────────────────────────────────────────────

    def _save_all(self):
        all_data = {
            "target":      self.target,
            "scan_mode":   self.scan_profile,
            "timestamp":   datetime.now().isoformat(),
            "scan_runtime_s": self._scan_elapsed_s,
            "ports":       self._results.get("nmap",       []),
            "subdomains":  self._results.get("subdomain",  []),
            "dir_enum":    self._results.get("dir_enum",   []),
            "subdomain_fuzz": self._results.get("subdomain_fuzz", []),
            "ctf_web_targets": self._results.get("ctf_web_targets", []),
            "headers":     self._results.get("headers",    []),
            "live_hosts":  self._results.get("live_host",  []),
            "http_probe":  self._results.get("http_probe", []),
            "js_files":    self._results.get("js_collector", []),
            "waf":         self._results.get("waf",        []),
            "whatweb":     self._results.get("whatweb",    []),
            "sslcert":     self._results.get("sslcert",    []),
            "dns":         self._results.get("dns",        []),
            "url_harvest": self._results.get("url_harvest",[]),
            "js_secrets":  self._results.get("js_secrets", []),
            "nuclei":      self._results.get("nuclei",     []),
        }
        path = save_results(all_data, self.output_dir, "results.json")
        self._say("INFO", f"✔  Results saved → {path}")

    def _generate_report(self):
        try:
            # Compute the timestamp here rather than reading it from the
            # output directory name. Output dirs are now per-target (no
            # timestamped subfolder), so output_dir.name is e.g.
            # "192.168.68.52_8080" — which is *not* parseable as %Y%m%d_%H%M%S
            # and would crash the reporter's strptime.
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            rpt  = generate_html_report(
                target     = self.target,
                timestamp  = ts,
                output_dir = self.output_dir,
                results    = {
                    "ports":       self._results.get("nmap",         []),
                    "subdomains":  self._results.get("subdomain",    []),
                    "dir_enum":    self._results.get("dir_enum",     []),
                    "subdomain_fuzz": self._results.get("subdomain_fuzz", []),
                    "ctf_web_targets": self._results.get("ctf_web_targets", []),
                    "headers":     self._results.get("headers",      []),
                    "live_hosts":  self._results.get("live_host",    []),
                    "http_probe":  self._results.get("http_probe",   []),
                    "js_files":    self._results.get("js_collector", []),
                    "waf":         self._results.get("waf",         []),
                    "whatweb":     self._results.get("whatweb",     []),
                    "sslcert":     self._results.get("sslcert",     []),
                    "dns":         self._results.get("dns",         []),
                    "url_harvest": self._results.get("url_harvest", []),
                    "js_secrets":  self._results.get("js_secrets",  []),
                    "nuclei":      self._results.get("nuclei",      []),
                    "scan_mode":   self.scan_profile,
                    "scan_runtime_s": self._scan_elapsed_s,
                },
            )
            self._say("INFO", f"✔  HTML report → {rpt}")
        except Exception as exc:
            self._say("ERROR", f"Report generation failed: {exc}")
