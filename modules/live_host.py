from __future__ import annotations

import subprocess
import socket
import threading
import platform
import time
from typing import Callable

from utils.logger import ReconLogger
from utils.process_control import stopped

# No hard timeout is imposed by ReconPilot. Probes run until the underlying
# command/library succeeds, fails, or Stop Scan is pressed between steps.


def run_live_host_check(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Resolves and probes the target host.
    done_callback receives a list of result dicts:
      [{"host": str, "ip": str, "status": str, "method": str, "latency": str}]
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        line_callback(f"[LiveHost] ▶  Probing host: {target}")
        log.info(f"[LiveHost] Starting host detection for {target}")

        results: list[dict] = []

        # ── 1. DNS resolution ────────────────────────────────────────────
        ip = _resolve_dns(target, log, line_callback)
        if not ip:
            entry = {
                "host":    target,
                "ip":      "—",
                "status":  "DNS FAIL",
                "method":  "DNS",
                "latency": "—",
            }
            results.append(entry)
            line_callback(f"[LiveHost] ✘  DNS resolution failed for {target}")
            done_callback(results)
            return

        line_callback(f"[LiveHost]   ✔  Resolved: {target} → {ip}")
        if stopped(stop_evt):
            done_callback([])
            return

        # ── 2. Ping ──────────────────────────────────────────────────────
        alive, latency, method = _ping(ip, log, line_callback)
        if stopped(stop_evt):
            done_callback([])
            return

        if not alive:
            # ── 3. HTTP fallback ─────────────────────────────────────────
            alive, latency, method = _http_probe(target, log, line_callback)
            if stopped(stop_evt):
                done_callback([])
                return

        status = "ALIVE" if alive else "UNREACHABLE"
        line_callback(f"[LiveHost]   {'✔' if alive else '✘'}  {target} ({ip}) → {status}  [{method}  {latency}]")
        log.info(f"[LiveHost] {target} ({ip}) — {status} via {method} in {latency}")

        results.append({
            "host":    target,
            "ip":      ip,
            "status":  status,
            "method":  method,
            "latency": latency,
        })

        line_callback("[LiveHost] ✔  Host detection complete.")
        done_callback(results)

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_dns(target: str, log: ReconLogger, line_cb) -> str | None:
    """Return first resolved IP or None on failure."""
    # Strip protocol if user passed a URL
    host = target.split("://")[-1].split("/")[0]
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as exc:
        log.error(f"[LiveHost] DNS error: {exc}")
        return None


def _ping(ip: str, log: ReconLogger, line_cb) -> tuple[bool, str, str]:
    """System ping. Returns (alive, latency_str, method_str)."""
    sys = platform.system().lower()
    if sys == "windows":
        cmd = ["ping", "-n", "1", ip]
    else:
        cmd = ["ping", "-c", "1", ip]

    try:
        t0  = time.perf_counter()
        ret = subprocess.run(cmd, capture_output=True, text=True)
        ms  = f"{(time.perf_counter() - t0)*1000:.0f}ms"
        alive = ret.returncode == 0
        return alive, ms, "ICMP"
    except Exception as exc:
        log.debug(f"[LiveHost] Ping failed: {exc}")
        return False, "—", "ICMP"


def _http_probe(target: str, log: ReconLogger, line_cb) -> tuple[bool, str, str]:
    """HEAD request as alive-check when ICMP is blocked."""
    import requests
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            t0   = time.perf_counter()
            resp = requests.head(url, allow_redirects=True,
                                 verify=False,
                                 headers={"User-Agent": "ReconPilot/2.0"})
            ms   = f"{(time.perf_counter() - t0)*1000:.0f}ms"
            line_cb(f"[LiveHost]   HTTP({resp.status_code}) → {url}")
            return True, ms, f"HTTP-{resp.status_code}"
        except Exception:
            continue
    return False, "—", "HTTP"
