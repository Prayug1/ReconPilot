from __future__ import annotations

import os
import signal
import subprocess
import shutil
import threading
from pathlib import Path
from typing import Callable

from utils.parser import parse_whatweb_output
from utils.logger import ReconLogger

# No hard timeout: WhatWeb runs until it exits naturally or Stop Scan is pressed.


def is_whatweb_available() -> bool:
    return shutil.which("whatweb") is not None


def _candidate_urls(target: str) -> list[str]:
    """
    Same scheme/port fallback as the WAF module.
    whatweb defaults to http://; if the service only listens on https or :8080
    the default scheme will silently miss it, so we probe both.
    """
    if target.startswith(("http://", "https://")):
        return [target]
    host = target.rstrip("/")
    return [
        f"https://{host}",
        f"http://{host}",
        f"http://{host}:8080",
    ]


def _kill_proc_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def run_whatweb_scan(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Fingerprint the target with WhatWeb.

    Writes machine-readable JSON to <output_dir>/whatweb.jsonl and streams the
    coloured-stripped human log to the UI. ``stop_evt`` mirrors the same
    cancellation contract as nuclei_scan — if the orchestrator sets it, the
    subprocess group is SIGKILLed and the read loop exits.

    done_callback receives a flat list of plugin findings:
      [{"target", "plugin", "version", "string", "http_status"}, ...]
    """

    def _run():
        if not is_whatweb_available():
            msg = ("✘ whatweb not found on PATH. Install with: "
                   "sudo apt install whatweb")
            log.error(msg)
            line_callback(f"[WhatWeb] {msg}")
            done_callback([])
            return

        jsonl_out = str(Path(output_dir) / "whatweb.jsonl")
        # Make sure stale data from a previous run can't bleed into this one.
        try:
            Path(jsonl_out).unlink(missing_ok=True)
        except Exception:
            pass

        combined_raw   = ""
        succeeded_url  = None

        for url in _candidate_urls(target):
            if stop_evt is not None and stop_evt.is_set():
                break

            cmd = [
                "whatweb",
                "--color=never",
                "--no-errors",
                "-a", "3",
                "--log-json=" + jsonl_out,
                url,
            ]

            log.info(f"[WhatWeb] {' '.join(cmd)}")
            line_callback(f"[WhatWeb] ▶  whatweb -a 3 {url}")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                    start_new_session=True,   # own pgid so we can SIGKILL cleanly
                )
            except FileNotFoundError:
                line_callback("[WhatWeb] ✘ whatweb vanished from PATH mid-run.")
                done_callback([])
                return
            except Exception as exc:
                log.error(f"[WhatWeb] {exc}")
                line_callback(f"[WhatWeb] ✘ Error launching whatweb: {exc}")
                done_callback([])
                return

            # Watchdog: terminate on orchestrator cancel.
            cancelled = threading.Event()
            if stop_evt is not None:
                def _watch(p=proc, c=cancelled):
                    while not stop_evt.is_set():
                        if p.poll() is not None:
                            return
                        if stop_evt.wait(timeout=0.5):
                            break
                    if p.poll() is None:
                        c.set()
                        log.warning("[WhatWeb] cancellation requested — terminating.")
                        _kill_proc_tree(p)
                threading.Thread(target=_watch, daemon=True,
                                 name="whatweb-watch").start()

            url_raw  = ""
            site_down = False
            try:
                for line in proc.stdout:                # type: ignore[union-attr]
                    if cancelled.is_set() or (stop_evt is not None and stop_evt.is_set()):
                        break
                    s = line.rstrip()
                    if not s:
                        continue
                    url_raw += s + "\n"
                    log.debug(f"[WhatWeb] {s}")
                    line_callback(f"[WhatWeb] {s}")

                    low = s.lower()
                    if any(x in low for x in (
                        "connection refused", "could not connect",
                        "timed out", "no route to host", "connection reset",
                    )):
                        site_down = True
                proc.wait()
            except Exception as exc:
                log.error(f"[WhatWeb] {exc}")
                if not cancelled.is_set():
                    line_callback(f"[WhatWeb] ✘ Error reading whatweb output: {exc}")
                continue

            if cancelled.is_set():
                line_callback("[WhatWeb] ⨯  Cancelled by orchestrator.")
                done_callback([])
                return

            combined_raw += url_raw

            # If the host responded, stop probing further schemes.
            if not site_down and proc.returncode == 0:
                succeeded_url = url
                break

            if site_down:
                line_callback(
                    f"[WhatWeb]   ⚠  {url} unreachable — trying next scheme/port…"
                )

        # Prefer the JSONL log file (clean, structured) and fall back to
        # whatever the streamed brief mode line gave us.
        parse_src = combined_raw
        try:
            jf = Path(jsonl_out)
            if jf.exists() and jf.stat().st_size > 0:
                parse_src = jf.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            log.debug(f"[WhatWeb] could not read {jsonl_out}: {exc}")

        findings = parse_whatweb_output(parse_src, target=target)

        if not findings:
            line_callback("[WhatWeb] ✔  No fingerprints extracted.")
        else:
            plugins = {f["plugin"] for f in findings}
            line_callback(
                f"[WhatWeb] ✔  {len(plugins)} plugin(s), "
                f"{len(findings)} fingerprint row(s)."
                + (f"  (responding URL: {succeeded_url})" if succeeded_url else "")
            )

        log.info(f"[WhatWeb] {len(findings)} fingerprint(s)")
        done_callback(findings)

    threading.Thread(target=_run, daemon=True).start()
