from __future__ import annotations

import subprocess
import shutil
import threading
from pathlib import Path
from typing import Callable

from utils.parser import parse_wafw00f_output
from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped

# No hard timeout: wafw00f runs until it exits naturally or Stop Scan is pressed.


def is_wafw00f_available() -> bool:
    return shutil.which("wafw00f") is not None


def _candidate_urls(target: str) -> list[str]:
    """
    Build the list of URLs to test.

    wafw00f defaults to http:// (port 80). The 'Connection refused / site
    appears to be down' error happens when port 80 is closed but the service
    actually lives on https (443) or an alternate port like 8080. So if the
    user did not supply an explicit scheme, we probe https first, then http,
    then the common 8080 fallback.
    """
    if target.startswith(("http://", "https://")):
        return [target]
    host = target.rstrip("/")
    return [
        f"https://{host}",
        f"http://{host}",
        f"http://{host}:8080",
    ]


def run_waf_scan(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Run wafw00f against the target to fingerprint web application firewalls.

    Handles the common 'site appears to be down / Connection refused' case by
    trying https and an :8080 fallback before giving up, and reports the cause
    clearly instead of failing silently.

    done_callback receives a list with a single result dict:
      [{"target", "status", "waf", "requests"}]
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not is_wafw00f_available():
            msg = "✘ wafw00f not found on PATH. Install with: pip install wafw00f"
            log.error(msg)
            line_callback(f"[WAF] {msg}")
            done_callback([])
            return

        urls = _candidate_urls(target)
        combined_raw = ""
        last_status  = "NONE"
        succeeded    = False

        for url in urls:
            if stopped(stop_evt):
                done_callback([])
                return
            line_callback(f"[WAF] ▶  wafw00f {url}")
            log.info(f"[WAF] wafw00f {url}")

            cmd = ["wafw00f", url, "-a"]   # -a = test against all WAF signatures
            try:
                proc = popen_scan(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                start_stop_watcher(proc, stop_evt, line_callback, "WAF")
            except FileNotFoundError:
                line_callback("[WAF] ✘ wafw00f vanished from PATH mid-run.")
                done_callback([])
                return
            except Exception as exc:
                log.error(f"[WAF] {exc}")
                line_callback(f"[WAF] ✘ Error launching wafw00f: {exc}")
                done_callback([])
                return

            url_raw = ""
            site_down = False
            conn_refused = False
            try:
                for line in proc.stdout:                # type: ignore[union-attr]
                    if stopped(stop_evt):
                        kill_process_tree(proc)
                        done_callback([])
                        return
                    s = line.rstrip()
                    if not s:
                        continue
                    url_raw += s + "\n"
                    log.debug(f"[WAF] {s}")
                    line_callback(f"[WAF] {s}")

                    low = s.lower()
                    if "appears to be down" in low:
                        site_down = True
                    if "connection refused" in low or "max retries exceeded" in low:
                        conn_refused = True
                proc.wait()
                if stopped(stop_evt):
                    done_callback([])
                    return
            except Exception as exc:
                log.error(f"[WAF] {exc}")
                line_callback(f"[WAF] ✘ Error reading wafw00f output: {exc}")
                continue

            combined_raw += url_raw

            # If the host responded (no refusal / not down), this URL is
            # authoritative — stop probing further fallbacks.
            if not site_down and not conn_refused:
                succeeded = True
                last_status = url
                break

            if conn_refused:
                line_callback(
                    f"[WAF]   ⚠  {url} refused the connection — "
                    f"trying next scheme/port…"
                )

        results = parse_wafw00f_output(combined_raw, target=target)

        if not succeeded and not results:
            line_callback(
                "[WAF] ✘  Target unreachable on http/https/:8080 "
                "(connection refused). Is the service running?"
            )
            done_callback([{
                "target":   target,
                "status":   "UNREACHABLE",
                "waf":      "Connection refused on all tested ports (80/443/8080)",
                "requests": "—",
            }])
            return

        row = results[0] if results else {}
        status = row.get("status", "NONE")
        if status == "DETECTED":
            line_callback(f"[WAF] ✔  WAF detected: {row.get('waf')}")
        elif status == "GENERIC":
            line_callback("[WAF] ✔  Generic firewall behaviour observed.")
        else:
            line_callback("[WAF] ✔  No WAF fingerprinted on target.")

        log.info(f"[WAF] status={status} waf={row.get('waf','—')}")
        done_callback(results)

    threading.Thread(target=_run, daemon=True).start()
