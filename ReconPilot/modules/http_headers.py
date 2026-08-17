from __future__ import annotations

import threading
import time
from typing import Callable

from utils.parser import parse_http_headers
from utils.logger import ReconLogger
from utils.process_control import stopped

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

# No request timeout: header checks run until the server responds/fails naturally.


def run_header_check(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    retries:       int = 2,
    stop_evt:      threading.Event | None = None,
) -> None:

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not _HAS_REQUESTS:
            line_callback("[Headers] ✘ 'requests' library not installed.")
            done_callback([])
            return

        urls = ([target] if target.startswith(("http://", "https://"))
                else [f"https://{target}", f"http://{target}"])

        line_callback(f"[Headers] ▶  Checking security headers for: {target}")
        headers = {}
        final_url = ""

        for url in urls:
            if stopped(stop_evt):
                done_callback(results if 'results' in locals() else [])
                return
            for attempt in range(1, retries + 2):
                try:
                    resp = requests.get(
                        url, allow_redirects=True,
                        verify=False,
                        headers={"User-Agent": "ReconPilot/2.0 security-scanner"},
                    )
                    headers   = dict(resp.headers)
                    final_url = resp.url
                    line_callback(f"[Headers]   {resp.status_code}  {resp.url}")
                    break
                except Exception as exc:
                    if attempt <= retries:
                        time.sleep(1)
                    else:
                        line_callback(f"[Headers]   ⚠  {url} — {exc}")
            if headers:
                break

        if not headers:
            line_callback("[Headers] ✘  Could not retrieve headers.")
            done_callback([])
            return

        results = parse_http_headers(headers)
        high    = sum(1 for r in results if r.get("risk") == "HIGH")
        medium  = sum(1 for r in results if r.get("risk") == "MEDIUM")
        ok_cnt  = sum(1 for r in results if r.get("risk") == "OK")

        line_callback(f"[Headers]   Risk: HIGH={high}  MEDIUM={medium}  OK={ok_cnt}")
        line_callback("[Headers] ✔  Header analysis complete.")
        log.info(f"[Headers] HIGH:{high} MEDIUM:{medium} OK:{ok_cnt}")
        done_callback(results)

    threading.Thread(target=_run, daemon=True).start()
