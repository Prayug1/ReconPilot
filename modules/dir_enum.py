from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped


# Keep the full CTF extension set requested by the user and use the
# DirBuster medium wordlist as the preferred/default CTF directory wordlist.
# Heartbeat progress messages prevent long feroxbuster runs from looking frozen.
EXTENSIONS = "php,txt,html,js,bak,zip,old,conf,json,xml,sql,db,log"
HEARTBEAT_SECONDS = 15
NO_FINDING_LIMIT_SECONDS = 30
PREFERRED_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
WORDLIST_CANDIDATES = [
    PREFERRED_WORDLIST,
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
]
_URL_RE = re.compile(r"https?://[^\s\]')\"]+", re.I)
_STATUS_RE = re.compile(r"(?:^|\s|\[)(?P<status>[1-5]\d\d)(?:\s|$|\])")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_HUMAN_METRIC_RE = re.compile(
    r"(?P<status>[1-5]\d\d)\s+"
    r"(?:[A-Z]+\s+)?"
    r"(?P<lines>\d+)l\s+"
    r"(?P<words>\d+)w\s+"
    r"(?P<size>\d+)c\s+"
    r"(?P<url>https?://\S+)",
    re.I,
)


def is_ferox_available() -> bool:
    return shutil.which("feroxbuster") is not None


def _wordlist() -> str | None:
    for path in WORDLIST_CANDIDATES:
        if Path(path).exists():
            return path
    return None


def _safe_name(url: str) -> str:
    p = urlparse(url)
    base = (p.netloc or p.path or url).replace(":", "_")
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_") or "target"


def _first_value(obj: dict, *keys: str) -> str:
    """Return the first present metric value from feroxbuster JSON variants."""
    for key in keys:
        if key in obj and obj.get(key) is not None:
            return str(obj.get(key))
    return ""


def _normalise_ferox_url(value: object, base_url: str = "") -> str:
    """Convert feroxbuster JSON path/url variants into a full URL when possible."""
    url = str(value or "").strip()
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    if base_url and url.startswith("/"):
        return base_url.rstrip("/") + url
    return url


def _parse_line(line: str, base_url: str = "") -> dict | None:
    s = _ANSI_RE.sub("", line).strip()
    if not s:
        return None

    # feroxbuster with --json writes one JSON object per result. Keep a
    # resilient parser because versions differ in field names. This is the
    # preferred format now because it preserves status and size.
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            # Ignore non-result messages/events if this feroxbuster build emits
            # JSON telemetry lines in addition to findings.
            candidate_url = obj.get("url") or obj.get("target") or obj.get("path")
            req = obj.get("request")
            if not candidate_url and isinstance(req, dict):
                candidate_url = req.get("url")
            resp = obj.get("response")
            if not candidate_url and isinstance(resp, dict):
                candidate_url = resp.get("url")
            url = _normalise_ferox_url(candidate_url, base_url)
            if not url:
                return None
            return {
                "url": url,
                "status": _first_value(obj, "status", "status_code", "code"),
                "size": _first_value(obj, "content_length", "contentLength", "content-length", "size", "length", "bytes"),
            }
        except Exception:
            pass

    # Human feroxbuster output commonly looks like:
    #   200      GET       12l       45w      1211c https://host/path
    # Parse status and response size for the GUI/report output.
    m_human = _HUMAN_METRIC_RE.search(s)
    if m_human:
        return {
            "url": m_human.group("url").rstrip(","),
            "status": m_human.group("status"),
            "size": m_human.group("size"),
        }

    # Very old/silent output may only expose the URL. Keep it as a finding,
    # but leave metrics blank because they are genuinely unavailable.
    m_url = _URL_RE.search(s)
    if not m_url:
        return None
    status = ""
    m_status = _STATUS_RE.search(s)
    if m_status:
        status = m_status.group("status")
    return {"url": m_url.group(0).rstrip(","), "status": status, "size": ""}


def _parse_saved_results(path: Path, base_url: str) -> list[dict]:
    """Read feroxbuster output from disk as a fallback after the process exits."""
    rows: list[dict] = []
    if not path.exists():
        return rows
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            row = _parse_line(line, base_url=base_url)
            if row and row.get("url"):
                rows.append(row)
    except Exception:
        return rows
    return rows


def run_dir_enum(
    target: str,
    web_targets: list[dict],
    output_dir: str,
    log: ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt: threading.Event | None = None,
) -> None:
    """Run feroxbuster against CTF web targets."""

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not is_ferox_available():
            msg = "✘ feroxbuster not found on PATH. Install feroxbuster and retry."
            log.error(msg)
            line_callback(f"[DirEnum] {msg}")
            done_callback([])
            return

        urls = []
        seen = set()
        for row in web_targets or []:
            if not isinstance(row, dict):
                continue
            u = str(row.get("url", "")).strip().rstrip("/")
            if u.startswith(("http://", "https://")) and u not in seen:
                seen.add(u)
                urls.append(u)

        if not urls:
            line_callback("[DirEnum] ⚠  No CTF web targets available. Run Nmap first or provide a URL target.")
            done_callback([])
            return

        wl = _wordlist()
        out_dir = Path(output_dir) / "feroxbuster"
        out_dir.mkdir(parents=True, exist_ok=True)
        all_rows: list[dict] = []
        all_urls: list[str] = []
        seen_result = set()

        if wl:
            line_callback(f"[DirEnum] ℹ  Wordlist: {wl}")
            if wl != PREFERRED_WORDLIST:
                line_callback(
                    f"[DirEnum] ⚠  Preferred wordlist not found: {PREFERRED_WORDLIST}. Using fallback medium list."
                )
            else:
                line_callback("[DirEnum] ℹ  Using requested DirBuster medium wordlist.")
        else:
            line_callback(
                f"[DirEnum] ⚠  Requested wordlist not found: {PREFERRED_WORDLIST}. Running feroxbuster without -w and relying on its config/defaults."
            )
        line_callback(f"[DirEnum] ℹ  Extensions: {EXTENSIONS}")
        line_callback(
            "[DirEnum] ℹ  Medium wordlist + full extension set can take time. "
            "If no new paths are found for 30 seconds, ReconPilot stops DirEnum and continues."
        )

        for idx, url in enumerate(urls, start=1):
            if stopped(stop_evt):
                break
            safe = _safe_name(url)
            raw_out = out_dir / f"{safe}.txt"
            cmd = ["feroxbuster", "-u", url, "-k", "-x", EXTENSIONS, "--depth", "1", "--no-state", "--json", "-o", str(raw_out)]
            if wl:
                cmd[3:3] = ["-w", wl]

            log.info(f"[DirEnum] {' '.join(cmd)}")
            line_callback(f"[DirEnum] ▶  {' '.join(cmd)}")
            try:
                proc = popen_scan(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                start_stop_watcher(proc, stop_evt, line_callback, "DirEnum")

                heartbeat_stop = threading.Event()
                started = time.time()
                target_start_count = len(all_rows)
                last_finding_time = [started]
                watchdog_reason = {"message": ""}

                def _heartbeat_watchdog() -> None:
                    while not heartbeat_stop.wait(HEARTBEAT_SECONDS):
                        if stopped(stop_evt):
                            return
                        if proc.poll() is not None:
                            return

                        elapsed = int(time.time() - started)
                        idle_for = int(time.time() - last_finding_time[0])
                        found_here = len(all_rows) - target_start_count

                        if idle_for >= NO_FINDING_LIMIT_SECONDS:
                            watchdog_reason["message"] = (
                                f"[DirEnum] ⚠  No new findings for {NO_FINDING_LIMIT_SECONDS}s on {url}; "
                                "stopping feroxbuster for this target and continuing."
                            )
                            line_callback(watchdog_reason["message"])
                            kill_process_tree(proc)
                            return

                        line_callback(
                            f"[DirEnum] … still running {url} "
                            f"({elapsed}s elapsed, {found_here} finding(s), {idle_for}s since last new finding)."
                        )

                threading.Thread(target=_heartbeat_watchdog, daemon=True).start()
                try:
                    for line in proc.stdout:  # type: ignore[union-attr]
                        if stopped(stop_evt):
                            kill_process_tree(proc)
                            done_callback(all_rows)
                            return
                        s = line.rstrip()
                        if not s:
                            continue
                        row = _parse_line(s, base_url=url)
                        if row and row.get("url"):
                            key = row["url"]
                            if key not in seen_result:
                                seen_result.add(key)
                                all_rows.append(row)
                                all_urls.append(key)
                                last_finding_time[0] = time.time()
                                status = f" [{row.get('status')}]" if row.get("status") else ""
                                metric_text = f" (size={row.get('size')})" if row.get("size") else ""
                                line_callback(f"[DirEnum]  FOUND  {key}{status}{metric_text}")
                        else:
                            log.debug(f"[DirEnum] {s}")
                    proc.wait()

                    # Some feroxbuster versions write JSON/results only to -o
                    # when --json is used. Re-read the saved file so GUI/report
                    # rows still get status and size even when
                    # stdout was quiet.
                    for saved_row in _parse_saved_results(raw_out, base_url=url):
                        key = saved_row.get("url", "")
                        if key and key not in seen_result:
                            seen_result.add(key)
                            all_rows.append(saved_row)
                            all_urls.append(key)
                            status = f" [{saved_row.get('status')}]" if saved_row.get("status") else ""
                            metric_text = f" (size={saved_row.get('size')})" if saved_row.get("size") else ""
                            line_callback(f"[DirEnum]  FOUND  {key}{status}{metric_text}")
                finally:
                    heartbeat_stop.set()
            except Exception as exc:
                log.error(f"[DirEnum] {exc}")
                line_callback(f"[DirEnum] ✘ Error scanning {url}: {exc}")

            line_callback(f"[DirEnum] ↓  Target progress: {idx}/{len(urls)} ({len(all_rows)} total finding(s))")

        out_json = Path(output_dir) / "feroxbuster_results.json"
        out_urls = Path(output_dir) / "feroxbuster_urls.txt"
        try:
            out_json.write_text(json.dumps(all_rows, indent=2), encoding="utf-8")
            out_urls.write_text("\n".join(sorted(set(all_urls))) + ("\n" if all_urls else ""), encoding="utf-8")
        except Exception as exc:
            log.debug(f"[DirEnum] could not save results: {exc}")

        line_callback(f"[DirEnum] ✔  {len(all_rows)} path(s) found.")
        line_callback(f"[DirEnum] ℹ  Saved URLs → {out_urls}")
        done_callback(all_rows)

    threading.Thread(target=_run, daemon=True).start()
