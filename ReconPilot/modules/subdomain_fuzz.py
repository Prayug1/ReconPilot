from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped

WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
]


def is_ffuf_available() -> bool:
    return shutil.which("ffuf") is not None


def _wordlist() -> str | None:
    for path in WORDLIST_CANDIDATES:
        if Path(path).exists():
            return path
    return None


def _target_parts(target: str) -> tuple[str, str, bool]:
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else "//" + raw)
    host = (parsed.hostname or raw.split("/")[0].split(":")[0]).strip("[]")
    scheme = parsed.scheme or "http"
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return host, scheme, is_ip


def _base_url(web_targets: list[dict], host: str, scheme: str) -> str:
    for row in web_targets or []:
        if isinstance(row, dict):
            u = str(row.get("url", "")).strip().rstrip("/")
            if u.startswith(("http://", "https://")):
                return u
    return f"{scheme or 'http'}://{host}"


def run_subdomain_fuzz(
    target: str,
    web_targets: list[dict],
    output_dir: str,
    log: ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt: threading.Event | None = None,
) -> None:
    """Run ffuf Host-header subdomain/vhost fuzzing for domain targets only."""

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return

        host, scheme, is_ip = _target_parts(target)
        if is_ip:
            line_callback("[SubFuzz] ⊘  Target is an IP address; subdomain/vhost fuzzing skipped.")
            done_callback([])
            return
        if not host or "." not in host:
            line_callback("[SubFuzz] ⊘  Target is not a domain; subdomain/vhost fuzzing skipped.")
            done_callback([])
            return
        if not is_ffuf_available():
            msg = "✘ ffuf not found on PATH. Install ffuf and retry."
            log.error(msg)
            line_callback(f"[SubFuzz] {msg}")
            done_callback([])
            return

        wl = _wordlist()
        if not wl:
            line_callback("[SubFuzz] ✘ No subdomain wordlist found. Install seclists and retry.")
            done_callback([])
            return

        base = _base_url(web_targets, host, scheme)
        out_json = Path(output_dir) / "ffuf_subdomain_fuzz.json"
        fuzz_host = f"FUZZ.{host}"
        cmd = [
            "ffuf", "-u", base.rstrip("/") + "/",
            "-H", f"Host: {fuzz_host}",
            "-w", wl,
            "-mc", "200,204,301,302,307,308,401,403",
            "-of", "json", "-o", str(out_json),
            "-s",
        ]

        log.info(f"[SubFuzz] {' '.join(cmd)}")
        line_callback(f"[SubFuzz] ▶  ffuf -u {base.rstrip('/')}/ -H 'Host: FUZZ.{host}' -w {wl}")

        try:
            proc = popen_scan(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            start_stop_watcher(proc, stop_evt, line_callback, "SubFuzz")
            for line in proc.stdout:  # type: ignore[union-attr]
                if stopped(stop_evt):
                    kill_process_tree(proc)
                    done_callback([])
                    return
                s = line.rstrip()
                if s:
                    log.debug(f"[SubFuzz] {s}")
            proc.wait()
        except Exception as exc:
            log.error(f"[SubFuzz] {exc}")
            line_callback(f"[SubFuzz] ✘ Error: {exc}")
            done_callback([])
            return

        rows: list[dict] = []
        try:
            obj = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
            for r in obj.get("results", []) or []:
                inp = r.get("input", {}) or {}
                fuzz = inp.get("FUZZ") or inp.get("fuzz") or ""
                found_host = f"{fuzz}.{host}" if fuzz else ""
                row = {
                    "host": found_host,
                    "status": r.get("status", ""),
                    "size": r.get("length", ""),
                    "url": r.get("url", base),
                }
                if found_host:
                    rows.append(row)
        except Exception as exc:
            log.debug(f"[SubFuzz] could not parse ffuf JSON: {exc}")

        out_hosts = Path(output_dir) / "ffuf_subdomain_fuzz_hosts.txt"
        try:
            out_hosts.write_text("\n".join(sorted({r['host'] for r in rows if r.get('host')})) + ("\n" if rows else ""), encoding="utf-8")
        except Exception:
            pass

        for r in rows[:50]:
            line_callback(f"[SubFuzz]  FOUND  {r.get('host')} [{r.get('status')}] size={r.get('size')}")
        if len(rows) > 50:
            line_callback(f"[SubFuzz]  … {len(rows) - 50} more result(s) saved to {out_json}")
        line_callback(f"[SubFuzz] ✔  {len(rows)} candidate subdomain/vhost result(s).")
        done_callback(rows)

    threading.Thread(target=_run, daemon=True).start()
