from __future__ import annotations

import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable

from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped

# This HTTP Probe intentionally uses the ProjectDiscovery Kali binary in the
# richer form the user runs manually:
#
#     httpx-toolkit -l subdomains.txt -silent -mc 200 -status-code -title -tech-detect -follow-redirects
#
# ReconPilot parses the live URL, HTTP status chain, page title, and detected
# technologies from httpx-toolkit's normal text output.

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_BRACKET_RE = re.compile(r"\[([^\]]*)\]")
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(text: str) -> str:
    """Remove terminal ANSI escape sequences from httpx-toolkit output."""
    return _ANSI_RE.sub("", text or "")


def _is_url_for_target(url: str, target: str) -> bool:
    """Keep only URLs that belong to the target root domain or its subdomains."""
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower().strip(".")
        root = target.lower().strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip(".")
        return host == root or host.endswith("." + root)
    except Exception:
        return False


def _clean_url(url: str) -> str:
    return url.strip().rstrip(".,;)]}>\'\"")


def _looks_like_tech_field(value: str) -> bool:
    """Best-effort detection for httpx lines where title is empty and only tech is emitted."""
    v = (value or "").strip()
    if not v:
        return False
    lower = v.lower()
    tech_markers = (
        "cloudflare", "http/", "react", "node.js", "express", "jquery",
        "bootstrap", "wordpress", "nginx", "apache", "jitsi", "tableau",
        "select2", "popper", "next.js", "vue", "angular", "php", "python",
    )
    return "," in v and any(marker in lower for marker in tech_markers)

def _parse_httpx_line(raw: str, target: str) -> dict | None:
    """Parse httpx-toolkit output with URL, status, title, and tech fields."""
    raw = _strip_ansi(raw or "")
    m = _URL_RE.search(raw)
    if not m:
        return None

    url = _clean_url(m.group(0))
    if not url or not _is_url_for_target(url, target):
        return None

    tail = raw[m.end():]
    fields = [x.strip() for x in _BRACKET_RE.findall(tail)]

    status = fields[0] if len(fields) >= 1 else "LIVE"
    title = ""
    tech = ""
    if len(fields) >= 3:
        title = fields[1]
        tech = fields[2]
    elif len(fields) == 2:
        if _looks_like_tech_field(fields[1]):
            tech = fields[1]
        else:
            title = fields[1]

    return {
        "url": url,
        "status": status,
        "title": title,
        "server": "",
        "tech": tech,
        "latency": "",
    }



def _write_probe_input(target: str, subdomains: list[str], output_dir: str) -> Path:
    """Return the input list passed to httpx-toolkit.

    Preference order:
    1. Use output/<target>/subdomains.txt if it already exists and is non-empty.
       This matches the requested command style: httpx-toolkit -l subdomains.txt
    2. Otherwise create output/<target>/http_probe_targets.txt from the target and
       any in-memory subdomains, so HTTP Probe still works if Subdomain Enum was
       not selected.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    sub_file = out / "subdomains.txt"
    if sub_file.exists() and sub_file.read_text(encoding="utf-8", errors="replace").strip():
        return sub_file

    hosts: list[str] = []
    seen: set[str] = set()
    for item in [target] + list(subdomains):
        h = str(item or "").strip()
        if not h:
            continue
        h = h.replace("http://", "").replace("https://", "").split("/")[0].strip()
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)

    fallback = out / "http_probe_targets.txt"
    fallback.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    return fallback


def run_http_probe(
    target:        str,
    subdomains:    list[str],
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    prog_callback: Callable[[int], None] | None = None,
    retries:       int = 1,  # kept for ScanManager compatibility; not used by httpx-toolkit simple mode
    stop_evt:      threading.Event | None = None,
) -> None:

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return

        httpx_bin = shutil.which("httpx-toolkit")
        if not httpx_bin:
            msg = "✘ httpx-toolkit not found on PATH. Install it with: sudo apt install httpx-toolkit"
            log.error(f"[HTTPProbe] {msg}")
            line_callback(f"[HTTPProbe] {msg}")
            done_callback([])
            return

        input_file = _write_probe_input(target, subdomains, output_dir)

        out = Path(output_dir)
        live_file = out / "live_urls.txt"
        jsonl_file = out / "http_probe.jsonl"

        # Run from output/<target>/ so the visible command matches manual usage:
        # httpx-toolkit -l subdomains.txt ...
        input_arg = input_file.name if input_file.parent.resolve() == out.resolve() else str(input_file)
        cmd = [
            "httpx-toolkit",
            "-l", input_arg,
            "-silent",
            "-mc", "200",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
        ]

        line_callback(f"[HTTPProbe] ▶  {' '.join(cmd)}")
        line_callback("[HTTPProbe] ℹ  Probing live URLs with status, title, technology detection, and redirects enabled.")
        log.info(f"[HTTPProbe] {' '.join(cmd)}")

        results: list[dict] = []
        seen_urls: set[str] = set()
        proc: subprocess.Popen | None = None

        try:
            proc = popen_scan(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(out),
            )
            start_stop_watcher(proc, stop_evt, line_callback, "HTTPProbe")

            for line in proc.stdout:  # type: ignore[union-attr]
                if stopped(stop_evt):
                    kill_process_tree(proc)
                    done_callback(results)
                    return

                raw_original = line.rstrip()
                raw = _strip_ansi(raw_original).strip()
                if not raw:
                    continue

                # Keep the transcript in scan.log for debugging, but strip ANSI
                # colour escapes so logs, parsing, saved JSON, and the UI table
                # never contain sequences like "\x1b[32m200\x1b[0m".
                log.debug(f"[HTTPProbe/httpx] {raw}")

                item = _parse_httpx_line(raw, target)
                if not item:
                    continue

                url = item["url"]
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                results.append(item)

                status = item.get("status") or "LIVE"
                title = item.get("title") or ""
                tech = item.get("tech") or ""
                extra = ""
                if title:
                    extra += f" [{title[:60]}]"
                if tech:
                    extra += f" [{tech[:80]}]"
                line_callback(f"[HTTPProbe]  LIVE  {url[:90]} [{status}]{extra}")

            rc = proc.wait()
            if stopped(stop_evt):
                done_callback(results)
                return
            if rc not in (0, None):
                line_callback(f"[HTTPProbe] ⚠  httpx-toolkit exited with code {rc}; keeping collected live URLs.")

        except Exception as exc:
            if proc is not None:
                kill_process_tree(proc)
            log.error(f"[HTTPProbe] {exc}")
            line_callback(f"[HTTPProbe] ✘ {exc}")
            done_callback(results)
            return

        results.sort(key=lambda x: x.get("url", ""))

        try:
            live_file.write_text("\n".join(r["url"] for r in results) + ("\n" if results else ""), encoding="utf-8")
            # JSONL file without needing json import in a loop-heavy path.
            import json
            jsonl_file.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in results), encoding="utf-8")
        except Exception as exc:
            log.debug(f"[HTTPProbe] could not save live URL files: {exc}")

        if prog_callback:
            prog_callback(100)
        line_callback(f"[HTTPProbe] ✔  {len(results)} live URL(s) found.")
        line_callback(f"[HTTPProbe] ℹ  Saved live URLs → {live_file}")
        done_callback(results)

    threading.Thread(target=_run, daemon=True).start()
