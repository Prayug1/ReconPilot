from __future__ import annotations

import hashlib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

from utils.logger import ReconLogger
from utils.process_control import stopped

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

# No hard request timeout: fetches/downloads run until they complete/fail naturally.
# Matches inline script src or href ending in .js
_JS_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
_DIRECT_JS_RE = re.compile(r'\.js(?:$|[?#])', re.I)
_STATIC_SKIP_RE = re.compile(r'\.(?:css|jpe?g|png|gif|svg|ico|webp|woff2?|ttf|eot|mp4|mp3|avi|mov|pdf|zip|tar|gz|7z|rar|sql|db)(?:$|[?#])', re.I)
DOWNLOAD_WORKERS = 10
MAX_JS_BYTES = 5 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ReconPilot/2.0"
ARCHIVE_SOURCES = {"wayback", "waybackurls"}


def _normalise_sources(value) -> list[str]:
    """Return lower-case source names from URL Harvest rows / fallback labels."""
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str):
        raw = [x.strip() for x in value.split(",") if x.strip()]
    else:
        raw = []
    out: list[str] = []
    for item in raw:
        name = str(item).strip().lower()
        if name and name not in out:
            out.append(name)
    return out


def _uses_wayback_archive(sources: list[str]) -> bool:
    """Wayback-discovered JS must be downloaded from Wayback, not live origin."""
    return any(src in ARCHIVE_SOURCES for src in sources)


def _wayback_archive_url(original_url: str) -> str:
    """Return Wayback raw/latest URL for an archived asset.

    The 0id_ URL asks the Wayback Machine for the closest/latest raw body for
    the original URL. ReconPilot intentionally does not fall back to the live
    origin for wayback/waybackurls discoveries, so archived JS is assessed as it
    was found by those historical sources.
    """
    return "https://web.archive.org/web/0id_/" + original_url.strip()


def _merge_sources(source_map: dict[str, set[str]], url: str, sources: list[str] | set[str] | tuple[str, ...]) -> None:
    bucket = source_map.setdefault(url, set())
    for src in sources:
        name = str(src).strip().lower()
        if name:
            bucket.add(name)


def _extract_js_from_html(base_url: str, html: str) -> list[str]:
    """Return absolute JS URLs referenced in an HTML page."""
    js_urls = []
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        tags = soup.find_all("script", src=True)
        for tag in tags:
            src = tag.get("src", "")
            if src:
                js_urls.append(urljoin(base_url, src))
    else:
        for m in _JS_RE.finditer(html):
            js_urls.append(urljoin(base_url, m.group(1)))

    seen, out = set(), []
    for u in js_urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _is_direct_js_url(url: str) -> bool:
    """True when a URL path points directly to a JavaScript file."""
    if not url:
        return False
    try:
        parts = urlparse(url.strip())
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return False
        return bool(_DIRECT_JS_RE.search(parts.path or ""))
    except Exception:
        return False


def _read_direct_js_from_files(output_dir: str, log: ReconLogger) -> dict[str, set[str]]:
    """Read direct .js URLs and preserve where each URL came from.

    URL Harvest writes all_urls_with_sources.json, which lets us distinguish
    Wayback API / waybackurls discoveries from live/passive sources. JS found by
    wayback or waybackurls is later downloaded through web.archive.org only.
    """
    out = Path(output_dir)
    found: dict[str, set[str]] = {}

    # Preferred source-aware URL Harvest output.
    src_json = out / "all_urls_with_sources.json"
    if src_json.exists():
        try:
            rows = json.loads(src_json.read_text(encoding="utf-8", errors="replace"))
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    url = str(row.get("url") or "").strip()
                    if not _is_direct_js_url(url):
                        continue
                    sources = _normalise_sources(row.get("sources") or row.get("source"))
                    if not sources:
                        sources = ["url_harvest"]
                    _merge_sources(found, url, sources)
        except Exception as exc:
            log.debug(f"[JSCollect] could not read source-aware JS URLs from {src_json}: {exc}")

    # Backward-compatible fallback: all_urls.txt has no source metadata.
    all_urls = out / "all_urls.txt"
    if all_urls.exists():
        try:
            for line in all_urls.read_text(encoding="utf-8", errors="replace").splitlines():
                url = line.strip()
                if _is_direct_js_url(url) and url not in found:
                    _merge_sources(found, url, ["url_harvest"] )
        except Exception as exc:
            log.debug(f"[JSCollect] could not read JS URLs from {all_urls}: {exc}")

    # CTF directory enumeration output is a live-origin source.
    ferox = out / "feroxbuster_urls.txt"
    if ferox.exists():
        try:
            for line in ferox.read_text(encoding="utf-8", errors="replace").splitlines():
                url = line.strip()
                if _is_direct_js_url(url):
                    _merge_sources(found, url, ["feroxbuster"] )
        except Exception as exc:
            log.debug(f"[JSCollect] could not read JS URLs from {ferox}: {exc}")

    return found


def _is_page_candidate_url(url: str) -> bool:
    """True for URLs worth fetching as HTML/script-tag sources."""
    if not url:
        return False
    try:
        parts = urlparse(url.strip())
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return False
        if _is_direct_js_url(url):
            return False
        # Skip obvious binary/static assets that cannot contain useful
        # <script src=...> references. Direct .js is already imported above.
        return not bool(_STATIC_SKIP_RE.search(parts.path or ""))
    except Exception:
        return False


def _read_page_targets_from_files(output_dir: str, log: ReconLogger) -> list[str]:
    """Read CTF enumerated directories/paths to fetch for script tags."""
    files = [
        Path(output_dir) / "ctf_web_targets.txt",
        Path(output_dir) / "feroxbuster_urls.txt",
    ]
    found: list[str] = []
    seen: set[str] = set()
    for path in files:
        if not path.exists():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                url = line.strip().rstrip("/")
                if _is_page_candidate_url(url) and url not in seen:
                    seen.add(url)
                    found.append(url)
        except Exception as exc:
            log.debug(f"[JSCollect] could not read page targets from {path}: {exc}")
    return found


def _download_one_js(url: str, sources: list[str], cache_dir: Path, stop_evt: threading.Event | None) -> dict:
    """Download one JS URL and return a manifest row with success/failure details."""
    if stopped(stop_evt):
        return {"url": url, "status": "skipped", "error": "stop requested"}

    safe = hashlib.md5(url.encode("utf-8", errors="ignore")).hexdigest() + ".js"
    out_path = cache_dir / safe
    source_list = sorted(set(_normalise_sources(list(sources))))
    archive_mode = _uses_wayback_archive(source_list)
    download_url = _wayback_archive_url(url) if archive_mode else url
    row = {
        "url": url,
        "download_url": download_url,
        "download_mode": "wayback_archive" if archive_mode else "live_origin",
        "sources": source_list,
        "status": "failed",
        "path": str(out_path),
        "bytes": 0,
        "http_status": None,
        "content_type": None,
        "truncated": False,
        "error": None,
    }

    try:
        resp = requests.get(
            download_url,
            verify=False,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )
        row["http_status"] = resp.status_code
        row["content_type"] = resp.headers.get("content-type", "")

        if resp.status_code >= 400:
            row["error"] = f"HTTP {resp.status_code}"
            return row

        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if stopped(stop_evt):
                row["status"] = "skipped"
                row["error"] = "stop requested"
                return row
            if not chunk:
                continue
            remaining = MAX_JS_BYTES - total
            if remaining <= 0:
                row["truncated"] = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                row["truncated"] = True
                break
            chunks.append(chunk)
            total += len(chunk)

        body = b"".join(chunks)
        out_path.write_bytes(body)
        row["status"] = "downloaded"
        row["bytes"] = len(body)
        row["error"] = None
        return row
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        return row


def _save_download_artifacts(output_dir: str, manifest: list[dict], log: ReconLogger) -> tuple[Path, Path]:
    out = Path(output_dir)
    manifest_path = out / "js_download_manifest.json"
    failures_path = out / "js_download_failures.json"

    failures = [r for r in manifest if r.get("status") != "downloaded"]
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        failures_path.write_text(json.dumps(failures, indent=2), encoding="utf-8")
    except Exception as exc:
        log.debug(f"[JSCollect] could not save JS download manifest/failures: {exc}")
    return manifest_path, failures_path


def _download_js_files(
    output_dir: str,
    urls: list[str],
    source_map: dict[str, set[str]],
    log: ReconLogger,
    line_callback: Callable[[str], None],
    stop_evt: threading.Event | None,
) -> list[dict]:
    """Download collected JS URLs as part of JS Collect, with progress and failure reasons."""
    out = Path(output_dir)
    cache_dir = out / "js" / "downloaded"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if not urls:
        manifest_path, failures_path = _save_download_artifacts(output_dir, [], log)
        line_callback(f"[JSCollect] ℹ  No JS URLs to download. Manifest saved → {manifest_path}")
        return []

    archive_count = sum(1 for u in urls if _uses_wayback_archive(_normalise_sources(list(source_map.get(u, set())))))
    line_callback(f"[JSCollect] ▶  Downloading {len(urls)} JS file(s) (up to {DOWNLOAD_WORKERS} in parallel)…")
    if archive_count:
        line_callback(f"[JSCollect] ℹ  {archive_count} Wayback/waybackurls JS file(s) will be downloaded from web.archive.org only.")

    manifest: list[dict] = []
    ok = 0
    failed = 0
    completed = 0
    progress_every = 10 if len(urls) <= 200 else 25

    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as ex:
        futures = {
            ex.submit(_download_one_js, url, sorted(source_map.get(url, set())), cache_dir, stop_evt): url
            for url in urls
        }
        for fut in as_completed(futures):
            row = fut.result()
            manifest.append(row)
            completed += 1

            if row.get("status") == "downloaded":
                ok += 1
            else:
                failed += 1
                reason = row.get("error") or row.get("status") or "unknown error"
                mode = row.get("download_mode") or "live_origin"
                if mode == "wayback_archive":
                    line_callback(f"[JSCollect]   ✘  {row.get('url')} — {reason} (Wayback archive only)")
                else:
                    line_callback(f"[JSCollect]   ✘  {row.get('url')} — {reason}")

            if completed == 1 or completed == len(urls) or completed % progress_every == 0:
                line_callback(f"[JSCollect]   ↓  Download progress: {completed}/{len(urls)} "
                              f"(downloaded={ok}, failed={failed})")

            if stopped(stop_evt):
                for pending in futures:
                    pending.cancel()
                break

    manifest.sort(key=lambda r: r.get("url", ""))
    manifest_path, failures_path = _save_download_artifacts(output_dir, manifest, log)
    line_callback(f"[JSCollect] ✔  Downloaded {ok} / {len(urls)} JS file(s) ({failed} failed).")
    line_callback(f"[JSCollect] ℹ  Download manifest → {manifest_path}")
    if failed:
        line_callback(f"[JSCollect] ℹ  Failure reasons saved → {failures_path}")
    return manifest


def run_js_collector(
    target:        str,
    probe_results: list[dict],
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Collect and download JavaScript files from multiple sources:
      1. Direct .js URLs already found by URL Harvest / CTF DirEnum outputs.
         Wayback API / waybackurls JS is downloaded from web.archive.org only.
      2. <script src="...js"> references extracted from live HTTP Probe pages.
      3. CTF mode: <script src="...js"> references extracted from feroxbuster-enumerated paths.

    The collector now owns the download step. It writes:
      - js_files.txt                  collected JS URLs
      - js_files_with_sources.json     source/download-mode metadata
      - js/downloaded/*.js            downloaded JS bodies
      - js_download_manifest.json     per-file status, path, bytes, HTTP status, error
      - js_download_failures.json     failed/skipped downloads with reasons

    JS Secret Scanner then scans the downloaded files only; it does not download.
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not _HAS_REQUESTS:
            line_callback("[JSCollect] ✘ 'requests' library not installed.")
            done_callback([])
            return

        all_js: set[str] = set()
        source_map: dict[str, set[str]] = {}

        # ── Source 1: direct .js URLs from URL Harvest / CTF directory enum ─
        direct_js = _read_direct_js_from_files(output_dir, log)
        if direct_js:
            archive_count = sum(1 for srcs in direct_js.values() if _uses_wayback_archive(_normalise_sources(list(srcs))))
            msg = f"[JSCollect] ▶  Importing {len(direct_js)} direct .js URL(s) from saved URL outputs"
            if archive_count:
                msg += f" ({archive_count} from Wayback/waybackurls archive)"
            line_callback(msg + " …")
            for js_url, srcs in direct_js.items():
                if stopped(stop_evt):
                    break
                all_js.add(js_url)
                _merge_sources(source_map, js_url, srcs)
        else:
            line_callback("[JSCollect] ℹ  No direct .js URLs found in saved URL outputs.")

        if stopped(stop_evt):
            _save_and_download(output_dir, all_js, source_map, log, line_callback, done_callback, stop_evt)
            return

        # ── Source 2: fetch live HTTP Probe pages and parse script tags ────
        def _is_live_probe(row):
            if not isinstance(row, dict) or not row.get("url"):
                return False
            status = row.get("status", 0)
            if isinstance(status, str):
                if status.upper() == "LIVE":
                    return True
                # httpx-toolkit may return redirect chains like "301,200".
                codes = [int(x) for x in re.findall(r"\d{3}", status)]
                return bool(codes and any(200 <= c < 400 for c in codes))
            try:
                return int(status) < 400
            except Exception:
                return False

        targets: list[str] = []
        seen_targets: set[str] = set()

        for row in probe_results:
            if _is_live_probe(row):
                u = str(row.get("url", "")).strip().rstrip("/")
                if _is_page_candidate_url(u) and u not in seen_targets:
                    seen_targets.add(u)
                    targets.append(u)

        ctf_page_targets = _read_page_targets_from_files(output_dir, log)
        added_ctf_targets = 0
        for u in ctf_page_targets:
            if u not in seen_targets:
                seen_targets.add(u)
                targets.append(u)
                added_ctf_targets += 1

        if added_ctf_targets:
            line_callback(f"[JSCollect] ▶  Added {added_ctf_targets} CTF enumerated path(s) for script-tag extraction …")

        if targets:
            line_callback(f"[JSCollect] ▶  Extracting script tags from {len(targets)} page/path target(s) …")
            log.info(f"[JSCollect] Starting JS collection from {len(targets)} page/path targets plus direct .js URLs")
        else:
            line_callback("[JSCollect] ℹ  No live pages or CTF enumerated paths available for script-tag extraction.")

        for idx, url in enumerate(targets, start=1):
            if stopped(stop_evt):
                line_callback(f"[JSCollect] ⚠  Stop requested after {idx - 1}/{len(targets)} live page(s).")
                break
            try:
                resp = requests.get(
                    url,
                    verify=False,
                    headers={"User-Agent": USER_AGENT},
                )
                js_found = _extract_js_from_html(url, resp.text)
                for js_url in js_found:
                    all_js.add(js_url)
                    _merge_sources(source_map, js_url, ["page_script"])
                if idx == 1 or idx == len(targets) or idx % 25 == 0:
                    line_callback(f"[JSCollect]   ↓  Page scan progress: {idx}/{len(targets)} "
                                  f"({len(all_js)} unique JS URL(s) so far)")
            except Exception as exc:
                log.debug(f"[JSCollect] {url} failed: {exc}")
                line_callback(f"[JSCollect]   ✘  Could not fetch page {url} — {type(exc).__name__}: {exc}")

        _save_and_download(output_dir, all_js, source_map, log, line_callback, done_callback, stop_evt)

    threading.Thread(target=_run, daemon=True).start()


def _save_and_download(
    output_dir: str,
    all_js: set[str],
    source_map: dict[str, set[str]],
    log: ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt: threading.Event | None,
) -> None:
    sorted_js = sorted(all_js)
    out = Path(output_dir)
    out_file = out / "js_files.txt"
    out_file.write_text("\n".join(sorted_js) + ("\n" if sorted_js else ""), encoding="utf-8")
    meta_rows = []
    for js_url in sorted_js:
        sources = sorted(source_map.get(js_url, set()))
        archive_mode = _uses_wayback_archive(_normalise_sources(sources))
        meta_rows.append({
            "url": js_url,
            "sources": sources,
            "download_mode": "wayback_archive" if archive_mode else "live_origin",
            "download_url": _wayback_archive_url(js_url) if archive_mode else js_url,
        })
    meta_file = out / "js_files_with_sources.json"
    meta_file.write_text(json.dumps(meta_rows, indent=2), encoding="utf-8")
    log.info(f"[JSCollect] Saved {len(sorted_js)} JS URLs → {out_file}")
    line_callback(f"[JSCollect] ✔  {len(sorted_js)} JS URL(s) collected.")
    line_callback(f"[JSCollect] ℹ  Saved JS URLs → {out_file}")
    line_callback(f"[JSCollect] ℹ  Saved JS source metadata → {meta_file}")

    _download_js_files(output_dir, sorted_js, source_map, log, line_callback, stop_evt)
    done_callback(sorted_js)
