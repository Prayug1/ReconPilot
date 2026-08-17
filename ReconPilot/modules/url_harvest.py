"""
URL harvesting — pulls historical / archived URLs for the target
from multiple public sources, and optionally runs a simple active crawl with gospider.

Sources used (each runs until it finishes naturally or Stop Scan is pressed):
  1. Wayback Machine CDX API
  2. URLScan.io public search
  3. AlienVault OTX passive DNS
  4. gau         (if installed)
  5. waybackurls (if installed)
  6. gospider    (if installed; active crawl seeded with full http(s) URLs)

Most sources are passive. gospider is active and must be called with a full
URL such as `gospider -s https://www.example.com`; passing only example.com
will not work reliably.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import queue
import html
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from utils.logger import ReconLogger
from utils.parser import split_host_port
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped

WAYBACK_PAGE_SIZE  = 5000
WAYBACK_MAX_PAGES  = 10
URLSCAN_PAGE_SIZE  = 10000
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ReconPilot/1.0"

NOISY_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".mp4", ".mp3", ".webm", ".m4a", ".m4v",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf",
)


def _is_noisy(url: str) -> bool:
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return any(path.endswith(ext) for ext in NOISY_EXTENSIONS)




def _normalize_url(url: str) -> str | None:
    """Return a canonical URL string used for duplicate filtering.

    Passive sources often return the same URL with small formatting differences,
    for example mixed-case hosts, URL fragments, empty paths, or default ports.
    This normalisation keeps the URL semantically useful while avoiding duplicate
    rows in the UI/report/all_urls.txt.
    """
    if not url:
        return None
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return None

    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        return None

    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None

    host = (parts.hostname or "").strip(".").lower()
    if not host:
        return None

    netloc = host
    if parts.port and not ((scheme == "http" and parts.port == 80) or
                           (scheme == "https" and parts.port == 443)):
        netloc = f"{host}:{parts.port}"

    # Keep the encoded path intact but ensure root URLs are represented as /.
    path = parts.path or "/"

    # Drop URL fragments. They are client-side only and cause noisy duplicates.
    # Sort query parameters to collapse duplicates like ?b=2&a=1 and ?a=1&b=2.
    query = parts.query
    if query:
        try:
            qsl = urllib.parse.parse_qsl(query, keep_blank_values=True)
            query = urllib.parse.urlencode(sorted(qsl), doseq=True)
        except Exception:
            pass

    normalised = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    return normalised


def _add_url(out: set[str], url: str) -> None:
    """Normalise, filter noise, and add a URL to a result set."""
    normalised = _normalize_url(url)
    if normalised and not _is_noisy(normalised):
        out.add(normalised)


def _url_belongs_to_domain(url: str, domain: str) -> bool:
    """Return True when a URL belongs to the target domain or its subdomains."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").strip(".").lower()
    except Exception:
        return False
    domain = domain.strip(".").lower()
    return host == domain or host.endswith(f".{domain}")


def _url_belongs_to_hosts(url: str, allowed_hosts: set[str]) -> bool:
    """Return True when a URL belongs to one of the exact CTF target hosts."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").strip(".").lower()
    except Exception:
        return False
    return host in allowed_hosts


def _add_allowed_host_url(out: set[str], url: str, allowed_hosts: set[str]) -> None:
    """Normalise/filter a URL and add it only for the CTF target host set."""
    normalised = _normalize_url(url)
    if normalised and not _is_noisy(normalised) and _url_belongs_to_hosts(normalised, allowed_hosts):
        out.add(normalised)


def _seed_hosts(seeds: list[str]) -> set[str]:
    hosts: set[str] = set()
    for seed in seeds:
        try:
            h = (urllib.parse.urlsplit(seed).hostname or "").strip(".").lower()
            if h:
                hosts.add(h)
        except Exception:
            pass
    return hosts


def _add_domain_url(out: set[str], url: str, domain: str) -> None:
    """Normalise/filter a URL and add it only if it belongs to this target."""
    normalised = _normalize_url(url)
    if normalised and not _is_noisy(normalised) and _url_belongs_to_domain(normalised, domain):
        out.add(normalised)


def _http_get(url: str) -> bytes | None:
    """Fetch a URL without a hard timeout. Stop Scan will stop between requests."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read()
    except Exception:
        return None


def _candidate_bin_dirs() -> list[str]:
    """Return common user-bin locations even when ReconPilot is launched from a GUI.

    GUI launchers on Kali/Linux often do not inherit ~/.bashrc or ~/.zshrc,
    so Go tools installed in ~/go/bin can be available in a terminal but invisible
    to the Python process. We explicitly check those locations for gau and
    waybackurls.
    """
    dirs: list[str] = []
    home = str(Path.home())

    for d in (
        os.environ.get("GOBIN", ""),
        os.path.join(os.environ.get("GOPATH", os.path.join(home, "go")), "bin"),
        os.path.join(home, ".local", "bin"),
        os.path.join(home, "go", "bin"),
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ):
        if d and d not in dirs:
            dirs.append(d)
    return dirs


def _tool_path(name: str) -> str | None:
    """Find a CLI tool using PATH plus common Go/user install paths."""
    found = shutil.which(name)
    if found:
        return found

    for d in _candidate_bin_dirs():
        candidate = Path(d) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    path_parts = _candidate_bin_dirs() + env.get("PATH", "").split(os.pathsep)
    seen: set[str] = set()
    clean_parts: list[str] = []
    for part in path_parts:
        if part and part not in seen:
            seen.add(part)
            clean_parts.append(part)
    env["PATH"] = os.pathsep.join(clean_parts)
    return env


def _wayback_urls(domain: str, line_cb, stop_evt) -> set[str]:
    out: set[str] = set()
    base = ("https://web.archive.org/cdx/search/cdx"
            f"?url=*.{urllib.parse.quote(domain)}/*"
            "&output=json&fl=original&collapse=urlkey"
            f"&limit={WAYBACK_PAGE_SIZE}")
    for page in range(WAYBACK_MAX_PAGES):
        if stop_evt and stop_evt.is_set():
            break
        body = _http_get(base + f"&page={page}")
        if not body:
            break
        try:
            data = json.loads(body)
        except Exception:
            break
        if not data or len(data) <= 1:
            break
        before = len(out)
        for row in data[1:]:
            if row and row[0]:
                _add_domain_url(out, row[0], domain)
        if len(out) == before:
            break
    return out


def _urlscan_urls(domain: str, line_cb, stop_evt) -> set[str]:
    out: set[str] = set()
    q = urllib.parse.quote(f"domain:{domain}")
    body = _http_get(f"https://urlscan.io/api/v1/search/?q={q}&size={URLSCAN_PAGE_SIZE}")
    if not body:
        return out
    try:
        data = json.loads(body)
    except Exception:
        return out
    for result in data.get("results", []):
        if stop_evt and stop_evt.is_set():
            break
        u = (result.get("page") or {}).get("url")
        if u:
            _add_domain_url(out, u, domain)
        u2 = (result.get("task") or {}).get("url")
        if u2:
            _add_domain_url(out, u2, domain)
    return out


def _otx_urls(domain: str, line_cb, stop_evt) -> set[str]:
    out: set[str] = set()
    page = 1
    while page <= 20:
        if stop_evt and stop_evt.is_set():
            break
        api = (f"https://otx.alienvault.com/api/v1/indicators/"
               f"hostname/{urllib.parse.quote(domain)}/url_list"
               f"?limit=50&page={page}")
        body = _http_get(api)
        if not body:
            break
        try:
            data = json.loads(body)
        except Exception:
            break
        urls = data.get("url_list") or []
        if not urls:
            break
        before = len(out)
        for row in urls:
            u = row.get("url") if isinstance(row, dict) else None
            if u:
                _add_domain_url(out, u, domain)
        if len(out) == before:
            break
        if not data.get("has_next"):
            break
        page += 1
    return out


def _run_cmd(argv: list[str], stop_evt=None, merge_stderr: bool = False) -> list[str]:
    """Run a URL collector CLI until it exits naturally or Stop Scan is pressed.

    Output is streamed line by line while the process is running, so tools such
    as waybackurls, gau, and gospider can run for as long as they need without
    ReconPilot killing them because of a timer.
    """
    if stopped(stop_evt):
        return []

    lines: list[str] = []
    proc = None
    try:
        proc = popen_scan(
            argv,
            stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if merge_stderr else subprocess.DEVNULL),
            text=True,
            bufsize=1,
            env=_subprocess_env(),
        )
        start_stop_watcher(proc, stop_evt, None, "URLHarvest")

        q: queue.Queue[str | None] = queue.Queue()

        def _reader():
            try:
                assert proc is not None and proc.stdout is not None
                for line in proc.stdout:
                    q.put(line)
            except Exception:
                pass
            finally:
                q.put(None)

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()

        reader_done = False
        while True:
            if stopped(stop_evt):
                kill_process_tree(proc)
                break

            try:
                item = q.get(timeout=0.2)
            except queue.Empty:
                if proc.poll() is not None and reader_done:
                    break
                continue

            if item is None:
                reader_done = True
            else:
                clean = item.strip()
                if clean:
                    lines.append(clean)

            if reader_done and proc.poll() is not None:
                break

        # Drain queued lines that were read before exit/stop.
        while True:
            try:
                item = q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                continue
            clean = item.strip()
            if clean:
                lines.append(clean)

        if stopped(stop_evt):
            return []
        return lines
    except Exception:
        if proc is not None:
            try:
                kill_process_tree(proc)
            except Exception:
                pass
        return lines


def _gau_urls(domain: str, line_cb, stop_evt) -> set[str]:
    gau_bin = _tool_path("gau")
    if not gau_bin:
        line_cb("[URLHarvest]   gau         → not found on PATH / common Go paths")
        return set()
    blacklist = ",".join(ext.lstrip(".") for ext in NOISY_EXTENSIONS)
    lines = _run_cmd(
        [gau_bin, "--subs", "--threads", "10",
         "--blacklist", blacklist, domain],
        stop_evt=stop_evt,
    )
    out: set[str] = set()
    for u in lines:
        _add_domain_url(out, u, domain)
    return out


def _waybackurls(domain: str, line_cb, stop_evt) -> set[str]:
    wb_bin = _tool_path("waybackurls")
    if not wb_bin:
        line_cb("[URLHarvest]   waybackurls → not found on PATH / common Go paths")
        return set()
    try:
        lines = _run_cmd([wb_bin, domain], stop_evt=stop_evt)
        out: set[str] = set()
        for ln in lines:
            _add_domain_url(out, ln, domain)
        return out
    except Exception:
        return set()


def _gospider_seed_urls(domain: str) -> list[str]:
    """Build full URL seeds for gospider.

    gospider requires a scheme, for example:
        gospider -s https://www.example.com

    ReconPilot therefore never passes only `example.com`. It tries the apex and
    www host over HTTPS and HTTP, then deduplicates while preserving order.
    """
    domain = domain.strip(".")
    hosts = [domain]
    if not domain.lower().startswith("www."):
        hosts.insert(0, f"www.{domain}")

    seeds: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        for scheme in ("https", "http"):
            seed = f"{scheme}://{host}"
            if seed not in seen:
                seen.add(seed)
                seeds.append(seed)
    return seeds



def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text or "")


def _gospider_base_cmd(gs_bin: str, seed: str) -> list[str]:
    """Build the exact simple gospider command requested by the user.

    We intentionally do not add depth, concurrency, sitemap, robots,
    include-subs, other-source, or output flags. ReconPilot only runs:
        gospider -s https://www.example.com
    using full http(s) seed URLs.
    """
    return [gs_bin, "-s", seed]


def _extract_gospider_urls(lines: list[str], seed: str, domain: str) -> set[str]:
    """Extract absolute, scheme-relative, and relative URLs from gospider output.

    Some gospider versions print absolute URLs, while others print entries such
    as `[href] - /path` or `href="/path"`. The older parser only captured
    absolute `http(s)://` URLs, which is why gospider could show many URLs in a
    terminal but ReconPilot kept only a few. This parser resolves relative URLs
    against the seed and still applies the target-domain filter afterwards.
    """
    out: set[str] = set()
    abs_re = re.compile(r"https?://[^\s\]\)\}\"\'<>]+", re.IGNORECASE)
    scheme_rel_re = re.compile(r"(?<!:)//[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
    # Relative paths that commonly appear after ` - `, href=, src=, or in plain output.
    rel_re = re.compile(
        r"(?:(?<=\s)|(?<=['\"]))(\/[^\s\]\)\}\"\'<>]+)",
        re.IGNORECASE,
    )

    for raw in lines:
        ln = html.unescape(_strip_ansi(raw)).strip()
        if not ln:
            continue

        # Absolute URLs.
        for match in abs_re.findall(ln):
            cleaned = match.rstrip(".,;:)]}'\"")
            _add_domain_url(out, cleaned, domain)

        # Scheme-relative URLs, e.g. //www.example.com/app.js
        for match in scheme_rel_re.findall(ln):
            cleaned = match.rstrip(".,;:)]}'\"")
            base_scheme = urllib.parse.urlsplit(seed).scheme or "https"
            _add_domain_url(out, f"{base_scheme}:{cleaned}", domain)

        # Relative paths, e.g. /login or /static/app.js. Resolve them against
        # the current seed URL so gospider's shorter output format is not lost.
        for match in rel_re.findall(ln):
            if match.startswith("//"):
                continue
            cleaned = match.rstrip(".,;:)]}'\"")
            # Avoid interpreting ANSI/terminal separators or malformed values as paths.
            if cleaned in {"/", "/-"}:
                continue
            _add_domain_url(out, urllib.parse.urljoin(seed.rstrip("/") + "/", cleaned), domain)

    return out


def _extract_gospider_urls_for_hosts(lines: list[str], seed: str, allowed_hosts: set[str]) -> set[str]:
    """Extract URLs from gospider output and keep only exact CTF target hosts.

    This mirrors the domain parser, but CTF targets are often IPs or local lab
    hostnames, so suffix-domain filtering would be wrong. Relative paths are
    resolved against the current seed URL.
    """
    out: set[str] = set()
    abs_re = re.compile(r"https?://[^\s\]\)\}\"\'<>]+", re.IGNORECASE)
    scheme_rel_re = re.compile(r"(?<!:)//[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
    rel_re = re.compile(
        r'(?:(?<=\s)|(?<=[\'"]))(\/[^\s\]\)\}\"\'<>]+)',
        re.IGNORECASE,
    )

    for raw in lines:
        ln = html.unescape(_strip_ansi(raw)).strip()
        if not ln:
            continue

        for match in abs_re.findall(ln):
            cleaned = match.rstrip(".,;:)]}'\"")
            _add_allowed_host_url(out, cleaned, allowed_hosts)

        for match in scheme_rel_re.findall(ln):
            cleaned = match.rstrip(".,;:)]}'\"")
            base_scheme = urllib.parse.urlsplit(seed).scheme or "http"
            _add_allowed_host_url(out, f"{base_scheme}:{cleaned}", allowed_hosts)

        for match in rel_re.findall(ln):
            if match.startswith("//"):
                continue
            cleaned = match.rstrip(".,;:)]}'\"")
            if cleaned in {"/", "/-"}:
                continue
            _add_allowed_host_url(out, urllib.parse.urljoin(seed.rstrip("/") + "/", cleaned), allowed_hosts)

    return out


def _ctf_crawl_urls(seeds: list[str], line_cb, stop_evt) -> set[str]:
    """Active URL crawl for Controlled / CTF mode using gospider only."""
    gs_bin = _tool_path("gospider")
    if not gs_bin:
        line_cb("[URLHarvest]   gospider    → not found on PATH / common paths")
        return set()

    allowed_hosts = _seed_hosts(seeds)
    out: set[str] = set()

    clean_seeds: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        seed = (seed or "").strip().rstrip("/")
        if seed.lower().startswith(("http://", "https://")) and seed not in seen:
            seen.add(seed)
            clean_seeds.append(seed)

    for seed in clean_seeds:
        if stopped(stop_evt):
            break
        cmd = _gospider_base_cmd(gs_bin, seed)
        line_cb(f"[URLHarvest] ▶  {' '.join(cmd)}")
        lines = _run_cmd(cmd, stop_evt=stop_evt, merge_stderr=True)
        got = _extract_gospider_urls_for_hosts(lines, seed, allowed_hosts)
        out.update(got)
        line_cb(f"[URLHarvest]   crawl {seed} → {len(got):,} URL(s)")

    return out


def _read_text_files(root: Path) -> list[str]:
    lines: list[str] = []
    if not root.exists():
        return lines
    for file in root.rglob("*"):
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lines.extend(text.splitlines())
    return lines


def _gospider_urls(domain: str, line_cb, stop_evt) -> set[str]:
    gs_bin = _tool_path("gospider")
    if not gs_bin:
        line_cb("[URLHarvest]   gospider    → not found on PATH / common paths")
        return set()

    out: set[str] = set()

    for seed in _gospider_seed_urls(domain):
        if stopped(stop_evt):
            break

        # Required simple CLI form only: gospider -s https://www.example.com
        cmd = _gospider_base_cmd(gs_bin, seed)
        lines = _run_cmd(
            cmd,
            stop_evt=stop_evt,
            merge_stderr=True,
        )
        out.update(_extract_gospider_urls(lines, seed, domain))

    return out


def run_url_harvest(target, output_dir, log, line_callback, done_callback,
                    stop_evt=None, ctf_mode: bool = False, target_urls: list[str] | None = None):
    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        host, _ = split_host_port(target)
        if not host:
            line_callback(f"[URLHarvest] ✘ Could not parse target: {target!r}")
            done_callback([])
            return
        if target != host:
            line_callback(f"[URLHarvest] target {target!r} normalised to domain={host}")

        if ctf_mode:
            seeds = [u for u in (target_urls or []) if str(u or "").lower().startswith(("http://", "https://"))]
            if not seeds and str(target or "").lower().startswith(("http://", "https://")):
                seeds = [str(target)]
            elif not seeds:
                # CTF/local-lab fallback. These are active crawl seeds only,
                # not passive internet lookups.
                seeds = [f"http://{host}", f"https://{host}"]

            line_callback(f"[URLHarvest] ▶  CTF active crawl for {len(seeds)} web target(s)")
            results = {"gospider": _ctf_crawl_urls(seeds, line_callback, stop_evt)}
            sources = [("gospider", None)]

            url_sources: dict[str, set[str]] = {}
            for u in results["gospider"]:
                url_sources.setdefault(u, set()).add("gospider")

            all_seen: set[str] = set(url_sources)
            rows: list[dict] = []
            for u in sorted(url_sources):
                rows.append({"source": "gospider", "sources": ["gospider"], "url": u})

            try:
                out = Path(output_dir)
                (out / "all_urls.txt").write_text(
                    "\n".join(sorted(all_seen)) + ("\n" if all_seen else ""),
                    encoding="utf-8")
                src_dir = out / "url_harvest_sources"
                src_dir.mkdir(parents=True, exist_ok=True)
                (src_dir / "gospider.txt").write_text(
                    "\n".join(sorted(results["gospider"])) + ("\n" if results["gospider"] else ""),
                    encoding="utf-8",
                )
                (out / "all_urls_with_sources.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
                (out / "url_harvest_summary.json").write_text(json.dumps({
                    "target": host,
                    "mode": "ctf",
                    "counts_per_source": {"gospider": len(results["gospider"])},
                    "total_unique": len(all_seen),
                    "note": "CTF mode uses active crawling only against discovered/local web targets; passive internet URL sources are skipped.",
                }, indent=2), encoding="utf-8")
            except Exception as exc:
                log.debug(f"[URLHarvest] persist fail: {exc}")

            with_params = sum(1 for u in all_seen if "?" in u and "=" in u)
            line_callback(f"[URLHarvest] ✔  {len(all_seen):,} crawled URLs  ({with_params:,} carry parameters)")
            line_callback("[URLHarvest] ℹ  CTF mode used active gospider crawl only.")
            log.info(f"[URLHarvest] {len(all_seen)} CTF URLs crawled for {host}")
            done_callback(rows)
            return

        import ipaddress
        try:
            ipaddress.ip_address(host)
            line_callback(f"[URLHarvest] {host} is an IP literal — passive "
                          "URL sources are domain-only. Skipping.")
            done_callback([])
            return
        except ValueError:
            pass

        line_callback(f"[URLHarvest] ▶  Harvesting URLs for {host}")

        sources = [
            ("wayback",      _wayback_urls),
            ("urlscan",      _urlscan_urls),
            ("otx",          _otx_urls),
            ("gau",          _gau_urls),
            ("waybackurls",  _waybackurls),
            ("gospider",     _gospider_urls),
        ]
        results: dict[str, set[str]] = {name: set() for name, _ in sources}
        lock = threading.Lock()

        def _worker(name, fn):
            t0 = time.time()
            try:
                got = fn(host, line_callback, stop_evt)
            except Exception as exc:
                log.debug(f"[URLHarvest:{name}] {type(exc).__name__}: {exc}")
                got = set()
            with lock:
                results[name] = got
            line_callback(f"[URLHarvest]   {name:11s} → {len(got):>6,} URLs  "
                          f"({time.time() - t0:.1f}s)")

        threads = [threading.Thread(target=_worker, args=(n, f),
                                    daemon=True, name=f"url-{n}")
                   for n, f in sources]
        for t in threads:
            t.start()
        for t in threads:
            # No per-source join timeout: each collector runs until it finishes
            # naturally, or until Stop Scan requests cancellation.
            t.join()

        # Merge by normalised URL, but keep every source that produced it.
        # Every collector is filtered to the requested target domain or its
        # subdomains before this merge, so unrelated urlscan/page URLs such as
        # third-party domains are not shown. This removes duplicate URL rows
        # while still showing all collectors that found the URL, e.g.
        # "gau, waybackurls".
        url_sources: dict[str, set[str]] = {}
        for src_name, _ in sources:
            for u in results[src_name]:
                url_sources.setdefault(u, set()).add(src_name)

        all_seen: set[str] = set(url_sources)
        rows: list[dict] = []
        for u in sorted(url_sources):
            srcs = sorted(url_sources[u], key=lambda n: [s[0] for s in sources].index(n))
            rows.append({
                "source": ", ".join(srcs),
                "sources": srcs,
                "url": u,
            })

        try:
            out = Path(output_dir)
            (out / "all_urls.txt").write_text(
                "\n".join(sorted(all_seen)) + ("\n" if all_seen else ""),
                encoding="utf-8")

            # Save per-source filtered URL lists so users can verify exactly
            # what each collector returned after ReconPilot's noise filtering.
            src_dir = out / "url_harvest_sources"
            src_dir.mkdir(parents=True, exist_ok=True)
            for src_name, urls in results.items():
                (src_dir / f"{src_name}.txt").write_text(
                    "\n".join(sorted(urls)) + ("\n" if urls else ""),
                    encoding="utf-8",
                )

            (out / "all_urls_with_sources.json").write_text(json.dumps(rows, indent=2),
                                                             encoding="utf-8")
            (out / "url_harvest_summary.json").write_text(json.dumps({
                "target": host,
                "counts_per_source": {n: len(s) for n, s in results.items()},
                "total_unique": len(all_seen),
                "note": (
                    "URLs are filtered to the requested target domain/subdomains, normalised "
                    "and deduplicated globally, but all contributing sources are preserved in "
                    "all_urls_with_sources.json and shown in the UI. "
                    "gospider is active and is seeded with simple full http(s) URLs only, "
                    "for example gospider -s https://www.example.com. "
                    "Per-source filtered and deduplicated outputs are saved under "
                    "url_harvest_sources/."
                ),
            }, indent=2), encoding="utf-8")
        except Exception as exc:
            log.debug(f"[URLHarvest] persist fail: {exc}")

        with_params = sum(1 for u in all_seen if "?" in u and "=" in u)
        line_callback(f"[URLHarvest] ✔  {len(all_seen):,} unique deduplicated URLs  "
                      f"({with_params:,} carry parameters)")
        line_callback("[URLHarvest] ℹ  Per-source outputs saved in url_harvest_sources/")
        log.info(f"[URLHarvest] {len(all_seen)} URLs harvested for {host}")
        done_callback(rows)

    threading.Thread(target=_run, daemon=True).start()
