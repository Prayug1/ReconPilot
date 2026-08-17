import xml.etree.ElementTree as ET
import re
import json
from pathlib import Path
from typing import Any


# ── Nmap XML ─────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse nmap XML → list of open-port dicts."""
    path = Path(xml_path)
    if not path.exists():
        return []
    ports = []
    try:
        root = ET.parse(xml_path).getroot()
        for host in root.findall("host"):
            for pe in host.findall(".//port"):
                st = pe.find("state")
                if st is None or st.get("state") != "open":
                    continue
                # Do NOT use ``pe.find("service") or ET.Element(...)`` here.
                # In xml.etree.ElementTree, an Element with no child elements is
                # falsey. Nmap commonly writes service as a self-closing element:
                #
                #   <service name="http" product="Cloudflare http proxy" .../>
                #
                # That is a valid service element, but it evaluates to False and
                # the old ``or`` fallback replaced it with an empty element, so
                # the UI showed service="unknown" and blank product/version.
                svc = pe.find("service")
                if svc is None:
                    svc = ET.Element("service")

                service_name = svc.get("name") or "unknown"
                tunnel = svc.get("tunnel", "")
                if service_name == "http" and tunnel == "ssl":
                    service_name = "https"

                ports.append({
                    "port":     pe.get("portid", "?"),
                    "protocol": pe.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  service_name,
                    "product":  svc.get("product", ""),
                    "version":  svc.get("version", ""),
                    "extra":    svc.get("extrainfo", ""),
                    "tunnel":   tunnel,
                })
    except ET.ParseError:
        pass
    return ports


# ── Subfinder ────────────────────────────────────────────────────────────────

def parse_subfinder_output(raw: str) -> list[str]:
    """One subdomain per line → sorted deduplicated list."""
    seen, out = set(), []
    for line in raw.splitlines():
        sub = line.strip().lower()
        if sub and sub not in seen:
            seen.add(sub)
            out.append(sub)
    return sorted(out)


# ── HTTP security headers ─────────────────────────────────────────────────────

SECURITY_HEADERS = [
    ("Strict-Transport-Security",    "max-age should be ≥ 31536000"),
    ("Content-Security-Policy",      "Prevents XSS and data injection"),
    ("X-Content-Type-Options",       "Should be 'nosniff'"),
    ("X-Frame-Options",              "Should be DENY or SAMEORIGIN"),
    ("Referrer-Policy",              "Controls referrer information"),
    ("Permissions-Policy",           "Controls browser feature access"),
    ("X-XSS-Protection",             "Legacy XSS filter (still useful)"),
    ("Cache-Control",                "Controls caching behavior"),
    ("Cross-Origin-Opener-Policy",   "Isolates browsing context"),
    ("Cross-Origin-Resource-Policy", "Controls cross-origin reads"),
]

def parse_http_headers(headers: dict) -> list[dict]:
    norm = {k.lower(): v for k, v in headers.items()}
    result = []
    for hdr, desc in SECURITY_HEADERS:
        val  = norm.get(hdr.lower())
        risk = _header_risk(hdr, val)
        result.append({
            "header":  hdr,
            "present": "✔ Yes" if val else "✘ No",
            "value":   val or "—",
            "risk":    risk,
            "note":    desc,
        })
    return result

def _header_risk(hdr: str, val: str | None) -> str:
    if val is None:
        return "HIGH"
    hdr_l = hdr.lower()
    if "strict-transport" in hdr_l:
        m = re.search(r"max-age=(\d+)", val or "")
        return "MEDIUM" if not m or int(m.group(1)) < 31536000 else "OK"
    if "x-frame" in hdr_l:
        return "OK" if val.upper() in ("DENY", "SAMEORIGIN") else "MEDIUM"
    if "x-content-type" in hdr_l:
        return "OK" if "nosniff" in val.lower() else "MEDIUM"
    return "OK"


# ── WAFW00F ──────────────────────────────────────────────────────────────────

# wafw00f prints lines such as:
#   [+] The site http://x is behind Cloudflare (Cloudflare Inc.) WAF.
#   [-] No WAF detected by the generic detection
#   [+] Generic Detection results:
_WAF_BEHIND = re.compile(
    r"is behind\s+(?P<waf>.+?)\s+WAF", re.IGNORECASE
)
_WAF_NUMBER = re.compile(r"Number of requests:\s*(?P<n>\d+)", re.IGNORECASE)


def parse_wafw00f_output(raw: str, target: str = "") -> list[dict]:
    """
    Parse wafw00f stdout → a single-row result list describing whether a
    WAF was detected, which one, and how many probe requests were sent.
    """
    detected   = False
    waf_names: list[str] = []
    requests_n = "—"
    generic    = False
    explicit_none = False

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _WAF_BEHIND.search(line)
        if m:
            detected = True
            name = m.group("waf").strip()
            if name and name not in waf_names:
                waf_names.append(name)

        low = line.lower()
        # wafw00f prints this exact line on a clean scan; it is the verdict and
        # outranks the "Generic Detection results:" header that precedes it.
        if "no waf detected" in low:
            explicit_none = True

        if "generic detection results" in low:
            generic = True

        mn = _WAF_NUMBER.search(line)
        if mn:
            requests_n = mn.group("n")

    if detected:
        waf_str = ", ".join(waf_names) if waf_names else "Unknown WAF"
        status  = "DETECTED"
    elif explicit_none:
        waf_str = "No WAF detected (generic detection ran, no fingerprint)"
        status  = "NONE"
    elif generic:
        waf_str = "Generic firewall behaviour (no fingerprint match)"
        status  = "GENERIC"
    else:
        waf_str = "No WAF detected"
        status  = "NONE"

    return [{
        "target":   target or "—",
        "status":   status,
        "waf":      waf_str,
        "requests": requests_n,
    }]


# ── Nuclei ─────────────────────────────────────────────────────────────────

# Nuclei JSONL emits one JSON object per finding. We also keep a regex
# fallback for the classic bracketed text format:
#   [template-id] [protocol] [severity] http://target [extractor]
_NUCLEI_TXT = re.compile(
    r"\[(?P<template>[^\]]+)\]\s*"
    r"\[(?P<type>[^\]]+)\]\s*"
    r"\[(?P<severity>[^\]]+)\]\s*"
    r"(?P<url>\S+)"
    r"(?:\s*\[(?P<extra>[^\]]*)\])?"
)

_SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2,
    "low": 3, "info": 4, "unknown": 5,
}


def parse_nuclei_output(raw: str) -> list[dict]:
    """
    Parse nuclei output → structured finding list.

    Accepts JSONL (preferred, via `-jsonl`) and falls back to the default
    bracketed text format. Results are sorted by severity (critical first).
    """
    results, seen = [], set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        finding = None

        # 1) Try JSON first (nuclei -jsonl / -json). Ignore progress/stat
        # objects from nuclei -stats; they are not findings and should not
        # appear in results.json/report.html as an "unknown" issue.
        if line.startswith("{"):
            try:
                obj  = json.loads(line)
                info = obj.get("info", {}) or {}

                if not any(k in obj for k in ("template-id", "templateID", "template")):
                    finding = None
                else:
                    template_id = (
                        obj.get("template-id")
                        or obj.get("templateID")
                        or Path(str(obj.get("template", ""))).stem
                        or "—"
                    )
                    finding = {
                        "template": template_id,
                        "name":     info.get("name", "—"),
                        "severity": (info.get("severity", "unknown") or "unknown").lower(),
                        "type":     obj.get("type", "—"),
                        "url":      obj.get("matched-at", obj.get("host", "—")),
                    }
            except (json.JSONDecodeError, AttributeError):
                finding = None

        # 2) Fall back to bracketed text
        if finding is None:
            m = _NUCLEI_TXT.search(line)
            if not m:
                continue
            finding = {
                "template": m.group("template"),
                "name":     m.group("extra") or m.group("template"),
                "severity": (m.group("severity") or "unknown").lower(),
                "type":     m.group("type"),
                "url":      m.group("url"),
            }

        key = (finding["template"], finding["url"])
        if key in seen:
            continue
        seen.add(key)
        results.append(finding)

    results.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 5))
    return results


# ── WhatWeb fingerprint output ───────────────────────────────────────────────

def parse_whatweb_output(raw: str, target: str = "") -> list[dict]:
    """
    Parse WhatWeb's --log-json output (one JSON object per scanned URL) into
    a flat plugin list:

        [{"target", "plugin", "version", "string", "http_status"}, ...]

    Each WhatWeb plugin can contribute multiple "keys" (version, string,
    module, account, …). We flatten them into one row per plugin per URL and
    join multi-valued fields with ", ".
    """
    if not raw:
        return []

    rows: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()

    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or not ln.startswith("{"):
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue

        url     = obj.get("target") or target
        status  = obj.get("http_status") or obj.get("status") or ""
        plugins = obj.get("plugins") or {}
        if not isinstance(plugins, dict):
            continue

        for plugin_name, data in plugins.items():
            if not isinstance(data, dict):
                continue
            version = ", ".join(str(v) for v in data.get("version", []) if v)
            strings = ", ".join(str(s) for s in data.get("string",  []) if s)
            # Include some less-common fields too — accounts, modules, etc.
            extras = []
            for k in ("module", "account", "os"):
                vals = data.get(k) or []
                if vals:
                    extras.append(f"{k}={', '.join(str(v) for v in vals)}")
            extra_str = "; ".join(extras)

            row_string = strings
            if extra_str:
                row_string = f"{row_string} ({extra_str})" if row_string else extra_str

            key = (url, plugin_name, version, row_string)
            if key in seen:
                continue
            seen.add(key)

            rows.append({
                "target":      url,
                "plugin":      plugin_name,
                "version":     version,
                "string":      row_string,
                "http_status": str(status),
            })

    # Stable, human-friendly order: by plugin name then version.
    rows.sort(key=lambda r: (r["plugin"].lower(), r["version"]))
    return rows


# ── JSON persistence ─────────────────────────────────────────────────────────

def split_host_port(target: str) -> tuple[str, str | None]:
    """
    Normalise a user-supplied target into (host, port).

    Accepted shapes (and what comes back):
      192.168.1.10            → ("192.168.1.10",  None)
      192.168.1.10:8080       → ("192.168.1.10",  "8080")
      example.com:8443        → ("example.com",   "8443")
      http://example.com/x    → ("example.com",   None)   # implicit 80, no -p
      https://example.com:8443/p → ("example.com", "8443")
      [::1]:8080              → ("::1",           "8080")
      [2001:db8::1]           → ("2001:db8::1",   None)

    Nmap takes the bare host as a positional arg and the port via -p, so
    every module that runs a non-URL tool routes its target through here.
    """
    if not target:
        return target, None

    s = target.strip()

    # 1) Strip scheme + path if present (URL form).
    if "://" in s:
        from urllib.parse import urlsplit
        u = urlsplit(s)
        host = u.hostname or ""
        port = str(u.port) if u.port else None
        return host, port

    # 2) Bracketed IPv6 with optional :port  → [addr]  or  [addr]:port
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            host = s[1:end]
            rest = s[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, rest[1:]
            return host, None

    # 3) Bare IPv6 (multiple colons, no brackets) — leave as-is, no port.
    if s.count(":") > 1:
        return s, None

    # 4) host  OR  host:port
    if ":" in s:
        host, _, port = s.rpartition(":")
        if port.isdigit():
            return host, port
    return s, None


def save_results(data: Any, output_dir: str, filename: str) -> str:
    out = Path(output_dir) / filename
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return str(out)
