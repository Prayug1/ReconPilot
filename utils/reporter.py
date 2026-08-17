from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.runtime import format_duration


# ── HTML template ─────────────────────────────────────────────────────────────

_STYLE = """
:root{--bg:#0d0f14;--bg2:#12151c;--bg3:#1a1e28;--border:#252a36;
      --accent:#00ff9d;--accent2:#00c9ff;--red:#ff4d6d;--yellow:#ffb86c;
      --text:#e2e8f0;--dim:#64748b;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:24px;}
.header{border-bottom:1px solid var(--accent);padding-bottom:16px;margin-bottom:32px;}
.logo{font-size:28px;font-weight:bold;color:var(--accent);letter-spacing:6px;}
.tagline{font-size:11px;color:var(--dim);letter-spacing:2px;margin-top:4px;}
.meta{font-size:11px;color:var(--dim);margin-top:8px;}
.meta span{color:var(--accent2);margin-right:24px;}
.section{margin-bottom:36px;}
.section-title{font-size:13px;font-weight:bold;color:var(--accent2);
  letter-spacing:3px;border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:16px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:var(--bg3);color:var(--accent);padding:8px 12px;
   text-align:left;letter-spacing:1px;border:1px solid var(--border);}
td{background:var(--bg2);padding:7px 12px;border:1px solid var(--border);
   vertical-align:top;word-break:break-all;}
tr:hover td{background:var(--bg3);}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:bold;}
.ok{color:#22c55e;border:1px solid #22c55e;}
.warn{color:var(--yellow);border:1px solid var(--yellow);}
.fail{color:var(--red);border:1px solid var(--red);}
.info-box{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
  padding:16px;margin-bottom:16px;}
.stat{display:inline-block;margin-right:32px;}
.stat-val{font-size:28px;font-weight:bold;color:var(--accent);}
.stat-lbl{font-size:10px;color:var(--dim);letter-spacing:2px;margin-top:2px;}
.no-data{color:var(--dim);font-size:12px;padding:12px;text-align:center;}
footer{margin-top:48px;border-top:1px solid var(--border);padding-top:12px;
  font-size:10px;color:var(--dim);text-align:center;letter-spacing:2px;}
"""

def _badge(text: str, risk: str = "") -> str:
    cls = {
        "OK": "ok", "MEDIUM": "warn", "HIGH": "fail", "LOW": "ok",
        # nuclei severities
        "CRITICAL": "fail", "INFO": "ok", "UNKNOWN": "ok",
        # wafw00f statuses
        "DETECTED": "fail", "UNREACHABLE": "fail", "GENERIC": "warn", "NONE": "ok",
    }.get(risk.upper(), "ok")
    return f'<span class="badge {cls}">{text}</span>'

def _status_badge(code: int | str) -> str:
    try:
        c = int(code)
        cls = "ok" if c < 300 else ("warn" if c < 400 else "fail")
    except Exception:
        cls = "ok" if str(code).upper() == "LIVE" else "warn"
    return f'<span class="badge {cls}">{code}</span>'

def _table(headers: list[str], rows: list[list[str]], empty_msg: str = "No data found") -> str:
    if not rows:
        return f'<p class="no-data">{empty_msg}</p>'
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(f"<td>{cell}</td>" for cell in row)
        trs += f"<tr>{tds}</tr>"
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"


# ── Public function ───────────────────────────────────────────────────────────

def generate_html_report(
    target:     str,
    timestamp:  str,
    output_dir: str,
    results:    dict[str, Any],
) -> str:
    """
    Build an HTML report from all scan results and write to disk.

    Parameters
    ----------
    results keys expected:
        ports, subdomains, dir_enum, subdomain_fuzz, headers, live_hosts,
        http_probe, js_files, waf, whatweb, sslcert, dns, url_harvest,
        js_secrets, nuclei, scan_runtime_s
    """
    ts_human = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%d %b %Y  %H:%M:%S")

    ports       = results.get("ports",       [])
    subs        = results.get("subdomains",  [])
    dir_enum    = results.get("dir_enum",    [])
    sub_fuzz    = results.get("subdomain_fuzz", [])
    headers     = results.get("headers",     [])
    live_hosts  = results.get("live_hosts",  [])
    http_probe  = results.get("http_probe",  [])
    js_files    = results.get("js_files",    [])
    waf         = results.get("waf",         [])
    whatweb     = results.get("whatweb",     [])
    sslcert     = results.get("sslcert",     [])
    dns_recs    = results.get("dns",         [])
    url_harvest = results.get("url_harvest", [])
    js_secrets  = results.get("js_secrets",  [])
    nuclei      = results.get("nuclei",      [])
    scan_mode   = str(results.get("scan_mode", "bug_bounty") or "bug_bounty").lower()
    scan_runtime_s = results.get("scan_runtime_s")
    scan_runtime_html = (
        f'<span>OBSERVED SCAN RUNTIME: {format_duration(scan_runtime_s)}</span>'
        if scan_runtime_s is not None else ""
    )
    is_ctf_report = scan_mode == "ctf"

    # ── Summary stats ────────────────────────────────────────────────────
    if is_ctf_report:
        stats_html = f"""
    <div class="info-box" style="display:flex;gap:48px;">
      <div class="stat"><div class="stat-val">{len(ports)}</div><div class="stat-lbl">OPEN PORTS</div></div>
      <div class="stat"><div class="stat-val">{len(sub_fuzz)}</div><div class="stat-lbl">FUZZ HOSTS</div></div>
      <div class="stat"><div class="stat-val">{len(dir_enum)}</div><div class="stat-lbl">DIR PATHS</div></div>
      <div class="stat"><div class="stat-val">{len(live_hosts)}</div><div class="stat-lbl">LIVE HOSTS</div></div>
      <div class="stat"><div class="stat-val">{len(js_files)}</div><div class="stat-lbl">JS FILES</div></div>
      <div class="stat"><div class="stat-val">{sum(1 for h in headers if h.get("risk")=="HIGH")}</div><div class="stat-lbl">HEADER RISKS</div></div>
    </div>"""
    else:
        stats_html = f"""
    <div class="info-box" style="display:flex;gap:48px;">
      <div class="stat"><div class="stat-val">{len(ports)}</div><div class="stat-lbl">OPEN PORTS</div></div>
      <div class="stat"><div class="stat-val">{len(subs) + len(sub_fuzz)}</div><div class="stat-lbl">SUBDOMAINS</div></div>
      <div class="stat"><div class="stat-val">{len(dir_enum)}</div><div class="stat-lbl">DIR PATHS</div></div>
      <div class="stat"><div class="stat-val">{len(live_hosts)}</div><div class="stat-lbl">LIVE HOSTS</div></div>
      <div class="stat"><div class="stat-val">{len(js_files)}</div><div class="stat-lbl">JS FILES</div></div>
      <div class="stat"><div class="stat-val">{sum(1 for h in headers if h.get("risk")=="HIGH")}</div><div class="stat-lbl">HEADER RISKS</div></div>
    </div>"""

    # ── Ports table ───────────────────────────────────────────────────────
    ports_rows = [
        [f'<b style="color:#00ff9d">{p["port"]}/{p["protocol"]}</b>',
         p.get("service",""), p.get("product",""),
         f'{p.get("version","")} {p.get("extra","")}']
        for p in ports
    ]
    ports_html = _table(["Port/Proto","Service","Product","Version/Extra"], ports_rows, "No open ports found")


    # ── Subdomains table ──────────────────────────────────────────────────
    subs_rows = [[f'<code>{s}</code>'] for s in subs]
    subs_html = _table(["Subdomain"], subs_rows, "No subdomains found")

    # ── CTF directory enumeration ─────────────────────────────────────────
    dir_rows = [
        [f'<a href="{r.get("url","")}" style="color:var(--accent2)">{r.get("url","")}</a>',
         str(r.get("status", "")), str(r.get("size", ""))]
        for r in dir_enum
    ]
    dir_html = _table(["URL","Status","Size"], dir_rows,
                      "Directory enumeration not run / no paths found")

    # ── CTF subdomain/vhost fuzz ──────────────────────────────────────────
    sub_fuzz_rows = [
        [f'<code>{r.get("host","")}</code>', str(r.get("status", "")),
         str(r.get("size", "")), r.get("url", "")]
        for r in sub_fuzz
    ]
    sub_fuzz_html = _table(["Host","Status","Size","URL"], sub_fuzz_rows,
                           "Subdomain fuzz not run / skipped for IP target / no results")

    # ── Live hosts ────────────────────────────────────────────────────────
    live_rows = [
        [h.get("host",""), _status_badge(h.get("status","")),
         h.get("method",""), h.get("latency","")]
        for h in live_hosts
    ]
    live_html = _table(["Host","Status","Method","Latency"], live_rows, "No live hosts detected")

    # ── HTTP probe / live URLs ────────────────────────────────────────────
    probe_rows = [
        [
            f'<a href="{p.get("url","")}" style="color:var(--accent2)">{p.get("url","")}</a>',
            p.get("status", ""),
            p.get("title", ""),
            p.get("tech", ""),
        ]
        for p in http_probe
        if p.get("url", "")
    ]
    probe_html = _table(["Live URL", "Status", "Title", "Tech"], probe_rows, "No live URLs found")

    # ── JS files ──────────────────────────────────────────────────────────
    js_rows = [[f'<a href="{js}" style="color:var(--accent2)">{js}</a>'] for js in js_files]
    js_files_html = _table(["JS File URL"], js_rows, "No JS files found")

    # ── Security headers ──────────────────────────────────────────────────
    hdr_rows = [
        [h["header"],
         h["present"],
         _badge(h.get("risk","—"), h.get("risk","")),
         f'<small style="color:var(--dim)">{h.get("value","—")}</small>',
         f'<small>{h.get("note","")}</small>']
        for h in headers
    ]
    hdr_html = _table(["Header","Present","Risk","Value","Notes"], hdr_rows, "No header data")

    # ── WAF detection ─────────────────────────────────────────────────────
    waf_rows = [
        [w.get("target",""),
         _badge(w.get("status","NONE"), w.get("status","")),
         w.get("waf","—"),
         str(w.get("requests","—"))]
        for w in waf
    ]
    waf_html = _table(["Target","Status","WAF / Firewall","Requests"], waf_rows,
                      "WAF detection not run")

    # ── WhatWeb fingerprints ──────────────────────────────────────────────
    whatweb_rows = [
        [w.get("plugin","—"),
         w.get("version","") or "—",
         w.get("string","") or "—",
         w.get("http_status","") or "—",
         f'<a href="{w.get("target","")}" style="color:var(--accent2)">{w.get("target","—")}</a>']
        for w in whatweb
    ]
    whatweb_html = _table(
        ["Plugin","Version","Detail","HTTP","Target"],
        whatweb_rows,
        "WhatWeb fingerprinting not run / no plugins matched",
    )

    # ── SSL/TLS certificate ───────────────────────────────────────────────
    ssl_rows = [
        [s.get("category","—"),
         s.get("field","—"),
         s.get("value","") or "—",
         _badge(s.get("risk","") or "—", s.get("risk","") or "")]
        for s in sslcert
    ]
    ssl_html = _table(
        ["Category","Field","Value","Risk"],
        ssl_rows,
        "SSL/TLS enumeration not run / target has no TLS service",
    )

    # ── DNS records ───────────────────────────────────────────────────────
    dns_rows = [
        [d.get("group","—"),
         d.get("type","—"),
         d.get("value","") or "—",
         _badge(d.get("risk","") or "—", d.get("risk","") or "")]
        for d in dns_recs
    ]
    dns_html = _table(
        ["Group","Type","Value","Risk"],
        dns_rows,
        "DNS enumeration not run / target is not a domain",
    )

    # ── URL Harvest ───────────────────────────────────────────────────────
    UH_CAP = 500
    uh_show = url_harvest[:UH_CAP]
    uh_rows = [[u.get("source","—"), u.get("url","")] for u in uh_show]
    uh_html = _table(
        ["Source","URL"], uh_rows,
        "URL Harvest not run / no URLs found",
    )
    uh_note = (f"<p style='color:#888;font-size:0.85em;margin-top:6px'>"
               f"Showing first {UH_CAP:,} of {len(url_harvest):,} URLs. "
               f"Full corpus in <code>all_urls.txt</code>.</p>"
               if len(url_harvest) > UH_CAP else "")


    # ── JS Secrets (sort HIGH first) ──────────────────────────────────────
    sev_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    js_sorted = sorted(js_secrets,
                       key=lambda r: sev_order.get(r.get("severity","INFO"), 9))
    js_rows = [
        [_badge(r.get("severity","—"), r.get("severity","").lower() or "info"),
         r.get("label","—"),
         r.get("value","") or "—",
         r.get("source_url","")]
        for r in js_sorted
    ]
    js_secrets_html = _table(
        ["Severity","Type","Value","Source URL"], js_rows,
        "JS Secrets not run / no secret patterns matched",
    )

    # ── Nuclei findings ───────────────────────────────────────────────────
    nuclei_rows = [
        [f.get("template","—"),
         f.get("name","—"),
         _badge(f.get("severity","info").upper(), f.get("severity","")),
         f.get("type","—"),
         f'<a href="{f.get("url","")}" style="color:var(--accent2)">{f.get("url","—")}</a>']
        for f in nuclei
    ]
    nuclei_html = _table(["Template","Name","Severity","Type","URL"], nuclei_rows,
                         "Nuclei scan not run / no findings")

    # ── Sections that differ by report mode ────────────────────────────────
    if is_ctf_report:
        # CTF/controlled reports should not include empty passive sections or
        # visibly label the report as CTF. Keep the useful lab findings, but
        # present them with neutral section names.
        mode_specific_sections = f"""
<div class="section">
  <div class="section-title">DIRECTORY ENUMERATION  ({len(dir_enum)})</div>
  {dir_html}
</div>

<div class="section">
  <div class="section-title">SUBDOMAIN / VHOST FUZZ  ({len(sub_fuzz)})</div>
  {sub_fuzz_html}
</div>"""
    else:
        mode_specific_sections = f"""
<div class="section">
  <div class="section-title">LIVE URLS  ({len(http_probe)})</div>
  {probe_html}
</div>

<div class="section">
  <div class="section-title">SUBDOMAINS  ({len(subs)})</div>
  {subs_html}
</div>

<div class="section">
  <div class="section-title">DIRECTORY ENUMERATION  ({len(dir_enum)})</div>
  {dir_html}
</div>

<div class="section">
  <div class="section-title">SUBDOMAIN / VHOST FUZZ  ({len(sub_fuzz)})</div>
  {sub_fuzz_html}
</div>

<div class="section">
  <div class="section-title">DNS ENUMERATION  ({len(dns_recs)})</div>
  {dns_html}
</div>"""

    # ── Assemble full HTML ─────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ReconPilot Report — {target}</title>
<style>{_STYLE}</style>
</head>
<body>

<div class="header">
  <div class="logo">◈ RECONPILOT</div>
  <div class="tagline">Automated Reconnaissance Framework</div>
  <div class="meta">
    <span>TARGET: {target}</span>
    <span>SCAN: {ts_human}</span>
    <span>OUTPUT: {output_dir}</span>
    {scan_runtime_html}
  </div>
</div>

<div class="section">
  <div class="section-title">EXECUTIVE SUMMARY</div>
  {stats_html}
</div>

<div class="section">
  <div class="section-title">OPEN PORTS  ({len(ports)})</div>
  {ports_html}
</div>

<div class="section">
  <div class="section-title">LIVE HOSTS  ({len(live_hosts)})</div>
  {live_html}
</div>

{mode_specific_sections}

<div class="section">
  <div class="section-title">SECURITY HEADERS  ANALYSIS</div>
  {hdr_html}
</div>

<div class="section">
  <div class="section-title">WAF DETECTION  ({len(waf)})</div>
  {waf_html}
</div>

<div class="section">
  <div class="section-title">WHATWEB FINGERPRINTS  ({len(whatweb)})</div>
  {whatweb_html}
</div>

<div class="section">
  <div class="section-title">SSL/TLS CERTIFICATE  ({len(sslcert)})</div>
  {ssl_html}
</div>

<div class="section">
  <div class="section-title">URL HARVEST  ({len(url_harvest):,} unique URLs)</div>
  {uh_html}
  {uh_note}
</div>


<div class="section">
  <div class="section-title">JS SECRETS  ({len(js_secrets)} finding{"s" if len(js_secrets) != 1 else ""})</div>
  {js_secrets_html}
</div>


<div class="section">
  <div class="section-title">NUCLEI FINDINGS  ({len(nuclei)})</div>
  {nuclei_html}
</div>

<div class="section">
  <div class="section-title">JS FILES  ({len(js_files)})</div>
  {js_files_html}
</div>

<footer>◈ RECONPILOT  //  {ts_human}</footer>
</body>
</html>
"""

    out = Path(output_dir) / "report.html"
    out.write_text(html, encoding="utf-8")
    return str(out)
