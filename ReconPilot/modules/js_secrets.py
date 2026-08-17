"""
JavaScript secret scanner.

Scans JS files already downloaded by ``js_collector`` and runs a curated
regex pack against them looking for leaked credentials. The regex pack
is intentionally conservative — every hit is a real lead worth manual
verification, not noise.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from utils.logger import ReconLogger
from utils.process_control import stopped

# Downloading is now handled by JS Collector. JS Secrets scans local files only.


def _c(pattern: str, flags: int = 0):
    return re.compile(pattern, flags)


# (pattern_id, severity, label, regex)
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    # AWS
    ("aws_access_key", "HIGH", "AWS Access Key ID",
     _c(r"\b(AKIA|ASIA|AIDA|AGPA|ANPA|ANVA|AROA|APKA|AIPA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("aws_secret", "HIGH", "AWS Secret Access Key (context)",
     _c(r"aws[_\-]?secret[_\-]?(access[_\-]?)?key[\"'\s:=]+([A-Za-z0-9/+=]{40})", re.IGNORECASE)),
    # Google / GCP
    ("google_api_key", "HIGH", "Google API Key",
     _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google_oauth", "HIGH", "Google OAuth Client ID",
     _c(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("gcp_service_account", "HIGH", "GCP service-account JSON fragment",
     _c(r"\"type\"\s*:\s*\"service_account\"")),
    # GitHub / GitLab / Bitbucket
    ("github_pat", "HIGH", "GitHub Personal Access Token",
     _c(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_fine_grained", "HIGH", "GitHub fine-grained PAT",
     _c(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("gitlab_pat", "HIGH", "GitLab Personal Access Token",
     _c(r"\bglpat-[A-Za-z0-9\-_]{20}\b")),
    ("bitbucket_app", "MEDIUM", "Bitbucket app password (context)",
     _c(r"bitbucket[_\-]?(app[_\-]?password|password|token)[\"'\s:=]+[A-Za-z0-9]{20,}", re.IGNORECASE)),
    # Slack
    ("slack_token", "HIGH", "Slack token",
     _c(r"\bxox[abprs]-[0-9]{10,12}-[0-9]{10,13}-[A-Za-z0-9\-]{24,34}\b")),
    ("slack_webhook", "HIGH", "Slack incoming webhook",
     _c(r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,11}/B[A-Z0-9]{8,11}/[A-Za-z0-9]{24}\b")),
    # Payments
    ("stripe_live", "HIGH", "Stripe live secret key",
     _c(r"\bsk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_test", "MEDIUM", "Stripe test secret key",
     _c(r"\bsk_test_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_restricted", "HIGH", "Stripe restricted key",
     _c(r"\brk_live_[0-9a-zA-Z]{24,99}\b")),
    ("square_token", "HIGH", "Square OAuth token",
     _c(r"\bsq0(atp|csp)-[A-Za-z0-9_\-]{22,43}\b")),
    # Email / Messaging
    ("twilio_sid", "MEDIUM", "Twilio Account SID",
     _c(r"\bAC[a-f0-9]{32}\b")),
    ("twilio_auth", "HIGH", "Twilio auth token (context)",
     _c(r"twilio[_\-]?(auth[_\-]?token|token)[\"'\s:=]+[a-f0-9]{32}", re.IGNORECASE)),
    ("sendgrid_key", "HIGH", "SendGrid API key",
     _c(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("mailgun_key", "HIGH", "Mailgun API key",
     _c(r"\bkey-[a-f0-9]{32}\b")),
    # AI / SaaS
    ("openai_key", "HIGH", "OpenAI API key",
     _c(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_key", "HIGH", "Anthropic API key",
     _c(r"\bsk-ant-(api03|admin01)-[A-Za-z0-9_\-]{40,}\b")),
    ("heroku_key", "HIGH", "Heroku API key (context)",
     _c(r"heroku[_\-]?(api[_\-]?key|key)[\"'\s:=]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)),
    ("datadog_key", "MEDIUM", "Datadog API key (context)",
     _c(r"datadog[_\-]?(api[_\-]?key|key)[\"'\s:=]+[a-f0-9]{32}", re.IGNORECASE)),
    ("atlassian_token", "HIGH", "Atlassian API token (context)",
     _c(r"atlassian[_\-]?(api[_\-]?token|token)[\"'\s:=]+[A-Za-z0-9]{20,}", re.IGNORECASE)),
    # Generic high-signal
    ("jwt", "MEDIUM", "JWT token",
     _c(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private_key_pem", "HIGH", "PEM-encoded private key",
     _c(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("generic_api_key_assign", "MEDIUM", "Hardcoded api_key / secret assignment",
     _c(r"""(?ix)
         (?:api[_\-]?key|api[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)
         \s* [:=] \s*
         [\"']
         ([A-Za-z0-9_\-]{16,})
         [\"']
     """)),
    ("basic_auth_url", "HIGH", "Credentials in URL (user:pass@host)",
     _c(r"\bhttps?://[A-Za-z0-9._%+\-]+:[^@\s/'\"]{4,}@[A-Za-z0-9.\-]+")),
]

INTERNAL_HOST_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("rfc1918_ip", "INFO",
     _c(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("internal_host", "INFO",
     _c(r"\b[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(?:internal|local|corp|lan|intranet)\b")),
    ("localhost_url", "INFO",
     _c(r"\bhttps?://(?:localhost|127\.0\.0\.1)(?::\d+)?\b")),
]


def run_js_secrets(target, output_dir, log, line_callback, done_callback, stop_evt=None):
    """Scan JS files already downloaded by JS Collector.

    Downloading now belongs to JS Collector. This module reads
    js_download_manifest.json, loads only successfully downloaded files, and
    scans their local contents for secrets.
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return

        out = Path(output_dir)
        manifest_file = out / "js_download_manifest.json"
        js_list_file = out / "js_files.txt"
        cache_dir = out / "js" / "downloaded"

        if not manifest_file.exists():
            line_callback("[JSSecrets] ✘ No js_download_manifest.json found — run JS File Collector first.")
            done_callback([])
            return

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(manifest, list):
                raise ValueError("manifest is not a list")
        except Exception as exc:
            line_callback(f"[JSSecrets] ✘ Could not read JS download manifest: {exc}")
            done_callback([])
            return

        downloaded = []
        failed = []
        for row in manifest:
            if not isinstance(row, dict):
                continue
            if row.get("status") == "downloaded" and row.get("path"):
                downloaded.append(row)
            else:
                failed.append(row)

        if not downloaded:
            total_urls = 0
            if js_list_file.exists():
                total_urls = len([u for u in js_list_file.read_text(encoding="utf-8", errors="replace").splitlines() if u.strip()])
            line_callback(f"[JSSecrets] ✘ No downloaded JS files to scan. "
                          f"Collected URLs={total_urls}, download failures={len(failed)}.")
            line_callback(f"[JSSecrets] ℹ  Check failure reasons in {out / 'js_download_failures.json'}")
            done_callback([])
            return

        line_callback(f"[JSSecrets] ▶  Scanning {len(downloaded)} downloaded JS file(s) "
                      f"({len(failed)} download failure(s) skipped)…")

        bodies: dict[str, str] = {}
        read_fail = 0
        for idx, row in enumerate(downloaded, start=1):
            if stopped(stop_evt):
                line_callback(f"[JSSecrets] ⚠  Stop requested after reading {idx - 1}/{len(downloaded)} JS file(s).")
                break
            url = row.get("url", "")
            path = Path(row.get("path", ""))
            try:
                if not path.exists():
                    # Backward compatibility if the path was saved relative.
                    alt = cache_dir / path.name
                    path = alt if alt.exists() else path
                text = path.read_text(encoding="utf-8", errors="replace")
                bodies[url] = text
            except Exception as exc:
                read_fail += 1
                line_callback(f"[JSSecrets]   ✘  Could not read downloaded file for {url} — {type(exc).__name__}: {exc}")
                log.debug(f"[JSSecrets] local read fail {url} {path}: {exc}")

            if idx == 1 or idx == len(downloaded) or idx % 50 == 0:
                line_callback(f"[JSSecrets]   ↓  Read progress: {idx}/{len(downloaded)} "
                              f"({len(bodies)} loaded, {read_fail} read failed)")

        if not bodies:
            line_callback("[JSSecrets] ✘ No readable downloaded JS files to scan.")
            done_callback([])
            return

        total_bytes = sum(len(b) for b in bodies.values())
        line_callback(f"[JSSecrets] ▶  Scanning {total_bytes:,} bytes for secrets…")

        rows: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        for file_idx, (url, body) in enumerate(bodies.items(), start=1):
            if stopped(stop_evt):
                line_callback(f"[JSSecrets] ⚠  Stop requested after scanning {file_idx - 1}/{len(bodies)} JS file(s).")
                break

            for pid, severity, label, rx in SECRET_PATTERNS:
                for m in rx.finditer(body):
                    raw = m.group(0)
                    value = m.group(m.lastindex) if m.lastindex else raw
                    value = value.strip().strip("\"'")
                    key = (pid, value, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "pattern":    pid,
                        "severity":   severity,
                        "label":      label,
                        "value":      value,
                        "raw_length": len(value),
                        "source_url": url,
                    })
            for pid, severity, rx in INTERNAL_HOST_PATTERNS:
                for m in rx.finditer(body):
                    value = m.group(0)
                    key = (pid, value, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "pattern":    pid,
                        "severity":   severity,
                        "label":      pid.replace("_", " ").title(),
                        "value":      value,
                        "raw_length": len(value),
                        "source_url": url,
                    })

            if file_idx == 1 or file_idx == len(bodies) or file_idx % 50 == 0:
                line_callback(f"[JSSecrets]   ↓  Scan progress: {file_idx}/{len(bodies)} "
                              f"({len(rows)} finding(s) so far)")

        try:
            (out / "js_secrets.json").write_text(json.dumps({
                "target":               target,
                "files_collected":      len(manifest),
                "files_downloaded":     len(downloaded),
                "files_download_failed": len(failed),
                "files_read_failed":    read_fail,
                "files_scanned":        len(bodies),
                "findings":             rows,
            }, indent=2), encoding="utf-8")
        except Exception as exc:
            log.debug(f"[JSSecrets] persist fail: {exc}")

        sev_counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
        for r in rows:
            sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

        if sev_counts["HIGH"]:
            line_callback(f"[JSSecrets]   ⚠  {sev_counts['HIGH']} HIGH-severity "
                          "finding(s) — verify manually before reporting")
        if sev_counts["MEDIUM"]:
            line_callback(f"[JSSecrets]   ⚠  {sev_counts['MEDIUM']} MEDIUM-severity "
                          "finding(s)")
        if sev_counts["INFO"]:
            line_callback(f"[JSSecrets]   ℹ  {sev_counts['INFO']} internal-host "
                          "reference(s)")

        line_callback(f"[JSSecrets] ✔  {len(rows)} total finding(s) across "
                      f"{len({r['source_url'] for r in rows})} JS file(s)")
        log.info(f"[JSSecrets] {len(rows)} findings "
                 f"(HIGH={sev_counts['HIGH']}, MED={sev_counts['MEDIUM']}, "
                 f"INFO={sev_counts['INFO']})")
        done_callback(rows)

    threading.Thread(target=_run, daemon=True).start()
