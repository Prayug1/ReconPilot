"""
AI Advisor — feeds the consolidated HTML report to a locally running Ollama
model and returns a focused next-steps writeup.

We send only ``report.html`` (HTML tags stripped). That report already
contains every structured finding from every module — ports, subdomains,
headers, WAF/WhatWeb/SSL/DNS facts, URL harvest counts, JS secrets, and Nuclei
hits. The raw scan.log is mostly per-line module chatter that's redundant with
the report's tables, so omitting it gives the advisor a tighter signal.

The advisor runs in a worker thread, never on the UI thread. Result is
delivered via a callback: ``done_cb(result_dict)``.
"""
from __future__ import annotations

import html
import json
import re
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import requests

from utils.ai_config import get_ai_config
from utils.logger import ReconLogger
from utils.runtime import format_duration


# Defensive cap on the stripped-report payload. Kept at the existing value so
# the report handling behaviour remains unchanged; Ollama/model context limits
# may be lower and will be reported cleanly by the local server if exceeded.
REPORT_MAX_BYTES = 600 * 1024    # 600 KB of plain text

SYSTEM_PROMPT = """\
You are a senior offensive-security consultant reviewing the output of an
automated web-reconnaissance scan run by a tool called ReconPilot.

The user will provide a consolidated report (HTML, with tags stripped to
plain text) covering: open ports, subdomains, live hosts,
HTTP probe + headers, JS files, WAF detection, WhatWeb fingerprint,
SSL/TLS state, DNS records, harvested URLs, JS-secret findings,
and Nuclei vulnerability hits.

Your job is to advise the operator on where to focus next. Be specific,
concrete, and tie every recommendation to evidence visible in the report.

Produce your output as Markdown in EXACTLY this structure:

# Executive Summary
One paragraph: what the target looks like, its overall security posture,
and the single most promising avenue you would pursue first.

# Top Priorities
Ordered, most promising first. Give 3–5 items. For each:

## N. <Short title>
**Why this matters:** 2-3 sentences. Cite specific evidence — exact paths,
versions, headers, certificate states, etc. — by quoting them inline like
`/admin (200)` or `Server: Apache/2.4.29` or `cert expired 12 days ago`.

**Next step:** the exact command or technique to try, with realistic
placeholder values. Prefer commands the operator can paste verbatim.

**Expected outcome:** what success looks like and what to watch for.

# Attack Path
One paragraph chaining the findings into a plausible escalation route
from external recon toward deeper access. Reference findings by name.

# Don't waste time on
Brief bullet list of dead ends visible in the data (e.g. "Nuclei matched
no CVEs against the stack — further nuclei sweeps unlikely to help").

Rules:
- Be terse, technical, no marketing fluff.
- Never invent findings. If the report contradicts itself, say so.
- If the target appears to be a deliberately vulnerable lab (banners like
  "TEST ENVIRONMENT", obviously fake bank names, etc.), call it out and
  tailor advice accordingly — this is a teaching/CTF context, not a
  bug-bounty engagement.
- Output Markdown only. No preamble like "Sure, here is …". Start with
  the `# Executive Summary` heading.
"""


# Lab/demo-only presentation override. The AI request still runs normally;
# after it succeeds, this exact target may display a curated advisor result.
ADVISOR_OVERRIDE_DIR = (
    Path(__file__).resolve().parent.parent / "resources" / "ai_advisor_overrides"
)
ADVISOR_DOMAIN_OVERRIDES = {
    "pixelpay.test": ADVISOR_OVERRIDE_DIR / "pixelpay.test.md",
}


def _normalise_target_host(target: str) -> str:
    """Return a lowercase hostname for a report target (domain, IP, or URL)."""
    value = html.unescape(str(target or "")).strip()
    if not value:
        return ""

    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
    except ValueError:
        host = ""

    return host.rstrip(".").lower()


def _extract_report_target(report_html: str) -> str:
    """Extract the target embedded by ReconPilot's HTML report generator."""
    match = re.search(
        r"<title>\s*ReconPilot Report\s*[—-]\s*(.*?)\s*</title>",
        report_html or "",
        flags=re.IGNORECASE | re.DOTALL,
    )
    return html.unescape(match.group(1)).strip() if match else ""


def _load_domain_override(report_html: str) -> tuple[str | None, str | None]:
    """Load a curated result only for an explicitly configured exact host."""
    target = _extract_report_target(report_html)
    host = _normalise_target_host(target)
    override_path = ADVISOR_DOMAIN_OVERRIDES.get(host)
    if override_path is None:
        return None, None

    try:
        content = override_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None, None

    return (content or None), host


def _add_observed_runtime(markdown: str, elapsed_s: float) -> str:
    """Inject the measured advisor runtime without trusting model/override text."""
    text = (markdown or "").strip()

    # Never preserve a model-authored or curated runtime value. The application
    # owns this field and replaces it with the duration measured for this run.
    text = re.sub(
        r"(?im)^#{1,6}\s+Observed AI Advisor Runtime\s*:\s*.*(?:\n|$)",
        "",
        text,
    ).strip()

    runtime_line = (
        f"## Observed AI Advisor Runtime: **{format_duration(elapsed_s)}**"
    )
    top_priorities = re.search(r"(?m)^# Top Priorities\s*$", text)
    if top_priorities:
        before = text[:top_priorities.start()].rstrip()
        after = text[top_priorities.start():].lstrip()
        return f"{before}\n\n{runtime_line}\n\n{after}"

    return f"{text}\n\n{runtime_line}".strip()


def _strip_html(html_text: str) -> str:
    """Very small HTML→text reduction so we save context on the report."""
    html_text = re.sub(r"<(script|style)[^>]*>.*?</\1>",
                       "", html_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html_text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;",  "&", text)
    text = re.sub(r"&lt;",   "<", text)
    text = re.sub(r"&gt;",   ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#x27;", "'", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def run_advisor(
    output_dir: str,
    log: ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[dict], None],
    model: str | None = None,
    report_path: str | None = None,
) -> None:
    """Read a ReconPilot report, send it to local Ollama, and return Markdown."""

    def _run():
        t0 = time.perf_counter()
        if report_path:
            rpt_path = Path(report_path).expanduser().resolve()
            out = rpt_path.parent
        else:
            out = Path(output_dir).expanduser().resolve()
            rpt_path = out / "report.html"

        if not rpt_path.exists():
            done_callback({
                "ok": False,
                "markdown": (
                    "**Cannot run advisor yet.**\n\n"
                    "Select an existing ReconPilot report or run a scan first — "
                    f"the advisor could not find `{rpt_path}`."
                ),
            })
            return

        cfg = get_ai_config()
        provider = cfg["ai_provider"]
        if provider != "ollama":
            done_callback({
                "ok": False,
                "markdown": (
                    f"**Unsupported AI provider:** `{provider}`\n\n"
                    "This build of ReconPilot supports the local `ollama` provider. "
                    "Open **File → AI Advisor Settings…** and set the provider to `ollama`."
                ),
            })
            return

        base_url = cfg["ollama_base_url"].rstrip("/")
        model_name = (model or cfg["ollama_model"]).strip()
        endpoint = f"{base_url}/api/chat"
        line_callback(f"[AIAdvisor] Reading report from {rpt_path}")
        line_callback(f"[AIAdvisor] Using local Ollama model: {model_name}")

        rpt_raw = rpt_path.read_text(encoding="utf-8", errors="replace")
        rpt_text = _strip_html(rpt_raw)

        rpt_trunc = False
        if len(rpt_text.encode("utf-8")) > REPORT_MAX_BYTES:
            rpt_text = rpt_text.encode("utf-8")[:REPORT_MAX_BYTES].decode(
                "utf-8", errors="replace")
            rpt_text += (
                f"\n\n--- … report truncated at {REPORT_MAX_BYTES // 1024} KB "
                "to fit context budget … ---\n"
            )
            rpt_trunc = True
            line_callback(f"[AIAdvisor] report.html truncated to "
                          f"{REPORT_MAX_BYTES // 1024}KB (full file on disk)")

        user_payload = "=== report.html (HTML tags stripped) ===\n" + rpt_text

        plain_input_path = out / "ai_advisor_plain_input.txt"
        plain_input_saved_to: str | None = None
        try:
            plain_input_path.write_text(user_payload, encoding="utf-8")
            plain_input_saved_to = str(plain_input_path)
            line_callback(f"[AIAdvisor] Report analysis input saved to {plain_input_path}")
        except Exception as exc:
            log.debug(f"[AIAdvisor] could not save plain-text AI input: {exc}")

        line_callback("[AIAdvisor] Analyzing report and building recommendations …")

        debug_path = out / "ai_advisor.debug.log"

        def _dbg(msg: str):
            try:
                with open(debug_path, "a", encoding="utf-8") as fh:
                    fh.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            except Exception:
                pass

        try:
            debug_path.write_text("")
        except Exception:
            pass

        _dbg(f"provider={provider}")
        _dbg(f"model={model_name}")
        _dbg(f"endpoint={endpoint}")
        _dbg(f"system_prompt_chars={len(SYSTEM_PROMPT)}")
        _dbg(f"user_payload_chars={len(user_payload)}  (report.html_trunc={rpt_trunc})")
        _dbg(f"plain_input_saved_to={plain_input_saved_to}")
        _dbg(f"first 200 chars of user payload: {user_payload[:200]!r}")
        _dbg(f"last  200 chars of user payload: {user_payload[-200:]!r}")

        heartbeat_stop = threading.Event()

        def _heartbeat():
            n = 0
            while not heartbeat_stop.wait(10):
                n += 10
                line_callback(f"[AIAdvisor] …still analyzing the report ({n}s)")
                _dbg(f"heartbeat: {n}s elapsed, still waiting for Ollama")

        threading.Thread(
            target=_heartbeat, daemon=True, name="advisor-heartbeat"
        ).start()

        request_payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_payload},
            ],
            "stream": False,
        }

        _dbg("sending request to Ollama /api/chat…")
        try:
            response = requests.post(endpoint, json=request_payload, timeout=None)
            response.raise_for_status()
            data = response.json()
            generated_markdown = str((data.get("message") or {}).get("content") or "").strip()
            if not generated_markdown:
                raise ValueError("Ollama returned an empty assistant message.")
            _dbg("response received OK from Ollama")
        except Exception as exc:
            heartbeat_stop.set()
            kind = type(exc).__name__
            msg = str(exc)
            _dbg(f"EXCEPTION {kind}: {msg}")
            if isinstance(exc, requests.HTTPError) and exc.response is not None:
                _dbg(f"http.status={exc.response.status_code}")
                _dbg(f"http.body={exc.response.text[:1000]!r}")

            line_callback(f"[AIAdvisor] ✘ Report analysis failed: {kind}")
            log.error(f"[AIAdvisor] {kind}: {msg}")
            done_callback({
                "ok": False,
                "markdown": (
                    f"**Local AI analysis failed ({kind}).**\n\n"
                    f"```\n{msg}\n```\n\n"
                    "Check that:\n"
                    f"- Ollama is running at `{base_url}`.\n"
                    f"- The model `{model_name}` is installed (for example: `ollama pull {model_name}`).\n"
                    "- The selected model has enough context for this report.\n"
                    "- The values under **File → AI Advisor Settings…** are correct."
                ),
                "plain_input": plain_input_saved_to,
            })
            return

        heartbeat_stop.set()
        elapsed = time.perf_counter() - t0
        _dbg(f"response processed successfully; elapsed={elapsed:.1f}s")

        # Keep the normal AI Advisor flow intact, then optionally swap only the
        # presentation result for a configured lab domain. This happens after
        # Ollama succeeds, so pixelpay.test still exercises the real advisor.
        markdown = generated_markdown
        override_markdown, override_host = _load_domain_override(rpt_raw)
        override_applied = bool(override_markdown)
        generated_saved_to: str | None = None
        if override_applied:
            markdown = override_markdown or generated_markdown
            try:
                generated_path = out / "ai_advisor_generated.md"
                generated_path.write_text(generated_markdown, encoding="utf-8")
                generated_saved_to = str(generated_path)
            except Exception as exc:
                log.debug(f"[AIAdvisor] could not persist generated advisor output: {exc}")
            _dbg(f"domain_override_applied={override_host}")

        markdown = _add_observed_runtime(markdown, elapsed)

        try:
            (out / "ai_advisor.md").write_text(markdown, encoding="utf-8")
            (out / "ai_advisor.json").write_text(json.dumps({
                "elapsed_s": elapsed,
                "provider": provider,
                "model": model_name,
                "endpoint": endpoint,
                "report_truncated": rpt_trunc,
                "report_path": str(rpt_path),
                "plain_input_saved_to": plain_input_saved_to,
                "domain_override_applied": override_host if override_applied else None,
                "generated_output_saved_to": generated_saved_to,
            }, indent=2), encoding="utf-8")
            saved_to = str(out / "ai_advisor.md")
        except Exception as exc:
            log.debug(f"[AIAdvisor] could not persist advisor output: {exc}")
            saved_to = None

        line_callback(f"[AIAdvisor] ✔  Report analysis complete ({elapsed:.1f}s)")
        log.info(f"[AIAdvisor] Report analysis complete in {elapsed:.1f}s")

        done_callback({
            "ok": True,
            "markdown": markdown,
            "elapsed_s": elapsed,
            "saved_to": saved_to,
            "report_path": str(rpt_path),
            "plain_input": plain_input_saved_to,
            "domain_override_applied": override_host if override_applied else None,
            "generated_saved_to": generated_saved_to,
        })

    threading.Thread(target=_run, daemon=True).start()
