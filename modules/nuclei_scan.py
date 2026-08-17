from __future__ import annotations

import os
import signal
import subprocess
import shutil
import threading
import json
from pathlib import Path
from typing import Callable

from utils.parser import parse_nuclei_output
from utils.logger import ReconLogger

# No hard timeout: nuclei runs until it exits naturally or Stop Scan is pressed.


def is_nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _build_url(target: str) -> str:
    """
    nuclei -u expects a full URL. If the target already carries a scheme we
    pass it straight through; otherwise we default to https:// (nuclei will
    follow redirects / fall back internally for most templates).
    """
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"https://{target.rstrip('/')}"


def _kill_proc_tree(proc: subprocess.Popen) -> None:
    """Best-effort termination of nuclei *and* anything it spawned."""
    try:
        # We launched with start_new_session=True, so the process is the
        # leader of its own group — kill the whole group to clean up any
        # children (some nuclei templates exec helper binaries).
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass




def _format_nuclei_live_line(line: str) -> str | None:
    """Render nuclei JSONL as compact terminal text.

    Nuclei is still executed with -jsonl so the report/parser gets exact
    machine-readable data. The UI should not show that raw JSON. This function
    turns finding objects into the familiar bracketed nuclei format and either
    hides or simplifies non-finding JSON such as progress stats.
    """
    s = line.strip()
    if not s:
        return None

    if not s.startswith("{"):
        return s

    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return s

    # -stats emits objects like {"duration": ..., "percent": ..., ...}.
    # Hide them by default; if an older binary/config still emits them, show
    # one compact progress line instead of raw JSON.
    if "duration" in obj and "percent" in obj and "template-id" not in obj:
        percent = obj.get("percent", "?")
        matched = obj.get("matched", "?")
        requests = obj.get("requests", "?")
        errors = obj.get("errors", "?")
        return f"Progress: {percent}% | matches: {matched} | requests: {requests} | errors: {errors}"

    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    template_id = (
        obj.get("template-id")
        or obj.get("templateID")
        or Path(str(obj.get("template", ""))).stem
        or "unknown-template"
    )

    # Objects without a template are not findings. Do not show raw JSON.
    if template_id == "unknown-template" and not info:
        return None

    matcher = obj.get("matcher-name") or obj.get("matcher") or ""
    template_label = f"{template_id}:{matcher}" if matcher else str(template_id)
    finding_type = obj.get("type") or obj.get("protocol") or "—"
    severity = (info.get("severity") or obj.get("severity") or "unknown").lower()
    matched_at = obj.get("matched-at") or obj.get("url") or obj.get("host") or "—"

    extras = obj.get("extracted-results") or obj.get("extracted_results") or []
    extra_text = ""
    if isinstance(extras, list) and extras:
        rendered = ", ".join(str(x) for x in extras[:5])
        if len(extras) > 5:
            rendered += f", +{len(extras) - 5} more"
        extra_text = f" [{rendered}]"
    elif isinstance(extras, str) and extras:
        extra_text = f" [{extras}]"

    return f"[{template_label}] [{finding_type}] [{severity}] {matched_at}{extra_text}"

def run_nuclei_scan(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    prog_callback: Callable[[int], None] | None = None,
    stop_evt:      threading.Event | None = None,
    target_urls:   list[str] | None = None,
) -> None:
    """
    Run `nuclei -u <url>` against the target and stream findings.

    Writes machine-readable JSONL to <output_dir>/nuclei.jsonl (preferred by
    the parser) and streams the human-readable lines to the UI log.

    ``stop_evt`` is an optional cancellation event supplied by the
    orchestrator. When set, the nuclei subprocess (and its process group) is
    terminated, the read loop exits, and ``done_callback`` is invoked with an
    empty result so the orchestrator's bookkeeping wraps up cleanly.

    done_callback receives the parsed findings list:
      [{"template", "name", "severity", "type", "url"}, ...]
    """

    def _run():
        if not is_nuclei_available():
            msg = ("✘ nuclei not found on PATH. Install from "
                   "https://github.com/projectdiscovery/nuclei")
            log.error(msg)
            line_callback(f"[Nuclei] {msg}")
            done_callback([])
            return

        jsonl_out = str(Path(output_dir) / "nuclei.jsonl")
        urls = []
        if target_urls:
            seen = set()
            for u in target_urls:
                if isinstance(u, str) and u.startswith(("http://", "https://")) and u not in seen:
                    seen.add(u)
                    urls.append(u.rstrip("/"))
        if not urls:
            urls = [_build_url(target)]

        target_list_path = Path(output_dir) / "nuclei_targets.txt"
        use_list = len(urls) > 1
        if use_list:
            target_list_path.write_text("\n".join(urls) + "\n", encoding="utf-8")

        cmd = ["nuclei"]
        if use_list:
            cmd += ["-l", str(target_list_path)]
        else:
            cmd += ["-u", urls[0]]
        cmd += [
            "-jsonl", "-o", jsonl_out,   # structured output for the parser/report
            "-silent",                   # suppress banner / noise on stdout
            # Do not pass -stats here. With -jsonl, nuclei emits progress stats
            # as JSON objects too; those are useful for machines but noisy in
            # the live terminal. ReconPilot keeps the JSONL file for reports
            # and renders findings below as clean human-readable lines.
        ]

        log.info(f"[Nuclei] {' '.join(cmd)}")
        if use_list:
            line_callback(f"[Nuclei] ▶  nuclei -l {target_list_path} ({len(urls)} target(s))")
        else:
            line_callback(f"[Nuclei] ▶  nuclei -u {urls[0]}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                # Own process group so we can SIGKILL nuclei + any helpers
                # in a single os.killpg call when the orchestrator cancels.
                start_new_session=True,
            )
        except FileNotFoundError:
            line_callback("[Nuclei] ✘ nuclei vanished from PATH mid-run.")
            done_callback([])
            return
        except Exception as exc:
            log.error(f"[Nuclei] {exc}")
            line_callback(f"[Nuclei] ✘ Error launching nuclei: {exc}")
            done_callback([])
            return

        # Watchdog: when the orchestrator sets stop_evt, kill the whole
        # process group so we stop emitting lines and stop hitting the target.
        cancelled = threading.Event()
        if stop_evt is not None:
            def _watch():
                while not stop_evt.is_set():
                    if proc.poll() is not None:
                        return                  # nuclei finished normally
                    if stop_evt.wait(timeout=0.5):
                        break
                if proc.poll() is None:
                    cancelled.set()
                    log.warning("[Nuclei] cancellation requested — terminating subprocess.")
                    _kill_proc_tree(proc)
            threading.Thread(target=_watch, daemon=True, name="nuclei-watch").start()

        raw = ""
        try:
            for line in proc.stdout:            # type: ignore[union-attr]
                if cancelled.is_set() or (stop_evt is not None and stop_evt.is_set()):
                    break
                s = line.rstrip()
                if not s:
                    continue

                # Keep the original JSONL line for parsing/report generation,
                # but never dump raw JSON into the live terminal.
                raw += s + "\n"
                display = _format_nuclei_live_line(s)
                if display:
                    line_callback(f"[Nuclei] {display}")
            # Wait for the proc to actually exit naturally, or after Stop Scan kills it.
            proc.wait()
        except Exception as exc:
            log.error(f"[Nuclei] {exc}")
            if not cancelled.is_set():
                line_callback(f"[Nuclei] ✘ Error reading nuclei output: {exc}")

        # Cancelled by orchestrator → don't try to summarise; UI callbacks
        # are already gated upstream so any line_callback here is a no-op.
        if cancelled.is_set():
            log.info("[Nuclei] cancelled before completion")
            line_callback("[Nuclei] ⨯  Cancelled by orchestrator.")
            done_callback([])
            return

        # Prefer the JSONL file on disk (cleaner than scraped stdout) and
        # fall back to streamed stdout if the file is missing/empty.
        parse_src = raw
        try:
            jf = Path(jsonl_out)
            if jf.exists() and jf.stat().st_size > 0:
                parse_src = jf.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            log.debug(f"[Nuclei] could not read {jsonl_out}: {exc}")

        findings = parse_nuclei_output(parse_src)

        if findings:
            crit = sum(1 for f in findings if f["severity"] == "critical")
            high = sum(1 for f in findings if f["severity"] == "high")
            line_callback(
                f"[Nuclei] ✔  {len(findings)} finding(s) "
                f"(critical={crit}, high={high})."
            )
        else:
            line_callback("[Nuclei] ✔  No findings reported by nuclei.")

        if prog_callback:
            prog_callback(100)

        log.info(f"[Nuclei] {len(findings)} finding(s)")
        done_callback(findings)

    threading.Thread(target=_run, daemon=True).start()
