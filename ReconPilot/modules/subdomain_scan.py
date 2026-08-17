from __future__ import annotations

import subprocess
import shutil
import threading
from pathlib import Path
from typing import Callable

from utils.parser import parse_subfinder_output
from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped


def is_subfinder_available() -> bool:
    return shutil.which("subfinder") is not None


def run_subdomain_scan(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Run subfinder and return a sorted list of subdomain strings.
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not is_subfinder_available():
            msg = "✘ subfinder not found on PATH. Install subfinder and retry."
            log.error(msg)
            line_callback(f"[Subdomain] {msg}")
            done_callback([])
            return

        out_file = str(Path(output_dir) / "subdomains.txt")
        cmd = ["subfinder", "-d", target, "-silent", "-o", out_file]

        log.info(f"[Subdomain] {' '.join(cmd)}")
        line_callback(f"[Subdomain] ▶  {' '.join(cmd)}")

        raw_lines: list[str] = []
        try:
            proc = popen_scan(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            start_stop_watcher(proc, stop_evt, line_callback, "Subdomain")
            for line in proc.stdout:            # type: ignore[union-attr]
                if stopped(stop_evt):
                    kill_process_tree(proc)
                    done_callback([])
                    return
                s = line.rstrip()
                if s:
                    log.debug(f"[Subdomain] {s}")
                    line_callback(f"[Subdomain] {s}")
                    raw_lines.append(s)
            proc.wait()
            if stopped(stop_evt):
                done_callback([])
                return
        except Exception as exc:
            log.error(f"[Subdomain] {exc}")
            done_callback([])
            return

        raw = "\n".join(raw_lines)
        if Path(out_file).exists():
            raw += "\n" + Path(out_file).read_text(encoding="utf-8", errors="replace")

        subs = parse_subfinder_output(raw)
        line_callback(f"[Subdomain] ✔  {len(subs)} subdomain(s) found.")
        done_callback(subs)

    threading.Thread(target=_run, daemon=True).start()
