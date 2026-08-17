from __future__ import annotations

import subprocess
import shutil
import threading
from pathlib import Path
from typing import Callable

from utils.parser import parse_nmap_xml, split_host_port
from utils.logger import ReconLogger
from utils.process_control import popen_scan, kill_process_tree, start_stop_watcher, stopped


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
    ctf_mode:      bool = False,
) -> None:
    """
    Run nmap -sC -sV -O --open -oX.
    Streams stdout to line_callback; calls done_callback(ports_list) on finish.

    The orchestrator passes the user's target verbatim. Nmap doesn't accept
    ``host:port`` (it wants the bare host and a separate ``-p`` flag), so we
    split the target here and re-route the port through ``-p``. URL forms
    like ``http://host:8080/path`` are normalised too.
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not is_nmap_available():
            msg = "✘ nmap not found on PATH. Install nmap and retry."
            log.error(msg)
            line_callback(f"[Nmap] {msg}")
            done_callback([])
            return

        host, port = split_host_port(target)
        if not host:
            line_callback(f"[Nmap] ✘ Could not parse target: {target!r}")
            done_callback([])
            return

        if port:
            # Nmap can't accept "host:port" as a positional target. Per project
            # rule, nmap is the *only* module that strips the port — every
            # other module receives the user's target verbatim. We discard the
            # port here and let nmap do its normal default port scan.
            line_callback(
                f"[Nmap] target {target!r} → scanning host {host} "
                f"(dropped :{port}, default port scan applies)"
            )

        xml_out = str(Path(output_dir) / "nmap.xml")
        if ctf_mode:
            # Controlled/CTF mode needs to discover non-standard web ports so
            # downstream web modules can append the correct :port values.
            cmd = ["nmap", "-sC", "-sV", "-O", "--open", "-T4", "-p-",
                   "-oX", xml_out, host]
        else:
            cmd = ["nmap", "-sC", "-sV", "-O", "--open", "-T4",
                   "-oX", xml_out, host]

        log.info(f"[Nmap] {' '.join(cmd)}")
        if ctf_mode:
            line_callback("[Nmap] ℹ  CTF mode: scanning all TCP ports to discover web services.")
        line_callback(f"[Nmap] ▶  {' '.join(cmd)}")

        try:
            proc = popen_scan(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            start_stop_watcher(proc, stop_evt, line_callback, "Nmap")
            for line in proc.stdout:            # type: ignore[union-attr]
                if stopped(stop_evt):
                    kill_process_tree(proc)
                    done_callback([])
                    return
                s = line.rstrip()
                if s:
                    log.debug(f"[Nmap] {s}")
                    line_callback(f"[Nmap] {s}")
            proc.wait()
            if stopped(stop_evt):
                done_callback([])
                return
        except FileNotFoundError:
            done_callback([])
            return
        except Exception as exc:
            log.error(f"[Nmap] {exc}")
            line_callback(f"[Nmap] ✘ Error: {exc}")
            done_callback([])
            return

        ports = parse_nmap_xml(xml_out)
        line_callback(f"[Nmap] ✔  {len(ports)} open port(s) found.")
        done_callback(ports)

    threading.Thread(target=_run, daemon=True).start()
