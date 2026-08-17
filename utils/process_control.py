from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import Callable


def popen_scan(cmd: list[str], **kwargs) -> subprocess.Popen:
    """Start an external scan command in its own process group.

    Putting each tool in a separate process group lets ReconPilot terminate the
    scanner and any children it spawns with one kill operation when the user
    presses Stop Scan.
    """
    if os.name == "nt":
        creationflags = kwargs.pop("creationflags", 0)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return subprocess.Popen(cmd, creationflags=creationflags, **kwargs)
    return subprocess.Popen(cmd, preexec_fn=os.setsid, **kwargs)


def kill_process_tree(proc: subprocess.Popen | None) -> None:
    """Forcefully terminate a process and its child process group."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def start_stop_watcher(
    proc: subprocess.Popen,
    stop_evt: threading.Event | None,
    log_callback: Callable[[str], None] | None = None,
    label: str = "Scan",
) -> threading.Thread | None:
    """Kill proc when stop_evt is set. Returns the watcher thread if created."""
    if stop_evt is None:
        return None

    def _watch() -> None:
        stop_evt.wait()
        if proc.poll() is None:
            if log_callback:
                try:
                    log_callback(f"[{label}] cancellation requested — killing process tree.")
                except Exception:
                    pass
            kill_process_tree(proc)

    t = threading.Thread(target=_watch, daemon=True, name=f"{label.lower()}-stop-watch")
    t.start()
    return t


def stopped(stop_evt: threading.Event | None) -> bool:
    return bool(stop_evt and stop_evt.is_set())
