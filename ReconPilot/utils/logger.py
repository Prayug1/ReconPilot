import logging
import os
from datetime import datetime
from pathlib import Path


class PlainFormatter(logging.Formatter):
    FMT    = "[%(asctime)s] [%(levelname)-8s] %(message)s"
    DATEFMT = "%Y-%m-%d %H:%M:%S"
    def format(self, record):
        self._style._fmt = self.FMT
        self.datefmt     = self.DATEFMT
        return super().format(record)


class ReconLogger:
    """
    One instance per scan session.

    Parameters
    ----------
    target        : target name (used for directory)
    log_callback  : callable(level: str, message: str) fired on every record
    """

    def __init__(self, target: str = "general", log_callback=None):
        self.target       = self._safe(target)
        self.log_callback = log_callback
        self._l           = logging.getLogger(f"ReconPilot.{self.target}.{id(self)}")
        self._l.setLevel(logging.DEBUG)
        self._l.handlers.clear()
        self._l.propagate = False

        self.log_dir = Path("output") / self.target
        self.log_dir.mkdir(parents=True, exist_ok=True)
        # One log file per target. Mode 'w' truncates on each run so repeated
        # scans overwrite the previous log instead of accumulating
        # scan_YYYYmmdd_HHMMSS.log files alongside the timestamped folders.
        log_file = self.log_dir / "scan.log"

        fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(PlainFormatter())
        self._l.addHandler(fh)

        if log_callback:
            ch = _CBHandler(log_callback)
            ch.setLevel(logging.DEBUG)
            self._l.addHandler(ch)

        self.log_file_path = str(log_file)

    # Public API ─────────────────────────────────────────────────────────────
    def debug(self, m):    self._l.debug(m)
    def info(self, m):     self._l.info(m)
    def warning(self, m):  self._l.warning(m)
    def error(self, m):    self._l.error(m)
    def critical(self, m): self._l.critical(m)

    @staticmethod
    def _safe(name: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


class _CBHandler(logging.Handler):
    def __init__(self, cb):
        super().__init__()
        self._cb = cb
    def emit(self, record):
        try:
            self._cb(record.levelname, self.format(record))
        except Exception:
            self.handleError(record)
