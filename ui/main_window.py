from __future__ import annotations

import errno
import fcntl
import html
import os
import pty
import re
import shutil
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    Qt, Signal, Slot, QUrl, QSocketNotifier, QTimer, QSize,
)
from PySide6.QtGui import (
    QColor, QTextCharFormat, QTextCursor, QDesktopServices, QAction, QActionGroup,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox,
    QTabWidget, QPlainTextEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QSplitter,
    QGroupBox, QProgressBar,
    QMessageBox, QSizePolicy, QScrollArea,
    QDialog, QDialogButtonBox, QTextBrowser, QFileDialog, QFormLayout, QComboBox,
    QListWidget, QListWidgetItem, QAbstractItemView,
)


# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE
# ═══════════════════════════════════════════════════════════════════════════════

C = {
    "bg":      "#0d0f14",
    "bg2":     "#12151c",
    "bg3":     "#1a1e28",
    "bg4":     "#20263a",
    "border":  "#252a36",
    "border2": "#2e3548",
    "accent":  "#00ff9d",
    "accent2": "#00c9ff",
    "accent3": "#ff4d6d",
    "accent4": "#bd93f9",
    "text":    "#e2e8f0",
    "dim":     "#64748b",
    "success": "#22c55e",
    "warning": "#f59e0b",
    "error":   "#ef4444",
    "running": "#00c9ff",
}

LOG_COLOURS = {
    "DEBUG":    C["dim"],
    "INFO":     C["accent"],
    "WARNING":  C["warning"],
    "ERROR":    C["error"],
    "CRITICAL": C["accent3"],
}

# Module metadata — "short" codes are kept to 4 chars max so the badge never
# overflows its fixed 68-px cell.
MODULES_META: dict[str, dict] = {
    "live_host":    {"label": "Live Host",      "short": "LIVE", "colour": C["success"]},
    "headers":      {"label": "HTTP Headers",   "short": "HDR",  "colour": C["warning"]},
    "waf":          {"label": "WAF Detect",     "short": "WAF",  "colour": C["accent3"]},
    "whatweb":      {"label": "WhatWeb",         "short": "WTWB", "colour": C["accent2"]},
    "sslcert":      {"label": "SSL/TLS Cert",    "short": "SSL",  "colour": C["accent3"]},
    "dns":          {"label": "DNS Enum",        "short": "DNS",  "colour": C["accent2"]},
    "subdomain":    {"label": "Subdomains",      "short": "SUBD", "colour": C["accent4"]},
    "http_probe":   {"label": "HTTP Probe",      "short": "PROB", "colour": C["accent2"]},
    "nmap":         {"label": "Nmap Scan",       "short": "NMAP", "colour": C["accent"]},
    "dir_enum":     {"label": "Directory Enumeration", "short": "DIR", "colour": C["warning"]},
    "subdomain_fuzz": {"label": "Subdomain Bruteforce", "short": "FUZZ", "colour": C["accent4"]},
    "url_harvest":  {"label": "URL Harvest",     "short": "URL",  "colour": C["accent2"]},
    "js_collector": {"label": "JS Collector",    "short": "JS",   "colour": C["accent4"]},
    "js_secrets":   {"label": "JS Secrets",      "short": "SEC",  "colour": C["error"]},
    "nuclei":       {"label": "Nuclei Scan",     "short": "NUCL", "colour": C["error"]},
}

# Default scan order for optional modules. Live Host is deliberately omitted
# here because it is compulsory and always runs first.
DEFAULT_SCAN_ORDER: list[str] = [
    "headers", "waf", "whatweb",
    "sslcert", "dns", "subdomain",
    "http_probe", "nmap", "url_harvest",
    "js_collector", "js_secrets", "nuclei",
]

CTF_SCAN_ORDER: list[str] = [
    "headers", "waf", "whatweb",
    "sslcert", "dir_enum", "subdomain_fuzz",
    "nmap", "url_harvest", "js_collector",
    "js_secrets", "nuclei",
]

# Tool rows shown in the TOOL STATUS panel. The panel is mode-aware: CTF mode
# hides bug-bounty-only tools so the left sidebar stays compact and relevant.
TOOL_STATUS_ORDER: list[str] = [
    "nmap", "subfinder", "httpx-toolkit", "wafw00f", "whatweb",
    "nuclei", "feroxbuster", "ffuf", "gospider", "gau", "waybackurls",
]

BUG_BOUNTY_TOOLS: set[str] = {
    "nmap", "subfinder", "httpx-toolkit", "wafw00f", "whatweb",
    "nuclei", "gospider", "gau", "waybackurls",
}

CTF_TOOLS: set[str] = {
    "nmap", "feroxbuster", "ffuf",
    "wafw00f", "whatweb", "nuclei", "gospider",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER — thin horizontal rule
# ═══════════════════════════════════════════════════════════════════════════════

def _hr(colour: str = C["border"]) -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background:{colour};border:none;")
    return line



# ═══════════════════════════════════════════════════════════════════════════════
#  PTY-BACKED TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

class PTYTerminalOutput(QPlainTextEdit):
    """
    Lightweight PTY-backed terminal-style output widget.

    ReconPilot still orchestrates scans through Python, but live log lines now
    pass through a Linux pseudo-terminal before being rendered. This gives the
    output area terminal-like buffering, CR/LF behaviour, and smoother handling
    of noisy tools than repeatedly appending rich QTextEdit fragments.
    """

    MAX_BLOCKS = 12000
    FLUSH_INTERVAL_MS = 25

    def __init__(self, parent=None):
        super().__init__(parent)
        self._master_fd: int | None = None
        self._slave_fd: int | None = None
        self._notifier: QSocketNotifier | None = None
        self._pending_text = ""

        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setMaximumBlockCount(self.MAX_BLOCKS)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background:{C['bg']}; color:{C['accent']}; border:none;
                font-family:'JetBrains Mono','Fira Code','Courier New',monospace;
                font-size:12px; padding:8px 12px;
                selection-background-color:{C['bg4']};
            }}
            QScrollBar:vertical {{
                background: {C['bg3']}; width: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border2']}; border-radius: 4px; min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C['accent']}66; }}
            QScrollBar:horizontal {{
                background: {C['bg3']}; height: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:horizontal {{
                background: {C['border2']}; border-radius: 4px; min-width: 24px;
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
        """)

        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(self.FLUSH_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush_pending)

        self._setup_pty()

    def _setup_pty(self) -> None:
        try:
            self._master_fd, self._slave_fd = pty.openpty()
            for fd in (self._master_fd, self._slave_fd):
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            self._notifier = QSocketNotifier(
                self._master_fd, QSocketNotifier.Type.Read, self
            )
            self._notifier.activated.connect(self._drain_pty)
        except Exception:
            # Fallback for unusual environments. The widget still works as a
            # fast terminal-style output area, only without PTY transport.
            self._master_fd = None
            self._slave_fd = None
            self._notifier = None

    def write_line(self, level: str, message: str) -> None:
        """Write one logical line to the PTY-backed output stream."""
        # Keep the live output visually like a terminal transcript. We do not
        # inject Qt rich text here, which avoids QTextEdit rendering glitches
        # when tools produce thousands of lines quickly.
        text = str(message).rstrip("\r\n") + "\r\n"
        data = text.encode("utf-8", errors="replace")

        if self._slave_fd is not None:
            try:
                os.write(self._slave_fd, data)
                return
            except BlockingIOError:
                # PTY buffer is temporarily full. Keep the line and flush it
                # through the normal text path rather than losing output.
                pass
            except OSError:
                pass

        self._pending_text += text
        if not self._flush_timer.isActive():
            self._flush_timer.start()

    @Slot()
    def _drain_pty(self) -> None:
        if self._master_fd is None:
            return

        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(self._master_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                break

        if chunks:
            self._pending_text += b"".join(chunks).decode("utf-8", errors="replace")
            if not self._flush_timer.isActive():
                self._flush_timer.start()

    @Slot()
    def _flush_pending(self) -> None:
        if not self._pending_text:
            self._flush_timer.stop()
            return

        text = self._pending_text
        self._pending_text = ""
        self._flush_timer.stop()

        # Normalise CR/LF terminal output for Qt rendering.
        text = text.replace("\r\n", "\n").replace("\r", "\n")

        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(text)
        self.setTextCursor(cur)
        self.ensureCursorVisible()

    def clear(self) -> None:  # noqa: D401 - Qt override
        """Clear the visible terminal and any queued buffered output."""
        self._pending_text = ""
        super().clear()

    def closeEvent(self, event):
        if self._notifier is not None:
            self._notifier.setEnabled(False)
        for fd in (self._master_fd, self._slave_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._master_fd = None
        self._slave_fd = None
        super().closeEvent(event)


# ═══════════════════════════════════════════════════════════════════════════════
#  RECON TABLE
# ═══════════════════════════════════════════════════════════════════════════════

class ReconTable(QTableWidget):

    def __init__(self, columns: list[str], parent=None):
        super().__init__(parent)
        self._col_count = len(columns)
        self.setColumnCount(self._col_count)
        self.setHorizontalHeaderLabels(columns)

        hh = self.horizontalHeader()
        # Each column auto-sizes to the widest cell in it (so values like
        # "Werkzeug/3.1.8 Python/3.12.3" no longer get clipped to "Werkzeug…").
        # The final column gets Stretch so it fills any horizontal slack
        # without leaving an awkward blank gutter on the right.
        for i in range(self._col_count - 1):
            hh.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        if self._col_count:
            hh.setSectionResizeMode(
                self._col_count - 1, QHeaderView.ResizeMode.Stretch
            )
        hh.setStretchLastSection(False)   # superseded by per-section mode above
        hh.setMinimumSectionSize(56)
        hh.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)

        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setWordWrap(False)
        self.setShowGrid(True)
        # Horizontal scrollbar appears automatically if combined content is
        # wider than the viewport — better than truncation.
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {C['bg2']};
                alternate-background-color: {C['bg3']};
                color: {C['text']};
                gridline-color: {C['border']};
                border: none;
                font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
                font-size: 12px;
                outline: none;
            }}
            QTableWidget::item {{ padding: 2px 8px; }}
            QTableWidget::item:selected {{
                background-color: #1a2a3a;
                color: {C['accent2']};
            }}
            QHeaderView {{ background-color: {C['bg3']}; }}
            QHeaderView::section {{
                background-color: {C['bg3']};
                color: {C['accent']};
                border: none;
                border-right: 1px solid {C['border']};
                border-bottom: 1px solid {C['border2']};
                padding: 6px 10px;
                font-weight: bold;
                font-size: 10px;
                letter-spacing: 1px;
            }}
            QScrollBar:vertical {{
                background: {C['bg3']}; width: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border2']}; border-radius: 4px; min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C['accent']}66; }}
            QScrollBar:horizontal {{
                background: {C['bg3']}; height: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:horizontal {{
                background: {C['border2']}; border-radius: 4px; min-width: 24px;
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
        """)

    def populate(self, rows: list[list]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(0)
        for row_data in rows:
            r = self.rowCount()
            self.insertRow(r)
            for col, val in enumerate(row_data):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                self.setItem(r, col, item)
        self.setSortingEnabled(True)

    def add_row(self, row_data: list, colours: dict[int, str] | None = None) -> None:
        self.setSortingEnabled(False)
        r = self.rowCount()
        self.insertRow(r)
        for col, val in enumerate(row_data):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            if colours and col in colours:
                item.setForeground(QColor(colours[col]))
            self.setItem(r, col, item)
        self.setSortingEnabled(True)


# ═══════════════════════════════════════════════════════════════════════════════
#  STATUS BADGE  — compact fixed-size pill (never overflows)
# ═══════════════════════════════════════════════════════════════════════════════

class StatusBadge(QLabel):
    """
    Fixed 68 x 20 px badge showing a short status.
    Using 4-letter codes keeps it stable regardless of module name length.
    """
    _MAP = {
        "idle":    (C["dim"],     C["bg3"],    "●", "IDLE"),
        "running": (C["running"], "#06161f",   "◎", "RUN "),
        "success": (C["success"], "#061408",   "✔", "DONE"),
        "failed":  (C["error"],   "#1a0606",   "✘", "FAIL"),
        "skipped": (C["dim"],     C["bg3"],    "—", "SKIP"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(68, 20)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_status("idle")

    def set_status(self, status: str):
        colour, bg, icon, text = self._MAP.get(status, self._MAP["idle"])
        self.setText(f"{icon} {text}")
        self.setStyleSheet(f"""
            QLabel {{
                color: {colour};
                background: {bg};
                border: 1px solid {colour}88;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 1px;
            }}
        """)


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE ROW  — label + badge + progress bar
# ═══════════════════════════════════════════════════════════════════════════════

class ModuleRow(QWidget):
    """
    Horizontal row: [label 106px fixed] [badge 68px fixed] [bar — stretches]

    Total min width ≈ 106 + 68 + 60 bar + 2×6 spacing = ~246 px.
    Fits comfortably in a 260 px minimum panel.
    """

    def __init__(self, module_id: str, parent=None):
        super().__init__(parent)
        meta   = MODULES_META.get(module_id, {"label": module_id, "short": "???", "colour": C["text"]})
        colour = meta["colour"]
        self._colour = colour

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(26)
        self.setStyleSheet("background: transparent;")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        # Label — fixed width so the badge and bar always have predictable space
        lbl = QLabel(meta["label"])
        lbl.setFixedWidth(106)
        lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        lbl.setStyleSheet(f"""
            color: {C['text']};
            font-family: 'Courier New', monospace;
            font-size: 10px;
            background: transparent;
        """)

        self.badge = StatusBadge()

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setFixedHeight(5)
        self.bar.setTextVisible(False)
        self.bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.bar.setStyleSheet(self._bar_css(colour))

        lay.addWidget(lbl)
        lay.addWidget(self.badge)
        lay.addWidget(self.bar, stretch=1)

    # ── CSS helpers ───────────────────────────────────────────────────────
    def _bar_css(self, colour: str) -> str:
        return f"""
            QProgressBar {{
                background: {C['bg3']};
                border: none;
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {colour}44, stop:1 {colour});
                border-radius: 2px;
            }}
        """

    def _bar_css_error(self) -> str:
        return f"""
            QProgressBar {{
                background: {C['bg3']};
                border: none;
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: {C['error']}77;
                border-radius: 2px;
            }}
        """

    # ── Public API ────────────────────────────────────────────────────────
    def set_status(self, status: str):
        self.badge.set_status(status)
        if status == "running":
            self.bar.setRange(0, 0)
            self.bar.setStyleSheet(self._bar_css(self._colour))
        elif status == "success":
            self.bar.setRange(0, 100)
            self.bar.setValue(100)
            self.bar.setStyleSheet(self._bar_css(self._colour))
        elif status == "failed":
            self.bar.setRange(0, 100)
            self.bar.setValue(100)
            self.bar.setStyleSheet(self._bar_css_error())
        else:  # idle / skipped
            self.bar.setRange(0, 100)
            self.bar.setValue(0)
            self.bar.setStyleSheet(self._bar_css(self._colour))

    def set_progress(self, pct: int):
        if self.bar.maximum() == 0:
            self.bar.setRange(0, 100)
        self.bar.setValue(min(100, max(0, pct)))





# ═══════════════════════════════════════════════════════════════════════════════
#  INLINE MODULE ORDER LIST — manual mouse reorder without Qt internal drag/drop
# ═══════════════════════════════════════════════════════════════════════════════

class ModuleOrderList(QListWidget):
    """
    Inline module-order list used by Custom Order mode.

    Qt's built-in InternalMove drag/drop is unreliable for checkable
    QListWidgetItem rows on some PySide6/Kali builds: items can lose their
    UserRole data or visually disappear after a native drop. To avoid that,
    this widget does not use Qt item drag/drop at all. It performs a simple
    mouse-driven reorder by taking the real QListWidgetItem and inserting it
    at the row under the cursor while the left mouse button is held.

    Because the original item instance is moved, its module id, check state,
    tooltip, flags, foreground colour, and selection state are preserved.
    """

    orderChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._manual_reorder_enabled = False
        self._press_pos = None
        self._drag_row = -1
        self._is_reordering = False
        self._order_dirty = False

    def set_manual_reorder_enabled(self, enabled: bool) -> None:
        self._manual_reorder_enabled = bool(enabled)
        self._press_pos = None
        self._drag_row = -1
        self._is_reordering = False
        self._order_dirty = False
        # Keep Qt's native DnD completely disabled. Reordering is handled in
        # mouseMoveEvent below, which prevents rows disappearing on drop.
        self.setDragEnabled(False)
        self.setAcceptDrops(False)
        self.setDropIndicatorShown(False)
        self.setDragDropMode(QAbstractItemView.DragDropMode.NoDragDrop)

    def mousePressEvent(self, event):
        if self._manual_reorder_enabled and event.button() == Qt.MouseButton.LeftButton:
            try:
                pos = event.position().toPoint()
            except AttributeError:
                pos = event.pos()
            self._press_pos = pos
            self._drag_row = self.indexAt(pos).row()
            self._is_reordering = False
            self._order_dirty = False
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not self._manual_reorder_enabled or self._drag_row < 0:
            super().mouseMoveEvent(event)
            return
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            super().mouseMoveEvent(event)
            return

        try:
            pos = event.position().toPoint()
        except AttributeError:
            pos = event.pos()

        if self._press_pos is None:
            self._press_pos = pos

        if not self._is_reordering:
            distance = (pos - self._press_pos).manhattanLength()
            if distance < QApplication.startDragDistance():
                super().mouseMoveEvent(event)
                return
            self._is_reordering = True

        target_row = self.indexAt(pos).row()
        if target_row < 0:
            # If dragged below the last visible item, move to the bottom. If
            # dragged above the list, move to the top.
            target_row = self.count() - 1 if pos.y() > self.viewport().height() // 2 else 0

        target_row = max(0, min(target_row, self.count() - 1))
        if target_row != self._drag_row:
            item = self.takeItem(self._drag_row)
            if item is not None:
                self.insertItem(target_row, item)
                self.setCurrentRow(target_row)
                self._drag_row = target_row
                self._order_dirty = True
        event.accept()

    def mouseReleaseEvent(self, event):
        if self._manual_reorder_enabled and self._is_reordering:
            event.accept()
            self._press_pos = None
            self._drag_row = -1
            self._is_reordering = False
            if self._order_dirty:
                self._order_dirty = False
                self.orderChanged.emit()
            return

        self._press_pos = None
        self._drag_row = -1
        self._is_reordering = False
        self._order_dirty = False
        super().mouseReleaseEvent(event)

# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN ORDER DIALOG
# ═══════════════════════════════════════════════════════════════════════════════

class ScanOrderDialog(QDialog):
    """Small reorder dialog for the custom scan order feature."""

    def __init__(self, current_order: list[str] | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Custom Scan Order")
        self.setMinimumSize(520, 620)
        self.resize(560, 680)
        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        title = QLabel("CUSTOM SCAN ORDER")
        title.setStyleSheet(f"""
            color:{C['accent']}; font-family:'Courier New', monospace;
            font-size:14px; font-weight:bold; letter-spacing:3px;
            background:transparent;
        """)
        lay.addWidget(title)

        note = QLabel(
            "Live Host always runs first. In custom mode, selected modules run "
            "one-by-one in the order below. Drag modules up/down and uncheck modules to skip them."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{C['dim']}; font-size:11px; background:transparent;")
        lay.addWidget(note)

        self.list = QListWidget()
        self.list.setAlternatingRowColors(False)
        self.list.setStyleSheet(f"""
            QListWidget {{
                background:{C['bg']}; color:{C['text']};
                border:1px solid {C['border2']}; border-radius:6px;
                padding:6px; font-family:'Courier New', monospace; font-size:12px;
            }}
            QListWidget::item {{ padding:8px 6px; border-bottom:1px solid {C['border']}; }}
            QListWidget::item:selected {{ background:{C['bg4']}; color:{C['accent']}; }}
        """)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.setDragEnabled(True)
        self.list.setAcceptDrops(True)
        self.list.setDropIndicatorShown(True)
        self.list.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.list.setToolTip("Drag modules up/down to set the custom scan order. Uncheck modules to skip them in custom mode.")
        self.list.model().rowsMoved.connect(lambda *args: QTimer.singleShot(0, self._after_drag_reorder))
        self.list.itemChanged.connect(lambda item: QTimer.singleShot(0, self._renumber))
        lay.addWidget(self.list, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addStretch(1)
        self.default_btn = QPushButton("RESET DEFAULT ORDER")
        self.default_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.default_btn.setMinimumHeight(32)
        self.default_btn.setStyleSheet(f"""
            QPushButton {{
                background:transparent; color:{C['accent2']};
                border:1px solid {C['accent2']}; border-radius:5px;
                font-family:'Courier New', monospace; font-size:10px;
                letter-spacing:1px; padding:0 12px;
            }}
            QPushButton:hover {{ background:#061620; }}
        """)
        btn_row.addWidget(self.default_btn)
        lay.addLayout(btn_row)

        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.setStyleSheet(f"""
            QPushButton {{
                background:{C['bg3']}; color:{C['text']};
                border:1px solid {C['border2']}; border-radius:5px;
                min-height:28px; min-width:82px;
            }}
            QPushButton:hover {{ color:{C['accent']}; border-color:{C['accent']}; }}
        """)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

        self.default_btn.clicked.connect(lambda: self._load_order(DEFAULT_SCAN_ORDER))

        self._load_order(current_order or DEFAULT_SCAN_ORDER)

    def _load_order(self, order: list[str]) -> None:
        """Load selected modules first, then unchecked remaining modules."""
        selected_set = {m for m in order if m in DEFAULT_SCAN_ORDER}
        seen: set[str] = set()
        cleaned: list[str] = []
        for mod in order:
            if mod in DEFAULT_SCAN_ORDER and mod not in seen:
                cleaned.append(mod)
                seen.add(mod)
        for mod in DEFAULT_SCAN_ORDER:
            if mod not in seen:
                cleaned.append(mod)
                seen.add(mod)

        self.list.blockSignals(True)
        self.list.clear()
        for mod in cleaned:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, mod)
            item.setFlags(
                item.flags()
                | Qt.ItemFlag.ItemIsUserCheckable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsDragEnabled
                | Qt.ItemFlag.ItemIsDropEnabled
            )
            item.setCheckState(
                Qt.CheckState.Checked if mod in selected_set else Qt.CheckState.Unchecked
            )
            self.list.addItem(item)
        self.list.blockSignals(False)
        self._renumber()
        if self.list.count():
            self.list.setCurrentRow(0)
        self._update_buttons()

    def _renumber(self) -> None:
        self.list.blockSignals(True)
        try:
            n = 0
            for i in range(self.list.count()):
                item = self.list.item(i)
                mod = item.data(Qt.ItemDataRole.UserRole)
                label = MODULES_META.get(mod, {}).get("label", mod)
                if item.checkState() == Qt.CheckState.Checked:
                    n += 1
                    item.setText(f"{n:02d}.  {label}")
                    item.setForeground(QColor(C["text"]))
                else:
                    item.setText(f"OFF   {label}")
                    item.setForeground(QColor(C["dim"]))
        finally:
            self.list.blockSignals(False)

    def _after_drag_reorder(self) -> None:
        self._renumber()

    def _move_selected(self, delta: int) -> None:
        row = self.list.currentRow()
        new_row = row + delta
        if row < 0 or new_row < 0 or new_row >= self.list.count():
            return
        item = self.list.takeItem(row)
        self.list.insertItem(new_row, item)
        self.list.setCurrentRow(new_row)
        self._renumber()
        self._update_buttons()

    def _update_buttons(self) -> None:
        # Kept for compatibility with older dialog flow; drag-and-drop reordering
        # no longer needs separate move buttons.
        return

    def accept(self) -> None:
        if not self.order():
            QMessageBox.warning(
                self,
                "No modules selected",
                "Select at least one optional module for the custom scan order, or cancel."
            )
            return
        super().accept()

    def order(self) -> list[str]:
        return [
            self.list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.list.count())
            if self.list.item(i).checkState() == Qt.CheckState.Checked
        ]

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):

    # Worker-thread → GUI-thread bridges. The AI Advisor runs in a daemon
    # thread; emitting these signals from there auto-queues delivery onto
    # the GUI thread (the thread MainWindow lives in), so the slots can
    # safely touch widgets. This is the *only* correct way to update the
    # UI from a non-Qt thread.
    _advisor_line_signal = Signal(str)
    _advisor_done_signal = Signal(dict)

    def __init__(self):
        super().__init__()
        self._scan_start: float | None = None
        self._active     = False
        self._output_dir = ""
        self._manager    = None
        self._module_rows: dict[str, ModuleRow] = {}
        self._advisor_active_btn = None
        self._scan_profile = "bug_bounty"
        self._scan_order_mode = "default"
        self._custom_scan_order = list(DEFAULT_SCAN_ORDER)
        self._custom_full_order = list(DEFAULT_SCAN_ORDER)
        self._ctf_selected_order = list(CTF_SCAN_ORDER)
        self._ctf_full_order = list(CTF_SCAN_ORDER)

        self._setup_ui()
        self._check_tools()

        # Wire the cross-thread signals to their handlers.
        self._advisor_line_signal.connect(
            lambda msg: self._on_log("INFO", msg)
        )
        self._advisor_done_signal.connect(self._on_advisor_done)

    # ══════════════════════════════════════════════════════════════════════
    #  WINDOW / ROOT SETUP
    # ══════════════════════════════════════════════════════════════════════

    def _setup_ui(self):
        self.setWindowTitle("ReconPilot  //  Automated Reconnaissance Framework")
        # Smaller minimum so users can resize freely; splitter handles the rest
        self.setMinimumSize(860, 580)
        self.resize(1420, 880)
        self._apply_global_style()
        self._build_menubar()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        # ── Main horizontal splitter ───────────────────────────────────────
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(1)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {C['border2']}; }}"
        )
        self._splitter.addWidget(self._build_left_panel())
        self._splitter.addWidget(self._build_right_panel())
        # Default split. With the left panel's maxWidth cap removed, the user
        # can drag the handle outward to give controls/status more room.
        self._splitter.setSizes([360, 1060])
        self._splitter.setStretchFactor(0, 0)   # left: stays at user's chosen size
        self._splitter.setStretchFactor(1, 1)   # right: takes all extra window space
        root.addWidget(self._splitter, stretch=1)

        self._build_statusbar()
        self._refresh_mode_visibility()

    def _apply_global_style(self):
        """Application-wide stylesheet — covers scrollbars and tooltips."""
        QApplication.instance().setStyleSheet(f"""
            * {{ outline: none; }}
            QMainWindow, QWidget {{
                background: {C['bg']};
                color: {C['text']};
                font-family: 'Courier New', monospace;
            }}
            QToolTip {{
                background: {C['bg3']};
                color: {C['accent']};
                border: 1px solid {C['accent']};
                padding: 4px 8px;
                font-size: 11px;
            }}
            QScrollBar:vertical {{
                background: {C['bg3']}; width: 8px;
                border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border2']}; border-radius: 4px; min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C['accent']}44; }}
            QScrollBar:horizontal {{
                background: {C['bg3']}; height: 8px;
                border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:horizontal {{
                background: {C['border2']}; border-radius: 4px; min-width: 24px;
            }}
            QScrollBar::add-line, QScrollBar::sub-line,
            QScrollBar::add-page, QScrollBar::sub-page {{
                width: 0; height: 0; background: none;
            }}
        """)

    # ══════════════════════════════════════════════════════════════════════
    #  HEADER BANNER
    # ══════════════════════════════════════════════════════════════════════

    def _build_menubar(self) -> None:
        """Top-left File menu for report/advisor workflow actions."""
        mb = self.menuBar()
        mb.setNativeMenuBar(False)
        mb.setStyleSheet(f"""
            QMenuBar {{
                background:{C['bg2']}; color:{C['text']};
                border-bottom:1px solid {C['border2']};
                font-family:'Courier New', monospace; font-size:11px;
            }}
            QMenuBar::item {{
                background:transparent; padding:5px 12px;
            }}
            QMenuBar::item:selected {{
                background:{C['bg3']}; color:{C['accent']};
            }}
            QMenu {{
                background:{C['bg2']}; color:{C['text']};
                border:1px solid {C['border2']};
                font-family:'Courier New', monospace; font-size:11px;
            }}
            QMenu::item {{ padding:7px 28px 7px 18px; }}
            QMenu::item:selected {{
                background:{C['bg3']}; color:{C['accent']};
            }}
            QMenu::separator {{
                height:1px; background:{C['border2']}; margin:5px 8px;
            }}
        """)

        file_menu = mb.addMenu("File")

        self.open_existing_report_action = QAction("Open Existing Report…", self)
        self.open_existing_report_action.triggered.connect(self._open_existing_report)
        file_menu.addAction(self.open_existing_report_action)

        file_menu.addSeparator()

        self.ai_settings_action = QAction("AI Advisor Settings…", self)
        self.ai_settings_action.triggered.connect(self._open_ai_advisor_settings)
        file_menu.addAction(self.ai_settings_action)

        file_menu.addSeparator()

        self.advisor_existing_action = QAction("Advise Existing Report…", self)
        self.advisor_existing_action.triggered.connect(self._open_advisor_for_existing_report)
        file_menu.addAction(self.advisor_existing_action)

        self.saved_advisor_action = QAction("Open Saved Advisor…", self)
        self.saved_advisor_action.triggered.connect(self._open_saved_advisor_report)
        file_menu.addAction(self.saved_advisor_action)

        mode_menu = mb.addMenu("Select Mode")
        self._mode_action_group = QActionGroup(self)
        self._mode_action_group.setExclusive(True)

        self.bug_bounty_mode_action = QAction("Bug Bounty Mode", self)
        self.bug_bounty_mode_action.setCheckable(True)
        self.bug_bounty_mode_action.setChecked(True)
        self.bug_bounty_mode_action.triggered.connect(lambda: self._set_scan_profile("bug_bounty"))
        self._mode_action_group.addAction(self.bug_bounty_mode_action)
        mode_menu.addAction(self.bug_bounty_mode_action)

        self.ctf_mode_action = QAction("Controlled / CTF Mode", self)
        self.ctf_mode_action.setCheckable(True)
        self.ctf_mode_action.triggered.connect(lambda: self._set_scan_profile("ctf"))
        self._mode_action_group.addAction(self.ctf_mode_action)
        mode_menu.addAction(self.ctf_mode_action)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(58)
        bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        bar.setStyleSheet(
            f"background: {C['bg2']}; border-bottom: 2px solid {C['accent']};"
        )

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(0)

        logo = QLabel("◈  RECONPILOT")
        logo.setStyleSheet(f"""
            font-family: 'Courier New', monospace;
            font-size: 19px; font-weight: bold;
            color: {C['accent']}; letter-spacing: 8px;
            background: transparent;
        """)

        sep = QLabel("  //  ")
        sep.setStyleSheet(f"color:{C['border2']}; font-size:16px; background:transparent;")

        tagline = QLabel("Automated Reconnaissance Framework")
        tagline.setStyleSheet(f"""
            font-family: 'Courier New', monospace; font-size: 10px;
            color: {C['dim']}; letter-spacing: 1px; background: transparent;
        """)

        lay.addWidget(logo)
        lay.addWidget(sep)
        lay.addWidget(tagline)
        lay.addStretch()
        return bar

    # ══════════════════════════════════════════════════════════════════════
    #  LEFT PANEL  — scrollable content + pinned action buttons
    # ══════════════════════════════════════════════════════════════════════

    def _build_left_panel(self) -> QWidget:
        """
        Structure
        ─────────
        container  (QWidget, min 255px — no max so the splitter can widen it
                    as far as the user drags)
          └── outer_lay  (QVBoxLayout, no margins)
                ├── QScrollArea  [stretch=1]
                │     └── inner  (groups: target / modules / tools / progress)
                ├── _hr divider
                └── btn_area  (start / stop / report — always visible)
        """
        container = QWidget()
        container.setMinimumWidth(255)
        # No maximumWidth — capping at 390 left the contents looking squeezed
        # on wider windows. The splitter still controls the actual width;
        # users can drag it inward to shrink or outward to expand freely.
        container.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        container.setStyleSheet(
            f"background: {C['bg2']}; border-right: 1px solid {C['border2']};"
        )

        outer_lay = QVBoxLayout(container)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.setSpacing(0)

        # ── Scroll area (houses all group boxes) ───────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        scroll.setStyleSheet("""
            QScrollArea         { border: none; background: transparent; }
            QScrollArea > QWidget > QWidget { background: transparent; }
        """)

        inner = QWidget()
        # Maximum instead of Preferred makes the inner widget shrink to its
        # natural height, which lets the scroll area handle overflow correctly.
        inner.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        inner.setStyleSheet("background: transparent;")

        inner_lay = QVBoxLayout(inner)
        inner_lay.setContentsMargins(10, 12, 10, 8)
        inner_lay.setSpacing(8)

        inner_lay.addWidget(self._build_target_group())
        inner_lay.addWidget(self._build_modules_group())
        inner_lay.addWidget(self._build_scan_order_group())
        inner_lay.addWidget(self._build_tools_group())
        inner_lay.addWidget(self._build_progress_group())
        inner_lay.addSpacing(6)   # breathing room at the bottom of the scroll

        scroll.setWidget(inner)
        outer_lay.addWidget(scroll, stretch=1)

        # ── Divider ────────────────────────────────────────────────────────
        outer_lay.addWidget(_hr(C["border2"]))

        # ── Pinned action buttons (never scroll away) ──────────────────────
        btn_area = QWidget()
        btn_area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn_area.setStyleSheet(f"background: {C['bg2']};")

        btn_lay = QVBoxLayout(btn_area)
        btn_lay.setContentsMargins(10, 10, 10, 12)
        btn_lay.setSpacing(6)

        self.scan_btn = self._btn(
            "⚡  START SCAN",
            fg=C["bg"], bg=C["accent"],
            hover="#00e08a", pressed="#009e60",
            height=44, bold=True, fs=13,
        )
        self.scan_btn.clicked.connect(self._start_scan)

        self.stop_btn = self._btn(
            "■  STOP SCAN",
            fg=C["error"], bg="transparent",
            border=C["error"], hover="#1a0606",
            height=30, fs=10,
        )
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)

        self.report_btn = self._btn(
            "📄  OPEN REPORT",
            fg=C["accent2"], bg="transparent",
            border=C["accent2"], hover="#061620",
            height=30, fs=10,
        )
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self._open_report)

        self.advisor_btn = self._btn(
            "🤖  AI ADVISOR",
            fg=C["accent"], bg="transparent",
            border=C["accent"], hover="#062018",
            height=30, fs=10,
        )
        self.advisor_btn.setEnabled(False)
        self.advisor_btn.clicked.connect(self._open_advisor)

        btn_lay.addWidget(self.scan_btn)
        btn_lay.addWidget(self.stop_btn)
        btn_lay.addWidget(self.report_btn)
        btn_lay.addWidget(self.advisor_btn)
        outer_lay.addWidget(btn_area)

        return container

    # ── Shared GroupBox factory ────────────────────────────────────────────
    def _grp(self, title: str) -> QGroupBox:
        g = QGroupBox(title)
        g.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        g.setStyleSheet(f"""
            QGroupBox {{
                color: {C['accent2']};
                border: 1px solid {C['border']};
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 8px;
                font-family: 'Courier New', monospace;
                font-size: 9px; font-weight: bold; letter-spacing: 3px;
                background: {C['bg3']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 6px; left: 10px;
                background: {C['bg3']};
            }}
        """)
        lay = QVBoxLayout(g)
        lay.setContentsMargins(8, 6, 8, 8)
        lay.setSpacing(5)
        return g

    # ── TARGET group ───────────────────────────────────────────────────────
    def _build_target_group(self) -> QGroupBox:
        g = self._grp("TARGET")

        hint = QLabel("Domain or IP address")
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"color:{C['dim']}; font-size:10px; letter-spacing:1px;"
            f"background:transparent;"
        )

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com  /  192.168.1.1")
        self.target_input.setMinimumHeight(36)
        self.target_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.target_input.setStyleSheet(f"""
            QLineEdit {{
                background: {C['bg']};
                color: {C['accent']};
                border: 1px solid {C['border2']};
                border-radius: 4px;
                padding: 0 10px;
                font-family: 'Courier New', monospace;
                font-size: 13px;
            }}
            QLineEdit:focus {{ border-color: {C['accent']}; background: {C['bg2']}; }}
        """)
        self.target_input.returnPressed.connect(self._start_scan)

        g.layout().addWidget(hint)
        g.layout().addWidget(self.target_input)
        return g


    # ── SCAN MODE group ───────────────────────────────────────────────────
    def _build_scan_mode_group(self) -> QGroupBox:
        g = self._grp("SCAN MODE")

        note = QLabel(
            "Bug Bounty uses the current recon workflow. Controlled / CTF mode uses a louder lab workflow: Nmap → feroxbuster/ffuf → JS/Nuclei."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{C['dim']}; font-size:10px; background:transparent;")

        self._scan_mode_lbl = QLabel()
        self._scan_mode_lbl.setWordWrap(True)
        self._scan_mode_lbl.setStyleSheet(f"""
            QLabel {{
                color:{C['accent2']}; background:{C['bg']};
                border:1px solid {C['border']}; border-radius:4px;
                padding:6px; font-family:'Courier New', monospace; font-size:10px;
            }}
        """)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self.bug_bounty_mode_btn = self._btn(
            "BUG BOUNTY",
            fg=C["accent2"], bg="transparent",
            border=C["accent2"], hover="#061620",
            height=28, fs=9,
        )
        self.ctf_mode_btn = self._btn(
            "CONTROLLED / CTF",
            fg=C["accent"], bg="transparent",
            border=C["accent"], hover="#062018",
            height=28, fs=9,
        )
        self.bug_bounty_mode_btn.clicked.connect(lambda: self._set_scan_profile("bug_bounty"))
        self.ctf_mode_btn.clicked.connect(lambda: self._set_scan_profile("ctf"))

        row.addWidget(self.bug_bounty_mode_btn)
        row.addWidget(self.ctf_mode_btn)

        g.layout().addWidget(note)
        g.layout().addWidget(self._scan_mode_lbl)
        g.layout().addLayout(row)
        self._refresh_scan_profile_ui(sync_modules=False)
        return g

    def _mode_button_style(self, active: bool, colour: str) -> str:
        fg = C["bg"] if active else colour
        bg = colour if active else "transparent"
        hover = colour if active else "#061620"
        return f"""
            QPushButton {{
                background:{bg}; color:{fg};
                border:1px solid {colour}; border-radius:5px;
                font-family:'Courier New', monospace; font-size:9px;
                letter-spacing:2px; padding:0 8px;
            }}
            QPushButton:hover {{ background:{hover}; }}
        """

    def _set_scan_profile(self, profile: str) -> None:
        self._scan_profile = "ctf" if profile == "ctf" else "bug_bounty"
        if self._scan_profile == "ctf":
            # Controlled/CTF mode uses the same Default/Custom behavior as Bug
            # Bounty mode: Default is locked, Custom enables drag + checkboxes.
            self._scan_order_mode = "default"
            self._ctf_full_order = list(CTF_SCAN_ORDER)
            self._ctf_selected_order = list(CTF_SCAN_ORDER)
            self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
        else:
            # Return to the normal Bug Bounty workflow and preserve the previous
            # default/custom order controls.
            if self._scan_order_mode == "custom":
                self._load_modules_list(self._custom_full_order, self._custom_scan_order, custom_enabled=True, reorder_enabled=True)
            else:
                self._load_modules_list(DEFAULT_SCAN_ORDER, DEFAULT_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
        self._refresh_scan_profile_ui(sync_modules=False)
        self._refresh_order_mode_ui(sync_modules=False)
        self._refresh_mode_visibility()

    def _refresh_scan_profile_ui(self, sync_modules: bool = True) -> None:
        ctf = self._scan_profile == "ctf"

        # The visible mode switch now lives in the top-left menu bar
        # (Select Mode). Older builds had a SCAN MODE group in the side panel,
        # so these checks stay optional for compatibility.
        if hasattr(self, "_scan_mode_lbl"):
            if ctf:
                self._scan_mode_lbl.setText("CONTROLLED / CTF ACTIVE  //  lab mode  //  headers → dir/ffuf → nmap/crawl/JS → secrets/nuclei")
            else:
                self._scan_mode_lbl.setText("BUG BOUNTY ACTIVE  //  standard phased recon workflow")

        if sync_modules and hasattr(self, "modules_list"):
            if ctf:
                if self._scan_order_mode == "custom":
                    self._load_modules_list(self._ctf_full_order, self._ctf_selected_order, custom_enabled=True, reorder_enabled=True)
                else:
                    self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
            elif self._scan_order_mode == "custom":
                self._load_modules_list(self._custom_full_order, self._custom_scan_order, custom_enabled=True, reorder_enabled=True)
            else:
                self._load_modules_list(DEFAULT_SCAN_ORDER, DEFAULT_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)

        if hasattr(self, "bug_bounty_mode_btn"):
            self.bug_bounty_mode_btn.setStyleSheet(self._mode_button_style(not ctf, C["accent2"]))
            self.ctf_mode_btn.setStyleSheet(self._mode_button_style(ctf, C["accent"]))

        if hasattr(self, "bug_bounty_mode_action"):
            self.bug_bounty_mode_action.blockSignals(True)
            self.ctf_mode_action.blockSignals(True)
            self.bug_bounty_mode_action.setChecked(not ctf)
            self.ctf_mode_action.setChecked(ctf)
            self.bug_bounty_mode_action.blockSignals(False)
            self.ctf_mode_action.blockSignals(False)

        if hasattr(self, "default_order_btn"):
            self.default_order_btn.setEnabled(True)
            self.custom_order_btn.setEnabled(True)

        self._refresh_mode_visibility()

    def _visible_module_ids_for_mode(self) -> list[str]:
        """Module rows/tabs that should be visible for the selected scan mode."""
        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            if self._scan_order_mode == "custom":
                selected = list(getattr(self, "_ctf_selected_order", CTF_SCAN_ORDER) or [])
            else:
                selected = list(CTF_SCAN_ORDER)
            return ["live_host", *selected]
        return ["live_host", *DEFAULT_SCAN_ORDER]

    def _visible_tools_for_mode(self) -> set[str]:
        """Tool Status rows that should be visible for the selected scan mode."""
        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            return set(CTF_TOOLS)
        return set(BUG_BOUNTY_TOOLS)

    def _refresh_mode_visibility(self) -> None:
        """Hide progress rows, result tabs, and tool rows not used by the mode."""
        visible = set(self._visible_module_ids_for_mode())

        for mod_id, row in getattr(self, "_module_rows", {}).items():
            row.setVisible(mod_id in visible)

        visible_tools = self._visible_tools_for_mode()
        for tool, row in getattr(self, "_tool_rows", {}).items():
            row.setVisible(tool in visible_tools)

        tabs = getattr(self, "tabs", None)
        tab_index = getattr(self, "_tab_index_by_attr", {})
        tab_module = getattr(self, "_tab_module_by_attr", {})
        if tabs is not None and tab_index and tab_module:
            for attr, mod_id in tab_module.items():
                idx = tab_index.get(attr)
                if idx is None:
                    continue
                try:
                    tabs.setTabVisible(idx, mod_id in visible)
                except Exception:
                    # Older/odd Qt builds may not support tab visibility; in
                    # that case keeping all tabs visible is safer than removing
                    # widgets and risking broken table references.
                    pass

    # ── MODULES group ──────────────────────────────────────────────────────
    def _build_modules_group(self) -> QGroupBox:
        g = self._grp("MODULES")
        self.modules_group = g
        self.cb: dict[str, QListWidgetItem] = {}

        self._module_checks_meta = [
            ("headers",      "HTTP Headers",         True,  "Phase 1: checks OWASP security headers"),
            ("waf",          "WAF Detection",        True,  "Phase 1: wafw00f -a (https + :8080 fallback)"),
            ("whatweb",      "WhatWeb Fingerprint",  True,  "Phase 1: whatweb -a 3 (tech / CMS / framework detection)"),
            ("sslcert",      "SSL/TLS Cert Enum",    True,  "Phase 2: TLS handshake + x509 parse (port from target, default 443)"),
            ("dns",          "DNS Enumeration",      True,  "Bug bounty Phase 2: A/AAAA/MX/NS/TXT/DMARC/SPF/DNSSEC"),
            ("subdomain",    "Subdomain Enum",       True,  "Bug bounty Phase 2: subfinder -d -silent"),
            ("http_probe",   "HTTP Probe",           True,  "Bug bounty Phase 3: live URL detection with httpx-toolkit"),
            ("nmap",         "Nmap Port Scan",       True,  "Bug bounty Phase 3 / CTF Phase 3: nmap service discovery"),
            ("dir_enum",     "Directory Enumeration", True,  "CTF mode Phase 2: feroxbuster against discovered/fallback web targets"),
            ("subdomain_fuzz", "Subdomain Bruteforce", True,  "CTF mode Phase 2: ffuf Host-header subdomain/vhost fuzzing; skipped for IP targets"),
            ("url_harvest",  "URL Harvest",          True,  "Bug bounty: passive sources + gospider; CTF Phase 3: active gospider crawl of web targets"),
            ("js_collector", "JS File Collector",    True,  "CTF Phase 3 / Bug bounty Phase 4: collects and downloads JavaScript files"),
            ("js_secrets",   "JS Secret Scanner",    True,  "CTF Phase 4: scans downloaded JS files for AWS keys / GitHub PATs / JWTs / API keys"),
            ("nuclei",       "Nuclei Vuln Scan",     True,  "Bug bounty main target / CTF Phase 4 discovered web targets: nuclei JSONL saved, clean terminal output"),
        ]

        self.modules_list = ModuleOrderList()
        self.modules_list.setAlternatingRowColors(False)
        self.modules_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.modules_list.setDragEnabled(False)
        self.modules_list.setAcceptDrops(False)
        self.modules_list.setDropIndicatorShown(False)
        self.modules_list.setDragDropMode(QAbstractItemView.DragDropMode.NoDragDrop)
        self.modules_list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.modules_list.setDragDropOverwriteMode(False)
        self.modules_list.setMinimumHeight(375)
        self.modules_list.setStyleSheet(f"""
            QListWidget {{
                background:{C['bg']}; color:{C['text']};
                border:1px solid {C['border']}; border-radius:6px;
                padding:5px; font-family:'Courier New', monospace; font-size:11px;
            }}
            QListWidget::item {{
                padding:6px 4px; border-bottom:1px solid {C['border']};
            }}
            QListWidget::item:selected {{ background:{C['bg4']}; color:{C['accent']}; }}
            QListWidget::indicator {{
                width:13px; height:13px;
                border:1px solid {C['accent']}77;
                border-radius:2px; background:{C['bg']};
            }}
            QListWidget::indicator:checked {{
                background:{C['accent']}; border-color:{C['accent']};
            }}
        """)
        self.modules_list.setToolTip(
            "Default: all modules are locked on. Custom: check/uncheck modules and drag rows to set order."
        )
        self.modules_list.itemChanged.connect(self._on_module_item_changed)
        self.modules_list.orderChanged.connect(lambda: QTimer.singleShot(0, self._after_module_drag_reorder))
        g.layout().addWidget(self.modules_list)

        self._load_modules_list(self._active_order_list(), self._active_order_list(), custom_enabled=False)
        return g

    def _module_label(self, module_id: str) -> str:
        return MODULES_META.get(module_id, {}).get("label", module_id)

    def _active_order_list(self) -> list[str]:
        return CTF_SCAN_ORDER if getattr(self, "_scan_profile", "bug_bounty") == "ctf" else DEFAULT_SCAN_ORDER

    def _normalise_full_order(self, order: list[str] | None = None) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        base_order = self._active_order_list()
        for mod in (order or []):
            if mod in base_order and mod not in seen:
                out.append(mod)
                seen.add(mod)
        for mod in base_order:
            if mod not in seen:
                out.append(mod)
                seen.add(mod)
        return out

    def _load_modules_list(self, full_order: list[str], selected_order: list[str], custom_enabled: bool, reorder_enabled: bool | None = None) -> None:
        """Render the MODULES list.

        custom_enabled controls whether users can tick/untick rows.
        reorder_enabled controls manual drag ordering separately.
        """
        if not hasattr(self, "modules_list"):
            return
        selected = set(selected_order)
        full_order = self._normalise_full_order(full_order)

        self.modules_list.blockSignals(True)
        try:
            self.modules_list.clear()
            self.cb.clear()
            for mod in full_order:
                item = QListWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, mod)
                item.setToolTip(next((tip for key, _label, _default, tip in self._module_checks_meta if key == mod), ""))
                # Only compact CTF rows. Leave Bug Bounty row geometry untouched
                # so its MODULES panel keeps the exact original look/spacing.
                if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
                    item.setSizeHint(QSize(0, 26))
                item.setCheckState(Qt.CheckState.Checked if mod in selected else Qt.CheckState.Unchecked)
                item.setFlags(self._module_item_flags(custom_enabled))
                self.modules_list.addItem(item)
                self.cb[mod] = item
        finally:
            self.modules_list.blockSignals(False)

        self.modules_list.set_manual_reorder_enabled(custom_enabled if reorder_enabled is None else reorder_enabled)

        self._renumber_module_list()
        self._apply_modules_group_sizing()

    def _module_item_flags(self, custom_enabled: bool) -> Qt.ItemFlag:
        if not custom_enabled:
            # Keep the green checked boxes visible in default mode, but do not
            # allow clicking, unchecking, selecting, or dragging.
            return Qt.ItemFlag.ItemIsUserCheckable
        return (
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )

    def _renumber_module_list(self) -> None:
        if not hasattr(self, "modules_list"):
            return
        self.modules_list.blockSignals(True)
        try:
            n = 0
            for row in range(self.modules_list.count()):
                item = self.modules_list.item(row)
                mod = item.data(Qt.ItemDataRole.UserRole)
                label = self._module_label(mod)
                if item.checkState() == Qt.CheckState.Checked:
                    n += 1
                    item.setText(f"{n:02d}.  {label}")
                    item.setForeground(QColor(C["text"]))
                else:
                    item.setText(f"OFF   {label}")
                    item.setForeground(QColor(C["dim"]))
        finally:
            self.modules_list.blockSignals(False)

    def _apply_modules_group_sizing(self) -> None:
        """Compact only the CTF MODULES list; keep Bug Bounty layout unchanged."""
        if not hasattr(self, "modules_list"):
            return

        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            # CTF has only a small lab-module set. Fix just this list/group to
            # the visible rows so the old Bug Bounty list height is not reused.
            # The Bug Bounty branch below deliberately restores the original
            # flexible layout and does not use any of this compact sizing.
            row_total = 0
            for i in range(self.modules_list.count()):
                row_total += max(24, self.modules_list.sizeHintForRow(i))
            list_h = max(36, row_total + (self.modules_list.frameWidth() * 2) + 10)

            self.modules_list.setMinimumHeight(list_h)
            self.modules_list.setMaximumHeight(list_h)
            self.modules_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self.modules_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

            if hasattr(self, "modules_group"):
                self.modules_group.setMinimumHeight(0)
                self.modules_group.setMaximumHeight(16777215)
                self.modules_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                # Finalize after Qt has recalculated the group-box title,
                # margins, hint label, and compact list size.
                QTimer.singleShot(0, self._finalize_ctf_modules_group_height)
        else:
            # Original Bug Bounty behavior: tall flexible module list. Do not
            # shrink-wrap the group and do not apply compact CTF row sizing.
            self.modules_list.setMinimumHeight(375)
            self.modules_list.setMaximumHeight(16777215)
            self.modules_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            self.modules_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

            if hasattr(self, "modules_group"):
                self.modules_group.setMinimumHeight(0)
                self.modules_group.setMaximumHeight(16777215)
                self.modules_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
                self.modules_group.updateGeometry()

    def _finalize_ctf_modules_group_height(self) -> None:
        if getattr(self, "_scan_profile", "bug_bounty") != "ctf":
            return
        if not hasattr(self, "modules_group"):
            return
        h = self.modules_group.sizeHint().height()
        # Small guard for Qt styles that under-report the group title/margins.
        h = max(h, self.modules_list.maximumHeight() + 58)
        self.modules_group.setMinimumHeight(h)
        self.modules_group.setMaximumHeight(h)
        self.modules_group.updateGeometry()

    def _sync_custom_order_from_modules_list(self) -> None:
        if not hasattr(self, "modules_list"):
            return
        full: list[str] = []
        selected: list[str] = []
        for row in range(self.modules_list.count()):
            item = self.modules_list.item(row)
            mod = item.data(Qt.ItemDataRole.UserRole)
            if mod not in self._active_order_list():
                continue
            full.append(mod)
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(mod)

        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            self._ctf_full_order = self._normalise_full_order(full)
            self._ctf_selected_order = selected
        else:
            self._custom_full_order = self._normalise_full_order(full)
            self._custom_scan_order = selected

    def _after_module_drag_reorder(self) -> None:
        if self._scan_order_mode != "custom":
            return
        self._sync_custom_order_from_modules_list()
        self._renumber_module_list()
        self._refresh_order_mode_ui(sync_modules=False)
        self._refresh_mode_visibility()

    def _on_module_item_changed(self, item: QListWidgetItem) -> None:
        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            if self._scan_order_mode != "custom":
                # CTF default order is locked on just like Bug Bounty default.
                self._ctf_full_order = list(CTF_SCAN_ORDER)
                self._ctf_selected_order = list(CTF_SCAN_ORDER)
                self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
                return
            self._sync_custom_order_from_modules_list()
            self._renumber_module_list()
            self._refresh_order_mode_ui(sync_modules=False)
            self._refresh_mode_visibility()
            return

        if self._scan_order_mode != "custom":
            # Bug Bounty default order is locked on. If Qt ever lets an item
            # toggle while default mode is active, immediately put it back.
            self._load_modules_list(DEFAULT_SCAN_ORDER, DEFAULT_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
            return
        self._sync_custom_order_from_modules_list()
        self._renumber_module_list()
        self._refresh_order_mode_ui(sync_modules=False)

    # ── SCAN ORDER group ──────────────────────────────────────────────────
    def _build_scan_order_group(self) -> QGroupBox:
        g = self._grp("SCAN ORDER")

        # Keep an internal status label for existing state-update code, but do
        # not add it to the visible layout. The user-facing scan order area now
        # only shows the Default/Custom buttons.
        self._scan_order_lbl = QLabel()
        self._scan_order_lbl.setVisible(False)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(6)

        self.default_order_btn = self._btn(
            "DEFAULT ORDER",
            fg=C["accent2"], bg="transparent",
            border=C["accent2"], hover="#061620",
            height=28, fs=9,
        )
        self.custom_order_btn = self._btn(
            "CUSTOM ORDER",
            fg=C["accent"], bg="transparent",
            border=C["accent"], hover="#062018",
            height=28, fs=9,
        )
        self.default_order_btn.clicked.connect(self._use_default_order)
        self.custom_order_btn.clicked.connect(self._use_custom_order)

        btn_row.addWidget(self.default_order_btn)
        btn_row.addWidget(self.custom_order_btn)

        g.layout().addLayout(btn_row)
        self._refresh_order_mode_ui()
        return g

    def _use_default_order(self) -> None:
        self._scan_order_mode = "default"
        if self._scan_profile == "ctf":
            # CTF Default mirrors Bug Bounty Default: every CTF module is
            # selected and the MODULES list is locked against dragging/toggling.
            self._ctf_full_order = list(CTF_SCAN_ORDER)
            self._ctf_selected_order = list(CTF_SCAN_ORDER)
            self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
            self._refresh_order_mode_ui(sync_modules=False)
            self._refresh_mode_visibility()
            return

        # Bug Bounty Default means a full phased scan: every optional module is
        # on and the inline MODULES list is locked.
        self._load_modules_list(DEFAULT_SCAN_ORDER, DEFAULT_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
        self._refresh_order_mode_ui(sync_modules=False)

    def _use_custom_order(self) -> None:
        self._scan_order_mode = "custom"
        # Custom order is edited directly inside the MODULES list: drag rows
        # up/down and tick/untick modules there. No separate dialog is used.
        if self._scan_profile == "ctf":
            self._ctf_full_order = self._normalise_full_order(getattr(self, "_ctf_full_order", CTF_SCAN_ORDER))
            if not getattr(self, "_ctf_selected_order", None):
                self._ctf_selected_order = list(CTF_SCAN_ORDER)
            self._load_modules_list(self._ctf_full_order, self._ctf_selected_order, custom_enabled=True, reorder_enabled=True)
            self._sync_custom_order_from_modules_list()
            self._refresh_order_mode_ui(sync_modules=False)
            self._refresh_mode_visibility()
            return

        self._custom_full_order = self._normalise_full_order(getattr(self, "_custom_full_order", DEFAULT_SCAN_ORDER))
        if not self._custom_scan_order:
            self._custom_scan_order = list(DEFAULT_SCAN_ORDER)
        self._load_modules_list(self._custom_full_order, self._custom_scan_order, custom_enabled=True, reorder_enabled=True)
        self._sync_custom_order_from_modules_list()
        self._refresh_order_mode_ui(sync_modules=False)

    def _set_module_checkboxes(self, selected_order: list[str], enabled: bool) -> None:
        """Compatibility wrapper used by scan startup and old code paths."""
        full_order = self._custom_full_order if enabled else DEFAULT_SCAN_ORDER
        self._load_modules_list(full_order, selected_order, custom_enabled=enabled)

    def _configure_custom_order(self) -> None:
        # Older builds opened a separate Custom Scan Order dialog. Custom order
        # is now edited inline in the MODULES list, so this just switches modes.
        self._use_custom_order()

    def _order_button_style(self, active: bool, colour: str) -> str:
        fg = C["bg"] if active else colour
        bg = colour if active else "transparent"
        hover = colour if active else "#061620"
        return f"""
            QPushButton {{
                background:{bg}; color:{fg};
                border:1px solid {colour}; border-radius:5px;
                font-family:'Courier New', monospace; font-size:9px;
                letter-spacing:2px; padding:0 8px;
            }}
            QPushButton:hover {{ background:{hover}; }}
        """

    def _refresh_order_mode_ui(self, sync_modules: bool = True) -> None:
        if not hasattr(self, "_scan_order_lbl"):
            return
        if getattr(self, "_scan_profile", "bug_bounty") == "ctf":
            custom_active = self._scan_order_mode == "custom"
            if sync_modules and hasattr(self, "modules_list"):
                if custom_active:
                    self._sync_custom_order_from_modules_list()
                    self._load_modules_list(self._ctf_full_order, self._ctf_selected_order, custom_enabled=True, reorder_enabled=True)
                else:
                    self._ctf_full_order = list(CTF_SCAN_ORDER)
                    self._ctf_selected_order = list(CTF_SCAN_ORDER)
                    self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)

            selected = list(getattr(self, "_ctf_selected_order", CTF_SCAN_ORDER) or [])
            if custom_active:
                if selected:
                    preview = " → ".join(MODULES_META.get(m, {}).get("short", m).upper() for m in selected[:6])
                    if len(selected) > 6:
                        preview += " → …"
                    self._scan_order_lbl.setText(
                        f"CTF CUSTOM ACTIVE  //  {len(selected)} selected  //  drag rows in MODULES  //  {preview}"
                    )
                else:
                    self._scan_order_lbl.setText("CTF CUSTOM ACTIVE  //  no lab modules selected  //  tick modules in MODULES")
            else:
                self._scan_order_lbl.setText("CTF DEFAULT ACTIVE  //  phased lab order  //  all CTF modules locked on")

            self.default_order_btn.setStyleSheet(self._order_button_style(not custom_active, C["accent2"]))
            self.custom_order_btn.setStyleSheet(self._order_button_style(custom_active, C["accent"]))
            self.default_order_btn.setEnabled(True)
            self.custom_order_btn.setEnabled(True)
            self.default_order_btn.setToolTip("Reset CTF modules to the default order, select all CTF modules, and lock the list.")
            self.custom_order_btn.setToolTip("Enable CTF custom order so you can drag rows and tick/untick lab modules.")
            return

        self.default_order_btn.setEnabled(True)
        self.custom_order_btn.setEnabled(True)
        custom_active = self._scan_order_mode == "custom"
        if custom_active:
            if sync_modules and hasattr(self, "modules_list"):
                self._sync_custom_order_from_modules_list()
            if self._custom_scan_order:
                preview = " → ".join(
                    MODULES_META.get(m, {}).get("short", m).upper()
                    for m in self._custom_scan_order[:6]
                )
                if len(self._custom_scan_order) > 6:
                    preview += " → …"
                self._scan_order_lbl.setText(
                    f"CUSTOM ACTIVE  //  {len(self._custom_scan_order)} selected  //  drag rows in MODULES  //  {preview}"
                )
            else:
                self._scan_order_lbl.setText("CUSTOM ACTIVE  //  no optional modules selected  //  tick modules in MODULES")
        else:
            self._scan_order_lbl.setText("DEFAULT ACTIVE  //  phased order with parallel modules  //  all modules locked on")

        if sync_modules and hasattr(self, "modules_list"):
            if custom_active:
                self._load_modules_list(self._custom_full_order, self._custom_scan_order, custom_enabled=True)
            else:
                self._load_modules_list(DEFAULT_SCAN_ORDER, DEFAULT_SCAN_ORDER, custom_enabled=False)

        self.default_order_btn.setStyleSheet(self._order_button_style(not custom_active, C["accent2"]))
        self.custom_order_btn.setStyleSheet(self._order_button_style(custom_active, C["accent"]))

    # ── TOOL STATUS group ──────────────────────────────────────────────────
    def _build_tools_group(self) -> QGroupBox:
        g = self._grp("TOOL STATUS")
        self._tool_lbl: dict[str, QLabel] = {}
        self._tool_rows: dict[str, QWidget] = {}

        for tool in TOOL_STATUS_ORDER:
            row_w = QWidget()
            row_w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            row_w.setStyleSheet("background: transparent;")

            row_lay = QHBoxLayout(row_w)
            row_lay.setContentsMargins(0, 0, 0, 0)
            row_lay.setSpacing(4)

            name_lbl = QLabel(tool)
            name_lbl.setStyleSheet(
                f"color:{C['text']}; font-family:monospace; font-size:11px;"
                f"background:transparent;"
            )
            status_lbl = QLabel("···")
            status_lbl.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            status_lbl.setStyleSheet(
                f"color:{C['dim']}; font-family:monospace; font-size:11px;"
                f"background:transparent;"
            )

            row_lay.addWidget(name_lbl)
            row_lay.addStretch()
            row_lay.addWidget(status_lbl)

            g.layout().addWidget(row_w)
            self._tool_lbl[tool] = status_lbl
            self._tool_rows[tool] = row_w

        return g

    # ── PROGRESS group ─────────────────────────────────────────────────────
    def _build_progress_group(self) -> QGroupBox:
        g = self._grp("PROGRESS")
        for mod_id in MODULES_META:
            mr = ModuleRow(mod_id)
            g.layout().addWidget(mr)
            self._module_rows[mod_id] = mr
        return g

    # ── Button factory ─────────────────────────────────────────────────────
    @staticmethod
    def _btn(
        text: str, *, fg: str, bg: str,
        border: str = "transparent",
        hover: str = "", pressed: str = "",
        height: int = 34, bold: bool = False, fs: int = 11,
    ) -> QPushButton:
        btn = QPushButton(text)
        btn.setMinimumHeight(height)
        btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        hover_r   = f"QPushButton:hover    {{ background:{hover}; }}"   if hover   else ""
        pressed_r = f"QPushButton:pressed  {{ background:{pressed}; }}" if pressed else ""
        weight    = "bold" if bold else "normal"

        btn.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; color: {fg};
                border: 1px solid {border}; border-radius: 5px;
                font-family: 'Courier New', monospace;
                font-size: {fs}px; font-weight: {weight}; letter-spacing: 2px;
                padding: 0 8px;
            }}
            {hover_r}
            {pressed_r}
            QPushButton:disabled {{
                background: transparent; color: {C['dim']};
                border-color: {C['border']};
            }}
        """)
        return btn

    # ══════════════════════════════════════════════════════════════════════
    #  RIGHT PANEL  — console + tabbed results
    # ══════════════════════════════════════════════════════════════════════

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        panel.setStyleSheet(f"background:{C['bg']};")

        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        vs = QSplitter(Qt.Orientation.Vertical)
        vs.setHandleWidth(1)
        vs.setChildrenCollapsible(False)
        vs.setStyleSheet(f"QSplitter::handle{{ background:{C['border2']}; }}")
        vs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        vs.addWidget(self._build_console())
        vs.addWidget(self._build_result_tabs())
        vs.setSizes([240, 520])
        vs.setStretchFactor(0, 0)
        vs.setStretchFactor(1, 1)

        lay.addWidget(vs)
        return panel

    # ── Console ────────────────────────────────────────────────────────────
    def _build_console(self) -> QWidget:
        w = QWidget()
        w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        w.setStyleSheet(f"background:{C['bg']};")

        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Title bar
        tb = QWidget()
        tb.setFixedHeight(30)
        tb.setStyleSheet(
            f"background:{C['bg3']}; border-bottom:1px solid {C['border']};"
        )
        tb_lay = QHBoxLayout(tb)
        tb_lay.setContentsMargins(14, 0, 10, 0)

        title = QLabel("◈  LIVE TERMINAL")
        title.setStyleSheet(f"""
            color:{C['accent']}; font-family:monospace;
            font-size:10px; font-weight:bold; letter-spacing:3px;
            background:transparent;
        """)

        clr = QPushButton("CLEAR")
        clr.setFixedSize(50, 18)
        clr.setCursor(Qt.CursorShape.PointingHandCursor)
        clr.setStyleSheet(f"""
            QPushButton {{
                background:transparent; color:{C['dim']};
                border:1px solid {C['border']}; border-radius:2px;
                font-family:monospace; font-size:8px; letter-spacing:1px;
            }}
            QPushButton:hover {{ color:{C['accent']}; border-color:{C['accent']}; }}
        """)
        clr.clicked.connect(lambda: self.console.clear())

        tb_lay.addWidget(title)
        tb_lay.addStretch()
        tb_lay.addWidget(clr)
        lay.addWidget(tb)

        self.console = PTYTerminalOutput()
        lay.addWidget(self.console)
        return w

    # ── Result tabs ────────────────────────────────────────────────────────
    def _build_result_tabs(self) -> QWidget:
        w = QWidget()
        w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        w.setStyleSheet(f"background:{C['bg2']};")

        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tabs.setDocumentMode(True)
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                background:{C['bg2']}; border:none;
                border-top:1px solid {C['border']};
            }}
            QTabBar {{ background:{C['bg3']}; }}
            QTabBar::tab {{
                background:{C['bg3']}; color:{C['dim']};
                border:none; border-right:1px solid {C['border']};
                padding:7px 12px;
                font-family:'Courier New',monospace;
                font-size:9px; font-weight:bold; letter-spacing:1px;
                min-width:68px;
            }}
            QTabBar::tab:selected {{
                background:{C['bg2']}; color:{C['accent']};
                border-bottom:2px solid {C['accent']};
            }}
            QTabBar::tab:hover:!selected {{ color:{C['text']}; background:{C['bg4']}; }}
        """)

        tab_defs = [
            ("PORTS",        "t_ports",       ["Port","Protocol","State","Service","Product","Version"], "nmap"),
            ("SUBDOMAINS",   "t_subs",        ["Subdomain"], "subdomain"),
            ("DIR ENUM",     "t_dirs",        ["URL","Status","Size"], "dir_enum"),
            ("SUB FUZZ",     "t_subfuzz",     ["Host","Status","Size","URL"], "subdomain_fuzz"),
            ("LIVE HOSTS",   "t_live",        ["Host","IP","Status","Method","Latency"], "live_host"),
            ("HTTP PROBE",   "t_probe",       ["Live URL", "Status", "Title", "Tech"], "http_probe"),
            ("HTTP HEADERS", "t_headers",     ["Header","Present","Risk","Value"], "headers"),
            ("JS FILES",     "t_js",          ["JS File URL"], "js_collector"),
            ("WAF",          "t_waf",         ["Target","Status","WAF / Firewall","Requests"], "waf"),
            ("WHATWEB",      "t_whatweb",     ["Plugin","Version","Detail","HTTP","Target"], "whatweb"),
            ("SSL/TLS",      "t_ssl",         ["Category","Field","Value","Risk"], "sslcert"),
            ("DNS",          "t_dns",         ["Group","Type","Value","Risk"], "dns"),
            ("URLS",         "t_urls",        ["Source","URL"], "url_harvest"),
            ("JS SECRETS",   "t_jssec",       ["Severity","Type","Value","Source URL"], "js_secrets"),
            ("NUCLEI",       "t_nuclei",      ["Template","Name","Severity","Type","URL"], "nuclei"),
        ]

        self._tab_index_by_attr: dict[str, int] = {}
        self._tab_module_by_attr: dict[str, str] = {}
        for tab_name, attr, cols, mod_id in tab_defs:
            tbl = ReconTable(cols)
            setattr(self, attr, tbl)
            idx = self.tabs.addTab(tbl, tab_name)
            self._tab_index_by_attr[attr] = idx
            self._tab_module_by_attr[attr] = mod_id

        lay.addWidget(self.tabs)
        self._refresh_mode_visibility()
        return w

    # ── Status bar ─────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = self.statusBar()
        sb.setFixedHeight(24)
        sb.setStyleSheet(f"""
            QStatusBar {{
                background:{C['bg3']}; color:{C['dim']};
                border-top:1px solid {C['border']};
                font-family:monospace; font-size:10px; padding:0 10px;
            }}
        """)
        self._sb_lbl = QLabel("Ready  //  Enter target and select modules.")
        self._sb_lbl.setStyleSheet("background:transparent;")
        sb.addWidget(self._sb_lbl)

    # ══════════════════════════════════════════════════════════════════════
    #  TOOL CHECK
    # ══════════════════════════════════════════════════════════════════════

    def _check_tools(self):
        for tool in TOOL_STATUS_ORDER:
            lbl = self._tool_lbl[tool]
            if shutil.which(tool):
                lbl.setText("● FOUND")
                lbl.setStyleSheet(
                    f"color:{C['success']}; font-family:monospace; font-size:10px;"
                    f"background:transparent;"
                )
            else:
                lbl.setText("✘ MISSING")
                lbl.setStyleSheet(
                    f"color:{C['error']}; font-family:monospace; font-size:10px;"
                    f"background:transparent;"
                )

    # ══════════════════════════════════════════════════════════════════════
    #  SCAN LIFECYCLE
    # ══════════════════════════════════════════════════════════════════════

    def _confirm_scan_authorization(self, target: str) -> bool:
        """Require explicit authorization and scope confirmation before scanning.

        The scan cannot start until the operator confirms both statements.
        Closing or cancelling the dialog returns False and leaves the target
        completely untouched.
        """
        dlg = QDialog(self)
        dlg.setWindowTitle("Authorization & Scope Confirmation")
        dlg.setModal(True)
        dlg.setMinimumWidth(520)
        dlg.setStyleSheet(f"""
            QDialog {{ background:{C['bg2']}; color:{C['text']}; }}
            QLabel {{ color:{C['text']}; background:transparent; }}
            QCheckBox {{
                color:{C['text']}; background:transparent;
                font-family:'Courier New', monospace; font-size:11px;
                spacing:8px; padding:4px 0;
            }}
            QCheckBox::indicator {{
                width:15px; height:15px;
                border:1px solid {C['accent']}88; border-radius:3px;
                background:{C['bg']};
            }}
            QCheckBox::indicator:checked {{
                background:{C['accent']}; border-color:{C['accent']};
            }}
            QPushButton {{
                min-width:110px; min-height:30px;
                border:1px solid {C['border2']}; border-radius:4px;
                background:{C['bg3']}; color:{C['text']};
                font-family:'Courier New', monospace; font-size:10px;
                padding:0 10px;
            }}
            QPushButton:hover {{ border-color:{C['accent2']}; }}
            QPushButton:disabled {{ color:{C['dim']}; border-color:{C['border']}; }}
        """)

        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)

        title = QLabel("Confirm authorization before scanning")
        title.setStyleSheet(
            f"color:{C['accent2']}; font-size:14px; font-weight:bold; "
            "font-family:'Courier New', monospace;"
        )
        lay.addWidget(title)

        target_lbl = QLabel(f"Target: <b>{html.escape(target)}</b>")
        target_lbl.setTextFormat(Qt.TextFormat.RichText)
        target_lbl.setWordWrap(True)
        target_lbl.setStyleSheet(
            f"color:{C['accent']}; background:{C['bg']}; "
            f"border:1px solid {C['border']}; border-radius:4px; padding:8px;"
        )
        lay.addWidget(target_lbl)

        notice = QLabel(
            "Only scan systems you are explicitly authorized to test. "
            "The target must also be included in the approved scope for this assessment."
        )
        notice.setWordWrap(True)
        notice.setStyleSheet(f"color:{C['dim']}; font-size:11px;")
        lay.addWidget(notice)

        auth_cb = QCheckBox("I confirm that I have permission to scan this target.")
        scope_cb = QCheckBox("I confirm that this target is within the authorized scope.")
        lay.addWidget(auth_cb)
        lay.addWidget(scope_cb)

        buttons = QDialogButtonBox()
        start_btn = buttons.addButton("START SCAN", QDialogButtonBox.ButtonRole.AcceptRole)
        cancel_btn = buttons.addButton("CANCEL", QDialogButtonBox.ButtonRole.RejectRole)
        start_btn.setEnabled(False)
        start_btn.setStyleSheet(f"""
            QPushButton {{
                min-width:120px; min-height:30px;
                border:1px solid {C['accent']}; border-radius:4px;
                background:transparent; color:{C['accent']};
                font-family:'Courier New', monospace; font-size:10px;
                font-weight:bold; letter-spacing:1px;
            }}
            QPushButton:hover:enabled {{ background:#062018; }}
            QPushButton:disabled {{ color:{C['dim']}; border-color:{C['border']}; }}
        """)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                min-width:100px; min-height:30px;
                border:1px solid {C['border2']}; border-radius:4px;
                background:transparent; color:{C['text']};
                font-family:'Courier New', monospace; font-size:10px;
            }}
            QPushButton:hover {{ border-color:{C['error']}; color:{C['error']}; }}
        """)

        def _refresh_start_state() -> None:
            start_btn.setEnabled(auth_cb.isChecked() and scope_cb.isChecked())

        auth_cb.toggled.connect(_refresh_start_state)
        scope_cb.toggled.connect(_refresh_start_state)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        return dlg.exec() == QDialog.DialogCode.Accepted

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self._alert("No target", "Enter a domain or IP address.")
            return

        if not self._confirm_scan_authorization(target):
            self._sb_lbl.setText("Scan cancelled — authorization/scope not confirmed.")
            return

        if self._scan_profile == "ctf":
            # CTF Default is locked and runs every CTF module. CTF Custom lets
            # the MODULES list define both selected modules and order.
            if self._scan_order_mode == "custom":
                self._sync_custom_order_from_modules_list()
                if not self._ctf_selected_order:
                    self._alert("No modules", "Select at least one CTF module in MODULES.")
                    return
                selected = {k: (k in self._ctf_selected_order) for k in MODULES_META}
                self._load_modules_list(self._ctf_full_order, self._ctf_selected_order, custom_enabled=True, reorder_enabled=True)
            else:
                self._ctf_full_order = list(CTF_SCAN_ORDER)
                self._ctf_selected_order = list(CTF_SCAN_ORDER)
                selected = {k: (k in CTF_SCAN_ORDER) for k in MODULES_META}
                self._load_modules_list(CTF_SCAN_ORDER, CTF_SCAN_ORDER, custom_enabled=False, reorder_enabled=False)
        elif self._scan_order_mode == "custom":
            # In custom mode, the module list controls which optional modules run.
            selected = {k: (k in self._custom_scan_order) for k in self.cb}
            if not self._custom_scan_order:
                self._alert("No modules", "Select at least one module in Custom Order.")
                return
        else:
            # Bug Bounty Default order is a full phased scan. Always force every
            # optional module on, even if a stale/loaded checkbox state says otherwise.
            selected = {k: (k in DEFAULT_SCAN_ORDER) for k in MODULES_META}
            self._set_module_checkboxes(DEFAULT_SCAN_ORDER, enabled=False)

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
        # One folder per target — repeated scans overwrite previous results
        # rather than piling up timestamped subdirectories.
        outd = str(Path("output") / safe)
        outp = Path(outd)
        # Wipe stale artifacts from any previous run on this target so an
        # un-selected module's old output doesn't carry forward.
        if outp.exists():
            for child in outp.iterdir():
                try:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
                except Exception:
                    pass    # best-effort cleanup; never block the scan on this
        outp.mkdir(parents=True, exist_ok=True)
        self._output_dir = outd
        selected["live_host"] = True

        self._reset_ui(target, ts)

        from core.scan_manager import ScanManager, ManagerSignals
        sigs = ManagerSignals()
        sigs.log.connect(self._on_log)
        sigs.module_state.connect(self._on_module_state)
        sigs.result.connect(self._on_result)
        sigs.all_done.connect(self._on_all_done)
        sigs.fatal_error.connect(self._on_fatal_error)
        sigs.progress.connect(self._on_progress)

        self._manager = ScanManager(
            target=target, output_dir=outd,
            modules=selected, signals=sigs,
            scan_order_mode=self._scan_order_mode,
            custom_order=list(self._ctf_selected_order if self._scan_profile == "ctf" else self._custom_scan_order),
            scan_profile=self._scan_profile,
        )
        self._manager.start()
        self._scan_start = None
        self._active = True

    def _stop_scan(self):
        if self._manager:
            self._manager.stop()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._sb_lbl.setText("Scan stopped by user.")
        self._on_log("WARNING", "⚠  Scan aborted by user.")

    def _reset_ui(self, target: str, ts: str):
        tab_labels = [
            "PORTS","SUBDOMAINS","DIR ENUM","SUB FUZZ","LIVE HOSTS",
            "HTTP PROBE","HTTP HEADERS","JS FILES",
            "WAF","WHATWEB","SSL/TLS","DNS",
            "URLS","JS SECRETS","NUCLEI",
        ]
        for i, lbl in enumerate(tab_labels):
            self.tabs.setTabText(i, lbl)
        self._refresh_mode_visibility()
        for tbl in [
            self.t_ports, self.t_subs, self.t_dirs, self.t_subfuzz, self.t_live,
            self.t_probe, self.t_headers, self.t_js,
            self.t_waf, self.t_whatweb, self.t_ssl, self.t_dns,
            self.t_urls, self.t_jssec, self.t_nuclei,
        ]:
            tbl.setRowCount(0)
        for mr in self._module_rows.values():
            mr.set_status("idle")
        self.console.clear()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.report_btn.setEnabled(False)
        self.advisor_btn.setEnabled(False)
        self._sb_lbl.setText(f"Scanning: {target}  //  {ts}")
        self._on_log("INFO", "─" * 58)
        self._on_log("INFO", f"  ReconPilot  ◈  Target: {target}")
        self._on_log("INFO", f"  Output:  {self._output_dir}")
        if self._scan_profile == "ctf":
            self._on_log("INFO", "  Scan mode: CONTROLLED / CTF")
            order_labels = [self._module_label(m) for m in getattr(self, "_ctf_selected_order", [])]
            self._on_log("INFO", "  CTF modules: " + (" → ".join(order_labels) if order_labels else "none selected"))
            if self._scan_order_mode == "custom":
                self._on_log("INFO", "  CTF order: CUSTOM  //  drag order from MODULES; unchecked modules are skipped")
            else:
                self._on_log("INFO", "  CTF order: DEFAULT PHASED")
        elif self._scan_order_mode == "custom":
            order_labels = [MODULES_META.get(m, {}).get("label", m) for m in self._custom_scan_order]
            self._on_log("INFO", "  Scan mode: BUG BOUNTY")
            self._on_log("INFO", "  Scan order: CUSTOM  //  " + (" → ".join(order_labels) if order_labels else "no optional modules selected"))
        else:
            self._on_log("INFO", "  Scan mode: BUG BOUNTY")
            self._on_log("INFO", "  Scan order: DEFAULT PHASED")
        self._on_log("INFO", "─" * 58)

    # ══════════════════════════════════════════════════════════════════════
    #  SIGNAL HANDLERS
    # ══════════════════════════════════════════════════════════════════════

    @Slot(str, str)
    def _on_log(self, level: str, message: str):
        self.console.write_line(level, message)

    @Slot(str, str)
    def _on_module_state(self, module: str, state: str):
        mr = self._module_rows.get(module)
        if mr:
            mr.set_status(state)

    @Slot(str, int)
    def _on_progress(self, module: str, pct: int):
        mr = self._module_rows.get(module)
        if mr:
            mr.set_progress(pct)

    @Slot(str, list)
    def _on_result(self, module: str, data: list):
        dispatch = {
            "nmap":         self._fill_ports,
            "subdomain":    self._fill_subs,
            "dir_enum":     self._fill_dirs,
            "subdomain_fuzz": self._fill_subfuzz,
            "live_host":    self._fill_live,
            "http_probe":   self._fill_probe,
            "headers":      self._fill_headers,
            "js_collector": self._fill_js,
            "waf":          self._fill_waf,
            "whatweb":      self._fill_whatweb,
            "sslcert":      self._fill_ssl,
            "dns":          self._fill_dns,
            "url_harvest":  self._fill_urls,
            "js_secrets":   self._fill_jssec,
            "nuclei":       self._fill_nuclei,
        }
        fn = dispatch.get(module)
        if fn:
            fn(data)


    @Slot(str, str)
    def _on_fatal_error(self, title: str, message: str):
        self._alert(title, message)

    @Slot()
    def _on_all_done(self):
        self._active = False
        was_stopped = bool(self._manager and getattr(self._manager, "stopped", False))
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(not was_stopped)
        self.advisor_btn.setEnabled(not was_stopped)
        self._on_log("INFO", "─" * 58)
        if was_stopped:
            self._on_log("WARNING", "  ⏹  Scan stopped. No report was generated.")
            self._sb_lbl.setText("⏹  Scan stopped by user.")
        else:
            self._on_log("INFO", "  ✔  All modules complete.")
            self._sb_lbl.setText("✔  Scan complete  //  Report ready.")
        self._on_log("INFO", "─" * 58)

    # ══════════════════════════════════════════════════════════════════════
    #  TABLE FILLERS
    # ══════════════════════════════════════════════════════════════════════

    def _fill_ports(self, data: list):
        rows = [
            [p["port"], p["protocol"], p.get("state",""),
             p.get("service",""), p.get("product",""), p.get("version","")]
            for p in data
        ]
        self.t_ports.populate(rows)
        for r in range(self.t_ports.rowCount()):
            item = self.t_ports.item(r, 0)
            if item:
                item.setForeground(QColor(C["accent"]))
        self.tabs.setTabText(0, f"PORTS ({len(data)})")

    def _fill_subs(self, data: list):
        self.t_subs.populate([[s] for s in data])
        self.tabs.setTabText(1, f"SUBDOMAINS ({len(data)})")

    def _fill_dirs(self, data: list):
        self.t_dirs.setRowCount(0)
        for r in data:
            self.t_dirs.add_row([
                r.get("url", ""), str(r.get("status", "")), str(r.get("size", "")),
            ], colours={0: C["accent2"]})
        self.tabs.setTabText(2, f"DIR ENUM ({len(data)})")

    def _fill_subfuzz(self, data: list):
        self.t_subfuzz.setRowCount(0)
        for r in data:
            self.t_subfuzz.add_row([
                r.get("host", ""), str(r.get("status", "")),
                str(r.get("size", "")), r.get("url", ""),
            ], colours={0: C["accent4"]})
        self.tabs.setTabText(3, f"SUB FUZZ ({len(data)})")

    def _fill_live(self, data: list):
        rows = [
            [h.get("host",""), h.get("ip",""), h.get("status",""),
             h.get("method",""), h.get("latency","")]
            for h in data
        ]
        self.t_live.populate(rows)
        for r in range(self.t_live.rowCount()):
            item = self.t_live.item(r, 2)
            if item:
                col = C["success"] if item.text() == "ALIVE" else C["error"]
                item.setForeground(QColor(col))
        self.tabs.setTabText(4, f"LIVE HOSTS ({len(data)})")

    def _fill_probe(self, data: list):
        """HTTP Probe tab shows live URLs plus status/title/technology from httpx-toolkit."""
        self.t_probe.setRowCount(0)
        for p in data:
            if isinstance(p, dict):
                url = p.get("url", "")
                status = str(p.get("status", ""))
                title = p.get("title", "")
                tech = p.get("tech", "")
            else:
                url = str(p or "")
                status = "LIVE"
                title = ""
                tech = ""
            if not url:
                continue
            self.t_probe.add_row([url, status, title, tech], colours={0: C["success"], 1: C["accent2"]})
        self.tabs.setTabText(5, f"LIVE URLS ({self.t_probe.rowCount()})")

    def _fill_headers(self, data: list):
        self.t_headers.setRowCount(0)
        for h in data:
            risk  = h.get("risk","")
            col   = (C["success"] if risk == "OK" else
                     C["warning"] if risk == "MEDIUM" else C["error"])
            pres  = h.get("present","")
            pcol  = C["success"] if "Yes" in pres else C["error"]
            self.t_headers.add_row(
                [h["header"], pres, risk, h.get("value","—")],
                colours={1: pcol, 2: col},
            )
        self.tabs.setTabText(6, f"HTTP HEADERS ({len(data)})")

    def _fill_js(self, data: list):
        self.t_js.populate([[js] for js in data])
        self.tabs.setTabText(7, f"JS FILES ({len(data)})")

    def _fill_waf(self, data: list):
        self.t_waf.setRowCount(0)
        for w in data:
            status = w.get("status", "NONE")
            col    = (C["error"]   if status in ("DETECTED", "UNREACHABLE") else
                      C["warning"] if status == "GENERIC" else
                      C["success"])
            self.t_waf.add_row(
                [w.get("target",""), status,
                 w.get("waf","—"), str(w.get("requests","—"))],
                colours={1: col},
            )
        self.tabs.setTabText(8, f"WAF ({len(data)})")

    def _fill_whatweb(self, data: list):
        """One row per (plugin, version, detail, http, target) tuple."""
        self.t_whatweb.setRowCount(0)
        for w in data:
            self.t_whatweb.add_row([
                w.get("plugin", "—"),
                w.get("version", "") or "—",
                w.get("string",  "") or "—",
                w.get("http_status", "") or "—",
                w.get("target",  "") or "—",
            ])
        self.tabs.setTabText(9, f"WHATWEB ({len(data)})")

    def _fill_ssl(self, data: list):
        """Render the SSL/TLS cert rows. Each row is (category, field, value, risk)."""
        self.t_ssl.setRowCount(0)
        risk_col = {
            "HIGH":   C["error"],
            "MEDIUM": C["warning"],
            "OK":     C["success"],
            "":       C["text"],
        }
        for r in data:
            risk = (r.get("risk") or "").upper()
            col  = risk_col.get(risk, C["text"])
            self.t_ssl.add_row(
                [r.get("category", "—"), r.get("field", "—"),
                 r.get("value", ""), risk or "—"],
                colours={3: col},
            )
        self.tabs.setTabText(10, f"SSL/TLS ({len(data)})")

    def _fill_dns(self, data: list):
        """Render DNS records grouped by category (group, type, value, risk)."""
        self.t_dns.setRowCount(0)
        risk_col = {
            "HIGH":   C["error"],
            "MEDIUM": C["warning"],
            "OK":     C["success"],
            "":       C["text"],
        }
        group_col = {
            "core":     C["text"],
            "DMARC":    C["accent2"],
            "security": C["accent3"],
            "mail":     C["accent2"],
            "network":  C["text"],
            "zone":     C["dim"],
            "info":     C["dim"],
        }
        for r in data:
            risk = (r.get("risk") or "").upper()
            grp  = r.get("group", "")
            self.t_dns.add_row(
                [grp, r.get("type", "—"),
                 r.get("value", ""), risk or "—"],
                colours={
                    0: group_col.get(grp, C["text"]),
                    3: risk_col.get(risk, C["text"]),
                },
            )
        self.tabs.setTabText(11, f"DNS ({len(data)})")

    def _fill_urls(self, data: list):
        """URL Harvest results.

        Large passive collectors such as gau can easily return 10k+ URLs. Adding
        every row to QTableWidget one by one, especially with sorting enabled,
        can freeze the GUI. The full accurate corpus is still saved by the URL
        Harvest module to all_urls.txt and all_urls_with_sources.json. The table
        is only a fast preview.
        """
        total = len(data)
        ui_cap = 2000
        shown = data[:ui_cap]
        has_more = total > ui_cap

        src_col = {
            "wayback":     C["accent"],
            "urlscan":     C["accent2"],
            "otx":         C["accent3"],
            "gau":         C["accent4"],
            "waybackurls": C["accent"],
            "gospider":    C["warning"],
        }

        self.t_urls.setUpdatesEnabled(False)
        self.t_urls.setSortingEnabled(False)
        try:
            self.t_urls.setRowCount(len(shown) + (1 if has_more else 0))
            for row_idx, r in enumerate(shown):
                src = r.get("source", "?")
                url = r.get("url", "")
                for col, val in enumerate([src, url]):
                    item = QTableWidgetItem(str(val))
                    item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                    if col == 0:
                        # If multiple sources are combined, colour by the first source.
                        first_src = src.split(",", 1)[0].strip()
                        item.setForeground(QColor(src_col.get(first_src, C["text"])))
                    self.t_urls.setItem(row_idx, col, item)

            if has_more:
                row_idx = len(shown)
                msg = (
                    f"Showing first {ui_cap:,} of {total:,} URLs. "
                    "Full results are saved in all_urls.txt and all_urls_with_sources.json."
                )
                for col, val in enumerate(["preview", msg]):
                    item = QTableWidgetItem(val)
                    item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                    item.setForeground(QColor(C["warning"] if col == 0 else C["dim"]))
                    self.t_urls.setItem(row_idx, col, item)
        finally:
            self.t_urls.setSortingEnabled(True)
            self.t_urls.setUpdatesEnabled(True)

        if has_more:
            self.tabs.setTabText(12, f"URLS ({total:,}, showing {ui_cap:,})")
        else:
            self.tabs.setTabText(12, f"URLS ({total:,})")

    def _fill_jssec(self, data: list):
        """JS Secrets — sort HIGH first; tab label flags HIGH count."""
        self.t_jssec.setRowCount(0)
        sev_col = {"HIGH": C["error"], "MEDIUM": C["warning"], "INFO": C["dim"]}
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        data_sorted = sorted(data, key=lambda r: order.get(r.get("severity", "INFO"), 9))
        for r in data_sorted:
            sev = r.get("severity", "INFO")
            self.t_jssec.add_row(
                [sev, r.get("label", "?"), r.get("value", ""),
                 r.get("source_url", "")],
                colours={0: sev_col.get(sev, C["text"])},
            )
        n_high = sum(1 for r in data if r.get("severity") == "HIGH")
        label = f"JS SECRETS ({len(data)})" if not n_high \
                else f"JS SECRETS ⚠ ({n_high} HIGH / {len(data)})"
        self.tabs.setTabText(13, label)

    def _fill_nuclei(self, data: list):
        self.t_nuclei.setRowCount(0)
        sev_col = {
            "critical": C["error"],
            "high":     C["error"],
            "medium":   C["warning"],
            "low":      C["text"],
            "info":     C["dim"],
            "unknown":  C["dim"],
        }
        for f in data:
            sev = (f.get("severity") or "unknown").lower()
            col = sev_col.get(sev, C["text"])
            self.t_nuclei.add_row(
                [f.get("template","—"), f.get("name","—"),
                 sev.upper(), f.get("type","—"), f.get("url","—")],
                colours={2: col},
            )
        self.tabs.setTabText(14, f"NUCLEI ({len(data)})")

    # ══════════════════════════════════════════════════════════════════════
    #  TIMER / REPORT / ALERT
    # ══════════════════════════════════════════════════════════════════════

    def _open_report(self):
        rpt = Path(self._output_dir) / "report.html"
        if not rpt.exists():
            self._alert("Report not found", str(rpt))
            return
        self._open_file_path(rpt, "Could not open report")

    def _open_existing_report(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Existing ReconPilot Report",
            str(Path.cwd()),
            "HTML reports (*.html *.htm);;All files (*)",
        )
        if not path:
            return
        self._open_file_path(Path(path), "Could not open existing report")

    def _open_file_path(self, path: str | Path, error_title: str = "Could not open file"):
        path = Path(path).expanduser()
        if not path.exists():
            self._alert("File not found", str(path))
            return

        # QDesktopServices.openUrl can fail on Linux with "Operation not
        # supported" when the Qt platform plugin has no URL handler. Run
        # through a fallback chain that's much more reliable on Linux:
        #   1. Python's webbrowser  — honours $BROWSER, xdg-open, gio open, etc.
        #   2. Direct xdg-open / open / start subprocess
        #   3. QDesktopServices                              (Qt's own attempt)
        url_str   = path.resolve().as_uri()          # file:///abs/path/file
        path_str  = str(path.resolve())
        last_err: Exception | None = None

        # 1) Python stdlib
        try:
            if webbrowser.open(url_str, new=2):
                return
        except Exception as exc:
            last_err = exc

        # 2) Platform-native opener as a direct subprocess
        platform_cmd: list[str] | None = None
        if sys.platform.startswith("linux"):
            platform_cmd = ["xdg-open", path_str]
        elif sys.platform == "darwin":
            platform_cmd = ["open", path_str]
        elif sys.platform.startswith("win"):
            platform_cmd = ["cmd", "/c", "start", "", path_str]

        if platform_cmd and shutil.which(platform_cmd[0]):
            try:
                subprocess.Popen(platform_cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                return
            except Exception as exc:
                last_err = exc

        # 3) Final fallback: Qt
        try:
            if QDesktopServices.openUrl(QUrl.fromLocalFile(path_str)):
                return
        except Exception as exc:
            last_err = exc

        # Nothing worked — surface the path so the user can copy it.
        self._alert(
            error_title,
            f"Open this file manually:\n\n{path_str}"
            + (f"\n\nLast error: {last_err}" if last_err else "")
        )

    def _alert(self, title: str, msg: str):
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setText(msg)
        dlg.setIcon(QMessageBox.Icon.Warning)
        dlg.setStyleSheet(f"""
            QMessageBox {{ background:{C['bg2']}; color:{C['text']}; font-family:monospace; }}
            QLabel       {{ color:{C['text']}; background:transparent; }}
            QPushButton  {{
                background:{C['bg3']}; color:{C['accent']};
                border:1px solid {C['accent']}; border-radius:4px;
                padding:5px 16px; font-family:monospace; font-size:11px;
                min-width:56px;
            }}
            QPushButton:hover {{ background:{C['bg4']}; }}
        """)
        dlg.exec()

    # ══════════════════════════════════════════════════════════════════════
    #  AI Advisor
    # ══════════════════════════════════════════════════════════════════════

    def _open_ai_advisor_settings(self) -> None:
        """Edit the local AI Advisor configuration stored under ~/.config."""
        from utils.ai_config import get_ai_config, save_ai_config, CONFIG_PATH

        cfg = get_ai_config()
        dlg = QDialog(self)
        dlg.setWindowTitle("AI Advisor Settings")
        dlg.setMinimumWidth(520)
        dlg.setStyleSheet(f"""
            QDialog {{ background:{C['bg2']}; color:{C['text']}; }}
            QLabel {{ color:{C['text']}; font-family:monospace; font-size:11px; }}
            QLineEdit, QComboBox {{
                background:{C['bg3']}; color:{C['text']};
                border:1px solid {C['border2']}; border-radius:4px;
                padding:6px 8px; font-family:monospace; font-size:11px;
            }}
            QLineEdit:focus, QComboBox:focus {{ border-color:{C['accent']}; }}
            QPushButton {{
                background:{C['bg3']}; color:{C['text']};
                border:1px solid {C['border2']}; border-radius:4px;
                padding:6px 14px; font-family:monospace;
            }}
            QPushButton:hover {{ color:{C['accent']}; border-color:{C['accent']}; }}
        """)

        layout = QVBoxLayout(dlg)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        provider = QComboBox()
        provider.addItem("ollama")
        provider.setCurrentText(cfg["ai_provider"])

        base_url = QLineEdit(cfg["ollama_base_url"])
        base_url.setPlaceholderText("http://127.0.0.1:11434")
        model = QLineEdit(cfg["ollama_model"])
        model.setPlaceholderText("gemma3:1b")

        form.addRow("AI provider:", provider)
        form.addRow("Ollama base URL:", base_url)
        form.addRow("Ollama model:", model)
        layout.addLayout(form)

        path_label = QLabel(f"Saved to: {CONFIG_PATH}")
        path_label.setStyleSheet(f"color:{C['dim']}; font-size:10px;")
        path_label.setWordWrap(True)
        layout.addWidget(path_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        layout.addWidget(buttons)
        buttons.rejected.connect(dlg.reject)

        def _save():
            try:
                saved = save_ai_config(
                    provider.currentText(),
                    base_url.text(),
                    model.text(),
                )
            except ValueError as exc:
                self._alert("Invalid AI Advisor settings", str(exc))
                return
            except Exception as exc:
                self._alert("Could not save AI Advisor settings", str(exc))
                return
            self._on_log("INFO", f"[AIAdvisor] Settings saved to {saved}")
            dlg.accept()

        buttons.accepted.connect(_save)
        dlg.exec()

    def _advisor_config_ready(self) -> bool:
        from utils.ai_config import get_ai_config
        cfg = get_ai_config()
        if cfg["ai_provider"] != "ollama":
            self._alert(
                "Unsupported AI provider",
                "This build supports the local Ollama provider. "
                "Use File → AI Advisor Settings… and select 'ollama'."
            )
            return False
        if not cfg["ollama_base_url"] or not cfg["ollama_model"]:
            self._alert(
                "AI Advisor not configured",
                "Set the Ollama base URL and model under File → AI Advisor Settings…."
            )
            return False
        return True

    def _set_advisor_busy(self, trigger):
        """Disable AI Advisor entry points while analysis is running."""
        self._advisor_active_btn = trigger
        self.advisor_btn.setEnabled(False)
        if hasattr(self, "advisor_existing_action"):
            self.advisor_existing_action.setEnabled(False)
        if hasattr(trigger, "setText"):
            trigger.setText("Analyzing Report…")

    def _restore_advisor_buttons(self):
        if self._advisor_active_btn:
            if self._advisor_active_btn is getattr(self, "advisor_existing_action", None):
                self._advisor_active_btn.setText("Advise Existing Report…")
            else:
                self._advisor_active_btn.setText("🤖  AI ADVISOR")
        self._advisor_active_btn = None
        if hasattr(self, "advisor_existing_action"):
            self.advisor_existing_action.setEnabled(True)
        has_current = bool(getattr(self, "_output_dir", None)) and (Path(self._output_dir) / "report.html").exists()
        self.advisor_btn.setEnabled(has_current)

    def _open_advisor_for_existing_report(self):
        """Run AI Advisor against a report.html selected from disk."""
        if not self._advisor_config_ready():
            return

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Existing ReconPilot Report for AI Advisor",
            str(Path.cwd()),
            "HTML reports (*.html *.htm);;All files (*)",
        )
        if not path:
            return

        rpt = Path(path).expanduser().resolve()
        if not rpt.exists():
            self._alert("Report not found", str(rpt))
            return

        self._set_advisor_busy(self.advisor_existing_action)
        self._on_log("INFO", f"[AIAdvisor] Reading selected report: {rpt}")

        from modules.ai_advisor import run_advisor

        def _ui_line(msg: str):
            self._advisor_line_signal.emit(msg)

        def _ui_done(result: dict):
            self._advisor_done_signal.emit(result)

        run_advisor(str(rpt.parent), self._make_advisor_logger(),
                    _ui_line, _ui_done, report_path=str(rpt))

    def _open_saved_advisor_report(self):
        """Open a previously saved AI Advisor markdown/text report."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Saved AI Advisor Report",
            str(Path.cwd()),
            "Advisor reports (*.md *.txt);;All files (*)",
        )
        if not path:
            return
        p = Path(path).expanduser()
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self._alert("Could not open saved advisor report", str(exc))
            return
        self._show_advisor_result({"ok": True, "markdown": text, "saved_to": str(p)})

    def _open_advisor(self):
        """Kick off the advisor in a worker thread; show the result when ready."""
        if not getattr(self, "_output_dir", None):
            self._alert("No scan yet", "Run a scan first, or use 'Advise Existing Report' "
                                       "to select a saved report.html file.")
            return

        rpt = Path(self._output_dir) / "report.html"
        if not rpt.exists():
            self._alert("Report not found", str(rpt))
            return

        if not self._advisor_config_ready():
            return

        # Disable the button while we're working so the user can't double-fire.
        self._set_advisor_busy(self.advisor_btn)
        self._on_log("INFO", "[AIAdvisor] Reading the generated report and preparing recommendations …")

        from modules.ai_advisor import run_advisor

        # The advisor runs in its own background daemon thread, so both
        # callbacks arrive off the GUI thread. We hop back onto the GUI
        # thread via Qt Signals — they're inherently thread-safe and queue
        # across thread boundaries. QTimer.singleShot does NOT work from
        # a non-Qt thread (no event loop in the worker → timer never fires
        # → the result dialog never opens, even though the call succeeded).
        def _ui_line(msg: str):
            self._advisor_line_signal.emit(msg)

        def _ui_done(result: dict):
            self._advisor_done_signal.emit(result)

        run_advisor(self._output_dir, self._make_advisor_logger(),
                    _ui_line, _ui_done)

    def _make_advisor_logger(self):
        """A tiny stand-in logger the advisor can call from its worker thread.

        The advisor only uses ``.info / .warning / .error / .debug`` — none of
        these touch the UI (they go to a per-process logger). Anything the
        user should see is routed through ``line_callback`` instead.
        """
        import logging
        log = logging.getLogger("reconpilot.advisor")
        if not log.handlers:
            log.addHandler(logging.StreamHandler())
            log.setLevel(logging.INFO)
        return log

    def _on_advisor_done(self, result: dict):
        self._restore_advisor_buttons()

        if result.get("ok"):
            self._on_log("INFO", "[AIAdvisor] ✔  Report analysis ready.")
        else:
            self._on_log("WARNING", "[AIAdvisor] ✘ Report analysis could not be completed.")

        self._show_advisor_result(result)

    def _advisor_markdown_to_safe_html(self, text: str) -> str:
        """Render advisor markdown as attractive HTML without losing <placeholders>.

        The AI answer is markdown/plain text, but it often contains placeholders
        such as <account>, <bucket_name>, and <randomroom>. Rendering that raw
        text directly as HTML causes Qt to treat those placeholders as tags and
        hide them, so every line is escaped before lightweight markdown styling
        is applied.
        """
        raw = text or "(no content)"

        def inline(src: str) -> str:
            safe = html.escape(src, quote=False)
            safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
            safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", safe)
            return safe

        parts: list[str] = []
        in_list = False
        in_code = False
        code_lines: list[str] = []

        def close_list():
            nonlocal in_list
            if in_list:
                parts.append("</ul>")
                in_list = False

        def close_code():
            nonlocal in_code, code_lines
            if in_code:
                parts.append("<pre><code>" + html.escape("\n".join(code_lines), quote=False) + "</code></pre>")
                code_lines = []
                in_code = False

        for line in raw.splitlines():
            stripped = line.strip()

            if stripped.startswith("```"):
                if in_code:
                    close_code()
                else:
                    close_list()
                    in_code = True
                    code_lines = []
                continue

            if in_code:
                code_lines.append(line)
                continue

            if not stripped:
                close_list()
                continue

            if stripped.startswith("# "):
                close_list()
                parts.append(f"<h1>{inline(stripped[2:].strip())}</h1>")
                continue

            if stripped.startswith("## "):
                close_list()
                title = stripped[3:].strip()
                parts.append(f"<h2>{inline(title)}</h2>")
                continue

            if stripped.startswith("### "):
                close_list()
                parts.append(f"<h3>{inline(stripped[4:].strip())}</h3>")
                continue

            if stripped.startswith("- ") or stripped.startswith("• "):
                if not in_list:
                    parts.append("<ul>")
                    in_list = True
                item = stripped[2:].strip()
                parts.append(f"<li>{inline(item)}</li>")
                continue

            close_list()
            if stripped.startswith("**Why this matters:**"):
                body = stripped.replace("**Why this matters:**", "", 1).strip()
                parts.append(f"<div class='callout why'><b>Why this matters</b><p>{inline(body)}</p></div>")
            elif stripped.startswith("**Next step:**"):
                parts.append("<div class='callout next'><b>Next step</b></div>")
            elif stripped.startswith("**Expected outcome:**"):
                body = stripped.replace("**Expected outcome:**", "", 1).strip()
                parts.append(f"<div class='callout outcome'><b>Expected outcome</b><p>{inline(body)}</p></div>")
            else:
                parts.append(f"<p>{inline(stripped)}</p>")

        close_code()
        close_list()

        css = f"""
        body {{
            background: {C['bg']};
            color: {C['text']};
            font-family: 'Segoe UI', 'Inter', Arial, sans-serif;
            font-size: 13px;
            line-height: 1.55;
            margin: 0;
        }}
        h1 {{
            color: {C['accent']};
            font-size: 23px;
            margin: 8px 0 14px 0;
            padding-bottom: 10px;
            border-bottom: 1px solid {C['border2']};
            letter-spacing: .2px;
        }}
        h2 {{
            color: {C['accent2']};
            font-size: 17px;
            margin: 20px 0 10px 0;
            padding: 8px 10px;
            border-left: 3px solid {C['accent']};
            background: {C['bg2']};
            border-radius: 5px;
        }}
        h3 {{
            color: {C['accent4']};
            font-size: 14px;
            margin: 16px 0 8px 0;
        }}
        p {{ margin: 8px 0; }}
        ul {{ margin: 6px 0 12px 14px; padding: 0; }}
        li {{ margin: 5px 0; padding-left: 2px; }}
        strong {{ color: #ffffff; }}
        code {{
            background: {C['bg3']};
            color: {C['accent']};
            border: 1px solid {C['border2']};
            border-radius: 4px;
            padding: 1px 5px;
            font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
            font-size: 12px;
        }}
        pre {{
            background: {C['bg2']};
            color: {C['text']};
            border: 1px solid {C['border2']};
            border-radius: 6px;
            padding: 10px;
            white-space: pre-wrap;
            font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
            font-size: 12px;
        }}
        .callout {{
            border: 1px solid {C['border2']};
            background: {C['bg2']};
            border-radius: 7px;
            padding: 10px 12px;
            margin: 10px 0;
        }}
        .callout b {{
            color: {C['accent']};
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: .5px;
        }}
        .callout p {{ margin: 6px 0 0 0; }}
        .next b {{ color: {C['accent2']}; }}
        .outcome b {{ color: {C['success']}; }}
        """
        return f"<!doctype html><html><head><meta charset='utf-8'><style>{css}</style></head><body>{''.join(parts)}</body></html>"

    def _show_advisor_result(self, result: dict):
        """Window rendering the advisor output in a safe, readable format."""
        dlg = QDialog(self)
        dlg.setWindowTitle("AI Advisor — next steps")
        dlg.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowSystemMenuHint
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        dlg.setSizeGripEnabled(True)
        dlg.resize(980, 760)
        dlg.setStyleSheet(f"""
            QDialog {{ background:{C['bg2']}; }}
            QLabel  {{ color:{C['accent2']}; font-family:monospace; font-size:11px; }}
            QPushButton {{
                background:{C['bg3']}; color:{C['accent']};
                border:1px solid {C['accent']}; border-radius:4px;
                padding:6px 16px; font-family:monospace; font-size:11px;
                min-width:80px;
            }}
            QPushButton:hover {{ background:{C['bg4']}; }}
        """)

        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(14, 14, 14, 12)
        lay.setSpacing(8)

        advisor_text = result.get("markdown") or "(no content)"

        intro = QLabel("Prioritized findings and next steps")
        intro.setStyleSheet(f"color:{C['accent']}; font-family:monospace; font-size:12px; font-weight:600;")
        lay.addWidget(intro)

        body = QTextBrowser()
        body.setReadOnly(True)
        body.setOpenExternalLinks(True)
        body.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        body.setHtml(self._advisor_markdown_to_safe_html(advisor_text))
        body.setStyleSheet(f"""
            QTextBrowser {{
                background:{C['bg']}; color:{C['text']};
                border:1px solid {C['border']}; border-radius:6px;
                padding:14px;
                selection-background-color:{C['bg4']};
            }}
            QScrollBar:vertical {{
                background: {C['bg3']}; width: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border2']}; border-radius: 4px; min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C['accent']}66; }}
            QScrollBar:horizontal {{
                background: {C['bg3']}; height: 8px; border-radius: 4px; margin: 0;
            }}
            QScrollBar::handle:horizontal {{
                background: {C['border2']}; border-radius: 4px; min-width: 24px;
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
        """)
        lay.addWidget(body, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        if result.get("saved_to"):
            saved_lbl = QLabel(f"saved to: {result['saved_to']}")
            saved_lbl.setStyleSheet(f"color:{C['dim']}; font-family:monospace; font-size:10px;")
            btn_row.addWidget(saved_lbl)

        btn_row.addStretch(1)

        copy_btn = QPushButton("Copy")
        def _copy():
            QApplication.clipboard().setText(advisor_text)
            copy_btn.setText("Copied ✓")
        copy_btn.clicked.connect(_copy)
        btn_row.addWidget(copy_btn)

        save_btn = QPushButton("Save As")
        def _save_as():
            default_name = "ai_advisor.md"
            if result.get("saved_to"):
                default_name = str(Path(result["saved_to"]).name)
            path, _ = QFileDialog.getSaveFileName(
                dlg,
                "Save AI Advisor Report",
                default_name,
                "Markdown (*.md);;Text files (*.txt);;All files (*)",
            )
            if not path:
                return
            try:
                Path(path).write_text(advisor_text, encoding="utf-8")
                save_btn.setText("Saved ✓")
            except Exception as exc:
                self._alert("Could not save advisor report", str(exc))
        save_btn.clicked.connect(_save_as)
        btn_row.addWidget(save_btn)

        if result.get("saved_to"):
            open_saved_btn = QPushButton("Open Saved")
            open_saved_btn.clicked.connect(lambda: self._open_file_path(Path(result["saved_to"]), "Could not open saved advisor report"))
            btn_row.addWidget(open_saved_btn)

        lay.addLayout(btn_row)
        dlg.showMaximized()
        dlg.exec()

