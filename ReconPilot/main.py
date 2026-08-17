from __future__ import annotations

import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_LOGGING_RULES", "*.debug=false;qt.qpa.*=false")
os.environ.setdefault("PYTHONWARNINGS", "ignore")

os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ui.main_window import MainWindow


def main() -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("ReconPilot")
    app.setOrganizationName("ReconPilot")

    font = QFont("Courier New", 10)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    win = MainWindow()
    win.showMaximized()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
