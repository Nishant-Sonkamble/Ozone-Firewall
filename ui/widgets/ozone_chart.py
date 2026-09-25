from pathlib import Path

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QWidget


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EARTH_PATH = PROJECT_ROOT / "assets" / "earth.svg"


class OzoneChart(QWidget):

    def __init__(self):
        super().__init__()

        self.setMinimumSize(450, 450)

        self.earth = QSvgRenderer(str(EARTH_PATH))

        # (Label, Value, Color)
        self.segments = []

        # Overall glow color (can be changed from StatisticsPage)
        self.glow_color = QColor(0, 170, 255)

    def setSegments(self, segments):

        self.segments = segments
        self.update()

    def setGlowColor(self, color):

        self.glow_color = color
        self.update()

    def paintEvent(self, event):

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        painter.fillRect(
            self.rect(),
            QColor("#1f2126")
        )

        self.drawOzoneRing(painter)

        self.drawEarth(painter)

        painter.end()

    def drawEarth(self, painter):

        size = min(
            self.width(),
            self.height()
        )

        center = self.rect().center()

        radius = size * 0.24

        target = QRectF(

            center.x() - radius,
            center.y() - radius,

            radius * 2,
            radius * 2

        )

        self.earth.render(
            painter,
            target
        )

    def drawRingGlow(self, painter, rect):

        layers = [

            (36, 10),

            (30, 20),

            (24, 35)

        ]

        for width, alpha in layers:

            pen = QPen(
                QColor(

                    self.glow_color.red(),
                    self.glow_color.green(),
                    self.glow_color.blue(),
                    alpha

                )
            )

            pen.setWidth(width)

            pen.setCapStyle(Qt.RoundCap)

            painter.setPen(pen)

            painter.setBrush(Qt.NoBrush)

            painter.drawEllipse(rect)

    def drawOzoneRing(self, painter):

        total = sum(
            value
            for _, value, _ in self.segments
        )

        if total == 0:
            total = 1

        size = min(
            self.width(),
            self.height()
        )

        center = self.rect().center()

        radius = size * 0.35

        rect = QRectF(

            center.x() - radius,
            center.y() - radius,

            radius * 2,
            radius * 2

        )

        self.drawRingGlow(
            painter,
            rect
        )

        # Atmosphere Base Ring

        base_pen = QPen(
            QColor(60, 110, 180, 80)
        )

        base_pen.setWidth(28)

        painter.setPen(base_pen)

        painter.drawArc(

            rect,

            0,

            360 * 16

        )

        # Threat Segments

        pen = QPen()

        pen.setWidth(20)

        pen.setCapStyle(Qt.RoundCap)

        start = 90 * 16

        for label, value, color in self.segments:

            if value == 0:
                continue

            angle = int(
                (value / total) * 360 * 16
            )

            pen.setColor(color)

            painter.setPen(pen)

            painter.drawArc(

                rect,

                start,

                -angle

            )

            start -= angle


if __name__ == "__main__":

    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)

    widget = OzoneChart()

    widget.resize(500, 500)

    widget.setSegments([

        ("Safe", 70, QColor("#4CAF50")),

        ("High", 20, QColor("#FF9800")),

        ("Critical", 10, QColor("#F44336")),

        ("Unknown", 5, QColor("#607D8B"))

    ])

    widget.show()

    sys.exit(app.exec())