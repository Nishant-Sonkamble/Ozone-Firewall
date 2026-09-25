from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget


class AtmosphereRing(QWidget):

    def __init__(self):
        super().__init__()

        self.setMinimumSize(700, 500)

    def paintEvent(self, event):

        painter = QPainter(self)

        painter.setRenderHint(QPainter.Antialiasing)

        pen = QPen(QColor(53, 201, 255, 45))

        pen.setWidth(5)

        painter.setPen(pen)

        margin_x = 90
        margin_y = 50

        painter.drawEllipse(
            margin_x,
            margin_y,
            self.width() - (margin_x * 2),
            self.height() - (margin_y * 2)
        )