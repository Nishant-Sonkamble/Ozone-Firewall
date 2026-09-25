from PySide6.QtCore import (
    QEasingCurve,
    Property,
    QPropertyAnimation,
)
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QStackedLayout,
    QVBoxLayout,
    QWidget,
)


class FlipCard(QFrame):

    def __init__(self, front_widget, back_widget):
        super().__init__()

        self.setObjectName("flipCard")

        self._rotation = 0

        self.stack = QStackedLayout()

        self.stack.addWidget(front_widget)
        self.stack.addWidget(back_widget)

        self.setLayout(self.stack)

        self.animation = QPropertyAnimation(self, b"rotation")

        self.animation.setDuration(500)

        self.animation.setStartValue(0)

        self.animation.setEndValue(180)

        self.animation.setEasingCurve(
            QEasingCurve.InOutCubic
        )

    def mousePressEvent(self, event):

        if self.stack.currentIndex() == 0:
            self.stack.setCurrentIndex(1)
        else:
            self.stack.setCurrentIndex(0)

        self.animation.start()

        super().mousePressEvent(event)

    def getRotation(self):
        return self._rotation

    def setRotation(self, value):
        self._rotation = value

    rotation = Property(float, getRotation, setRotation)