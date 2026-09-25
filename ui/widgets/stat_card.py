from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from ui.widgets.flip_card import FlipCard


class StatCard(FlipCard):

    def __init__(self,
                 icon,
                 title,
                 value,
                 back_text):

        # ==========================
        # Front Side
        # ==========================

        front = QWidget()

        front_layout = QVBoxLayout(front)

        front_layout.setContentsMargins(
            20,
            20,
            20,
            20
        )

        front_layout.setSpacing(10)

        self.emoji = QLabel(icon)
        self.emoji.setObjectName("cardIcon")
        self.emoji.setAlignment(Qt.AlignCenter)

        self.heading = QLabel(title)
        self.heading.setObjectName("cardTitle")
        self.heading.setAlignment(Qt.AlignCenter)

        self.number = QLabel(str(value))
        self.number.setObjectName("cardValue")
        self.number.setAlignment(Qt.AlignCenter)

        if title == "Protocols":
         self.number.setObjectName("protocolValue")

        else:
         self.number.setObjectName("cardValue")

        front_layout.addStretch()

        front_layout.addWidget(self.emoji)
        front_layout.addWidget(self.heading)
        front_layout.addWidget(self.number)

        front_layout.addStretch()

        # ==========================
        # Back Side
        # ==========================

        back = QWidget()

        back_layout = QVBoxLayout(back)

        back_layout.setContentsMargins(
            20,
            20,
            20,
            20
        )

        back_layout.setSpacing(10)

        explanation = QLabel(back_text)
        explanation.setObjectName("cardDescription")
        explanation.setAlignment(Qt.AlignCenter)
        explanation.setWordWrap(True)

        back_layout.addStretch()
        back_layout.addWidget(explanation)
        back_layout.addStretch()

        super().__init__(front, back)

    def setValue(self, value):

        self.number.setText(str(value))