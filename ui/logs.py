from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHBoxLayout,
    QHeaderView,
    QAbstractItemView
)
from PySide6.QtCore import Qt

from logger import load_logs


class LogsPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        title = QLabel("Firewall Activity Logs")
        title.setAlignment(Qt.AlignCenter)

        layout.addWidget(title)

        # Empty state message
        self.empty_label = QLabel(
            "📋 No security events recorded yet.\n"
            "Activity will appear here as Ozone Firewall runs and records your actions."
        )
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)

        layout.addWidget(self.empty_label)

        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setColumnCount(3)

        self.table.setHorizontalHeaderLabels([
            "Time",
            "Process",
            "Action"
        ])

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.table)

        buttons = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")

        buttons.addStretch()
        buttons.addWidget(self.refresh_btn)

        layout.addLayout(buttons)

        self.refresh_btn.clicked.connect(
            self.load_log_table
        )

        self.load_log_table()

    def load_log_table(self):

        logs = load_logs()

        if not logs:
            self.table.setRowCount(0)
            self.empty_label.show()
            return

        self.empty_label.hide()

        self.table.setRowCount(len(logs))

        for row, log in enumerate(logs):

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(log["time"])
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(log["process"])
            )

            self.table.setItem(
                row,
                2,
                QTableWidgetItem(log["action"])
            )