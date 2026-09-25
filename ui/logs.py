from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHBoxLayout,
    QHeaderView
)
from PySide6.QtCore import Qt

from logger import load_logs
from PySide6.QtWidgets import QAbstractItemView

class LogsPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        title = QLabel("Firewall Activity Logs")
        title.setAlignment(Qt.AlignCenter)

        layout.addWidget(title)

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
        

        self.table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

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

        def load_log_table(self):

         logs = load_logs()

         print(logs)   # <-- add this

         self.table.setRowCount(len(logs))

         