from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt, QTimer

from ui.widgets.stat_card import StatCard
from statistics_manager import get_dashboard_stats
from logger import load_logs

class DashboardPage(QWidget):

    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout(self)

        heading = QLabel("🌍 OZONE LAYER")
        heading.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Your Device's Protective Atmosphere")
        subtitle.setAlignment(Qt.AlignCenter)

        main_layout.addWidget(heading)
        main_layout.addWidget(subtitle)

        grid = QGridLayout()

        # Create cards
        self.connections_card = StatCard(
            "🌐",
            "Protected Connections",
            "0",
            "Trusted network traffic safely passes through the digital atmosphere."
        )

        self.blocked_card = StatCard(
            "☀️",
            "Threats Neutralized",
            "0",
            "Just as the ozone layer blocks harmful UV radiation, Ozone Layer blocks malicious traffic."
        )

        self.rules_card = StatCard(
            "🛡",
            "Protection Rules",
            "0",
            "Every packet is checked against your protection policies."
        )

        self.logs_card = StatCard(
            "📄",
            "Activity Logs",
            "0",
            "Total recorded firewall events."
        )

        grid.addWidget(self.connections_card, 0, 0)
        grid.addWidget(self.blocked_card, 0, 1)
        grid.addWidget(self.rules_card, 1, 0)
        grid.addWidget(self.logs_card, 1, 1)

        main_layout.addLayout(grid)

        activity = QFrame()
        activity_layout = QVBoxLayout(activity)

        activity_layout.addWidget(QLabel("Recent Activity"))

        self.activity1 = QLabel("Waiting...")
        self.activity2 = QLabel("")
        self.activity3 = QLabel("")
        self.activity4 = QLabel("")

        activity_layout.addWidget(self.activity1)
        activity_layout.addWidget(self.activity2)
        activity_layout.addWidget(self.activity3)
        activity_layout.addWidget(self.activity4)

        main_layout.addWidget(activity)

        # Load statistics
        self.update_dashboard()

        # Auto refresh every 2 seconds
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_dashboard)
        self.timer.start(2000)

    def update_dashboard(self):

     stats = get_dashboard_stats()

     self.connections_card.setValue(str(stats["connections"]))
     self.blocked_card.setValue(str(stats["blocked"]))
     self.rules_card.setValue(str(stats["rules"]))
     self.logs_card.setValue(str(stats["logs"]))

     logs = load_logs()

     if not logs:

        self.activity1.setText("No activity yet.")
        self.activity2.setText("")
        self.activity3.setText("")
        self.activity4.setText("")

        return

     latest = logs[-4:]
     latest.reverse()

     labels = [

        self.activity1,
        self.activity2,
        self.activity3,
        self.activity4

    ]

     for label, log in zip(labels, latest):

        icon = "🟢" if log["action"] == "ALLOW" else "🔴"

        label.setText(
            f"{icon} {log['process']} ({log['action']})"
        )

     for i in range(len(latest), 4):

        labels[i].setText("")