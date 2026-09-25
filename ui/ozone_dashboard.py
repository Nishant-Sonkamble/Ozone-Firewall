from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)
from ui.widgets.atmosphere_ring import AtmosphereRing
from logger import load_logs
from statistics_manager import get_dashboard_stats
from ui.widgets.stat_card import StatCard

class OzoneDashboardPage(QWidget):

    def __init__(self):
     super().__init__()

     main_layout = QVBoxLayout(self)

    # ==========================================
    # Header
    # ==========================================

     heading = QLabel("🛡 OZONE LAYER")
     heading.setAlignment(Qt.AlignCenter)

     subtitle = QLabel("Digital Atmospheric Protection")
     subtitle.setAlignment(Qt.AlignCenter)

     main_layout.addWidget(heading)
     main_layout.addWidget(subtitle)

    # ==========================================
    # Stat Cards
    # ==========================================

     self.connections_card = StatCard(
        "🌐",
        "Protected Connections",
        "0",
        "Trusted network traffic safely passes through the digital atmosphere."
    )

     self.rules_card = StatCard(
        "🛡",
        "Protection Rules",
        "0",
        "Every packet is checked against your protection policies."
    )

     self.blocked_card = StatCard(
        "☀️",
        "Threats Neutralized",
        "0",
        "Just as the ozone layer blocks harmful UV radiation, Ozone Layer blocks malicious traffic."
    )

     self.logs_card = StatCard(
        "📄",
        "Activity Logs",
        "0",
        "Total recorded firewall events."
    )

     def create_card_frame(card):
         
      frame = QFrame()
      frame.setObjectName("ozoneCard")
         
      layout = QVBoxLayout(frame)
      layout.setContentsMargins(8, 8, 8, 8)
      layout.addWidget(card)
      return frame
         
     self.connections_frame = create_card_frame(self.connections_card)
     self.rules_frame = create_card_frame(self.rules_card)
     self.blocked_frame = create_card_frame(self.blocked_card)
     self.logs_frame = create_card_frame(self.logs_card)
         
             # ==========================================
             # Atmosphere Ring
             # ==========================================
         
     self.atmosphere = AtmosphereRing()
         
     ring_layout = QGridLayout(self.atmosphere)
         
     ring_layout.setContentsMargins(20,20,20,20)
     ring_layout.setHorizontalSpacing(30)
     ring_layout.setVerticalSpacing(30)
         
     ring_layout.setColumnStretch(0,1)
     ring_layout.setColumnStretch(1,1)
     ring_layout.setColumnStretch(2,1)
         
     ring_layout.setRowStretch(0,1)
     ring_layout.setRowStretch(1,1)
     ring_layout.setRowStretch(2,1)
         
             # ==========================================
             # Center Icon
             # ==========================================
         
     self.dashboard_icon = QLabel()
     self.dashboard_icon.setAlignment(Qt.AlignCenter)
         
     pixmap = QPixmap("assets/dashboard_icon.svg")
         
     self.dashboard_icon.setPixmap(
     pixmap.scaled(
                     180,
                     180,
                     Qt.KeepAspectRatio,
                     Qt.SmoothTransformation
                 )
             )
         
             # ==========================================
             # Layout
             # ==========================================
         
     ring_layout.addWidget(
                 self.connections_frame,
                 0,
                 1,
                 alignment=Qt.AlignCenter
             )
         
     ring_layout.addWidget(
                 self.rules_frame,
                 1,
                 0,
                 alignment=Qt.AlignCenter
             )
         
     ring_layout.addWidget(
                 self.dashboard_icon,
                 1,
                 1,
                 alignment=Qt.AlignCenter
             )
         
     ring_layout.addWidget(
                 self.blocked_frame,
                 1,
                 2,
                 alignment=Qt.AlignCenter
             )
         
     ring_layout.addWidget(
                 self.logs_frame,
                 2,
                 1,
                 alignment=Qt.AlignCenter
             )
         
     main_layout.addWidget(self.atmosphere)
         
             # ==========================================
             # Recent Activity
             # ==========================================
    

     activity = QFrame()

     activity_layout = QVBoxLayout(activity)

     activity_layout.addWidget(
        QLabel("Recent Activity")
    )

     self.activity1 = QLabel("Waiting...")
     self.activity2 = QLabel("")
     self.activity3 = QLabel("")
     self.activity4 = QLabel("")

     activity_layout.addWidget(self.activity1)
     activity_layout.addWidget(self.activity2)
     activity_layout.addWidget(self.activity3)
     activity_layout.addWidget(self.activity4)

     main_layout.addWidget(activity)

    # ==========================================
    # Timer
    # ==========================================

     self.update_dashboard() 

     self.timer = QTimer(self)

     self.timer.timeout.connect(
        self.update_dashboard
    )

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

    # ==========================================
        # Individual Card Frames
        # ==========================================
    
    