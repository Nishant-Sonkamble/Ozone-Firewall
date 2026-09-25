from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QLabel,
    QGridLayout,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView
)
from statistics_manager import (
    get_statistics_summary,
    get_top_processes,
    get_top_remote_connections
)
from PySide6.QtWidgets import QGroupBox, QVBoxLayout, QHBoxLayout
from ui.widgets.stat_card import StatCard
from ui.widgets.ozone_chart import OzoneChart
from statistics_manager import get_statistics_summary


class StatisticsPage(QWidget):

    def __init__(self):
        super().__init__()

        self.connections = []

        layout = QVBoxLayout(self)

        title = QLabel("📊 Statistics")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # ---------------- Summary Cards ---------------- #

        self.summary_grid = QGridLayout()
        layout.addLayout(self.summary_grid)

        self.connections_card = StatCard(
            "🌐",
            "Connections",
            0,
            "Currently active network connections."
        )

        self.processes_card = StatCard(
            "⚙",
            "Processes",
            0,
            "Unique running processes using the network."
        )

        self.high_card = StatCard(
            "🟠",
            "High Threats",
            0,
            "Connections classified as HIGH risk."
        )

        self.critical_card = StatCard(
            "🔴",
            "Critical",
            0,
            "Connections classified as CRITICAL."
        )

        self.protocol_card = StatCard(
            "📡",
            "Protocols",
            0,
            "TCP and UDP usage."
        )

        self.rules_card = StatCard(
            "🛡",
            "Rules",
            0,
            "Firewall rules currently configured."
        )

        self.vt_card = StatCard(
            "☁",
            "VirusTotal",
            0,
            "VirusTotal scan history."
        )

        self.safe_card = StatCard(
            "🟢",
            "Safe",
            0,
            "LOW risk connections."
        )

        self.unknown_card = StatCard(
            "❓",
            "Unknown",
            0,
            "Connections awaiting classification."
        )

        cards = [

            self.connections_card,
            self.processes_card,
            self.high_card,

            self.critical_card,
            self.protocol_card,
            self.rules_card,

            self.vt_card,
            self.safe_card,
            self.unknown_card

        ]

        for index, card in enumerate(cards):

            row = index // 3
            column = index % 3

            self.summary_grid.addWidget(
                card,
                row,
                column
            )

        # ---------------- Ozone Layer ---------------- #

        self.ozone_chart = OzoneChart()

        layout.addWidget(self.ozone_chart)

        self.legend_layout = QGridLayout()
        layout.addLayout(self.legend_layout)
        self.safe_label = QLabel()
        self.high_label = QLabel()
        self.critical_label = QLabel()
        self.unknown_label = QLabel()

        self.legend_layout.addWidget(
    self.safe_label,
    0,
    0
)

        self.legend_layout.addWidget(
    self.high_label,
    0,
    1
)

        self.legend_layout.addWidget(
    self.critical_label,
    1,
    0
)

        self.legend_layout.addWidget(
    self.unknown_label,
    1,
    1
)

        # ==========================================
# Top Network Processes
# ==========================================

        process_box = QGroupBox("Top Network Processes")

        process_layout = QVBoxLayout(process_box)

        self.process_table = QTableWidget()

        self.process_table.setColumnCount(3)

        self.process_table.setHorizontalHeaderLabels([
    "Process",
    "Connections",
    "Risk"
])

        self.process_table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

        self.process_table.verticalHeader().hide()

        self.process_table.setEditTriggers(
    QAbstractItemView.NoEditTriggers
)

        self.process_table.setSelectionMode(
    QAbstractItemView.NoSelection
)

        self.process_table.setVerticalScrollBarPolicy(
    Qt.ScrollBarAlwaysOff
)

        process_layout.addWidget(self.process_table)


# ==========================================
# Top Remote Connections
# ==========================================

        remote_box = QGroupBox("Top Remote Hosts")

        remote_layout = QVBoxLayout(remote_box)

        self.remote_table = QTableWidget()

        self.remote_table.setColumnCount(2)

        self.remote_table.setHorizontalHeaderLabels([
    "Remote Address",
    "Connections"
])

        self.remote_table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

        self.remote_table.verticalHeader().hide()

        self.remote_table.setEditTriggers(
    QAbstractItemView.NoEditTriggers
)

        self.remote_table.setSelectionMode(
    QAbstractItemView.NoSelection
)

        self.remote_table.setVerticalScrollBarPolicy(
    Qt.ScrollBarAlwaysOff
)

        remote_layout.addWidget(self.remote_table)

        tables_layout = QHBoxLayout()

        tables_layout.addWidget(process_box)

        tables_layout.addWidget(remote_box)

        tables_layout.setStretch(0, 1)

        tables_layout.setStretch(1, 1)

        layout.addLayout(tables_layout)

        self.update_statistics()


    # ------------------------------------------------ #

    def set_connections(self, connections):

        self.connections = connections

        print(
            "Statistics received:",
            len(connections)
        )

        self.update_statistics()

    # ------------------------------------------------ #

    def update_statistics(self):

        stats = get_statistics_summary(
            self.connections
        )

        # -------- Cards -------- #

        self.connections_card.setValue(
            stats["connections"]
        )

        self.processes_card.setValue(
            stats["processes"]
        )

        self.high_card.setValue(
            stats["high"]
        )

        self.critical_card.setValue(
            stats["critical"]
        )

        self.protocol_card.setValue(
            f'TCP {stats["tcp"]}\nUDP {stats["udp"]}'
        )

        self.rules_card.setValue(
            stats["rules"]
        )

        self.vt_card.setValue(
            stats["vt_scans"]
        )

        self.safe_card.setValue(
            stats["low"]
        )

        self.unknown_card.setValue(
            stats["unknown"]
        )

        # -------- Ozone Layer -------- #

        self.update_ozone_chart(stats)
        self.update_legend(stats)
        self.update_process_table()
        self.update_remote_table()
    # ------------------------------------------------ #

    def update_ozone_chart(self, stats):

        segments = [

            (
                "Safe",
                stats["low"],
                QColor("#4CAF50")
            ),

            (
                "High",
                stats["high"],
                QColor("#FF9800")
            ),

            (
                "Critical",
                stats["critical"],
                QColor("#F44336")
            ),

            (
                "Unknown",
                stats["unknown"],
                QColor("#607D8B")
            )

        ]

        self.ozone_chart.setSegments(
            segments
        )

        if stats["critical"] > 0:

            self.ozone_chart.setGlowColor(
                QColor("#F44336")
            )

        elif stats["high"] > 0:

            self.ozone_chart.setGlowColor(
                QColor("#FF9800")
            )

        else:

            self.ozone_chart.setGlowColor(
                QColor("#2196F3")
            )

    def update_legend(self, stats):

     total = max(
        stats["connections"],
        1
    )

     safe_percent = stats["low"] * 100 / total

     high_percent = stats["high"] * 100 / total

     critical_percent = stats["critical"] * 100 / total

     unknown_percent = stats["unknown"] * 100 / total

     self.safe_label.setText(

        f"🟢 Safe\n"
        f"{stats['low']} ({safe_percent:.1f}%)"

    )

     self.high_label.setText(

        f"🟠 High\n"
        f"{stats['high']} ({high_percent:.1f}%)"

    )

     self.critical_label.setText(

        f"🔴 Critical\n"
        f"{stats['critical']} ({critical_percent:.1f}%)"

    )

     self.unknown_label.setText(

        f"⚪ Unknown\n"
        f"{stats['unknown']} ({unknown_percent:.1f}%)"

    )

    def update_process_table(self):

     processes = get_top_processes(

        self.connections

    )

     self.process_table.setRowCount(

        len(processes)

    )

     for row, process in enumerate(processes):

        self.process_table.setItem(
            row,
            0,

            QTableWidgetItem(
                process["process"]
            )
        )

        self.process_table.setItem(
            row,
            1,

            QTableWidgetItem(
                str(
                    process["connections"]
                )
            )
        )

        self.process_table.setItem(
            row,
            2,
            QTableWidgetItem(
                process["risk"]
            )
        ) 

        self.process_table.resizeRowsToContents()

        self.process_table.resizeColumnsToContents()

        height = (

    self.process_table.horizontalHeader().height()

    +

    self.process_table.rowCount()

    *

    self.process_table.verticalHeader().defaultSectionSize()

    +

    2

)

        self.process_table.setFixedHeight(height)
        self.process_table.verticalHeader().hide()
        self.process_table.setEditTriggers(
    QTableWidget.NoEditTriggers
)
        self.process_table.setSelectionMode(
    QTableWidget.NoSelection
)

    def update_remote_table(self):

     remotes = get_top_remote_connections(
        self.connections
    )

     self.remote_table.setRowCount(
        len(remotes)
    )

     for row, remote in enumerate(remotes):

        self.remote_table.setItem(

            row,
            0,

            QTableWidgetItem(
                remote["remote"]
            )

        )

        self.remote_table.setItem(

            row,
            1,

            QTableWidgetItem(
                str(remote["connections"])
            )

        )

     self.remote_table.resizeRowsToContents()

     self.remote_table.resizeColumnsToContents()

     height = (

        self.remote_table.horizontalHeader().height()

        +

        self.remote_table.rowCount()

        *

        self.remote_table.verticalHeader().defaultSectionSize()

        +

        2

    )

     self.remote_table.setFixedHeight(height)