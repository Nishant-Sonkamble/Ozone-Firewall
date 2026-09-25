from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QScrollArea,
    QStackedWidget,
    QWidget,
)
from PySide6.QtWidgets import QProgressDialog
from PySide6.QtCore import Qt
import notification_manager
from settings_manager import load_settings, save_settings
from ui.dashboard import DashboardPage
from ui.connections import ConnectionsPage
from ui.rules import RulesPage
from ui.logs import LogsPage
from ui.statistics import StatisticsPage
from ui.settings import SettingsPage
from ui.virustotal_page import VirusTotalPage
from ui.ozone_dashboard import OzoneDashboardPage

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sentinel Firewall")

        self.resize(1300, 800)

        central = QWidget()

        self.setCentralWidget(central)

        layout = QHBoxLayout()

        central.setLayout(layout)

        self.sidebar = QListWidget()

        self.sidebar.addItems([
    "🏠 Dashboard",
    "🌐 Live Connections",
    "🛡 Rules",
    "📄 Logs",
    "📊 Statistics",
    "☁ VirusTotal",
    "⚙ Settings"
])

        self.sidebar.setFixedWidth(220)

        layout.addWidget(self.sidebar)

        settings = load_settings()
        theme = settings.get("theme", "ozone")

        self.pages = QStackedWidget()

        self.dashboard_page = DashboardPage()
        self.ozone_dashboard_page = OzoneDashboardPage()
        self.connections_page = ConnectionsPage()
        self.rules_page = RulesPage()
        self.logs_page = LogsPage()
        self.statistics_page = StatisticsPage()
        self.virustotal_page = VirusTotalPage()
        self.settings_page = SettingsPage(self)
        

        # ==========================================
# Dashboard Pages
# ==========================================

        self.dashboard_scroll = self.make_scrollable(
    self.dashboard_page
)

        self.ozone_dashboard_scroll = self.make_scrollable(
    self.ozone_dashboard_page
)

        self.pages.addWidget(self.dashboard_scroll)        # Index 0
        self.pages.addWidget(self.ozone_dashboard_scroll)  # Index 1  

        
        self.pages.addWidget(
    self.make_scrollable(
        self.connections_page
    )
)
        self.pages.addWidget(
    self.make_scrollable(
        self.rules_page
    )
)
        self.pages.addWidget(
    self.make_scrollable(
        self.logs_page
    )
)
        self.pages.addWidget(
    self.make_scrollable(
        self.statistics_page
    )
)
        self.pages.addWidget(
    self.make_scrollable(
        self.virustotal_page
    )
)
        self.pages.addWidget(
    self.make_scrollable(
        self.settings_page
    )
)
        layout.addWidget(self.pages)
        self.first_connection_load = True
        self.loading_dialog = QProgressDialog(
    "Scanning active network connections...\n\n"
    "Please wait...",
    None,
    0,
    100,
    self
)


        self.loading_dialog.setWindowTitle("Sentinel Firewall")
        self.loading_dialog.setCancelButton(None)
        self.loading_dialog.setMinimumDuration(0)
        self.loading_dialog.setWindowModality(Qt.ApplicationModal)

        self.loading_dialog.hide()
        self.sidebar.currentRowChanged.connect(
    self.change_page
)    
        self.sidebar.setCurrentRow(0)

    def show_loading(self):

     self.loading_dialog.setValue(0)
     self.loading_dialog.show()

     self.sidebar.setEnabled(False)


    def update_loading(self, current, total):

     self.loading_dialog.setMaximum(total)
     self.loading_dialog.setValue(current)

     self.loading_dialog.setLabelText(
        "Scanning active network connections...\n\n"
        f"Processed {current} of {total} connections..."
    )


    def hide_loading(self):

     self.loading_dialog.hide()

     self.sidebar.setEnabled(True)

    def change_page(self, index):

     settings = load_settings()

     theme = settings.get("theme", "ozone")

    # ---------------- Dashboard ----------------

     if index == 0:

        if theme == "ozone":

            self.pages.setCurrentIndex(1)

            self.ozone_dashboard_page.update_dashboard()

        else:

            self.pages.setCurrentIndex(0)

            self.dashboard_page.update_dashboard()

    # ---------------- Connections ----------------

     elif index == 1:

        self.pages.setCurrentIndex(2)

        self.connections_page.load_connections()

    # ---------------- Rules ----------------

     elif index == 2:

        self.pages.setCurrentIndex(3)

        self.rules_page.load_rules()

    # ---------------- Logs ----------------

     elif index == 3:

        self.pages.setCurrentIndex(4)

        self.logs_page.load_logs()

    # ---------------- Statistics ----------------

     elif index == 4:

        self.pages.setCurrentIndex(5)

        self.statistics_page.set_connections(
            self.connections_page.connections
        )

    # ---------------- VirusTotal ----------------

     elif index == 5:

        self.pages.setCurrentIndex(6)

        self.virustotal_page.load_history()

    # ---------------- Settings ----------------

     elif index == 6:

        self.pages.setCurrentIndex(7)

    def change_theme(self, theme):

     settings = load_settings()

     settings["theme"] = theme

     save_settings(settings)

     with open(f"themes/{theme}.qss", "r") as f:

        self.setStyleSheet(f.read())

    # Refresh dashboard only if user is on Dashboard

     if self.sidebar.currentRow() == 0:

        self.change_page(0)

    def make_scrollable(self, widget):

     scroll = QScrollArea()

     scroll.setWidget(widget)

     scroll.setWidgetResizable(True)

     scroll.setFrameShape(QScrollArea.NoFrame)

     return scroll