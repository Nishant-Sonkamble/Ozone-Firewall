import socket
from windows_firewall import (
    block_application,
    allow_application
)
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
)
import psutil
from network_monitor import get_connections
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QMenu,
    QMessageBox,
    QApplication
)
from PySide6.QtWidgets import (
    QFrame,
    QPushButton,
    QHBoxLayout
)
import subprocess
from firewall_engine import (
    add_process_rule,
    check_process
)

from notification_manager import notification_manager
from virustotal import check_hash, summarize_result
from PySide6.QtCore import Qt
from hash_reputation import get_file_hash
from firewall_engine import add_process_rule
from logger import add_log
from PySide6.QtCore import QThread
from connection_loader import ConnectionLoader
from threat_analyzer import analyze_connection
from PySide6.QtCore import Qt, QTimer, QObject, QThread, Signal
from PySide6.QtGui import QColor

# add_event helper to record connection events (CONNECTED/DISCONNECTED)
from history_manager import add_event
import os

from vt_history_manager import add_scan, create_scan_record 
class ConnectionWorker(QObject):

    finished = Signal(list)
    progress = Signal(int, int)

    def run(self):

        data = []

        connections = psutil.net_connections(kind="inet")
        total = len(connections)

        for index, conn in enumerate(connections):

            try:
                if conn.pid:
                    process_obj = psutil.Process(conn.pid)
                    process = process_obj.name()

                    try:
                        exe = process_obj.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe = ""

                else:
                    process = "System"
                    exe = ""

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process = "Unknown"
                exe = ""

            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            local = (
                f"{conn.laddr.ip}:{conn.laddr.port}"
                if conn.laddr else ""
            )

            remote = (
                f"{conn.raddr.ip}:{conn.raddr.port}"
                if conn.raddr else "-"
            )

            connection = {
                "process": process,
                "pid": conn.pid,
                "exe": exe,
                "protocol": protocol,
                "local": local,
                "remote": remote,
                "status": conn.status,
            }

            connection["analysis"] = analyze_connection(connection)
            analysis = connection["analysis"]

            if analysis.get("risk", "").upper() in ("HIGH", "CRITICAL"):
             notification_manager.notify_threat(connection, analysis)

            data.append(connection)
            self.progress.emit(index + 1, total)

        notification_manager.cleanup(data)

        self.finished.emit(data)

class ConnectionsPage(QWidget):

    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout(self)

        title = QLabel("Live Network Connections")
        title.setAlignment(Qt.AlignCenter)
        from PySide6.QtWidgets import QLineEdit
        self.search = QLineEdit()

        self.search.setPlaceholderText(
    "Search by process..."
)

        layout.addWidget(self.search)
        self.search.textChanged.connect(self.filter_connections)
        self.table = QTableWidget()

        self.table.setColumnCount(8)

        self.table.setHorizontalHeaderLabels([
            "Process",
            "PID",
            "Protocol",
            "Local Address",
            "Remote Address",
            "Status",
            "Firewall",
            "Risk"
        ])
        from PySide6.QtWidgets import QHeaderView
        self.table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

        self.table.setAlternatingRowColors(True)

        self.table.setEditTriggers(
    QTableWidget.NoEditTriggers
)

        self.table.setSelectionBehavior(
    QTableWidget.SelectRows
)
        self.table.itemDoubleClicked.connect(
    lambda _: self.show_connection_details()
)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        self.table.customContextMenuRequested.connect(
    self.show_context_menu
)
        self.details = QLabel("Select a connection to view details.")
        # ---------- Details Panel ----------

        self.details_frame = QFrame()
        self.details_frame.setFrameShape(QFrame.StyledPanel)

        details_layout = QVBoxLayout(self.details_frame)

        header = QHBoxLayout()

        header.addWidget(QLabel("<b>Connection Details</b>"))

        
        
        self.close_button = QPushButton()
        self.close_button.setText("×")

        self.close_button.setObjectName(
    "closeConnectionButton"

)       
        self.close_button.setFixedSize(36, 36)
        
        self.close_button.clicked.connect(self.hide_details)

        header.addStretch()
        header.addWidget(self.close_button)

        details_layout.addLayout(header)
    
        self.details = QLabel()
        self.details.setWordWrap(True)

        details_layout.addWidget(self.details)

        buttons = QHBoxLayout()

        self.copy_hash_btn = QPushButton("📋 Copy Hash")
        self.copy_path_btn = QPushButton("📋 Copy Path")
        self.copy_remote_btn = QPushButton("📋 Copy Remote")
        self.copy_all_btn = QPushButton("📋 Copy All")

        buttons.addWidget(self.copy_hash_btn)
        buttons.addWidget(self.copy_path_btn)
        buttons.addWidget(self.copy_remote_btn)
        buttons.addWidget(self.copy_all_btn)

        details_layout.addLayout(buttons)
 
        buttons2 = QHBoxLayout()

        self.open_file_btn = QPushButton("📄 Open File")
        self.open_folder_btn = QPushButton("📂 Open Folder")
        self.scan_vt_btn = QPushButton("🛡 Scan with VirusTotal")
        details_layout.addWidget(self.scan_vt_btn)
        
        self.scan_vt_btn.clicked.connect(self.scan_virustotal)

        buttons2.addWidget(self.open_file_btn)
        buttons2.addWidget(self.open_folder_btn)

        details_layout.addLayout(buttons2)
        self.copy_hash_btn.clicked.connect(self.copy_hash)

        self.copy_path_btn.clicked.connect(self.copy_path)

        self.copy_remote_btn.clicked.connect(self.copy_remote)

        self.copy_all_btn.clicked.connect(self.copy_all)

        self.open_file_btn.clicked.connect(self.open_file)

        self.open_folder_btn.clicked.connect(self.open_folder)

        self.details_frame.hide()
        self.previous_connections = {}
        self.connections = []

        layout.addWidget(self.details_frame)

        layout.addWidget(title)
        layout.addWidget(self.table)
        self.current_hash = None

        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_connections)
        
        self.timer.start(3000)
        self.first_scan = True
        self.loading = False
        self.details_visible = False

    def hide_details(self):
        self.table.clearSelection()
        self.details_frame.hide()
        self.details.setText("Select a connection to view details.")

    def load_connections(self):

        # Don't refresh if a scan is already running
        if self.loading:
            return

        # Skip refresh while the user is interacting with the table
        if self.table.selectedItems():
            return

        self.loading = True

        self.thread = QThread()
        self.worker = ConnectionWorker()

        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.display_connections)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        window = self.window()

        if self.first_scan:

         self.worker.progress.connect(window.update_loading)

         self.worker.finished.connect(self.finish_first_scan)

         if hasattr(window, "show_loading"):
          window.show_loading()

        self.thread.start()

    def finish_first_scan(self):

     self.first_scan = False

     window = self.window()

     if hasattr(window, "hide_loading"):
        window.hide_loading()

    def filter_connections(self, text):

     for row in range(self.table.rowCount()):

        visible = False

        for column in range(self.table.columnCount()):

            item = self.table.item(row, column)

            if item and text.lower() in item.text().lower():

                visible = True
                break

        self.table.setRowHidden(row, not visible)

    def show_connection_details(self):
        self.details_visible = True
        row = self.table.currentRow()

        if row < 0:
            return


        conn = self.connections[row]
        self.selected_connection = conn
        
        analysis = conn.get("analysis", analyze_connection(conn))
        exe = conn.get("exe", "")

        
        if exe:

         if "hash" not in conn:
          conn["hash"] = get_file_hash(exe)

         file_hash = conn["hash"]

        else:

         file_hash = "Not Available"

        self.selected_hash = file_hash
        text = f"""
Process : {conn['process']}
PID     : {conn['pid']}
Protocol: {conn['protocol']}
Status  : {conn['status']}

Local   : {conn['local']}
Remote  : {conn['remote']}
Executable : {exe if exe else "Not Available"}

SHA-256 :
{file_hash}

Overall Risk : {analysis['level']} ({analysis['score']}/100)

Process Risk : {analysis['details']['process']['level']}
IP Risk      : {analysis['details']['ip']['level']}
Port Risk    : {analysis['details']['port']['level']}

Reasons:
"""

        for reason in analysis["reasons"]:
            text += "\n• " + reason

        self.details.setText(text)
        self.details_frame.show()

    def display_connections(self, data):
        self.table.setUpdatesEnabled(False)

        # Preserve selected row
        selected_pid = None

        current = self.table.currentRow()

        if current >= 0 and current < len(self.connections):
            selected_pid = self.connections[current]["pid"]

        self.connections = data

        self.table.clearContents()
        self.table.setRowCount(len(data))

        # ---------------- Populate Table ----------------
        for row, conn in enumerate(data):
            self.table.setItem(row, 0, QTableWidgetItem(conn["process"]))
            self.table.setItem(row, 1, QTableWidgetItem(str(conn["pid"])))
            self.table.setItem(row, 2, QTableWidgetItem(conn["protocol"]))
            self.table.setItem(row, 3, QTableWidgetItem(conn["local"]))
            self.table.setItem(row, 4, QTableWidgetItem(conn["remote"]))
            self.table.setItem(row, 5, QTableWidgetItem(conn["status"]))

            firewall_status = check_process(conn["process"])
            item = QTableWidgetItem(firewall_status)

            if firewall_status == "BLOCK":
                item.setBackground(Qt.red)
            else:
                item.setBackground(Qt.darkGreen)

            self.table.setItem(row, 6, item)

            analysis = conn["analysis"]

            notification_manager.notify_threat(conn, analysis)

            risk_item = QTableWidgetItem(
                f'{analysis["level"]} ({analysis["score"]})'
            )

            level = analysis["level"]

            if level == "LOW":
                risk_item.setBackground(QColor(0, 120, 0))
            elif level == "MEDIUM":
                risk_item.setBackground(QColor(200, 170, 0))
            elif level == "HIGH":
                risk_item.setBackground(QColor(255, 140, 0))
            else:
                risk_item.setBackground(QColor(180, 0, 0))

            self.table.setItem(row, 7, risk_item)

        # ---------------- Restore Selection ----------------
        if self.details_visible and selected_pid is not None:
            for row, conn in enumerate(data):
                if conn["pid"] == selected_pid:
                    self.table.selectRow(row)
                    break

        # ---------------- UI ----------------
        if not self.table.selectedItems():
            self.details_frame.hide()

        self.table.setUpdatesEnabled(True)

        # ---------------- Connection History ----------------
        current_connections = {}

        for conn in data:
            key = (
                conn["pid"],
                conn["local"],
                conn["remote"],
                conn["protocol"]
            )
            current_connections[key] = conn

        # New Connections
        for key, conn in current_connections.items():

         if key not in self.previous_connections:

          analysis = conn["analysis"]

          add_event(
            event="CONNECTED",
            process=conn["process"],
            pid=conn["pid"],
            local_ip=conn["local"],
            remote_ip=conn["remote"],
            protocol=conn["protocol"],
            risk=analysis["level"],
            score=analysis["score"]
        )

        for key, conn in self.previous_connections.items():

         if key not in current_connections:

          analysis = conn["analysis"]

          add_event(
            event="DISCONNECTED",
            process=conn["process"],
            pid=conn["pid"],
            local_ip=conn["local"],
            remote_ip=conn["remote"],
            protocol=conn["protocol"],
            risk=analysis["level"],
            score=analysis["score"]
        )

        self.previous_connections = current_connections
        self.loading = False

    def show_context_menu(self, position):
        row = self.table.currentRow()

        if row < 0:
            return

        conn = self.connections[row]

        menu = QMenu(self)

        details = menu.addAction("📄 View Details")
        copy_ip = menu.addAction("📋 Copy Remote IP")

        menu.addSeparator()

        allow = menu.addAction("🛡 Allow Process")
        block = menu.addAction("🚫 Block Process")

        menu.addSeparator()

        terminate = menu.addAction("❌ Terminate Process")

        action = menu.exec(
            self.table.viewport().mapToGlobal(position)
        )

        if action == details:
            info = (
                f"Process : {conn['process']}\n"
                f"PID     : {conn['pid']}\n"
                f"Protocol: {conn['protocol']}\n"
                f"Status  : {conn['status']}\n\n"
                f"Local   : {conn['local']}\n"
                f"Remote  : {conn['remote']}"
            )

            QMessageBox.information(
                self,
                "Connection Details",
                info
            )
        elif action == copy_ip:
            QApplication.clipboard().setText(conn["remote"])

            QMessageBox.information(
                self,
                "Copied",
                "Remote address copied to clipboard."
            )

        elif action == allow:
            exe = conn.get("exe")
            if not exe:
                QMessageBox.warning(
                    self,
                    "Unavailable",
                    "Executable path not available."
                )
                return

            success, out, err = allow_application(exe)
            if success:
                add_process_rule(conn["process"],conn["exe"],"ALLOW")
                add_log(conn["process"], "ALLOW")
                QMessageBox.information(
                    self,
                    "Firewall Updated",
                    f"{conn['process']} is now allowed."
                )

            elif out == "ALREADY_ALLOWED":

                QMessageBox.information(
                    self,
                    "Already Allowed",
                    f"{conn['process']} is already allowed.")    
            else:
                QMessageBox.critical(
                    self,
                    "Firewall Error",
                    err
                )

            self.load_connections()

        elif action == block:
            exe = conn.get("exe")
            if not exe:
                QMessageBox.warning(
                    self,
                    "Unavailable",
                    "Executable path not available."
                )
                return

            success, out, err = block_application(exe)
            if success:
                add_process_rule(conn["process"],conn["exe"],"BLOCK")
                add_log(conn["process"], "BLOCK")
                QMessageBox.warning(
                    self,
                    "Firewall Updated",
                    f"{conn['process']} has been blocked."
                )

            elif out == "ALREADY_BLOCKED":

                QMessageBox.information(
        self,
        "Already Blocked",
        f"{conn['process']} is already blocked."
    )    
            else:
                QMessageBox.critical(
                    self,
                    "Firewall Error",
                    err
                )

            self.load_connections()

        elif action == terminate:
            QMessageBox.information(
                self,
                "Coming Soon",
                "Terminate Process will be implemented later."
            )
            self.load_connections() 

    def copy_hash(self):

     QApplication.clipboard().setText(
        self.selected_hash
    )

     self.button_feedback(
        self.copy_hash_btn,
        "📋 Copy Hash"
    )

    def copy_remote(self):

     QApplication.clipboard().setText(
        self.selected_connection["remote"]
    )

     self.button_feedback(
        self.copy_remote_btn,
        "📋 Copy Remote"
    )

    def copy_path(self):

     QApplication.clipboard().setText(
        self.selected_connection["exe"]
    )

     self.button_feedback(
        self.copy_path_btn,
        "📋 Copy Path"
    )

    def copy_all(self):

     QApplication.clipboard().setText(
        self.details.text()
    )

     self.button_feedback(
        self.copy_all_btn,
        "📋 Copy All"
    )



    def open_file(self):

     path = self.selected_connection["exe"]

     if path:
      os.startfile(path)

    def open_folder(self):

     path = self.selected_connection["exe"]

     if path:

       subprocess.Popen(
            f'explorer /select,"{path}"'
        )

    def button_feedback(self, button, original_text):
     button.setText("✓ Copied")

     QTimer.singleShot(
        1500,
        lambda: button.setText(original_text)
    )

    def show_vt_api_warning(self):
     msg = QMessageBox(self)

     msg.setWindowTitle("VirusTotal API Required")
     msg.setIcon(QMessageBox.Information)

     msg.setText(
        "Ozone Layer's built-in security engine performs offline analysis.\n\n"
        "For additional cloud-based verification using VirusTotal's global "
        "malware database, a personal VirusTotal API key is required.\n\n"
        "Configure your API key in:\n\n"
        "Settings → VirusTotal"
    )

     open_settings = msg.addButton(
        "Open Settings",
        QMessageBox.AcceptRole
    )

     msg.addButton(
        "Cancel",
        QMessageBox.RejectRole
    )

     msg.exec()

     if msg.clickedButton() == open_settings:
        QMessageBox.information(
            self,
            "Coming Soon",
            "Settings page will be available soon."
        )

    def scan_virustotal(self):

     if not self.selected_hash:
        QMessageBox.warning(
            self,
            "No File Selected",
            "Unable to determine the file hash."
        )
        return

     result = check_hash(self.selected_hash)

    # Handle errors first
     if result.get("error") == "NO_API_KEY":
        self.show_vt_api_warning()
        return

     if result.get("error"):
        QMessageBox.warning(
            self,
            "VirusTotal Error",
            result["error"]
        )
        return

    # Create summary for UI
     summary = summarize_result(result)

    # Temporary popup (will be replaced by VirusTotal page later)
     self.show_vt_result(summary)

    # Save complete result to history
     record = create_scan_record(
        self.selected_connection,
        result
    )

     add_scan(record)

     

    def show_vt_result(self, summary):

     malicious = summary["malicious"]
     suspicious = summary["suspicious"]
     harmless = summary["harmless"]
     undetected = summary["undetected"]
     checked = summary["checked"]

     QMessageBox.information(
        self,
        "VirusTotal Scan Result",
        f"""
Checked     : {checked}

Malicious   : {malicious}
Suspicious  : {suspicious}
Harmless    : {harmless}
Undetected  : {undetected}
""".strip()
    )
     
    def hide_details(self):
     self.details_visible = False

     self.table.clearSelection()
     self.table.setCurrentCell(-1, -1)

     self.details_frame.hide()

     self.details.setText("Select a connection to view details.")

