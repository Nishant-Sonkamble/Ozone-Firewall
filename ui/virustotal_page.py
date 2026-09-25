from PySide6.QtWidgets import (
    QApplication,
    QMenu,
    QMessageBox,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLineEdit,
    QHeaderView,
    QFrame,
    QFormLayout,
    
)
import os
import subprocess


from hash_reputation import sha256_file
from virustotal import vt_lookup
from vt_history_manager import save_scan
from vt_history_manager import create_scan_record
from PySide6.QtWidgets import QHeaderView
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from vt_history_manager import (
    load_scans,
    delete_scan,
    clear_history
)
def format_file_size(size):
    
         if size is None:
            return "-"
    
         units = ["B", "KB", "MB", "GB", "TB"]
    
         size = float(size)
    
         for unit in units:
    
            if size < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.2f} {unit}"
    
            size /= 1024

class NumericTableWidgetItem(QTableWidgetItem):

    def __lt__(self, other):

        return (
            self.data(Qt.UserRole)
            <
            other.data(Qt.UserRole)
        )
    
class VirusTotalPage(QWidget):

    def __init__(self):
        super().__init__()

        self.scans = []

        self.build_ui()

        self.load_history()

    def build_ui(self):

     main_layout = QHBoxLayout(self)

     left_frame = QFrame()
     left_layout = QVBoxLayout(left_frame)
     title = QLabel("VirusTotal")

     self.search_box = QLineEdit()
     self.search_box.setPlaceholderText(
    "Search process..."
)   
     self.search_box.textChanged.connect(self.filter_history)
     self.history_table = QTableWidget()

     self.history_table.setColumnCount(4)

     self.history_table.setHorizontalHeaderLabels([
    "Process",
    "Status",
    "Threat Detection",
    "Checked"
])

     self.history_table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

     self.history_table.setSelectionBehavior(
    QTableWidget.SelectRows
)

     self.history_table.setEditTriggers(
    QTableWidget.NoEditTriggers
)
     self.history_table.itemSelectionChanged.connect(
    self.on_scan_selected
)
     self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)

     self.history_table.customContextMenuRequested.connect(
    self.show_context_menu
)
     self.history_table.setSortingEnabled(True)
     left_layout.addWidget(title)
     left_layout.addWidget(self.search_box)
     left_layout.addWidget(self.history_table)
     
     right_frame = QFrame()
     right_layout = QVBoxLayout(right_frame)

     details_title = QLabel("Scan Details")

     right_layout.addWidget(details_title)

     form = QFormLayout()

     self.lbl_process = QLabel("-")
     self.lbl_hash = QLabel("-")
     self.lbl_status = QLabel("-")
     self.lbl_detection = QLabel("-")
     self.lbl_checked = QLabel("-")
     self.lbl_size = QLabel("-")
     self.lbl_type = QLabel("-")
     self.lbl_votes = QLabel("-")

     form.addRow("Process", self.lbl_process)
     form.addRow("SHA-256", self.lbl_hash)
     form.addRow("Status", self.lbl_status)
     form.addRow("Detection", self.lbl_detection)
     form.addRow("Checked", self.lbl_checked)
     form.addRow("File Size", self.lbl_size)
     form.addRow("File Type", self.lbl_type)
     form.addRow("Community Votes", self.lbl_votes)

     right_layout.addLayout(form)

     self.engine_table = QTableWidget()

     self.engine_table.setColumnCount(3)

     self.engine_table.setHorizontalHeaderLabels([
    "Engine",
    "Category",
    "Result"
])

     self.engine_table.horizontalHeader().setSectionResizeMode(
    QHeaderView.Stretch
)

     right_layout.addWidget(QLabel("Engine Results"))

     right_layout.addWidget(self.engine_table)

     main_layout.addWidget(left_frame, 3)

     main_layout.addWidget(right_frame, 4)

    def load_history(self):
     self.scans = load_scans()

     print(f"Loaded {len(self.scans)} scans.")

     self.populate_table()

    def filter_history(self):

     text = self.search_box.text().lower().strip()

     for row in range(self.history_table.rowCount()):

        process = self.history_table.item(row, 0).text().lower()

        status = self.history_table.item(row, 1).text().lower()

        visible = (
            text in process or
            text in status
        )

        self.history_table.setRowHidden(row, not visible)

    def on_scan_selected(self):

     row = self.history_table.currentRow()

     if row < 0:
        return

     record = self.scans[row]

     self.show_scan_details(record)

     self.populate_engines(record)

    def show_scan_details(self, record):

     result = record.get("result", {})

     attributes = result.get("data", {}).get("attributes", {})

     stats = attributes.get("last_analysis_stats", {})

     total = (
        stats.get("malicious", 0)
        + stats.get("suspicious", 0)
        + stats.get("harmless", 0)
        + stats.get("undetected", 0)
    )

     detection = f'{stats.get("malicious",0)} / {total}'

     self.lbl_process.setText(
        record.get("process", "-")
    )

     self.lbl_hash.setText(
        record.get("hash", "-")
    )

     self.lbl_status.setText(
        record.get("status", "-")
    )

     self.lbl_detection.setText(
        detection
    )

     self.lbl_checked.setText(
        record.get("scan_time", "-")
    )

     size = attributes.get("size")

     if size is None:
        self.lbl_size.setText("-")
     else:
        self.lbl_size.setText(
        format_file_size(size)
)


     self.lbl_type.setText(
        attributes.get(
            "type_description",
            "-"
        )
    )

     votes = attributes.get(
        "total_votes",
        {}
    )

     harmless_votes = votes.get("harmless", 0)
     malicious_votes = votes.get("malicious", 0)

     self.lbl_votes.setText(
        f"👍 {harmless_votes}   👎 {malicious_votes}"
    )

    def show_context_menu(self, position):

     item = self.history_table.itemAt(position)

     if item is None:
      return

     row = item.row()

     self.history_table.selectRow(row)
     record = self.scans[row]
     if row < 0:
        return

     menu = QMenu(self)

     rescan_action = menu.addAction("🔄 Rescan")
     copy_hash_action = menu.addAction("📋 Copy SHA-256")
     open_action = menu.addAction("📂 Open File Location")

     menu.addSeparator()

     delete_action = menu.addAction("🗑 Delete Scan")
     clear_action = menu.addAction("🗑 Delete All History")

     action = menu.exec(
        self.history_table.viewport().mapToGlobal(position)
    )

     if action == rescan_action:

      self.rescan_file(record)

     elif action == copy_hash_action:

      QApplication.clipboard().setText(
        record.get("hash", "")
    )
      QMessageBox.information(
    self,
    "Copied",
    "SHA-256 copied to clipboard."
)
     elif action == open_action:

      path = record.get("path", "")

      if path and os.path.exists(path):
          subprocess.Popen(
            ["explorer", "/select,", path]
        )    
      

     elif action == delete_action:

      reply = QMessageBox.question(
        self,
        "Delete Scan",
        "Delete this scan history?",
        QMessageBox.Yes | QMessageBox.No
    )

      if reply == QMessageBox.Yes:

        delete_scan(row)

        self.load_history()

     elif action == clear_action:

      reply = QMessageBox.question(
        self,
        "Delete All History",
        "Are you sure you want to delete all VirusTotal scan history?\n\nThis action cannot be undone.",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
    )

      if reply == QMessageBox.Yes:

        clear_history()

        self.load_history()

        QMessageBox.information(
            self,
            "History Cleared",
            "All VirusTotal scan history has been deleted."
        )

    def populate_engines(self, record):

     self.engine_table.setRowCount(0)

     result = record.get("result", {})

     attributes = result.get("data", {}).get("attributes", {})

     engines = attributes.get(
        "last_analysis_results",
        {}
    )

     for engine_name, engine in engines.items():

        row = self.engine_table.rowCount()

        self.engine_table.insertRow(row)

        self.engine_table.setItem(
            row,
            0,
            QTableWidgetItem(engine_name)
        )

        self.engine_table.setItem(
            row,
            1,
            QTableWidgetItem(
                engine.get("category", "-")
            )
        )

        self.engine_table.setItem(
            row,
            2,
            QTableWidgetItem(
                engine.get("result") or "-"
            )
        )

        category = engine.get("category", "-")

        category_item = QTableWidgetItem(category)

        if category == "malicious":
         category_item.setForeground(Qt.red)

        elif category == "suspicious":
         category_item.setForeground(QColor(255, 140, 0))    # Orange

        elif category == "undetected":
         category_item.setForeground(Qt.darkGreen)

        else:
         category_item.setForeground(Qt.gray)

        self.engine_table.setItem(row, 1, category_item)

    def populate_table(self):
     self.history_table.setSortingEnabled(False)
     if not self.scans:
      self.history_table.setRowCount(0)
      return
     self.history_table.setRowCount(0)

     for record in self.scans:

        row = self.history_table.rowCount()
        self.history_table.insertRow(row)

        # Process
        self.history_table.setItem(
            row,
            0,
            QTableWidgetItem(record.get("process", "Unknown"))
        )

        # Status
        status = record.get("status", "Unknown")

        if status == "Clean":
         status_text = "🟢 Clean"

        elif status == "Suspicious":
         status_text = "🟡 Suspicious"

        elif status == "Malicious":
         status_text = "🔴 Malicious"

        else:
         status_text = status

        status_item = QTableWidgetItem(status_text)
        status_item.setTextAlignment(Qt.AlignCenter)

        self.history_table.setItem(
    row,
    1,
    status_item
)

        # Detection
        result = record.get("result", {})
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)

        total = (
            stats.get("malicious", 0)
            + stats.get("suspicious", 0)
            + stats.get("harmless", 0)
            + stats.get("undetected", 0)
        )

        detection = f"{malicious} / {total}"
        detection_item = NumericTableWidgetItem(detection)

        detection_item.setData(
    Qt.UserRole,
    malicious
)

        detection_item.setTextAlignment(Qt.AlignCenter)

        self.history_table.setItem(
    row,
    2,
    detection_item
)
        

        # Scan Time
        checked_item = QTableWidgetItem(
        record.get("scan_time", "-")
)
        checked_item.setTextAlignment(Qt.AlignCenter)

        self.history_table.setItem(
    row,
    3,
    checked_item
)
     self.history_table.setSortingEnabled(True)

    def rescan_file(self, record):

     path = record.get("path", "")

     if not path:
        QMessageBox.warning(
            self,
            "Missing Path",
            "The original file path is not available."
        )
        return

     if not os.path.exists(path):
        QMessageBox.warning(
            self,
            "File Not Found",
            "The file no longer exists."
        )
        return

     try:
        connection = {
            "process": record.get("process", ""),
            "pid": record.get("pid", ""),
            "exe": path
        }

        connection["hash"] = sha256_file(path)

        vt_result = vt_lookup(connection["hash"])

        new_record = create_scan_record(connection, vt_result)

        save_scan(new_record)

        self.load_history()

        QMessageBox.information(
            self,
            "Rescan Complete",
            "VirusTotal scan completed successfully."
        )

     except Exception as e:
        QMessageBox.critical(
            self,
            "Scan Failed",
            str(e)
        )
