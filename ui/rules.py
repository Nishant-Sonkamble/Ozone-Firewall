from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHBoxLayout,
    QHeaderView,
    QAbstractItemView,
    QMessageBox,
)

from firewall_engine import get_process_rule
from logger import add_log

from windows_firewall import (
    allow_application,
    block_application
)

from firewall_engine import (
    load_rules,
    update_process_rule,
    delete_process_rule,
)


class RulesPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        title = QLabel("🛡 Firewall Rules")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Empty-state message
        self.empty_label = QLabel(
            "🛡 No firewall rules configured yet.\n"
            "Rules you create will appear here."
        )

        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)

        layout.addWidget(self.empty_label)

        self.table = QTableWidget()

        self.table.setColumnCount(3)

        self.table.setHorizontalHeaderLabels([
            "Type",
            "Name",
            "Action"
        ])

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.table.setAlternatingRowColors(True)

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        layout.addWidget(self.table)

        buttons = QHBoxLayout()

        self.allow_btn = QPushButton("🟢 Allow")
        self.allow_btn.setObjectName("allowButton")

        self.block_btn = QPushButton("🔴 Block")
        self.block_btn.setObjectName("blockButton")

        self.delete_btn = QPushButton("🗑 Remove Rule")
        self.delete_btn.setObjectName("deleteButton")

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setObjectName("refreshButton")

        buttons.addWidget(self.allow_btn)
        buttons.addWidget(self.block_btn)
        buttons.addWidget(self.delete_btn)

        buttons.addStretch()

        buttons.addWidget(self.refresh_btn)

        layout.addLayout(buttons)

        self.allow_btn.clicked.connect(
            self.allow_rule
        )

        self.block_btn.clicked.connect(
            self.block_rule
        )

        self.delete_btn.clicked.connect(
            self.delete_rule
        )

        self.refresh_btn.clicked.connect(
            self.populate_table
        )

        self.populate_table()


    def populate_table(self):

        rules = load_rules()

        # Empty state
        if not rules:

            self.table.setRowCount(0)
            self.empty_label.show()

            return

        # Rules exist
        self.empty_label.hide()

        self.table.setRowCount(len(rules))

        for row, rule in enumerate(rules):

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(
                    rule["type"]
                )
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    rule["name"]
                )
            )

            action_item = QTableWidgetItem(
                rule["action"]
            )

            if rule["action"] == "BLOCK":

                action_item.setBackground(
                    Qt.red
                )

            else:

                action_item.setBackground(
                    Qt.darkGreen
                )

            self.table.setItem(
                row,
                2,
                action_item
            )


    def allow_rule(self):

        row = self.table.currentRow()

        if row < 0:

            QMessageBox.information(
                self,
                "No Selection",
                "Please select a rule."
            )

            return

        process = self.table.item(
            row,
            1
        ).text()

        rule = get_process_rule(process)

        if not rule:
            return

        success, out, err = allow_application(
            rule["path"]
        )

        if success:

            update_process_rule(
                process,
                "ALLOW"
            )

            add_log(
                process,
                "ALLOW"
            )

            action_item = self.table.item(
                row,
                2
            )

            action_item.setText("ALLOW")

            action_item.setBackground(
                Qt.darkGreen
            )

            QMessageBox.information(
                self,
                "🛡 Rule Applied",
                f"{process} is now allowed through Windows Firewall."
            )

            self.populate_table()

        elif out == "ALREADY_ALLOWED":

            QMessageBox.information(
                self,
                "Already Allowed",
                f"{process} is already allowed."
            )

        else:

            QMessageBox.critical(
                self,
                "Firewall Error",
                err
            )


    def block_rule(self):

        row = self.table.currentRow()

        if row < 0:

            QMessageBox.information(
                self,
                "No Selection",
                "Please select a rule."
            )

            return

        process = self.table.item(
            row,
            1
        ).text()

        rule = get_process_rule(process)

        if not rule:
            return

        success, out, err = block_application(
            rule["path"]
        )

        if success:

            update_process_rule(
                process,
                "BLOCK"
            )

            add_log(
                process,
                "BLOCK"
            )

            action_item = self.table.item(
                row,
                2
            )

            action_item.setText("BLOCK")

            action_item.setBackground(
                Qt.red
            )

            QMessageBox.warning(
                self,
                "🚫 Rule Applied",
                f"{process} has been blocked through Windows Firewall."
            )

            self.populate_table()

        elif out == "ALREADY_BLOCKED":

            QMessageBox.information(
                self,
                "Already Blocked",
                f"{process} is already blocked."
            )

        else:

            QMessageBox.critical(
                self,
                "Firewall Error",
                err
            )


    def delete_rule(self):

        row = self.table.currentRow()

        if row < 0:

            QMessageBox.information(
                self,
                "No Selection",
                "Please select a rule."
            )

            return

        process = self.table.item(
            row,
            1
        ).text()

        reply = QMessageBox.question(
            self,
            "Delete Rule",
            f"Remove the rule for '{process}'? Ozone will forget this rule",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:

            rule = get_process_rule(process)

            if rule and "path" in rule:

                success, out, err = allow_application(
                    rule["path"]
                )

                if not success and out != "ALREADY_ALLOWED":

                    QMessageBox.critical(
                        self,
                        "Firewall Error",
                        err
                    )

                    return

            delete_process_rule(process)

            add_log(
                process,
                "DELETE"
            )

            QMessageBox.information(
                self,
                "🗑 Rule Deleted",
                f"{process} has been removed from Ozone and Windows Firewall."
            )

            self.populate_table()