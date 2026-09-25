
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QGroupBox,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QButtonGroup,
    QHBoxLayout
)
from settings_manager import (
    load_settings,
    save_settings,
    get_theme,
    set_theme,
    load_stylesheet
)
from PySide6.QtWidgets import QApplication
class SettingsPage(QWidget):
    def __init__(self,main_window):
        super().__init__()
        self.main_window=main_window
        main_layout = QVBoxLayout(self)

        # ==========================
        # Appearance
        # ==========================
        appearance_box = QGroupBox("Appearance")
        appearance_layout = QVBoxLayout()

        self.ozone_theme = QRadioButton("Ozone Layer")
        self.dark_theme = QRadioButton("Dark")
        self.light_theme = QRadioButton("Light")

        self.theme_group = QButtonGroup(self)
        self.theme_group.addButton(self.ozone_theme)
        self.theme_group.addButton(self.dark_theme)
        self.theme_group.addButton(self.light_theme)

        self.ozone_theme.setChecked(True)

        appearance_layout.addWidget(self.ozone_theme)
        appearance_layout.addWidget(self.dark_theme)
        appearance_layout.addWidget(self.light_theme)

        

        appearance_box.setLayout(appearance_layout)

        # ==========================
        # VirusTotal
        # ==========================
        vt_box = QGroupBox("VirusTotal")
        vt_layout = QVBoxLayout()

        vt_layout.addWidget(QLabel("API Key"))

        self.api_key = QLineEdit()
        self.api_key.setPlaceholderText("Enter VirusTotal API Key")
        self.api_key.setEchoMode(QLineEdit.Password)

        vt_layout.addWidget(self.api_key)

        button_layout = QHBoxLayout()

        self.show_btn = QPushButton("Show")
        self.save_btn = QPushButton("Save API Key")

        button_layout.addWidget(self.show_btn)
        button_layout.addWidget(self.save_btn)

        vt_layout.addLayout(button_layout)

        self.status = QLabel("Status : Not Configured")

        vt_layout.addWidget(self.status)

        vt_box.setLayout(vt_layout)

        # ==========================

        main_layout.addWidget(appearance_box)
        main_layout.addWidget(vt_box)
        main_layout.addStretch()

        self.load_saved_settings()
        self.save_btn.clicked.connect(self.save_api_key)
        self.show_btn.clicked.connect(self.toggle_api_visibility)
        self.ozone_theme.toggled.connect(self.change_theme)
        self.dark_theme.toggled.connect(self.change_theme)
        self.light_theme.toggled.connect(self.change_theme)
        

        self.api_visible = False

    def load_saved_settings(self):
     settings = load_settings()

     theme = get_theme()

     if theme == "ozone":

      self.ozone_theme.setChecked(True)

     elif theme == "dark":

      self.dark_theme.setChecked(True)

     else:

      self.light_theme.setChecked(True)

     api_key = settings.get("virustotal_api_key", "")

     self.api_key.setText(api_key)

     if api_key:
        self.status.setText("Status : Configured")
     else:
        self.status.setText("Status : Not Configured")    

    def save_api_key(self):
     settings = load_settings()

     settings["virustotal_api_key"] = self.api_key.text().strip()

     save_settings(settings)

     api_key = self.api_key.text().strip()

     if api_key:
      self.status.setText("Status : Configured")
     else:
      self.status.setText("Status : Not Configured")

    def toggle_api_visibility(self):
     if self.api_visible:
        self.api_key.setEchoMode(QLineEdit.Password)
        self.show_btn.setText("Show")
     else:
        self.api_key.setEchoMode(QLineEdit.Normal)
        self.show_btn.setText("Hide")

     self.api_visible = not self.api_visible

    def change_theme(self):

     if self.ozone_theme.isChecked():

       theme = "ozone"

     elif self.dark_theme.isChecked():

        theme = "dark"

     else:

        theme = "light"

     set_theme(theme)

     QApplication.instance().setStyleSheet(

        load_stylesheet(theme)

    )