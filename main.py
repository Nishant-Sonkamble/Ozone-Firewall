import sys

from PySide6.QtWidgets import QApplication

from settings_manager import get_theme, load_stylesheet
from ui.main_window import MainWindow



def main():

    app = QApplication(sys.argv)
    
    app.setStyleSheet("""
QMainWindow{
    background-color:#202124;
}

QWidget{
    background-color:#202124;
    color:white;
    font-size:14px;
}

QListWidget{
    background:#2d2d30;
    border:none;
}

QListWidget::item{
    padding:12px;
}

QListWidget::item:selected{
    background:#0078d7;
    color:white;
}
""")
    
    window = MainWindow()
    from theme_manager import ThemeManager

    app.setStyleSheet(
    load_stylesheet(
        get_theme()
    )
)

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()