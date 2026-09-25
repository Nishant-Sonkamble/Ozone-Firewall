from pathlib import Path

STYLE_DIR = Path(__file__).parent / "styles"


class ThemeManager:

    @staticmethod
    def load_theme(name):

        common = STYLE_DIR / "common.qss"

        theme = STYLE_DIR / f"{name}.qss"

        stylesheet = ""

        with open(common, encoding="utf-8") as file:

            stylesheet += file.read()

        with open(theme, encoding="utf-8") as file:

            stylesheet += "\n"
            stylesheet += file.read()

        return stylesheet