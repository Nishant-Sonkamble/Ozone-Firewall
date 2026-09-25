import json
import os
from pathlib import Path
from paths import SETTINGS_FILE

STYLE_DIR = Path(__file__).parent / "styles"

DEFAULT_SETTINGS = {
    "virustotal_api_key": "",
    "theme": "ozone"
}


def load_settings():
    """Load settings from JSON file."""

    if not os.path.exists(SETTINGS_FILE):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()

    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)

    except Exception:
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()


def save_settings(settings):
    """Save settings to JSON file."""

    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)


def get_api_key():
    """Return VirusTotal API key."""

    settings = load_settings()

    return settings.get("virustotal_api_key", "")


def set_api_key(api_key):
    """Save VirusTotal API key."""

    settings = load_settings()

    settings["virustotal_api_key"] = api_key.strip()

    save_settings(settings)

def get_theme():
    """Return selected application theme."""

    settings = load_settings()

    return settings.get("theme", "ozone")


def set_theme(theme):
    """Save selected application theme."""

    settings = load_settings()

    settings["theme"] = theme

    save_settings(settings)

def load_stylesheet(theme):

    stylesheet = ""

    common = STYLE_DIR / "common.qss"

    theme_file = STYLE_DIR / f"{theme}.qss"

    if common.exists():

        stylesheet += common.read_text(
            encoding="utf-8"
        )

    if theme_file.exists():

        stylesheet += "\n"

        stylesheet += theme_file.read_text(
            encoding="utf-8"
        )

    return stylesheet