import ctypes
import subprocess
from hash_reputation import sha256_string

RULE_PREFIX = "Ozone Firewall - "

def get_rule_name(app_path):
    return RULE_PREFIX + sha256_string(app_path)[:12]

def is_admin():
    """Return True if the application is running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def block_application(app_path):
    """
    Create an outbound firewall rule blocking an application.
    """
    if not is_admin():
     return (
        False,
        "",
        "Administrator privileges are required."
    )

    if rule_exists(app_path):
     return (
        False,
        "ALREADY_BLOCKED",
        ""
    )

    rule_name = get_rule_name(app_path)

    command = [
        "powershell",
        "-Command",
        f'New-NetFirewallRule '
        f'-DisplayName "{rule_name}" '
        f'-Direction Outbound '
        f'-Program "{app_path}" '
        f'-Action Block'
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode == 0, result.stdout, result.stderr


def allow_application(app_path):
    """
    Remove Sentinel firewall rule for an application.
    """
    if not is_admin():
     return (
        False,
        "",
        "Administrator privileges are required."
    )

    if not rule_exists(app_path):
     return (
        False,
        "ALREADY_ALLOWED",
        ""
    )
    rule_name = get_rule_name(app_path)

    command = [
        "powershell",
        "-Command",
        f'Remove-NetFirewallRule '
        f'-DisplayName "{rule_name}"'
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode == 0, result.stdout, result.stderr


def rule_exists(app_path):
    """
    Check whether Sentinel rule already exists.
    """

    rule_name = get_rule_name(app_path)

    command = [
        "powershell",
        "-Command",
        f'Get-NetFirewallRule '
        f'-DisplayName "{rule_name}"'
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode == 0