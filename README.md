
````markdown
# 🛡️ Ozone Firewall

Ozone Firewall is a Windows desktop firewall and network security application built with Python and PySide6.

It monitors active network connections, analyzes potential threats, manages Windows Firewall rules, records security activity, and provides additional file analysis through VirusTotal.

## ✨ Features

- 🌐 **Live Network Monitoring**
  - Monitor active TCP/UDP connections
  - View process, PID, protocol, local/remote addresses and connection status

- 🧠 **Threat Analysis**
  - Analyze connections using multiple security factors
  - Process risk analysis
  - IP reputation analysis
  - Port analysis
  - Overall risk scoring

- 🛡️ **Firewall Rule Management**
  - Allow applications
  - Block applications
  - Remove application rules
  - Integrates with Windows Firewall

- 🔔 **Threat Notifications**
  - Desktop notifications for high-risk and critical connections

- 📋 **Security Logs**
  - Records firewall actions and security events
  - View activity directly from the application

- 📊 **Statistics**
  - View network and security statistics

- 🔍 **VirusTotal Integration**
  - Calculate file SHA-256 hashes
  - Search files through VirusTotal
  - View antivirus engine results
  - Maintain local scan history

- 💾 **Local Security Data**
  - Local rules
  - Whitelist/blacklist information
  - Reputation data
  - Scan history

- 🎨 **Multiple Themes**
  - Ozone theme
  - Dark theme
  - Light theme

## 🖥️ Requirements

- Windows
- Python 3.x
- Internet connection for VirusTotal features
- Administrator privileges for modifying Windows Firewall rules

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Nishant-Sonkamble/Ozone-Firewall.git
cd Ozone-Firewall
````

### 2. Install dependencies

You can use a virtual environment (recommended):

```bash
py -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

Then install the dependencies:

```bash
pip install -r requirements.txt
```

If you don't want to use a virtual environment, you can install the dependencies directly:

```bash
py -m pip install -r requirements.txt
```

### 3. Run Ozone Firewall

```bash
py main.py
```

## ⚠️ Administrator Privileges

Ozone Firewall can monitor network connections without administrator privileges, but actions that modify Windows Firewall rules require administrator privileges.

If Windows Firewall reports that administrator privileges are required:

1. Close Ozone Firewall.
2. Close Visual Studio Code.
3. Right-click **Visual Studio Code**.
4. Select **Run as administrator**.
5. Open the Ozone Firewall project again.
6. Start Ozone Firewall using the same Python setup you normally use.
7. Try the firewall action again.

You do not need to create a new virtual environment or reinstall dependencies.

## 🔑 VirusTotal Setup

VirusTotal scanning requires a personal VirusTotal API key.

After starting Ozone Firewall:

**Settings → VirusTotal**

Enter your API key and save it.

The API key is stored locally in `settings.json`, which is excluded from Git.

## 📁 Project Structure

```text
Ozone-Firewall/
│
├── main.py
├── firewall_engine.py
├── windows_firewall.py
├── network_monitor.py
├── threat_analyzer.py
├── threat_engine.py
├── trust_engine.py
├── ip_reputation.py
├── hash_reputation.py
├── notification_manager.py
├── virustotal.py
│
├── ui/
│   ├── main_window.py
│   ├── dashboard.py
│   ├── ozone_dashboard.py
│   ├── connections.py
│   ├── rules.py
│   ├── logs.py
│   ├── statistics.py
│   ├── settings.py
│   └── virustotal_page.py
│
├── assets/
├── styles/
├── requirements.txt
├── blacklist.json
├── whitelist.json
└── ip_database.json
```

## 🔐 Privacy & Local Data

Ozone Firewall stores application-specific data locally.

The following files are intentionally excluded from Git:

* `settings.json`
* `logs.json`
* `history.json`
* `vt_cache.json`
* `vt_history.json`

These may contain machine-specific information, application settings, or scan history.

## 🧪 Project Status

Ozone Firewall is an actively developed project.

The current version focuses on:

* Network monitoring
* Threat analysis
* Windows Firewall management
* Security logging
* VirusTotal integration
* Desktop security notifications

## 🛠️ Technologies

* **Python**
* **PySide6**
* **psutil**
* **Requests**
* **Winotify**
* **Tabulate**
* **Windows Firewall**
* **VirusTotal API**

## 📌 Notes

Ozone Firewall is designed for Windows environments because its firewall management functionality relies on Windows Firewall.

Use administrator privileges only when required by Windows Firewall operations.

## 👨‍💻 Author

**Nishant Sonkamble**

GitHub:
[https://github.com/Nishant-Sonkamble](https://github.com/Nishant-Sonkamble)



⭐ If you find the project interesting, consider giving it a star.

