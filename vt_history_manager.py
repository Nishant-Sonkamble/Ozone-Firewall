import json
import os
from datetime import datetime
VT_HISTORY_FILE = "vt_history.json"

MAX_SCANS = 1000

def load_scans():
    if not os.path.exists(VT_HISTORY_FILE):
        save_scans([])
        return []

    try:
        with open(VT_HISTORY_FILE, "r") as f:
            return json.load(f)

    except Exception:
        save_scans([])
        return []

def create_scan_record(connection, vt_result):
    attributes = vt_result["data"]["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        status = "Malicious"
    elif suspicious > 0:
        status = "Suspicious"
    else:
        status = "Clean"

    return {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "process": connection.get("process", ""),
        "pid": connection.get("pid", ""),
        "path": connection.get("exe", ""),
        "hash": connection.get("hash", ""),

        "status": status,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),

    "file_type": attributes.get("type_description", "Unknown"),
    "file_size": attributes.get("size", 0),
    "reputation": attributes.get("reputation", 0),
    "last_analysis_date": attributes.get("last_analysis_date"),
    "community_votes": attributes.get("total_votes", {}),
        "result": vt_result
    }

def save_scans(scans):
    with open(VT_HISTORY_FILE, "w") as f:
        json.dump(scans, f, indent=4)

def add_scan(scan):

    scans = load_scans()

    scans.insert(0, scan)

    scans = scans[:MAX_SCANS]

    save_scans(scans)

def delete_scan(index):

    scans = load_scans()

    if 0 <= index < len(scans):

        scans.pop(index)

        with open(VT_HISTORY_FILE, "w") as file:
            json.dump(scans, file, indent=4)
def save_scan(scan):

    scans = load_scans()

    scans.append(scan)

    save_scans(scans)
    
def clear_history():

    with open(VT_HISTORY_FILE, "w") as file:
        json.dump([], file, indent=4)
def clear_scans():
    save_scans([])