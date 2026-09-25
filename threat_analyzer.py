import json
import os
import ipaddress
from ip_reputation import check_ip
from paths import BLACKLIST_FILE, WHITELIST_FILE


def load_json(filename):
    if not os.path.exists(filename):
        return {}

    with open(filename, "r") as file:
        return json.load(file)


def analyze_process(process, exe_path=""):
    whitelist = load_json(WHITELIST_FILE)
    blacklist = load_json(BLACKLIST_FILE)

    process = process.lower()
    trusted, publisher = is_trusted_process(exe_path)

    if trusted:
     return {
        "score": 0,
        "level": "LOW",
        "reason": f"Digitally signed by {publisher}"
    }
    if process in [p.lower() for p in blacklist.get("processes", [])]:
        return {
            "score": 70,
            "level": "CRITICAL",
            "reason": "Blacklisted process."
        }

    if process in [p.lower() for p in whitelist.get("processes", [])]:
        return {
            "score": 0,
            "level": "LOW",
            "reason": "Trusted process."
        }

    return {
        "score": 5,
        "level": "LOW",
        "reason": "Unknown process."
    }


def analyze_port(port):
    blacklist = load_json(BLACKLIST_FILE)

    if port in blacklist.get("ports", []):
        return {
            "score": 25,
            "level": "HIGH",
            "reason": "Suspicious port."
        }

    if port in [80, 443]:
        return {
            "score": 0,
            "level": "LOW",
            "reason": "Standard web port."
        }

    return {
        "score": 5,
        "level": "LOW",
        "reason": "Uncommon port."
    }


def analyze_ip(ip):

    score = 0
    reasons = []

    blacklist = load_json(BLACKLIST_FILE)

    # ---------------- Validate ----------------

    try:
        ip_obj = ipaddress.ip_address(ip)

    except ValueError:

        return {
            "score": 40,
            "level": "HIGH",
            "reason": "Invalid IP address."
        }

    # ---------------- Safe Addresses ----------------

    if ip_obj.is_loopback:

        return {
            "score": 0,
            "level": "LOW",
            "reason": "Loopback address."
        }

    if ip_obj.is_private:

        return {
            "score": 0,
            "level": "LOW",
            "reason": "Private network."
        }

    # ---------------- User Blacklist ----------------

    if ip in blacklist.get("ips", []):

        score += 60
        reasons.append("User blacklisted IP")

    # ---------------- Reputation Database ----------------

    rep = check_ip(ip)

    if rep:

        score += rep.get("score", 0)

        if rep.get("reason"):
            reasons.append(rep["reason"])

    # ---------------- Unknown Public IP ----------------

    if score == 0:

        score = 0
        reasons.append("Unknown public IP")

    # ---------------- Clamp ----------------

    score = min(score, 100)

    return {

        "score": score,

        "level": get_risk_level(score),

        "reason": ", ".join(reasons)
    }

    

def get_risk_level(score):

    if score >= 70:
        return "CRITICAL"

    if score >= 40:
        return "HIGH"

    if score >= 15:
        return "MEDIUM"

    return "LOW"

from trust_engine import is_trusted_process

def analyze_connection(conn):
    process_name = conn.get("process", "Unknown")
    process_result = analyze_process(
    process_name,
    conn.get("exe", "")
)

    status = conn.get("status", "").upper()
    remote = conn.get("remote", "")
    
    
    # Default values
    ip_result = {
        "score": 0,
        "level": "LOW",
        "reason": "Not analyzed."
    }

    port_result = {
        "score": 0,
        "level": "LOW",
        "reason": "Not analyzed."
    }

    # -----------------------------
    # LISTEN sockets
    # -----------------------------
    if status == "LISTEN":

        ip_result = {
            "score": 0,
            "level": "LOW",
            "reason": "Listening socket (no remote connection)."
        }

        port_result = {
            "score": 0,
            "level": "LOW",
            "reason": "Waiting for incoming connections."
        }

    # -----------------------------
    # Active Connections
    # -----------------------------
    elif remote and remote != "-":

        try:
            ip, port = remote.rsplit(":", 1)
            port = int(port)

        except ValueError:
            ip = remote
            port = None

        ip_result = analyze_ip(ip)

        if port is not None:
            port_result = analyze_port(port)
        else:
            port_result = {
                "score": 0,
                "level": "LOW",
                "reason": "No remote port."
            }

    # -----------------------------
    # No Remote Address
    # -----------------------------
    else:

        ip_result = {
            "score": 0,
            "level": "LOW",
            "reason": "No remote connection."
        }

        port_result = {
            "score": 0,
            "level": "LOW",
            "reason": "No remote port."
        }

    # -----------------------------
    # Calculate Risk Score
    # -----------------------------
    total_score = (
        process_result["score"]
        + ip_result["score"]
        + port_result["score"]
    )

    total_score = min(total_score, 100)

    return {
        "score": total_score,
        "level": get_risk_level(total_score),

        "details": {
            "process": process_result,
            "ip": ip_result,
            "port": port_result
        },

        "reasons": [
            process_result["reason"],
            ip_result["reason"],
            port_result["reason"]
        ]
    }