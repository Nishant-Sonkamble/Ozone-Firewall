from collections import Counter
import ipaddress

ACTIVE_STATES = {
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "SYN_RECEIVED"
}


def analyze_connection_frequency(connections):
    """
    Detect processes with an unusually high number
    of active network connections.
    """

    process_counter = Counter()

    for conn in connections:
        status = conn.get("status", "").upper()

        if status not in ACTIVE_STATES:
            continue

        process = conn.get("process", "Unknown")
        process_counter[process] += 1

    results = {}

    for process, count in process_counter.items():
        if count >= 100:
            results[process] = {
                "score": 20,
                "level": "HIGH",
                "reason": f"Process has {count} active connections."
            }
        elif count >= 50:
            results[process] = {
                "score": 10,
                "level": "MEDIUM",
                "reason": f"Process has {count} active connections."
            }
        else:
            results[process] = {
                "score": 0,
                "level": "LOW",
                "reason": "Normal connection count."
            }

    return results


def analyze_shared_remote_ips(connections):
    """
    Detect remote IPs contacted by many processes.
    """

    ip_counter = Counter()

    for conn in connections:
        status = conn.get("status", "").upper()

        if status not in ACTIVE_STATES:
            continue

        remote = conn.get("remote", "")

        if not remote or remote == "-":
            continue

        ip = remote.split(":")[0]

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if ip_obj.is_loopback:
            continue

        if ip_obj.is_private:
            continue

        ip_counter[ip] += 1

    results = {}

    for ip, count in ip_counter.items():
        if count >= 15:
            results[ip] = {
                "score": 20,
                "level": "HIGH",
                "reason": f"Remote IP is contacted by {count} active connections."
            }
        elif count >= 8:
            results[ip] = {
                "score": 10,
                "level": "MEDIUM",
                "reason": f"Remote IP is contacted by {count} active connections."
            }
        else:
            results[ip] = {
                "score": 0,
                "level": "LOW",
                "reason": "Normal remote IP activity."
            }

    return results


def analyze_port_usage(connections):
    """
    Detect ports receiving an unusually high number
    of connections.
    """

    port_counter = Counter()

    for conn in connections:
        status = conn.get("status", "").upper()

        if status not in ACTIVE_STATES:
            continue

        remote = conn.get("remote", "")

        if not remote or remote == "-":
            continue

        try:
            port = int(remote.rsplit(":", 1)[1])
        except Exception:
            continue

        port_counter[port] += 1

    results = {}

    for port, count in port_counter.items():
        if count >= 50:
            results[port] = {
                "score": 15,
                "level": "HIGH",
                "reason": f"Remote port {port} is used by {count} active connections."
            }
        else:
            results[port] = {
                "score": 0,
                "level": "LOW",
                "reason": "Normal port activity."
            }

    return results

