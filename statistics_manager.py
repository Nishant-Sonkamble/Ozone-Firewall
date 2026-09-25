from network_monitor import get_connections
from firewall_engine import load_rules

from vt_history_manager  import load_scans
from collections import Counter
from network_monitor import get_connections

from logger import load_logs


def get_dashboard_stats():

    connections = get_connections()
    rules = load_rules()
    logs = load_logs()

    blocked_rules = sum(
        1
        for rule in rules
        if rule["action"] == "BLOCK"
    )

    return {
        "connections": len(connections),
        "rules": len(rules),
        "blocked": blocked_rules,
        "logs": len(logs)
    }

def get_statistics_summary(connections):

    rules = load_rules()
    scans = load_scans()

    return generate_statistics(
        connections,
        rules_count=len(rules),
        vt_scans=len(scans)
    )

def generate_statistics(connections, rules_count=0, vt_scans=0):
    """
    Generate summary statistics for the Statistics page.
    """

    total_connections = len(connections)

    unique_processes = {
        conn["pid"]
        for conn in connections
        if conn.get("pid")
    }

    tcp = 0
    udp = 0

    high = 0
    critical = 0
    low = 0
    unknown = 0

    for conn in connections:

        # ---------- Protocol ----------
        protocol = conn.get("protocol", "").upper()

        if protocol == "TCP":
            tcp += 1
        elif protocol == "UDP":
            udp += 1

        # ---------- Risk ----------
        risk = (
            conn.get("analysis", {})
            .get("level", "UNKNOWN")
            .upper()
        )

        if risk == "LOW":
            low += 1

        elif risk == "HIGH":
            high += 1

        elif risk == "CRITICAL":
            critical += 1

        else:
            unknown += 1

    return {

        "connections": total_connections,

        "processes": len(unique_processes),

        "tcp": tcp,

        "udp": udp,

        "low": low,

        "high": high,

        "critical": critical,

        "unknown": unknown,

        "rules": rules_count,

        "vt_scans": vt_scans,
    }

def get_top_processes(connections, limit=5):

    process_counter = Counter()

    process_risk = {}

    risk_priority = {

        "LOW": 0,
        "UNKNOWN": 1,
        "HIGH": 2,
        "CRITICAL": 3

    }

    for connection in connections:

        process = connection.get(
            "process",
            "Unknown"
        )

        process_counter[process] += 1

        risk = (
            connection
            .get("analysis", {})
            .get("level", "UNKNOWN")
            .upper()
        )
        
        if process not in process_risk:

            process_risk[process] = risk

        else:

            current = process_risk[process]

            if risk_priority[risk] > risk_priority[current]:

                process_risk[process] = risk

    results = []

    for process, count in process_counter.most_common(limit):

        results.append({

            "process": process,

            "connections": count,

            "risk": process_risk[process]

        })

    return results

def get_top_remote_connections(connections, limit=5):

    counter = Counter()

    for connection in connections:

        remote = connection.get("remote", "-")

        if (
            not remote
            or remote == "-"
        ):
            continue

        counter[remote] += 1

    results = []

    for remote, count in counter.most_common(limit):

        results.append({

            "remote": remote,

            "connections": count

        })

    return results


