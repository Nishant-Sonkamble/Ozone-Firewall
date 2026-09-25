from threat_analyzer import analyze_connection
from behavior_analyzer import (
    analyze_connection_frequency,
    analyze_shared_remote_ips,
    analyze_port_usage,
)

def merge_scores(static_score, behavior_score):
    total = min(static_score + behavior_score, 100)

    if total >= 70:
        level = "CRITICAL"
    elif total >= 40:
        level = "HIGH"
    elif total >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return total, level

def get_threat_scores(connections):
    """
    Analyze every connection using both
    static and behavioral analysis.
    """

    frequency_results = analyze_connection_frequency(connections)
    shared_ip_results = analyze_shared_remote_ips(connections)
    port_results = analyze_port_usage(connections)

    results = []

    for conn in connections:

        static = analyze_connection(conn)

        behavior_score = 0
        behavior_reasons = []

        process = conn.get("process", "Unknown")

        if process in frequency_results:
            freq = frequency_results[process]

            behavior_score += freq["score"]

            if freq["score"] > 0:
                behavior_reasons.append(freq["reason"])

        remote = conn.get("remote", "")

        if remote and remote != "-":

            try:
                ip, port = remote.rsplit(":", 1)
                port = int(port)

                if ip in shared_ip_results:
                    result = shared_ip_results[ip]

                    behavior_score += result["score"]

                    if result["score"] > 0:
                        behavior_reasons.append(result["reason"])

                if port in port_results:
                    result = port_results[port]

                    behavior_score += result["score"]

                    if result["score"] > 0:
                        behavior_reasons.append(result["reason"])

            except ValueError:
                pass

        total, level = merge_scores(
            static["score"],
            behavior_score
        )

        results.append({
            "connection": conn,
            "score": total,
            "level": level,
            "static": static,
            "behavior_score": behavior_score,
            "behavior_reasons": behavior_reasons
        })

    return results

