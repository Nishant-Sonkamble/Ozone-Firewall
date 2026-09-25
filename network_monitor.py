import psutil
import socket
from tabulate import tabulate


def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            TypeError):
        return "Unknown"


def get_protocol(sock_type):
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    elif sock_type == socket.SOCK_DGRAM:
        return "UDP"
    return "Unknown"

def get_connections():

    connections = []

    for conn in psutil.net_connections(kind="inet"):

        try:
            if conn.pid:
                process_obj = psutil.Process(conn.pid)
                process = process_obj.name()

                try:
                    exe = process_obj.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = ""

            else:
                process = "System"
                exe = ""

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process = "Unknown"
            exe = ""

        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        local = (
            f"{conn.laddr.ip}:{conn.laddr.port}"
            if conn.laddr else ""
        )

        remote = (
            f"{conn.raddr.ip}:{conn.raddr.port}"
            if conn.raddr else "-"
        )

        connections.append({
            "process": process,
            "pid": conn.pid,
            "exe": exe,
            "protocol": protocol,
            "local": local,
            "remote": remote,
            "status": conn.status,
        })

    return connections


if __name__ == "__main__":

    data = get_connections()

    headers = [
        "Process",
        "PID",
        "Protocol",
        "Status",
        "Local Address",
        "Remote Address"
    ]

    print(tabulate(data, headers=headers, tablefmt="grid"))