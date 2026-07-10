import psutil
import socket

def get_connections():
    connections = psutil.net_connections(kind="inet")

    for connection in connections:
        print(connection)


if __name__ == "__main__":
    get_connections()