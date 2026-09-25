from PySide6.QtCore import QObject, Signal
from network_monitor import get_connections
from threat_engine import get_threat_scores


class ConnectionLoader(QObject):

    finished = Signal(list)

    def load(self):

        connections = get_connections()

        results = get_threat_scores(connections)

        self.finished.emit(results)