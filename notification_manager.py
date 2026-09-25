from winotify import Notification, audio
import time


class NotificationManager:

    def __init__(self):
     self.last_notification = {}


    def notify(self, title, message, icon=None):
     print("notify() called")

     toast = Notification(
        app_id="Sentinel Firewall",
        title=title,
        msg=message
    )

     print("Before show()")
     toast.show()
     print("After show()")

    def notify_threat(self, connection, analysis):

     process = connection.get("process", "Unknown Process")
     pid = connection.get("pid", 0)
     remote = connection.get("remote", "Unknown")
     risk = analysis.get("risk", "UNKNOWN").upper()

    # Notify only for HIGH and CRITICAL
     if risk not in ("HIGH", "CRITICAL"):
        return

    # Different cooldowns
     if risk == "CRITICAL":
        cooldown = 60      # 1 minute
     else:
        cooldown = 300     # 5 minutes

     key = (pid, remote)

     now = time.time()

    # Check cooldown
     if key in self.last_notification:
        elapsed = now - self.last_notification[key]

        if elapsed < cooldown:
            return

    # Update timestamp
     self.last_notification[key] = now

     title = f"{risk} Threat Detected"

     message = (
        f"Process : {process}\n"
        f"Remote  : {remote}"
    )

     self.notify(title, message)

    def cleanup(self, active_connections):

     active_keys = {
        (c.get("pid"), c.get("remote"))
        for c in active_connections
    }

     self.last_notification = {
        key: timestamp
        for key, timestamp in self.last_notification.items()
        if key in active_keys
    }

    def clear_cache(self):
        self.notified_connections.clear()


notification_manager = NotificationManager()