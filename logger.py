import json
import os
from datetime import datetime

from paths import LOG_FILE


def load_logs():

    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as file:
        return json.load(file)


def save_logs(logs):

    with open(LOG_FILE, "w") as file:
        json.dump(logs, file, indent=4)


def add_log(process, action):

    logs = load_logs()

    logs.append({

        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "process": process,

        "action": action

    })

    save_logs(logs)