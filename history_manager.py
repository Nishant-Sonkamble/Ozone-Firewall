import json
import os
from datetime import datetime, timedelta
HISTORY_DAYS = 30
MAX_HISTORY = 10000
HISTORY_FILE = "history.json"

def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)

        history = cleanup_history(history)

        save_history(history)

        return history

    except Exception:
        return []


def save_history(history):

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


def add_event(
    event,
    process,
    pid,
    local_ip,
    remote_ip,
    protocol,
    risk,
    score
):

    history = load_history()

    history.append({

        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "event": event,

        "process": process,

        "pid": pid,

        "protocol": protocol,

        "local_ip": local_ip,

        "remote_ip": remote_ip,

        "risk": risk,

        "score": score

    })

    if len(history) > MAX_HISTORY:
        history = history[-MAX_HISTORY:]

    save_history(history)

def cleanup_history(history):

    cutoff = datetime.now() - timedelta(days=HISTORY_DAYS)

    cleaned = []

    for event in history:

        try:
            event_time = datetime.strptime(
                event["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            if event_time >= cutoff:
                cleaned.append(event)

        except Exception:
            # Ignore corrupted records
            continue

    return cleaned

def clear_history():

    save_history([])