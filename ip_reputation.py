import json
import os

DATABASE = "ip_database.json"

_cache = None


def load_database():
    global _cache

    if _cache is None:

        if os.path.exists(DATABASE):
            with open(DATABASE, "r") as f:
                _cache = json.load(f)
        else:
            _cache = {}

    return _cache


def check_ip(ip):

    if not ip:
        return None

    ip = ip.split(":")[0]

    db = load_database()

    return db.get(ip)

