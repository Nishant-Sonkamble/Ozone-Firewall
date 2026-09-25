import hashlib
import os
from paths import REPUTATION_FILE

import json


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "known_good": {},
            "known_bad": {}
        }
    
def sha256_file(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    if not file_path:
        return None

    if not os.path.exists(file_path):
        return None

    sha = hashlib.sha256()

    with open(file_path, "rb") as f:

        while True:

            chunk = f.read(65536)

            if not chunk:
                break

            sha.update(chunk)

    return sha.hexdigest()

_hash_cache = {}
def get_file_hash(path):

    if path in _hash_cache:
        return _hash_cache[path]

    h = sha256_file(path)

    _hash_cache[path] = h

    return h

def check_hash(hash_value):
    db = load_json(REPUTATION_FILE)

    if hash_value in db["known_bad"]:
        return {
            "trusted": False,
            "known": True,
            "score": 80,
            "reason": "Known malicious file."
        }

    if hash_value in db["known_good"]:
        return {
            "trusted": True,
            "known": True,
            "score": 0,
            "reason": "Known trusted file."
        }

    return {
        "trusted": None,
        "known": False,
        "score": 0,
        "reason": "Unknown file hash."
    }

def sha256_string(text):
    """
    Calculate SHA-256 hash of a string.
    Used for generating unique IDs (e.g. firewall rules).
    """

    if text is None:
        return None

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()