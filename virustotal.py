import requests
import json
import os

from datetime import datetime, timedelta

from settings_manager import get_api_key

CACHE_FILE = "vt_cache.json"
CACHE_DAYS = 1

def load_cache():

    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)

    except Exception:
        return {}

def save_cache(cache):

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=4)

def cache_valid(entry):

    try:

        checked = datetime.strptime(
            entry["checked"],
            "%Y-%m-%d %H:%M:%S"
        )

        return (
            datetime.now() - checked
        ) < timedelta(days=CACHE_DAYS)

    except Exception:

        return False

def vt_lookup(hash_value):
    VT_API_KEY = get_api_key()
    if not VT_API_KEY:
                return {
                    "error": "NO_API_KEY"
                }
    
    headers = {
        "x-apikey": VT_API_KEY 

        
    }
    
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )

    if response.status_code != 200:
        raise Exception(
            f"HTTP {response.status_code}: {response.text}"
        )

    data = response.json()

    data["checked"] = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

    return data

    

def check_hash(hash_value):

    cache = load_cache()

    if hash_value in cache:

        if cache_valid(cache[hash_value]):

            return cache[hash_value]

    try:

        result = vt_lookup(hash_value)

        cache[hash_value] = result

        save_cache(cache)

        return result

    except Exception as e:

        print("VirusTotal Error:", e)

        return {
    "error": str(e)
}

def summarize_result(vt_result):

    attributes = vt_result["data"]["attributes"]

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {

        "checked": vt_result.get(
            "checked",
            "Unknown"
        ),

        "malicious": stats.get(
            "malicious",
            0
        ),

        "suspicious": stats.get(
            "suspicious",
            0
        ),

        "harmless": stats.get(
            "harmless",
            0
        ),

        "undetected": stats.get(
            "undetected",
            0
        )

    }