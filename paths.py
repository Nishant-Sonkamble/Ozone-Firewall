import os

BASE_DIR = os.path.dirname(__file__)

RULE_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs.json")

BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.json")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.json")

REPUTATION_FILE = os.path.join(BASE_DIR, "reputation.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
VT_CACHE_FILE = os.path.join(BASE_DIR, "vt_cache.json")