import json
import os

import os

from paths import RULE_FILE


def load_rules():

    if not os.path.exists(RULE_FILE):

        return []

    with open(RULE_FILE, "r") as file:

        return json.load(file)


def save_rules(rules):

    with open(RULE_FILE, "w") as file:

        json.dump(rules, file, indent=4)


def add_process_rule(process_name, path, action):

    rules = load_rules()

    for rule in rules:

        if (
            rule["type"] == "process"
            and rule["name"].lower() == process_name.lower()
        ):
            rule["action"] = action
            rule["path"] = path
            save_rules(rules)
            return

    rules.append({
        "type": "process",
        "name": process_name,
        "path": path,
        "action": action
    })

    save_rules(rules)

def get_process_rule(process_name):

    rules = load_rules()

    for rule in rules:

        if (
            rule["type"] == "process"
            and rule["name"].lower() == process_name.lower()
        ):
            return rule

    return None

def check_process(process_name):
     rules = load_rules()

     for rule in rules:

        if (
            rule["type"] == "process"
            and rule["name"].lower() == process_name.lower()
        ):
            return rule["action"]

     return "ALLOW"

def update_process_rule(process_name, action):

    rules = load_rules()

    for rule in rules:

        if (
            rule["type"] == "process"
            and rule["name"].lower() == process_name.lower()
        ):

            rule["action"] = action
            save_rules(rules)
            return True

    return False

def delete_process_rule(process_name):

    rules = load_rules()

    rules = [
        rule
        for rule in rules
        if not (
            rule["type"] == "process"
            and rule["name"].lower() == process_name.lower()
        )
    ]

    save_rules(rules)