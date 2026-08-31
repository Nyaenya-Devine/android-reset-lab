# threat_detection.py - blue team: reads the log, catches the six attacks
import json
from datetime import datetime

import config

RULES = ["brute_force", "out_of_hours", "privilege_escalation",
         "unknown_device", "replay", "unapproved_execute"]


def _read_log():
    try:
        with open(config.LOG_FILE, "r") as f:
            return [json.loads(line) for line in f.read().splitlines() if line]
    except FileNotFoundError:
        return []


def scan():
    events = _read_log()
    findings = {rule: [] for rule in RULES}

    failed_counts = {}
    for e in events:
        if e["event_type"] == "LOGIN_FAILED":
            failed_counts[e["actor"]] = failed_counts.get(e["actor"], 0) + 1
    for e in events:
        if (e["event_type"] == "LOGIN_FAILED"
                and failed_counts[e["actor"]] >= config.MAX_FAILED_LOGINS):
            findings["brute_force"].append(e)

    for e in events:
        if e["event_type"] == "RESET_REQUESTED":
            hour = datetime.fromisoformat(e["timestamp"]).hour
            if not (config.RESET_WINDOW[0] <= hour < config.RESET_WINDOW[1]):
                findings["out_of_hours"].append(e)
            if "not in fleet" in e["outcome"]:
                findings["unknown_device"].append(e)

    for e in events:
        if e["event_type"] == "ACCESS_DENIED":
            findings["privilege_escalation"].append(e)
        if e["event_type"] == "RESET_BLOCKED":
            findings["unapproved_execute"].append(e)

    seen = {}
    for e in events:
        if e["event_type"] == "RESET_REQUESTED":
            rid = e.get("request_id", "-")
            if rid != "-":
                seen[rid] = seen.get(rid, 0) + 1
    for e in events:
        if e["event_type"] == "RESET_REQUESTED":
            rid = e.get("request_id", "-")
            if rid != "-" and seen[rid] > 1:
                findings["replay"].append(e)

    return findings


def metrics(findings):
    fired = [r for r in RULES if findings[r]]
    return {
        "rules_fired": fired,
        "flag_counts": {r: len(findings[r]) for r in RULES},
        "detection_rate": str(len(fired)) + "/6",
    }


if __name__ == "__main__":
    import os
    findings = scan()
    m = metrics(findings)
    for rule in RULES:
        print(rule.ljust(22), len(findings[rule]))
    print("detection rate:", m["detection_rate"])
    os.makedirs("reports", exist_ok=True)
    with open("reports/detection_metrics.json", "w") as f:
        json.dump(m, f, indent=2)
    print("metrics written to reports/detection_metrics.json")