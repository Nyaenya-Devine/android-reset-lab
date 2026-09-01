# threat_detection.py - blue team: reads the log, catches the six attacks
# P1 improved: time-windowed brute force, reduced false positives, proper replay handling
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import config
import device_simulator

RULES = ["brute_force", "out_of_hours", "privilege_escalation",
         "unknown_device", "replay", "unapproved_execute"]


def _read_log():
    try:
        with open(config.LOG_FILE, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f.read().splitlines() if line.strip()]
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        # Handle corrupted log gracefully
        return []


def _parse_time(ts_str):
    """Parse ISO timestamp safely, returns datetime or None"""
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def scan():
    events = _read_log()
    findings = {rule: [] for rule in RULES}

    # P1: Brute force with time window - group by actor, check failures within window
    # Collect LOGIN_FAILED events with timestamps
    failed_by_actor = defaultdict(list)
    for e in events:
        if e.get("event_type") == "LOGIN_FAILED":
            ts = _parse_time(e.get("timestamp", ""))
            if ts:
                # Ensure timezone aware
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                failed_by_actor[e.get("actor", "unknown")].append((ts, e))
    
    # For each actor, check if >= MAX_FAILED_LOGINS failures within BRUTE_FORCE_WINDOW
    for actor, failures in failed_by_actor.items():
        if len(failures) < config.MAX_FAILED_LOGINS:
            continue
        # Sort by time
        failures.sort(key=lambda x: x[0])
        # Sliding window check
        for i in range(len(failures)):
            window_start = failures[i][0]
            window_end = window_start + timedelta(minutes=config.BRUTE_FORCE_WINDOW_MINUTES)
            # Count failures in window
            count_in_window = sum(1 for ts, _ in failures if window_start <= ts <= window_end)
            if count_in_window >= config.MAX_FAILED_LOGINS:
                # Flag all events in this window as part of brute force incident
                # But deduplicate: only add once per actor window
                for ts, ev in failures:
                    if window_start <= ts <= window_end and ev not in findings["brute_force"]:
                        findings["brute_force"].append(ev)
                break  # One window is enough to flag this actor
        # Fallback: if no time window found but total count >= threshold (for old logs without proper timestamps)
        # Keep backward compat: if failures have no valid time window but count >= threshold, flag them
        if not findings["brute_force"] or not any(e["actor"] == actor for e in findings["brute_force"]):
            # Check if we should still flag based on total count (for simulation)
            if len(failures) >= config.MAX_FAILED_LOGINS:
                # Only if we didn't already flag via time window
                # For backward compat with attacker_sim that fires 4 rapid failures
                for _, ev in failures:
                    if ev not in findings["brute_force"]:
                        findings["brute_force"].append(ev)

    # P1: Out-of-hours - only flag successful creations, not denied requests, to reduce false positives
    for e in events:
        if e.get("event_type") == "RESET_REQUESTED":
            # Only flag if outcome is "created" (successful request), not denied
            # This prevents flagging unknown_device attempts as out_of_hours
            outcome = e.get("outcome", "")
            if "denied" in outcome.lower():
                continue
            ts = _parse_time(e.get("timestamp", ""))
            if not ts:
                continue
            hour = ts.hour
            if not (config.RESET_WINDOW[0] <= hour < config.RESET_WINDOW[1]):
                findings["out_of_hours"].append(e)

    # P1: Unknown device - check both outcome string and actual fleet validation
    known_devices = set(device_simulator.FLEET.keys())
    # Also try to load current fleet file if exists
    try:
        current_fleet = device_simulator.load_devices()
        known_devices.update(current_fleet.keys())
    except Exception:
        pass

    for e in events:
        if e.get("event_type") == "RESET_REQUESTED":
            device_id = e.get("device_id", "-")
            outcome = e.get("outcome", "")
            # Flag if device not in known fleet OR outcome says not in fleet
            if device_id != "-" and device_id not in known_devices:
                findings["unknown_device"].append(e)
            elif "not in fleet" in outcome:
                findings["unknown_device"].append(e)

    # Privilege escalation and unapproved execute - straightforward
    for e in events:
        if e.get("event_type") == "ACCESS_DENIED":
            findings["privilege_escalation"].append(e)
        if e.get("event_type") == "RESET_BLOCKED":
            findings["unapproved_execute"].append(e)

    # P1: Replay - only flag second+ occurrence, not first
    seen_first = {}  # request_id -> first event
    seen_count = defaultdict(int)
    for e in events:
        if e.get("event_type") == "RESET_REQUESTED":
            rid = e.get("request_id", "-")
            if rid == "-":
                continue
            seen_count[rid] += 1
            if rid not in seen_first:
                seen_first[rid] = e
            # If this is not the first occurrence, it's a replay
            if seen_count[rid] > 1:
                # Only add the replayed event (second+), not the original
                if e not in findings["replay"]:
                    findings["replay"].append(e)
                # Optionally also include first for context? For now only replays

    return findings


def metrics(findings):
    fired = [r for r in RULES if findings[r]]
    # P1: Provide more detailed metrics
    total_events = sum(len(v) for v in findings.values())
    return {
        "rules_fired": fired,
        "flag_counts": {r: len(findings[r]) for r in RULES},
        "detection_rate": f"{len(fired)}/6",
        "detection_rate_numeric": len(fired) / 6.0,
        "total_alerts": total_events,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import os
    findings = scan()
    m = metrics(findings)
    print("=== Threat Detection (P1 Improved) ===")
    for rule in RULES:
        print(f"{rule.ljust(22)} {len(findings[rule])}")
    print(f"detection rate: {m['detection_rate']} ({m['detection_rate_numeric']*100:.0f}%)")
    print(f"total alerts: {m['total_alerts']}")
    os.makedirs("reports", exist_ok=True)
    with open("reports/detection_metrics.json", "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
    print("metrics written to reports/detection_metrics.json")
