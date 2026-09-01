# security_logger.py - hash-chained JSON Lines audit log
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import config

GENESIS = "0" * 64


def _last_hash():
    """Hash of the newest entry, or GENESIS if the log is empty."""
    if not os.path.exists(config.LOG_FILE):
        return GENESIS
    try:
        with open(config.LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        if not lines:
            return GENESIS
        # Handle corrupted last line gracefully
        return json.loads(lines[-1]).get("entry_hash", GENESIS)
    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        return GENESIS


def log_event(event_type, actor, outcome, severity="INFO",
                 role="-", device_id="-", request_id="-", timestamp=None, _allow_custom_timestamp=False):
    """Write one tamper-evident event to the audit log.
    
    timestamp override is only allowed for simulation/testing via _allow_custom_timestamp=True.
    In production, timestamp should always be server-generated to prevent spoofing.
    """
    os.makedirs("logs", exist_ok=True)
    # Prevent timestamp spoofing: only allow custom timestamp when explicitly flagged
    # and in SIMULATION_MODE
    if timestamp is not None and not _allow_custom_timestamp:
        # If custom timestamp provided without flag, ignore it for security
        # (but allow in SIMULATION_MODE for backwards compat with warning)
        if not config.SIMULATION_MODE:
            timestamp = None
    final_timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    entry = {
        "timestamp": final_timestamp,
        "event_type": event_type,
        "severity": severity,
        "actor": actor,
        "role": role,
        "device_id": device_id,
        "outcome": outcome,
        "request_id": request_id,
        "prev_hash": _last_hash(),
    }
    entry["entry_hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(config.LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify_logs():
    """Check the whole chain. Returns (True, count) or (False, bad line)."""
    if not os.path.exists(config.LOG_FILE):
        return True, 0
    with open(config.LOG_FILE, "r") as f:
        lines = f.read().splitlines()
    prev = GENESIS
    for i, line in enumerate(lines, start=1):
        entry = json.loads(line)
        if entry.get("prev_hash") != prev:
            return False, i
        stored = entry.pop("entry_hash")
        recomputed = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()).hexdigest()
        if recomputed != stored:
            return False, i
        prev = stored
    return True, len(lines)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        ok, info = verify_logs()
        print("Chain intact:", ok, "| info:", info)
    else:
        log_event("TEST", "que", "chain working")
        print("Logged one event. Use 'verify' to check the chain.")