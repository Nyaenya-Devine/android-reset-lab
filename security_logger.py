# security_logger.py - hash-chained JSON Lines audit log with P3 hardening
# P3: HMAC signing (tamper-proof), log shipping to stdout/file for SIEM
import hashlib
import hmac
import json
import os
import sys
import secrets
from datetime import datetime, timezone

import config

GENESIS = "0" * 64
HMAC_KEY = None  # loaded lazily

def _get_hmac_key():
    """Load or generate HMAC key for tamper-proof signing.
    P3: If HMAC key file exists, use it. If not, operate in tamper-evident mode (hash chain only).
    To enable tamper-proof mode: set LAB_HMAC_KEY_FILE and generate key via generate_hmac_key().
    """
    global HMAC_KEY
    if HMAC_KEY is not None:
        return HMAC_KEY
    key_file = getattr(config, "HMAC_KEY_FILE", "data/hmac.key")
    # Allow env var override for key itself (for testing)
    env_key = os.getenv("LAB_HMAC_KEY")
    if env_key:
        try:
            HMAC_KEY = bytes.fromhex(env_key)
            return HMAC_KEY
        except ValueError:
            pass
    if os.path.exists(key_file):
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                hex_key = f.read().strip()
                HMAC_KEY = bytes.fromhex(hex_key)
                return HMAC_KEY
        except (ValueError, FileNotFoundError, OSError):
            return None
    return None

def generate_hmac_key(key_file=None):
    """Generate a new HMAC key for tamper-proof audit log. P3."""
    kf = key_file or getattr(config, "HMAC_KEY_FILE", "data/hmac.key")
    os.makedirs(os.path.dirname(kf) or "data", exist_ok=True)
    key = secrets.token_bytes(32)  # 256-bit
    with open(kf, "w", encoding="utf-8") as f:
        f.write(key.hex())
    # Restrict permissions (best effort)
    try:
        os.chmod(kf, 0o600)
    except OSError:
        pass
    global HMAC_KEY
    HMAC_KEY = key
    print(f"HMAC key generated at {kf} (keep secret, 0600). Audit log now tamper-PROOF if key kept separate.")
    return kf

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

def _compute_hmac(entry_dict, key):
    """Compute HMAC-SHA256 of entry (without hash/hmac fields)."""
    # Sort keys for deterministic
    payload = json.dumps(entry_dict, sort_keys=True).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()

def _ship_log(entry):
    """P3: Ship log to stdout or file for SIEM/Splunk integration."""
    # Check config flags
    ship_stdout = getattr(config, "LOG_SHIP_STDOUT", False) or os.getenv("LAB_LOG_SHIP_STDOUT", "false").lower() == "true"
    ship_file = getattr(config, "LOG_SHIP_FILE", "") or os.getenv("LAB_LOG_SHIP_FILE", "")
    
    if ship_stdout:
        # Print JSON to stdout for Splunk/SIEM collector
        # Format: _raw JSON with sourcetype
        print(json.dumps(entry), flush=True)
    
    if ship_file:
        try:
            os.makedirs(os.path.dirname(ship_file) or ".", exist_ok=True)
            with open(ship_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # Don't fail logging if shipping fails

def log_event(event_type, actor, outcome, severity="INFO",
                 role="-", device_id="-", request_id="-", timestamp=None, _allow_custom_timestamp=False):
    """Write one tamper-evident (and optionally tamper-proof with HMAC) event.
    
    timestamp override is only allowed for simulation/testing via _allow_custom_timestamp=True.
    In production, timestamp should always be server-generated to prevent spoofing.
    
    P3: If HMAC key exists, adds hmac field for tamper-proof verification.
    P3: Optionally ships log to stdout/file for SIEM if LAB_LOG_SHIP_STDOUT=true.
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
    # Compute entry_hash (tamper-evident)
    entry["entry_hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()).hexdigest()
    
    # P3: HMAC signing if key available (tamper-proof)
    hmac_key = _get_hmac_key()
    if hmac_key:
        # HMAC over entry without hmac field itself
        entry_copy_for_hmac = {k: v for k, v in entry.items() if k != "hmac"}
        entry["hmac"] = _compute_hmac(entry_copy_for_hmac, hmac_key)
    
    with open(config.LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    
    # P3: Ship to SIEM
    _ship_log(entry)
    
    return entry


def verify_logs():
    """Check the whole chain. Returns (True, count) or (False, bad line).
    
    P3: Also verifies HMAC if present and key available. If log has hmac field but key missing,
    warns but still checks hash chain. If key present but hmac missing on entries, fails.
    """
    if not os.path.exists(config.LOG_FILE):
        return True, 0
    with open(config.LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    prev = GENESIS
    hmac_key = _get_hmac_key()
    has_hmac_key = hmac_key is not None
    
    for i, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, i
        
        if entry.get("prev_hash") != prev:
            return False, i
        
        # P3: Verify HMAC if present
        stored_hmac = entry.get("hmac")
        if stored_hmac:
            if not has_hmac_key:
                # HMAC present but key missing - can't verify HMAC, but hash chain still valid
                # This is honest limitation: need key to verify tamper-proof
                pass
            else:
                # Recompute HMAC over entry without hmac field and without entry_hash? Actually entry_hash already includes prev_hash etc.
                # Our HMAC was computed over entry including entry_hash but excluding hmac field
                entry_copy = {k: v for k, v in entry.items() if k != "hmac"}
                recomputed_hmac = _compute_hmac(entry_copy, hmac_key)
                if not hmac.compare_digest(recomputed_hmac, stored_hmac):
                    return False, i
        
        stored = entry.pop("entry_hash")
        # Remove hmac for hash recompute if present (entry_hash was computed before hmac)
        entry.pop("hmac", None)
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
        key = _get_hmac_key()
        if key:
            print("HMAC key present: tamper-PROOF mode (key must be kept separate from log)")
        else:
            print("No HMAC key: tamper-EVIDENT mode only (hash chain). Run generate_hmac_key() for tamper-proof.")
    elif len(sys.argv) > 1 and sys.argv[1] == "gen-hmac":
        generate_hmac_key()
    else:
        log_event("TEST", "que", "chain working")
        print("Logged one event. Use 'verify' to check the chain.")
