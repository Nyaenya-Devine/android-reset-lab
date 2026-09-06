"""
demo_ledger_attack.py — Demonstrate actual attack against audit ledger and show detection

This script shows:
1. Normal operation creates hash-chained log
2. Attacker with write access tampers with log (changes outcome)
3. verify_logs() detects exact broken line
4. Restoration restores integrity

This is the educational proof that hash chaining is tamper-EVIDENT (not tamper-proof).
"""

import json
import os
import config
import security_logger
import seed_lab

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def demo():
    print_header("Android Reset Lab — Ledger Tampering Demo (Simulation Only)")
    print("Safety: All operations on local JSONL file, no real devices")
    
    # Clean start
    print("\n[1] Seeding lab and creating clean log...")
    os.makedirs("logs", exist_ok=True)
    with open(config.LOG_FILE, "w"):
        pass
    seed_lab.seed_all()
    
    # Create some legitimate events
    admin_token = seed_lab.get_default_token("que")
    ops_token = seed_lab.get_default_token("ops")
    
    import reset_workflow
    ok, rid = reset_workflow.request_reset(ops_token, "AND-001")
    print(f"  Created reset request: {rid}")
    ok, msg = reset_workflow.approve_reset(admin_token, rid)
    print(f"  Approved: {msg}")
    
    # Verify intact
    print("\n[2] Verifying log integrity (should be INTACT)...")
    ok, info = security_logger.verify_logs()
    print(f"  Chain intact: {ok} | events: {info}")
    assert ok, "Log should be intact initially"
    
    # Show log
    print("\n[3] Current log (last 2 events):")
    with open(config.LOG_FILE, "r") as f:
        lines = f.read().splitlines()
    for line in lines[-2:]:
        entry = json.loads(line)
        print(f"  Line {len(lines)-1}: {entry['event_type']} by {entry['actor']} -> {entry['outcome']} | hash {entry['entry_hash'][:12]}...")
    
    # Attack: tamper with log
    print("\n[4] ATTACK: Attacker with write access modifies log file...")
    print("  Scenario: Malicious insider tries to change RESET_APPROVED to look like it was never approved")
    print("  Action: Editing last event's outcome from 'approved' to 'denied'")
    
    with open(config.LOG_FILE, "r") as f:
        lines = f.read().splitlines()
    
    # Tamper with last event
    original_lines = lines.copy()
    last_entry = json.loads(lines[-1])
    original_outcome = last_entry["outcome"]
    last_entry["outcome"] = "tampered - attacker changed approved to denied"
    # Keep old hash to simulate attacker not recomputing chain
    lines[-1] = json.dumps(last_entry)
    
    with open(config.LOG_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    
    print(f"  Tampered line {len(lines)}: outcome '{original_outcome}' -> 'tampered...'")
    print(f"  Hash still old: {last_entry['entry_hash'][:12]}... (attacker didn't recompute)")
    
    # Detect tampering
    print("\n[5] DETECTION: Running verify_logs()...")
    ok, bad_line = security_logger.verify_logs()
    print(f"  Chain intact: {ok}")
    print(f"  Broken at line: {bad_line}")
    
    if not ok:
        print(f"\n  ✅ SUCCESS: Tampering detected at exact line {bad_line}!")
        print("  The hash recomputed from tampered data doesn't match stored hash.")
        print("  This proves log is tamper-EVIDENT.")
    else:
        print("\n  ❌ FAILED: Tampering not detected (bug)")
        return False
    
    # Show what detection does
    print("\n[6] How detection works:")
    print("  verify_logs() recomputes SHA-256 for each entry:")
    print("    recomputed = sha256(json.dumps(entry_without_hash, sort_keys=True))")
    print("    if recomputed != stored_entry_hash → BROKEN")
    print("  Also checks prev_hash chain:")
    print("    if entry.prev_hash != previous.entry_hash → BROKEN")
    
    # Restore
    print("\n[7] RESTORATION: Restoring original log...")
    with open(config.LOG_FILE, "w") as f:
        f.write("\n".join(original_lines) + "\n")
    
    ok, info = security_logger.verify_logs()
    print(f"  After restore - Chain intact: {ok} | events: {info}")
    
    if ok:
        print("\n  ✅ Log restored to INTACT")
    
    print_header("Demo Complete — Ledger is Tamper-Evident, Not Tamper-Proof")
    print("""
Known limitations (honest):
- Hash chain detects modification but not full deletion (attacker could delete entire log)
- No secret key/HMAC — real SIEM needs HMAC with secret or asymmetric signing
- No WORM storage — real compliance needs immutable storage
- This is educational, not production SIEM
""")
    return True

if __name__ == "__main__":
    demo()
