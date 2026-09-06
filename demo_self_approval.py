"""
demo_self_approval.py — Demonstrate attempted self-approval being blocked (Four-Eyes)

This script shows:
1. Admin requests reset for device
2. Same admin tries to approve own request → BLOCKED (four-eyes violation)
3. Different admin approves → ALLOWED
4. Audit log shows APPROVAL_DENIED for self-approval attempt

This proves separation of duties: no single account is a complete weapon.
"""

import os
import config
import security_logger
import seed_lab
import reset_workflow
import authentication

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def demo():
    print_header("Android Reset Lab — Self-Approval Block Demo (Four-Eyes)")
    print("Safety: Simulation only, no real devices")
    
    # Clean start
    print("\n[1] Seeding lab...")
    os.makedirs("logs", exist_ok=True)
    with open(config.LOG_FILE, "w"):
        pass
    seed_lab.seed_all()
    
    admin_token = seed_lab.get_default_token("que")
    ops_token = seed_lab.get_default_token("ops")
    
    # Get admin username from token
    admin_session = authentication.check_session(admin_token)
    admin_user = admin_session["username"]
    print(f"  Admin user: {admin_user} (role: {admin_session['role']})")
    
    # Step 1: Admin requests reset
    print(f"\n[2] {admin_user} requests reset for AND-003 (as admin, allowed to request)...")
    ok, rid = reset_workflow.request_reset(admin_token, "AND-003")
    print(f"  Request created: {ok} | request_id: {rid}")
    
    if not ok:
        print("  Failed to create request")
        return False
    
    # Step 2: Same admin tries self-approval (should be blocked)
    print(f"\n[3] ATTACK: {admin_user} tries to APPROVE OWN request (should be BLOCKED)...")
    print(f"  This is the four-eyes violation: requester == approver")
    ok, msg = reset_workflow.approve_reset(admin_token, rid)
    print(f"  Approve result: ok={ok} | msg='{msg}'")
    
    if not ok and "differ" in msg:
        print(f"\n  ✅ SUCCESS: Self-approval BLOCKED — '{msg}'")
        print("  Control: Separation of duties (AC-5) enforced")
    else:
        print(f"\n  ❌ FAILED: Self-approval should be blocked but wasn't")
        return False
    
    # Check audit log
    print("\n[4] Checking audit log for APPROVAL_DENIED...")
    import json
    with open(config.LOG_FILE, "r") as f:
        events = [json.loads(line) for line in f.read().splitlines() if line]
    
    denied_events = [e for e in events if e["event_type"] == "APPROVAL_DENIED"]
    print(f"  Found {len(denied_events)} APPROVAL_DENIED events")
    for ev in denied_events:
        print(f"    - {ev['timestamp']}: {ev['actor']} tried to approve {ev['request_id']} → {ev['outcome']}")
    
    if denied_events:
        print("\n  ✅ Audit log shows four-eyes violation captured")
    
    # Step 3: Different admin approves (should succeed) — need second admin
    print("\n[5] Creating second admin for proper approval...")
    authentication.create_user("admin2", "Admin2Pass!123", "admin")
    authentication.login("admin2", "Admin2Pass!123")
    admin2_token = authentication.start_session("admin2")
    admin2_session = authentication.check_session(admin2_token)
    print(f"  Second admin: {admin2_session['username']} (role: {admin2_session['role']})")
    
    print(f"\n[6] {admin2_session['username']} approves request from {admin_user} (different persons → should ALLOW)...")
    ok, msg = reset_workflow.approve_reset(admin2_token, rid)
    print(f"  Approve result: ok={ok} | msg='{msg}'")
    
    if ok:
        print(f"\n  ✅ SUCCESS: Different admin approval ALLOWED")
    else:
        print(f"\n  ❌ FAILED: Different admin should be allowed")
        return False
    
    # Step 4: Execute
    print(f"\n[7] {admin2_session['username']} executes approved reset (SIMULATED)...")
    ok, msg = reset_workflow.execute_reset(admin2_token, rid)
    print(f"  Execute: ok={ok} | msg='{msg}'")
    
    # Final verification
    print("\n[8] Final verification...")
    import device_simulator
    device = device_simulator.get_device("AND-003")
    print(f"  Device AND-003 status: {device['status']} (should be 'wiped' — simulated)")
    
    ok_chain, info = security_logger.verify_logs()
    print(f"  Log integrity: {'INTACT' if ok_chain else 'BROKEN'} | events: {info}")
    
    print_header("Demo Complete — Four-Eyes Enforced")
    print("""
What this proves:
- No single account can request + approve (separation of duties AC-5)
- Self-approval is blocked with clear message: 'approver must differ from requester'
- Audit log captures APPROVAL_DENIED with actor, device, request_id
- Different admin can approve — workflow continues

Business impact:
- Prevents compromised admin from being complete weapon
- Requires collusion of 2 accounts to cause damage
- Matches real enterprise MDM policy

Known limitation:
- Does not prevent collusion (2 malicious admins could still approve each other)
- Real systems need additional controls: MFA, time delays, SIEM alerting on approval patterns
""")
    return True

if __name__ == "__main__":
    demo()
