# attacker_sim.py - red team harness (simulated attacks only)
# P1: Improved timestamp handling to avoid false out_of_hours
import os

import config
import authentication
import authorization
import device_simulator
import reset_workflow
import security_logger
import seed_lab

NIGHT = "2026-08-31T03:00:00+00:00"
DAY = "2026-08-31T10:00:00+00:00"  # Within RESET_WINDOW 8-18 for clean detection


def reset_simulated_log():
    """Start the attack demonstration with a clean simulated audit log."""
    os.makedirs("logs", exist_ok=True)
    with open(config.LOG_FILE, "w", encoding="utf-8"):
        pass


def attack_brute_force():
    for i in range(4):
        ok, msg = authentication.login("ops", "wrong" + str(i))
        security_logger.log_event(
            "LOGIN_FAILED",
            "ops",
            msg,
            severity="WARNING",
            request_id="ATK-1",
            timestamp=DAY,
            _allow_custom_timestamp=True,
        )


def attack_out_of_hours():
    # This attack simulates timestamp spoofing - explicitly flagged as simulation
    security_logger.log_event(
        "RESET_REQUESTED",
        "attacker",
        "created",
        device_id="AND-001",
        request_id="ATK-2",
        timestamp=NIGHT,
        _allow_custom_timestamp=True,
    )


def attack_privilege_escalation(token):
    ok, msg = authorization.authorize(token, "approve_reset")
    security_logger.log_event(
        "ACCESS_DENIED",
        "attacker",
        msg,
        severity="WARNING",
        request_id="ATK-3",
        timestamp=DAY,
        _allow_custom_timestamp=True,
    )


def attack_unknown_device(token):
    # Use DAY timestamp for the denied event to avoid false out_of_hours
    original_log = security_logger.log_event
    def patched_log(event_type, actor, outcome, severity="INFO", role="-", device_id="-", request_id="-", timestamp=None, _allow_custom_timestamp=False):
        return original_log(event_type, actor, outcome, severity, role, device_id, request_id, timestamp=DAY, _allow_custom_timestamp=True)
    security_logger.log_event = patched_log
    try:
        reset_workflow.request_reset(token, "AND-999")
    finally:
        security_logger.log_event = original_log


def attack_replay():
    # Replay attack - same request_id twice (second should be flagged)
    # Use DAY timestamp to avoid false out_of_hours
    security_logger.log_event(
        "RESET_REQUESTED",
        "attacker",
        "created",
        device_id="AND-002",
        request_id="ATK-5",
        timestamp=DAY,
        _allow_custom_timestamp=True,
    )
    security_logger.log_event(
        "RESET_REQUESTED",
        "attacker",
        "created",
        device_id="AND-002",
        request_id="ATK-5",
        timestamp=DAY,
        _allow_custom_timestamp=True,
    )


def attack_unapproved_execute(admin_token, ops_token):
    # Patch to use DAY timestamp for clean detection
    original_log = security_logger.log_event
    def patched_log(event_type, actor, outcome, severity="INFO", role="-", device_id="-", request_id="-", timestamp=None, _allow_custom_timestamp=False):
        return original_log(event_type, actor, outcome, severity, role, device_id, request_id, timestamp=DAY, _allow_custom_timestamp=True)
    security_logger.log_event = patched_log
    try:
        ok, rid = reset_workflow.request_reset(ops_token, "AND-001")
        if ok:
            reset_workflow.execute_reset(admin_token, rid)
    finally:
        security_logger.log_event = original_log


if __name__ == "__main__":
    reset_simulated_log()

    # Use centralized seeding (env var override supported)
    seed_lab.seed_all()

    admin_token = seed_lab.get_default_token("que")
    ops_token = seed_lab.get_default_token("ops")

    if not admin_token or not ops_token:
        print("Failed to seed tokens. Check users.")
        exit(1)

    attack_brute_force()
    attack_out_of_hours()
    attack_privilege_escalation(ops_token)
    attack_unknown_device(ops_token)
    attack_replay()
    attack_unapproved_execute(admin_token, ops_token)

    print("6 attacks fired into the log.")
    print("Note: Credentials used are SIMULATION-ONLY defaults from seed_lab.py")
    print(f"DAY={DAY} (within allowed window), NIGHT={NIGHT} (outside)")
