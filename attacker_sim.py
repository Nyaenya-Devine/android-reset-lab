# attacker_sim.py - red team harness (simulated attacks only)
import os

import config
import authentication
import authorization
import device_simulator
import reset_workflow
import security_logger
import seed_lab

NIGHT = "2026-08-31T03:00:00+00:00"


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
    )


def attack_unknown_device(token):
    reset_workflow.request_reset(token, "AND-999")


def attack_replay():
    # Replay attack - same request_id twice (second should be flagged)
    security_logger.log_event(
        "RESET_REQUESTED",
        "attacker",
        "created",
        device_id="AND-002",
        request_id="ATK-5",
    )
    security_logger.log_event(
        "RESET_REQUESTED",
        "attacker",
        "created",
        device_id="AND-002",
        request_id="ATK-5",
    )


def attack_unapproved_execute(admin_token, ops_token):
    ok, rid = reset_workflow.request_reset(ops_token, "AND-001")
    if ok:
        reset_workflow.execute_reset(admin_token, rid)


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