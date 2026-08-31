# tests/test_workflow.py - the rules a reset can never break
import json
import os
import sys
import config
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import authentication
import authorization
import device_simulator
import reset_workflow


def _tokens():
    authentication.unlock("t_admin")
    authentication.unlock("t_ops")
    authentication.create_user("t_admin", "AdminPass!1", "admin")
    authentication.create_user("t_ops", "OpsPass!1", "operator")
    authentication.login("t_admin", "AdminPass!1")
    admin = authentication.start_session("t_admin")
    authentication.login("t_ops", "OpsPass!1")
    ops = authentication.start_session("t_ops")
    return admin, ops


def test_execute_without_approval_blocked():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-004")
    assert ok
    ok, msg = reset_workflow.execute_reset(admin, rid)
    assert not ok
    assert "not approved" in msg


def test_self_approval_blocked():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(admin, "AND-005")
    assert ok
    ok, msg = reset_workflow.approve_reset(admin, rid)
    assert not ok
    assert "differ" in msg


def test_unknown_device_denied():
    admin, ops = _tokens()
    ok, msg = reset_workflow.request_reset(ops, "AND-999")
    assert not ok
    assert "fleet" in msg


def test_operator_cannot_approve():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-004")
    ok, msg = reset_workflow.approve_reset(ops, rid)
    assert not ok


def test_approved_reset_wipes_simulated_device():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-004")
    ok, msg = reset_workflow.approve_reset(admin, rid)
    assert ok
    ok, msg = reset_workflow.execute_reset(admin, rid)
    assert ok
    assert device_simulator.get_device("AND-004")["status"] == "wiped"
def test_session_expires():
    authentication.create_user("t_exp", "ExpPass!1", "viewer")
    authentication.login("t_exp", "ExpPass!1")
    token = authentication.start_session("t_exp")
    sessions = authentication._load_sessions()
    sessions[token]["created_at"] = "2020-01-01T00:00:00+00:00"
    authentication._save_sessions(sessions)
    assert authentication.check_session(token) is None


def test_wrong_password_rejected():
    authentication.create_user("t_wrong", "CorrectPass!1", "viewer")
    ok, msg = authentication.login("t_wrong", "WrongPass!1")
    assert not ok
    assert "bad password" in msg


def test_account_locks_after_three_failures():
    authentication.create_user("t_lock", "CorrectPass!1", "viewer")

    for _ in range(3):
        ok, msg = authentication.login("t_lock", "WrongPass!1")
        assert not ok

    ok, msg = authentication.login("t_lock", "CorrectPass!1")
    assert not ok
    assert msg == "account locked"


def test_successful_login_resets_failed_counter():
    authentication.create_user("t_reset", "CorrectPass!1", "viewer")

    authentication.login("t_reset", "WrongPass!1")
    ok, msg = authentication.login("t_reset", "CorrectPass!1")

    assert ok
    assert msg == "welcome"


def test_invalid_session_rejected():
    assert authentication.check_session("definitely-invalid-token") is None


def test_logout_invalidates_session():
    authentication.create_user("t_logout", "LogoutPass!1", "viewer")
    authentication.login("t_logout", "LogoutPass!1")
    token = authentication.start_session("t_logout")

    assert authentication.check_session(token) is not None

    authentication.end_session(token)

    assert authentication.check_session(token) is None


def test_unknown_role_denied():
    assert authorization.can("unknown_role", "view_dashboard") is False


def test_viewer_cannot_request_reset():
    assert authorization.can("viewer", "request_reset") is False


def test_operator_cannot_approve_reset():
    assert authorization.can("operator", "approve_reset") is False


def test_admin_can_approve_reset():
    assert authorization.can("admin", "approve_reset") is True


def test_viewer_cannot_request_reset():
    assert authorization.can("viewer", "request_reset") is False


def test_operator_cannot_approve_reset():
    assert authorization.can("operator", "approve_reset") is False


def test_admin_can_approve_reset():
    assert authorization.can("admin", "approve_reset") is True
def test_audit_log_tampering_detected():
    import security_logger

    security_logger.log_event(
        "TEST_INTEGRITY",
        "tester",
        "original"
    )

    with open(config.LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    entry = json.loads(lines[-1])
    entry["outcome"] = "tampered"

    lines[-1] = json.dumps(entry)

    with open(config.LOG_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    ok, bad_line = security_logger.verify_logs()

    assert ok is False
    assert bad_line == len(lines)