# tests/test_workflow.py - the rules a reset can never break
import os
import sys

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