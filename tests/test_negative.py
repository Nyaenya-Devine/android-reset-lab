# tests/test_negative.py — Negative and attack tests (P2)
# Tests that verify system correctly rejects malicious or invalid inputs
import sys
import os
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import authentication
import authorization
import reset_workflow
import device_simulator
import security_logger
import config

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

# === Authentication Negative Tests ===

def test_login_with_empty_username():
    ok, msg = authentication.login("", "somepass")
    assert not ok

def test_login_with_empty_password():
    authentication.create_user("t_empty_pass", "ValidPass!1", "viewer")
    ok, msg = authentication.login("t_empty_pass", "")
    assert not ok

def test_login_with_sql_injection_username():
    # Username with SQL injection attempt should be treated as invalid credentials, not crash
    ok, msg = authentication.login("admin' OR '1'='1", "password")
    assert not ok
    assert "invalid credentials" in msg

def test_login_with_xss_payload():
    ok, msg = authentication.login("<script>alert(1)</script>", "password")
    assert not ok

def test_create_user_with_invalid_role():
    ok = authentication.create_user("t_hacker", "ValidPass!1", "superadmin")
    assert not ok

def test_create_user_with_weak_password():
    ok = authentication.create_user("t_weak", "123", "viewer")
    assert not ok
    ok = authentication.create_user("t_weak2", "short", "viewer")
    assert not ok

def test_rate_limiting_blocks_after_many_attempts():
    """P2: Rate limiting around authentication"""
    authentication.create_user("t_ratelimit", "ValidPass!1", "viewer")
    # Clear rate limit store
    authentication._auth_rate_limit_store.clear()
    
    # Try many rapid logins (should trigger rate limit after 5)
    for i in range(5):
        authentication.login("t_ratelimit", f"wrong{i}", client_ip="1.2.3.4")
    
    # 6th attempt should be rate limited
    ok, msg = authentication.login("t_ratelimit", "ValidPass!1", client_ip="1.2.3.4")
    # Could be rate limited or account locked - both are valid blocks
    assert not ok
    assert "too many" in msg or "account locked" in msg

def test_csrf_token_validation():
    """P2: CSRF token validation"""
    authentication.create_user("t_csrf", "ValidPass!1", "admin")
    authentication.login("t_csrf", "ValidPass!1")
    token = authentication.start_session("t_csrf")
    session = authentication.check_session(token)
    
    csrf = session.get("csrf_token")
    assert csrf is not None
    assert len(csrf) > 10
    
    # Valid CSRF should pass
    assert authentication.validate_csrf_token(token, csrf)
    
    # Invalid CSRF should fail
    assert not authentication.validate_csrf_token(token, "invalid-token")
    assert not authentication.validate_csrf_token(token, "")
    assert not authentication.validate_csrf_token("invalid-session", csrf)

# === Authorization Negative Tests ===

def test_stolen_token_rejected():
    ok, msg = authorization.authorize("deadbeef-invalid-token", "request_reset")
    assert not ok
    assert "no session" in msg

def test_viewer_cannot_request_or_approve():
    authentication.create_user("t_viewer", "ViewerPass!1", "viewer")
    authentication.login("t_viewer", "ViewerPass!1")
    viewer_token = authentication.start_session("t_viewer")
    
    ok, msg = reset_workflow.request_reset(viewer_token, "AND-001")
    assert not ok
    
    # Even if request exists, viewer cannot approve
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-001")
    assert ok
    ok, msg = reset_workflow.approve_reset(viewer_token, rid)
    assert not ok

def test_operator_cannot_approve_or_manage_users():
    admin, ops = _tokens()
    assert not authorization.can("operator", "approve_reset")
    assert not authorization.can("operator", "manage_users")
    assert authorization.can("operator", "request_reset")

def test_expired_session_rejected():
    authentication.create_user("t_exp2", "ExpPass!1", "admin")
    authentication.login("t_exp2", "ExpPass!1")
    token = authentication.start_session("t_exp2")
    
    # Manually expire session
    sessions = authentication._load_sessions()
    sessions[token]["created_at"] = "2020-01-01T00:00:00+00:00"
    authentication._save_sessions(sessions)
    
    ok, msg = reset_workflow.request_reset(token, "AND-001")
    assert not ok
    assert "no session" in msg or "forbidden" in msg or "no session" in msg

# === Workflow Negative Tests ===

def test_request_with_invalid_device_id():
    admin, ops = _tokens()
    # SQL injection attempt in device_id
    ok, msg = reset_workflow.request_reset(ops, "AND-001' OR '1'='1")
    assert not ok
    
    # XSS attempt
    ok, msg = reset_workflow.request_reset(ops, "<script>alert(1)</script>")
    assert not ok
    
    # Empty
    ok, msg = reset_workflow.request_reset(ops, "")
    assert not ok

def test_approve_nonexistent_request():
    admin, ops = _tokens()
    ok, msg = reset_workflow.approve_reset(admin, "nonexistent-id-12345")
    assert not ok
    assert "no such request" in msg

def test_execute_without_approval():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-002")
    assert ok
    # Try execute without approval
    ok, msg = reset_workflow.execute_reset(admin, rid)
    assert not ok
    assert "not approved" in msg

def test_double_execution_blocked():
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(ops, "AND-003")
    assert ok
    ok, _ = reset_workflow.approve_reset(admin, rid)
    assert ok
    ok, _ = reset_workflow.execute_reset(admin, rid)
    assert ok
    # Second execution should fail
    ok, msg = reset_workflow.execute_reset(admin, rid)
    assert not ok
    assert "already wiped" in msg or "not approved" in msg or "executed" in msg

def test_self_approval_blocked_regression():
    """Demo: self-approval blocked - critical for four-eyes"""
    admin, ops = _tokens()
    ok, rid = reset_workflow.request_reset(admin, "AND-004")
    assert ok
    ok, msg = reset_workflow.approve_reset(admin, rid)
    assert not ok
    assert "differ" in msg

# === Storage and Integrity Negative Tests ===

def test_audit_log_tampering_detected_detailed():
    """Demo: ledger attack detected"""
    import json
    security_logger.log_event("TEST_TAMPER", "tester", "original")
    
    with open(config.LOG_FILE, "r") as f:
        lines = f.read().splitlines()
    
    # Tamper
    entry = json.loads(lines[-1])
    entry["outcome"] = "hacked"
    lines[-1] = json.dumps(entry)
    
    with open(config.LOG_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    
    ok, bad_line = security_logger.verify_logs()
    assert not ok
    assert bad_line == len(lines)

def test_device_fleet_immutable_via_shallow_copy():
    """P2: Ensure FLEET global not mutated via shallow copy bug"""
    original_status = device_simulator.FLEET["AND-001"]["status"]
    
    devices = device_simulator.load_devices()
    devices["AND-001"]["status"] = "hacked"
    
    # Global FLEET should still be original
    assert device_simulator.FLEET["AND-001"]["status"] == original_status
