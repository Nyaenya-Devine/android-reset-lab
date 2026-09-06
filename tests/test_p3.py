# tests/test_p3.py — P3 hardening tests: Argon2id, HMAC, TOTP, SIEM shipping
import os
import sys
import json
import shutil
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import authentication
import security_logger
import config

def test_argon2id_hash_and_verify():
    """P3: Argon2id with PBKDF2 fallback"""
    try:
        import argon2
        has_argon2 = True
    except ImportError:
        has_argon2 = False
    
    # Always test PBKDF2 default
    os.environ["LAB_HASH_ALGO"] = "pbkdf2"
    config.HASH_ALGO = "pbkdf2"
    authentication.create_user("t_argon_pbkdf2", "StrongPass!123", "viewer")
    assert authentication.verify_password("t_argon_pbkdf2", "StrongPass!123")
    assert not authentication.verify_password("t_argon_pbkdf2", "wrong")
    
    if has_argon2:
        os.environ["LAB_HASH_ALGO"] = "argon2"
        config.HASH_ALGO = "argon2"
        authentication.create_user("t_argon2", "StrongPass!123", "viewer")
        users = authentication._load_users()
        assert users["t_argon2"]["algo"] == "argon2id"
        assert authentication.verify_password("t_argon2", "StrongPass!123")
        assert not authentication.verify_password("t_argon2", "wrong")
    
    # Reset
    os.environ["LAB_HASH_ALGO"] = "pbkdf2"
    config.HASH_ALGO = "pbkdf2"

def test_hmac_signed_log():
    """P3: HMAC-signed audit log tamper-proof"""
    # Clean
    if os.path.exists(config.LOG_FILE):
        os.remove(config.LOG_FILE)
    if os.path.exists("data/hmac.key"):
        os.remove("data/hmac.key")
    security_logger.HMAC_KEY = None
    
    # Without HMAC - should still work
    security_logger.log_event("TEST", "alice", "no hmac")
    ok, _ = security_logger.verify_logs()
    assert ok
    
    # With HMAC
    security_logger.generate_hmac_key()
    security_logger.log_event("TEST_HMAC", "bob", "with hmac")
    ok, count = security_logger.verify_logs()
    assert ok
    assert count == 2
    
    # Check hmac field present
    with open(config.LOG_FILE, "r") as f:
        lines = f.read().splitlines()
        last = json.loads(lines[-1])
        assert "hmac" in last
        assert "entry_hash" in last
    
    # Tamper detection
    entry = json.loads(lines[-1])
    entry["outcome"] = "hacked"
    lines[-1] = json.dumps(entry)
    with open(config.LOG_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    
    ok, bad = security_logger.verify_logs()
    assert not ok
    assert bad == 2
    
    # Cleanup
    if os.path.exists("data/hmac.key"):
        os.remove("data/hmac.key")
    security_logger.HMAC_KEY = None

def test_totp_generation_and_verification():
    """P3: TOTP MFA simulation"""
    secret = authentication.generate_totp_secret()
    assert secret
    assert len(secret) >= 16
    
    code = authentication.get_totp_code(secret)
    assert code
    assert len(code) == 6
    assert code.isdigit()
    
    assert authentication.verify_totp(secret, code)
    assert not authentication.verify_totp(secret, "123456")
    assert not authentication.verify_totp(secret, "")
    assert not authentication.verify_totp("", code)

def test_totp_mfa_login_flow():
    """P3: MFA login flow"""
    authentication.create_user("t_mfa", "StrongPass!123", "viewer")
    secret = authentication.enable_totp("t_mfa")
    assert secret
    
    code = authentication.get_totp_code(secret)
    
    # Login with valid code should succeed
    ok, msg = authentication.login("t_mfa", "StrongPass!123", totp_code=code)
    assert ok
    
    # Login with invalid code should fail
    ok, msg = authentication.login("t_mfa", "StrongPass!123", totp_code="000000")
    assert not ok
    assert "mfa" in msg.lower() or "invalid" in msg.lower()
    
    # When MFA_REQUIRED=true, login without code should fail
    os.environ["LAB_MFA_REQUIRED"] = "true"
    config.MFA_REQUIRED = True
    ok, msg = authentication.login("t_mfa", "StrongPass!123")
    assert not ok
    assert "mfa required" in msg.lower()
    
    # Cleanup
    os.environ["LAB_MFA_REQUIRED"] = "false"
    config.MFA_REQUIRED = False
    authentication.disable_totp("t_mfa")

def test_log_shipping_stdout_and_file(tmp_path):
    """P3: SIEM log shipping"""
    # Test file shipping
    siem_file = str(tmp_path / "siem.log")
    os.environ["LAB_LOG_SHIP_FILE"] = siem_file
    config.LOG_SHIP_FILE = siem_file
    
    # Clean log
    if os.path.exists(config.LOG_FILE):
        os.remove(config.LOG_FILE)
    
    security_logger.HMAC_KEY = None
    if os.path.exists("data/hmac.key"):
        os.remove("data/hmac.key")
    
    security_logger.log_event("TEST_SHIP", "alice", "ship test")
    
    # Check siem file exists and has content
    assert os.path.exists(siem_file)
    with open(siem_file, "r") as f:
        content = f.read()
        assert "TEST_SHIP" in content
        assert "alice" in content
    
    # Cleanup
    os.environ.pop("LAB_LOG_SHIP_FILE", None)
    config.LOG_SHIP_FILE = ""
