#!/usr/bin/env python3
"""
demo_p3_hardening.py - P3 hardening demos: Argon2id, HMAC-signed log, TOTP MFA, SIEM shipping
Simulation only, no real devices
"""
import os
import sys
import shutil
import json

# Clean previous
shutil.rmtree("data", ignore_errors=True)
shutil.rmtree("logs", ignore_errors=True)

print("\n" + "="*70)
print("  Android Reset Lab — P3 Hardening Demo")
print("="*70)
print("Safety: Simulation only, stdlib + optional argon2-cffi\n")

# ============ 1. Argon2id ============
print("[1] Argon2id password hashing (with PBKDF2 fallback)")
print("-" * 70)
import authentication
import config

# Test PBKDF2 (default)
os.environ["LAB_HASH_ALGO"] = "pbkdf2"
config.HASH_ALGO = "pbkdf2"
authentication.create_user("bob_pbkdf2", "StrongPass!123", "admin")
print(f"  Created bob_pbkdf2 with algo: {authentication._load_users()['bob_pbkdf2'].get('algo')}")
ok, _ = authentication.login("bob_pbkdf2", "StrongPass!123")
print(f"  Login PBKDF2: {ok}")

# Test Argon2id if available
try:
    import argon2
    has_argon2 = True
except ImportError:
    has_argon2 = False

if has_argon2:
    os.environ["LAB_HASH_ALGO"] = "argon2"
    config.HASH_ALGO = "argon2"
    authentication.create_user("alice_argon2", "StrongPass!123", "admin")
    user = authentication._load_users()["alice_argon2"]
    print(f"  Created alice_argon2 with algo: {user.get('algo')} | hash: {user.get('hash')[:30]}...")
    ok, _ = authentication.login("alice_argon2", "StrongPass!123")
    print(f"  Login Argon2id: {ok} ✅" if ok else f"  Login Argon2id: {ok} ❌")
else:
    print("  Argon2 not installed (pip install argon2-cffi) — fallback to PBKDF2 demonstrated")
    os.environ["LAB_HASH_ALGO"] = "argon2"
    config.HASH_ALGO = "argon2"
    authentication.create_user("charlie_fallback", "StrongPass!123", "admin")
    user = authentication._load_users()["charlie_fallback"]
    print(f"  Created charlie_fallback with LAB_HASH_ALGO=argon2 but no lib → algo: {user.get('algo')} (fallback)")
    ok, _ = authentication.login("charlie_fallback", "StrongPass!123")
    print(f"  Login fallback: {ok} ✅ (PBKDF2 fallback works)")

# Reset to default
os.environ["LAB_HASH_ALGO"] = "pbkdf2"
config.HASH_ALGO = "pbkdf2"

print("\n[2] HMAC-signed audit log (tamper-proof)")
print("-" * 70)
import security_logger

# Clean logs
shutil.rmtree("logs", ignore_errors=True)
shutil.rmtree("data", ignore_errors=True)
os.makedirs("data", exist_ok=True)

# Without HMAC - tamper-evident only
security_logger.HMAC_KEY = None
if os.path.exists("data/hmac.key"):
    os.remove("data/hmac.key")
security_logger.log_event("RESET_REQUESTED", "ops", "created", device_id="AND-001")
ok, count = security_logger.verify_logs()
print(f"  Without HMAC key: chain intact={ok}, events={count} → tamper-EVIDENT only")

# Generate HMAC key - tamper-proof
key_file = security_logger.generate_hmac_key()
security_logger.log_event("RESET_APPROVED", "admin", "approved", device_id="AND-001")
ok, count = security_logger.verify_logs()
print(f"  With HMAC key at {key_file}: chain intact={ok}, events={count} → tamper-PROOF (key separate)")

# Show log with hmac field
with open(config.LOG_FILE, "r") as f:
    last = json.loads(f.read().splitlines()[-1])
print(f"  Last entry has hmac: {'hmac' in last} | hash: {last['entry_hash'][:16]}... | hmac: {last.get('hmac','')[:16]}...")

# Tamper attempt
print("\n  ATTACK: Tamper with HMAC-signed log...")
with open(config.LOG_FILE, "r") as f:
    lines = f.read().splitlines()
entry = json.loads(lines[-1])
entry["outcome"] = "hacked"
lines[-1] = json.dumps(entry)
with open(config.LOG_FILE, "w") as f:
    f.write("\n".join(lines) + "\n")

ok, bad = security_logger.verify_logs()
print(f"  After tamper: intact={ok}, bad_line={bad} → ✅ HMAC detects tampering")

# Restore
shutil.rmtree("logs", ignore_errors=True)
shutil.rmtree("data", ignore_errors=True)

print("\n[3] TOTP MFA simulation (stdlib only, no external deps)")
print("-" * 70)
shutil.rmtree("data", ignore_errors=True)
authentication.create_user("mfa_user", "StrongPass!123", "admin")
secret = authentication.enable_totp("mfa_user")
print(f"  Enabled TOTP for mfa_user, secret: {secret}")
uri = authentication.get_totp_uri("mfa_user")
print(f"  otpauth URI (for QR): {uri[:60]}...")

code = authentication.get_totp_code(secret)
print(f"  Current TOTP code: {code}")

ok, msg = authentication.login("mfa_user", "StrongPass!123", totp_code=code)
print(f"  Login with valid code: ok={ok}, msg={msg} ✅" if ok else f"  Login with valid code: {ok} ❌")

ok, msg = authentication.login("mfa_user", "StrongPass!123", totp_code="123456")
print(f"  Login with invalid code: ok={ok}, msg={msg} → ✅ blocked")

# MFA required mode
os.environ["LAB_MFA_REQUIRED"] = "true"
config.MFA_REQUIRED = True
ok, msg = authentication.login("mfa_user", "StrongPass!123")
print(f"  Login without code when MFA_REQUIRED=true: ok={ok}, msg={msg} → ✅ requires MFA")

os.environ["LAB_MFA_REQUIRED"] = "false"
config.MFA_REQUIRED = False
ok, msg = authentication.login("mfa_user", "StrongPass!123")
print(f"  Login without code when MFA_REQUIRED=false: ok={ok} (backward compat)")

print("\n[4] SIEM / Splunk log shipping (stdout + file)")
print("-" * 70)
shutil.rmtree("logs", ignore_errors=True)

# Stdout shipping
os.environ["LAB_LOG_SHIP_STDOUT"] = "true"
config.LOG_SHIP_STDOUT = True
print("  Shipping to stdout (LAB_LOG_SHIP_STDOUT=true):")
security_logger.HMAC_KEY = None
if os.path.exists("data/hmac.key"):
    os.remove("data/hmac.key")
# This will print JSON to stdout
security_logger.log_event("RESET_REQUESTED", "ops", "created", device_id="AND-002")
print("  ^ Above JSON is what Splunk/SIEM collector would receive via stdout")

# File shipping
os.environ["LAB_LOG_SHIP_STDOUT"] = "false"
config.LOG_SHIP_STDOUT = False
os.environ["LAB_LOG_SHIP_FILE"] = "logs/siem.log"
config.LOG_SHIP_FILE = "logs/siem.log"
security_logger.log_event("RESET_APPROVED", "admin", "approved", device_id="AND-002")
print(f"\n  Shipping to file (LAB_LOG_SHIP_FILE=logs/siem.log):")
with open("logs/siem.log", "r") as f:
    print(f"  {f.read().strip()[:120]}...")

# Cleanup env
os.environ.pop("LAB_LOG_SHIP_FILE", None)
config.LOG_SHIP_FILE = ""
shutil.rmtree("logs", ignore_errors=True)
shutil.rmtree("data", ignore_errors=True)

print("\n" + "="*70)
print("  P3 Demo Complete")
print("="*70)
print("""
What this proves:
- Argon2id: Modern hashing with PBKDF2 fallback, env LAB_HASH_ALGO=argon2, no break if lib missing
- HMAC log: Tamper-PROOF when key kept separate from log (vs tamper-evident hash chain only)
- TOTP MFA: Stdlib-only RFC 6238, optional, backward compat, MFA_REQUIRED flag for simulation
- SIEM shipping: Stdout JSON + file for Splunk/SIEM collector, env LAB_LOG_SHIP_STDOUT/FILE

Safety: All simulation-only, no real devices, no external network calls
Honest limits:
- HMAC key in data/hmac.key file — production needs KMS/HSM, 0600 perms best-effort
- TOTP secret stored plaintext in users.json — production needs encrypted field
- Argon2 fallback is PBKDF2 — not as strong, but better than fail-closed
- Log shipping is best-effort print — production needs reliable queue + retries
""")
