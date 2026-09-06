# authentication.py - salted hashing, login, lockout with P3 hardening
# P3: Argon2id option with PBKDF2 fallback, TOTP MFA simulation, rate limiting
import hashlib
import hmac
import json
import os
import secrets
import time
import base64
import struct
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import config

USERS_FILE = "data/users.json"
SESSIONS_FILE = "data/sessions.json"
ITERATIONS = 100_000
# Allowed roles - prevents arbitrary role injection
ALLOWED_ROLES = {"viewer", "operator", "admin", "security_analyst"}

# P2: Rate limiting for authentication (per IP and per username)
_auth_rate_limit_store = defaultdict(deque)  # key -> deque of timestamps

def _is_rate_limited(key, max_requests, window_seconds):
    """Check if key is rate limited"""
    now = time.time()
    window_start = now - window_seconds
    dq = _auth_rate_limit_store[key]
    while dq and dq[0] < window_start:
        dq.popleft()
    if len(dq) >= max_requests:
        return True
    dq.append(now)
    return False

def is_auth_rate_limited(client_ip=None, username=None):
    """Check if authentication is rate limited by IP or username"""
    if client_ip:
        if _is_rate_limited(f"ip:{client_ip}", config.AUTH_RATE_LIMIT_REQUESTS, config.AUTH_RATE_LIMIT_WINDOW_SECONDS):
            return True, "too many attempts from this IP, try again later"
    if username:
        if _is_rate_limited(f"user:{username}", config.AUTH_RATE_LIMIT_REQUESTS, config.AUTH_RATE_LIMIT_WINDOW_SECONDS):
            return True, "too many attempts for this user, try again later"
    return False, ""

# P2: Use storage abstraction if available, fallback to JSON
try:
    import storage as storage_backend
    _USE_STORAGE = True
except ImportError:
    _USE_STORAGE = False

def _load_users():
    # Use storage abstraction if backend is sqlite
    if _USE_STORAGE:
        try:
            # Check if storage backend is sqlite via config
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                return storage_backend.load_users()
        except Exception:
            pass
    # Fallback to JSON file (original behavior, also used by tests via monkeypatch)
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _save_users(users):
    if _USE_STORAGE:
        try:
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                storage_backend.save_users(users)
                return
        except Exception:
            pass
    os.makedirs("data", exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


# ============ P3: Password Hashing - Argon2id with PBKDF2 fallback ============

def _get_hash_algo():
    """Get configured hash algo from env/config, default pbkdf2."""
    algo = os.getenv("LAB_HASH_ALGO", getattr(config, "HASH_ALGO", "pbkdf2")).lower()
    # Normalize: argon2, argon2id, argon2i all map to argon2id
    if algo.startswith("argon2"):
        return "argon2id"
    return "pbkdf2"

def _hash_password_pbkdf2(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), ITERATIONS
    ).hex()

def _hash_password_argon2(password):
    """Hash with Argon2id if available, else fallback to PBKDF2 with warning."""
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        return ph.hash(password), True
    except ImportError:
        # Fallback: PBKDF2 but mark as argon2 attempt
        salt_hex = secrets.token_hex(16)
        hash_hex = _hash_password_pbkdf2(password, salt_hex)
        # Store as pbkdf2 but with note - will be upgraded when argon2 available
        return f"$pbkdf2_fallback${salt_hex}${hash_hex}", False

def _verify_password_argon2(password, hash_str):
    """Verify Argon2id hash, with fallback handling."""
    if hash_str.startswith("$pbkdf2_fallback$"):
        # Fallback case
        try:
            _, _, salt_hex, stored_hash = hash_str.split("$")
            actual = _hash_password_pbkdf2(password, salt_hex)
            return hmac.compare_digest(stored_hash, actual)
        except ValueError:
            return False
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        ph.verify(hash_str, password)
        return True
    except ImportError:
        return False
    except Exception:
        return False

def _hash_password(password, salt_hex=None):
    """Legacy wrapper - PBKDF2 only for backward compat."""
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    return _hash_password_pbkdf2(password, salt_hex)

def create_user(username, password, role="viewer"):
    if role not in ALLOWED_ROLES:
        return False
    # Basic password strength: at least 8 chars (simulation-only check)
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return False
    users = _load_users()
    if username in users:
        return False
    
    algo = _get_hash_algo()
    
    if algo == "argon2id":
        hash_result, is_argon2 = _hash_password_argon2(password)
        if is_argon2:
            users[username] = {
                "algo": "argon2id",
                "hash": hash_result,
                "role": role,
                "failed": 0,
                "locked_until": None,
                "last_failed_at": None,
                "totp_secret": None,  # P3: MFA optional
            }
        else:
            # Fallback stored as pbkdf2_fallback
            # Parse fallback
            try:
                _, _, salt_hex, hash_hex = hash_result.split("$")
                users[username] = {
                    "algo": "pbkdf2",
                    "salt": salt_hex,
                    "hash": hash_hex,
                    "role": role,
                    "failed": 0,
                    "locked_until": None,
                    "last_failed_at": None,
                    "totp_secret": None,
                    "_argon2_fallback": True,
                }
            except ValueError:
                # Ultimate fallback
                salt_hex = secrets.token_hex(16)
                users[username] = {
                    "algo": "pbkdf2",
                    "salt": salt_hex,
                    "hash": _hash_password_pbkdf2(password, salt_hex),
                    "role": role,
                    "failed": 0,
                    "locked_until": None,
                    "last_failed_at": None,
                    "totp_secret": None,
                }
    else:
        salt_hex = secrets.token_hex(16)
        users[username] = {
            "algo": "pbkdf2",
            "salt": salt_hex,
            "hash": _hash_password_pbkdf2(password, salt_hex),
            "role": role,
            "failed": 0,
            "locked_until": None,
            "last_failed_at": None,
            "totp_secret": None,
        }
    _save_users(users)
    return True


def verify_password(username, password):
    users = _load_users()
    if username not in users:
        return False
    record = users[username]
    algo = record.get("algo", "pbkdf2")
    
    if algo == "argon2id":
        return _verify_password_argon2(password, record["hash"])
    else:
        # PBKDF2
        salt = record.get("salt")
        if not salt:
            # Try fallback parsing
            h = record.get("hash", "")
            if h.startswith("$pbkdf2_fallback$"):
                return _verify_password_argon2(password, h)
            return False
        expected = record["hash"]
        actual = _hash_password_pbkdf2(password, salt)
        # Constant-time compare to prevent timing attacks
        return hmac.compare_digest(expected, actual)


# ============ P3: TOTP MFA Simulation (stdlib only, no external deps) ============

def _base32_decode(s):
    """Base32 decode with padding handling."""
    s = s.upper().replace(" ", "")
    # Add padding if needed
    pad_len = (8 - len(s) % 8) % 8
    s += "=" * pad_len
    try:
        return base64.b32decode(s)
    except Exception:
        return None

def generate_totp_secret():
    """Generate a random base32 secret for TOTP (160-bit)."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode().rstrip("=")

def _hotp(secret_bytes, counter, digits=6):
    """HOTP per RFC 4226."""
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code = ((hmac_hash[offset] & 0x7F) << 24 |
            (hmac_hash[offset+1] & 0xFF) << 16 |
            (hmac_hash[offset+2] & 0xFF) << 8 |
            (hmac_hash[offset+3] & 0xFF))
    return code % (10 ** digits)

def get_totp_code(secret, timestamp=None, digits=6, period=30):
    """Get current TOTP code for secret."""
    if timestamp is None:
        timestamp = int(time.time())
    counter = timestamp // period
    secret_bytes = _base32_decode(secret)
    if secret_bytes is None:
        return None
    return f"{_hotp(secret_bytes, counter, digits):0{digits}d}"

def verify_totp(secret, code, window=1, digits=6, period=30):
    """Verify TOTP code with window for clock skew. window=1 allows +-1 period."""
    if not secret or not code:
        return False
    try:
        code_int = int(code)
    except ValueError:
        return False
    now = int(time.time())
    secret_bytes = _base32_decode(secret)
    if secret_bytes is None:
        return False
    # Check current and adjacent periods
    for i in range(-window, window+1):
        counter = (now // period) + i
        expected = _hotp(secret_bytes, counter, digits)
        if hmac.compare_digest(f"{expected:0{digits}d}", f"{code_int:0{digits}d}"):
            return True
    return False

def enable_totp(username):
    """Enable TOTP for user, returns secret (show QR)."""
    users = _load_users()
    if username not in users:
        return None
    secret = generate_totp_secret()
    users[username]["totp_secret"] = secret
    _save_users(users)
    return secret

def disable_totp(username):
    """Disable TOTP for user."""
    users = _load_users()
    if username not in users:
        return False
    users[username]["totp_secret"] = None
    _save_users(users)
    return True

def get_totp_uri(username, secret=None):
    """Get otpauth URI for QR code (for authenticator apps)."""
    if secret is None:
        users = _load_users()
        if username not in users:
            return None
        secret = users[username].get("totp_secret")
        if not secret:
            return None
    issuer = getattr(config, "TOTP_ISSUER", "AndroidResetLab")
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def login(username, password, client_ip=None, totp_code=None):
    """Returns (ok, message). Locks the account after repeated failures with time-based auto-unlock.
    Uses generic messages to prevent user enumeration.
    P2: Optional client_ip for IP-based rate limiting
    P3: Optional totp_code for MFA, Argon2id support
    """
    # P2: Check rate limiting before processing
    if client_ip or username:
        limited, msg = is_auth_rate_limited(client_ip, username)
        if limited:
            return False, msg
    
    users = _load_users()
    if username not in users:
        # Generic message - don't reveal if user exists
        return False, "invalid credentials"
    record = users[username]
    
    # P1: Handle time-based lockout with auto-unlock
    # Ensure backward compat: add missing fields if old user record
    if "locked_until" not in record:
        record["locked_until"] = None
    if "failed" not in record:
        record["failed"] = 0
    
    now = datetime.now(timezone.utc)
    
    # Check if currently locked
    locked_until_str = record.get("locked_until")
    if locked_until_str:
        try:
            locked_until = datetime.fromisoformat(locked_until_str)
            if now < locked_until:
                # Still locked
                remaining = int((locked_until - now).total_seconds() / 60) + 1
                return False, f"account locked (try again in {remaining}m)"
            else:
                # Lockout expired - auto-unlock
                record["failed"] = 0
                record["locked_until"] = None
        except (ValueError, TypeError):
            # Corrupted locked_until, reset
            record["locked_until"] = None
            record["failed"] = 0
    
    if record["failed"] >= config.MAX_FAILED_LOGINS:
        # Should have been caught by locked_until check, but handle legacy case
        # Set lockout now
        lockout_until = now + timedelta(minutes=config.LOCKOUT_DURATION_MINUTES)
        record["locked_until"] = lockout_until.isoformat()
        _save_users(users)
        return False, f"account locked (try again in {config.LOCKOUT_DURATION_MINUTES}m)"
    
    # Verify password based on algo
    algo = record.get("algo", "pbkdf2")
    password_ok = False
    if algo == "argon2id":
        password_ok = _verify_password_argon2(password, record.get("hash", ""))
    else:
        salt = record.get("salt")
        if not salt:
            # Handle fallback hash format
            h = record.get("hash", "")
            if h.startswith("$pbkdf2_fallback$"):
                password_ok = _verify_password_argon2(password, h)
            else:
                password_ok = False
        else:
            expected = record["hash"]
            actual = _hash_password_pbkdf2(password, salt)
            password_ok = hmac.compare_digest(expected, actual)
    
    if password_ok:
        # P3: Check TOTP MFA if enabled
        totp_secret = record.get("totp_secret")
        if totp_secret:
            mfa_required = getattr(config, "MFA_REQUIRED", False) or os.getenv("LAB_MFA_REQUIRED", "false").lower() == "true"
            if mfa_required or totp_code is not None:
                if not totp_code:
                    return False, "mfa required"
                if not verify_totp(totp_secret, totp_code):
                    record["failed"] += 1
                    record["last_failed_at"] = now.isoformat()
                    if record["failed"] >= config.MAX_FAILED_LOGINS:
                        lockout_until = now + timedelta(minutes=config.LOCKOUT_DURATION_MINUTES)
                        record["locked_until"] = lockout_until.isoformat()
                    _save_users(users)
                    return False, "invalid mfa code"
        
        record["failed"] = 0
        record["locked_until"] = None
        record["last_failed_at"] = None
        _save_users(users)
        return True, "welcome"
    
    # Failed attempt
    record["failed"] += 1
    record["last_failed_at"] = now.isoformat()
    if record["failed"] >= config.MAX_FAILED_LOGINS:
        lockout_until = now + timedelta(minutes=config.LOCKOUT_DURATION_MINUTES)
        record["locked_until"] = lockout_until.isoformat()
        _save_users(users)
        return False, f"account locked (try again in {config.LOCKOUT_DURATION_MINUTES}m)"
    
    _save_users(users)
    # Generic message - don't reveal tries left to prevent enumeration
    return False, "invalid credentials"


def login_with_mfa(username, password, totp_code, client_ip=None):
    """Explicit MFA login wrapper."""
    return login(username, password, client_ip=client_ip, totp_code=totp_code)


def unlock(username):
    users = _load_users()
    if username in users:
        users[username]["failed"] = 0
        users[username]["locked_until"] = None
        users[username]["last_failed_at"] = None
        _save_users(users)
        return True
    return False


def _load_sessions():
    if _USE_STORAGE:
        try:
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                return storage_backend.load_sessions()
        except Exception:
            pass
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _save_sessions(sessions):
    if _USE_STORAGE:
        try:
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                storage_backend.save_sessions(sessions)
                return
        except Exception:
            pass
    os.makedirs("data", exist_ok=True)
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)


def generate_csrf_token():
    """Generate a CSRF token for form protection"""
    return secrets.token_hex(16)

def start_session(username):
    """Issue a session token; the password is no longer needed.
    P2: Includes CSRF token for form protection
    P3: Includes MFA verified flag
    """
    sessions = _load_sessions()
    token = secrets.token_hex(16)
    csrf_token = generate_csrf_token()
    users = _load_users()
    mfa_enabled = bool(users.get(username, {}).get("totp_secret"))
    sessions[token] = {
        "username": username,
        "role": users[username]["role"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "csrf_token": csrf_token,  # P2: CSRF protection
        "mfa_verified": mfa_enabled,  # P3: track if MFA was used
        "hash_algo": users[username].get("algo", "pbkdf2"),  # P3: for audit
    }
    _save_sessions(sessions)
    return token

def validate_csrf_token(session_token, csrf_token):
    """Validate CSRF token for session"""
    if not session_token or not csrf_token:
        return False
    session = check_session(session_token)
    if not session:
        return False
    expected = session.get("csrf_token")
    if not expected:
        return False
    # Constant-time compare
    return hmac.compare_digest(expected, csrf_token)



def check_session(token):
    """Who does this token belong to? None if invalid or expired."""
    sessions = _load_sessions()
    session = sessions.get(token)
    if session is None:
        return None
    created = session.get("created_at")
    if created is None:
        return None
    age = (datetime.now(timezone.utc) -
           datetime.fromisoformat(created)).total_seconds() / 60
    if age > config.SESSION_TTL_MINUTES:
        del sessions[token]
        _save_sessions(sessions)
        return None
    return session


def end_session(token):
    sessions = _load_sessions()
    if token in sessions:
        del sessions[token]
        _save_sessions(sessions)
        return True
    return False


if __name__ == "__main__":
    print("Authentication module loaded successfully.")
    print(f"Hash algo: {_get_hash_algo()} (set LAB_HASH_ALGO=argon2 for Argon2id)")
    try:
        import argon2
        print("Argon2 available: yes")
    except ImportError:
        print("Argon2 available: no (pip install argon2-cffi for Argon2id, fallback to PBKDF2)")
    print("Use the application or test suite to exercise authentication.")
