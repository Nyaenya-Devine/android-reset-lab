# authentication.py - salted hashing, login, lockout with persistent storage + rate limiting
import hashlib
import hmac
import json
import os
import secrets
import time
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


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), ITERATIONS
    ).hex()


def create_user(username, password, role="viewer"):
    if role not in ALLOWED_ROLES:
        return False
    # Basic password strength: at least 8 chars (simulation-only check)
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return False
    users = _load_users()
    if username in users:
        return False
    salt_hex = secrets.token_hex(16)
    users[username] = {
        "salt": salt_hex,
        "hash": _hash_password(password, salt_hex),
        "role": role,
        "failed": 0,
        "locked_until": None,  # P1: time-based lockout
        "last_failed_at": None,
    }
    _save_users(users)
    return True


def verify_password(username, password):
    users = _load_users()
    if username not in users:
        return False
    record = users[username]
    expected = record["hash"]
    actual = _hash_password(password, record["salt"])
    # Constant-time compare to prevent timing attacks
    return hmac.compare_digest(expected, actual)


def login(username, password, client_ip=None):
    """Returns (ok, message). Locks the account after repeated failures with time-based auto-unlock.
    Uses generic messages to prevent user enumeration.
    P2: Optional client_ip for IP-based rate limiting
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
    
    expected = record["hash"]
    actual = _hash_password(password, record["salt"])
    if hmac.compare_digest(expected, actual):
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
    """
    sessions = _load_sessions()
    token = secrets.token_hex(16)
    csrf_token = generate_csrf_token()
    sessions[token] = {
        "username": username,
        "role": _load_users()[username]["role"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "csrf_token": csrf_token,  # P2: CSRF protection
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
    print("Use the application or test suite to exercise authentication.")
    