# authentication.py - salted hashing, login, lockout
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone

import config

USERS_FILE = "data/users.json"
ITERATIONS = 100_000
# Allowed roles - prevents arbitrary role injection
ALLOWED_ROLES = {"viewer", "operator", "admin", "security_analyst"}


def _load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users):
    os.makedirs("data", exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), ITERATIONS
    ).hex()


def create_user(username, password, role="viewer"):
    if role not in ALLOWED_ROLES:
        return False
    # Basic password strength: at least 8 chars (simulation-only check)
    if len(password) < 8:
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


def login(username, password):
    """Returns (ok, message). Locks the account after repeated failures.
    Uses generic messages to prevent user enumeration.
    """
    users = _load_users()
    if username not in users:
        # Generic message - don't reveal if user exists
        return False, "invalid credentials"
    record = users[username]
    if record["failed"] >= config.MAX_FAILED_LOGINS:
        return False, "account locked"
    expected = record["hash"]
    actual = _hash_password(password, record["salt"])
    if hmac.compare_digest(expected, actual):
        record["failed"] = 0
        _save_users(users)
        return True, "welcome"
    record["failed"] += 1
    _save_users(users)
    # Generic message - don't reveal tries left to prevent enumeration
    # Internal counter still enforced, but message is generic until lockout
    if record["failed"] >= config.MAX_FAILED_LOGINS:
        return False, "account locked"
    return False, "invalid credentials"


def unlock(username):
    users = _load_users()
    if username in users:
        users[username]["failed"] = 0
        _save_users(users)
        return True
    return False


SESSIONS_FILE = "data/sessions.json"


def _load_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return {}
    with open(SESSIONS_FILE, "r") as f:
        return json.load(f)


def _save_sessions(sessions):
    os.makedirs("data", exist_ok=True)
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=2)


def start_session(username):
    """Issue a session token; the password is no longer needed."""
    sessions = _load_sessions()
    token = secrets.token_hex(16)
    sessions[token] = {
        "username": username,
        "role": _load_users()[username]["role"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_sessions(sessions)
    return token



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
    