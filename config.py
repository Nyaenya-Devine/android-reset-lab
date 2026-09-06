# config.py - policy settings only, no logic here
import os

LAB_NAME = "Android Reset Lab"
SIMULATION_MODE = True        # must stay True: the lab never touches real devices
LOG_FILE = "logs/security_log.jsonl"
RESET_WINDOW = (8, 18)        # approved hours: 08:00-18:00 (inclusive start, exclusive end)
MAX_FAILED_LOGINS = 3         # lockout threshold
LOCKOUT_DURATION_MINUTES = 15 # time-based lockout: auto-unlock after 15 min (P1 fix)
SESSION_TTL_MINUTES = 30      # sessions expire after 30 minutes

# P1: Detection and rate limiting settings
BRUTE_FORCE_WINDOW_MINUTES = 10  # brute force detection window
RATE_LIMIT_REQUESTS = 10         # max requests per IP per minute for web console
RATE_LIMIT_WINDOW_SECONDS = 60
PASSWORD_MIN_LENGTH = 8

# P2: Persistent storage settings
# Options: "json" (default, simple, human-readable) or "sqlite" (ACID, better concurrency)
STORAGE_BACKEND = os.getenv("LAB_STORAGE_BACKEND", "json")
STORAGE_DB = os.getenv("LAB_STORAGE_DB", "data/lab.db")

# P2: Additional security settings
AUTH_RATE_LIMIT_REQUESTS = 5      # max login attempts per IP per minute
AUTH_RATE_LIMIT_WINDOW_SECONDS = 60
CSRF_TOKEN_TTL_MINUTES = 30       # CSRF token validity

# P3: Slow improvements - keep simulation-only guard
HASH_ALGO = os.getenv("LAB_HASH_ALGO", "pbkdf2")  # pbkdf2 (default) or argon2id
HMAC_KEY_FILE = os.getenv("LAB_HMAC_KEY_FILE", "data/hmac.key")
LOG_SHIP_STDOUT = os.getenv("LAB_LOG_SHIP_STDOUT", "false").lower() == "true"
LOG_SHIP_FILE = os.getenv("LAB_LOG_SHIP_FILE", "")  # optional SIEM file
TOTP_ISSUER = os.getenv("LAB_TOTP_ISSUER", "AndroidResetLab")
MFA_REQUIRED = os.getenv("LAB_MFA_REQUIRED", "false").lower() == "true"  # simulation only