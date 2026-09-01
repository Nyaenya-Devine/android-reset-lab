# config.py - policy settings only, no logic here
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