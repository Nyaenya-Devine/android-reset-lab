# config.py - policy settings only, no logic here
LAB_NAME = "Android Reset Lab"
SIMULATION_MODE = True        # must stay True: the lab never touches real devices
LOG_FILE = "logs/security_log.jsonl"
RESET_WINDOW = (8, 18)        # approved hours: 08:00-18:00
MAX_FAILED_LOGINS = 3         # lockout threshold
SESSION_TTL_MINUTES = 30      # sessions expire after 30 minutes