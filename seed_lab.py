# seed_lab.py - centralized lab seeding (simulation-only)
# This file contains default credentials for the SIMULATION ONLY.
# In production, credentials must come from env vars / secret manager.
# Passwords here are for demo/testing and must not be reused in production.
import os
import authentication
import device_simulator

# Default simulation credentials - override via env vars if set
DEFAULT_USERS = {
    "que": {"password": os.getenv("LAB_ADMIN_PASS", "LabRat!2026"), "role": "admin"},
    "ops": {"password": os.getenv("LAB_OPS_PASS", "OpsOps!123"), "role": "operator"},
    "analyst": {"password": os.getenv("LAB_ANALYST_PASS", "Analyst!2026"), "role": "security_analyst"},
}

def seed_all():
    """Seed devices and default users. Safe to call multiple times."""
    device_simulator.seed_devices()
    created = []
    for username, info in DEFAULT_USERS.items():
        if authentication.create_user(username, info["password"], info["role"]):
            created.append(username)
    return created

def get_default_token(username="que"):
    """Helper for demos: login and get token for a seeded user."""
    users = DEFAULT_USERS
    if username not in users:
        return None
    ok, _ = authentication.login(username, users[username]["password"])
    if not ok:
        # Try unlock if locked
        authentication.unlock(username)
        ok, _ = authentication.login(username, users[username]["password"])
        if not ok:
            return None
    return authentication.start_session(username)

if __name__ == "__main__":
    created = seed_all()
    print(f"Seeded devices and users. New users created: {created}")
    print("Default users (SIMULATION ONLY):")
    for u, info in DEFAULT_USERS.items():
        print(f"  {u} / role={info['role']} (password from env or default)")
