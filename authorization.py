# authorization.py - role-based access control (RBAC)
PERMISSIONS = {
    "viewer": {"view_dashboard"},
    "operator": {"view_dashboard", "request_reset"},
    "admin": {"view_dashboard", "request_reset",
              "approve_reset", "manage_users"},
    "security_analyst": {"view_dashboard", "view_logs"},
}


def can(role, action):
    """Default deny: unknown role or missing permission -> False."""
    return action in PERMISSIONS.get(role, set())


import authentication


def authorize(token, action):
    """Does this session token permit this action? Default deny."""
    session = authentication.check_session(token)
    if session is None:
        return False, "no session"
    if can(session["role"], action):
        return True, "allowed"
    return False, "forbidden for role " + session["role"]


if __name__ == "__main__":
    authentication.create_user("que", "LabRat!2026", "admin")
    authentication.create_user("ops", "OpsOps!123", "operator")
    authentication.login("que", "LabRat!2026")
    admin_token = authentication.start_session("que")
    authentication.login("ops", "OpsOps!123")
    ops_token = authentication.start_session("ops")

    print("admin approve_reset:", authorize(admin_token, "approve_reset"))
    print("operator approve_reset:", authorize(ops_token, "approve_reset"))
    print("operator request_reset:", authorize(ops_token, "request_reset"))
    print("stolen token:", authorize("deadbeef", "view_dashboard"))
    for role in PERMISSIONS:
        print(role, "may approve_reset:", can(role, "approve_reset"))
    print("ghost role:", can("intern", "view_dashboard"))