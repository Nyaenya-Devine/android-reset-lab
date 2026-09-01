# reset_workflow.py - request -> approve -> simulated execute
import json
import os
import secrets

import authentication
import authorization
import device_simulator
import security_logger

REQUESTS_FILE = "data/requests.json"


def _load_requests():
    if not os.path.exists(REQUESTS_FILE):
        return {}
    with open(REQUESTS_FILE, "r") as f:
        return json.load(f)


def _save_requests(requests):
    os.makedirs("data", exist_ok=True)
    with open(REQUESTS_FILE, "w") as f:
        json.dump(requests, f, indent=2)


def request_reset(token, device_id):
    ok, msg = authorization.authorize(token, "request_reset")
    if not ok:
        return False, msg
    session = authentication.check_session(token)
    if session is None:
        return False, "no session"
    # Validate device exists before creating request
    if device_simulator.get_device(device_id) is None:
        # Fixed: log actual actor, not "unknown" (was bug)
        security_logger.log_event("RESET_REQUESTED", session["username"],
                                  "denied: device not in fleet",
                                  severity="WARNING", device_id=device_id)
        return False, "device not in fleet"
    # Ensure request_id uniqueness (avoid collision)
    requests = _load_requests()
    for _ in range(5):
        request_id = secrets.token_hex(8)
        if request_id not in requests:
            break
    else:
        return False, "could not generate unique request id"
    requests[request_id] = {
        "device_id": device_id,
        "requester": session["username"],
        "approver": None,
        "status": "requested",
    }
    _save_requests(requests)
    security_logger.log_event("RESET_REQUESTED", session["username"], "created",
                              device_id=device_id, request_id=request_id)
    return True, request_id


def approve_reset(token, request_id):
    ok, msg = authorization.authorize(token, "approve_reset")
    if not ok:
        return False, msg
    requests = _load_requests()
    if request_id not in requests:
        return False, "no such request"
    req = requests[request_id]
    if req["status"] != "requested":
        return False, "not in requested state"
    session = authentication.check_session(token)
    if session["username"] == req["requester"]:
        security_logger.log_event("APPROVAL_DENIED", session["username"],
                                  "four-eyes violation", severity="WARNING",
                                  device_id=req["device_id"], request_id=request_id)
        return False, "approver must differ from requester"
    req["approver"] = session["username"]
    req["status"] = "approved"
    _save_requests(requests)
    security_logger.log_event("RESET_APPROVED", session["username"], "approved",
                              device_id=req["device_id"], request_id=request_id)
    return True, "approved"


def execute_reset(token, request_id):
    ok, msg = authorization.authorize(token, "approve_reset")
    if not ok:
        return False, msg
    session = authentication.check_session(token)
    if session is None:
        return False, "no session"
    requests = _load_requests()
    if request_id not in requests:
        return False, "no such request"
    req = requests[request_id]
    if req["status"] != "approved":
        # Fixed: log actual executor, not "system"
        security_logger.log_event("RESET_BLOCKED", session["username"],
                                  "execute without approval denied",
                                  severity="HIGH", device_id=req["device_id"],
                                  request_id=request_id)
        return False, "SIMULATION GUARD: reset not approved"
    # Re-validate device exists at execution time
    devices = device_simulator.load_devices()
    if req["device_id"] not in devices:
        return False, "device not in fleet"
    # Prevent double-wipe
    if devices[req["device_id"]].get("status") == "wiped":
        return False, "device already wiped"
    devices[req["device_id"]]["status"] = "wiped"
    device_simulator.save_devices(devices)
    req["status"] = "executed"
    _save_requests(requests)
    # Fixed: log actual executor, not approver (was bug)
    security_logger.log_event("RESET_EXECUTED", session["username"],
                              "SIMULATED wipe complete", severity="WARNING",
                              device_id=req["device_id"], request_id=request_id)
    return True, "SIMULATED wipe complete (no real device touched)"


if __name__ == "__main__":
    import seed_lab
    seed_lab.seed_all()
    admin_token = seed_lab.get_default_token("que")
    ops_token = seed_lab.get_default_token("ops")

    ok, rid1 = request_reset(ops_token, "AND-003")
    print("1 request by operator:", ok)
    print("2 execute too early:", execute_reset(admin_token, rid1))
    print("3 approve by admin:", approve_reset(admin_token, rid1))
    print("4 execute:", execute_reset(admin_token, rid1))
    print("5 device AND-003:", device_simulator.get_device("AND-003")["status"])
    ok, rid2 = request_reset(admin_token, "AND-006")
    print("6 request by admin:", ok)
    print("7 admin self-approve:", approve_reset(admin_token, rid2))
    print("Note: Using seed_lab.py for simulation credentials")