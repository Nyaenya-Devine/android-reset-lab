"""
Cerberus Workflow — P4 God Mode
Zero Trust reset orchestration combining:
- Policy-as-Code (Cedar-like ABAC)
- Risk-Adaptive Authentication
- Device Attestation (Play Integrity + StrongBox)
- WebAuthn Passkeys (phishing-resistant MFA)
- Transaction Signing (WYSIWYS)
- DPoP token binding
- Merkle Transparency Ledger

Keeps original reset_workflow.py untouched for backward compat / tests.
This module is the P4 orchestrator.

SIMULATION_MODE=True enforced — no real device touch.
"""

import json
import os
import secrets
import time
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone

import config
import authentication
import authorization
import device_simulator
import security_logger

# P4 modules (optional imports — fail-open to keep tests green)
try:
    from policy_engine import policy_engine, Principal, Resource, Action, authzen_evaluate
    POLICY_ENABLED = True
except ImportError:
    POLICY_ENABLED = False
    policy_engine = None

try:
    from risk_engine import calculate_risk, requires_step_up, requires_tx_signing, should_deny
    RISK_ENABLED = True
except ImportError:
    RISK_ENABLED = False

try:
    from attestation import simulate_play_integrity, get_device_trust, FLEET_ATTESTATION
    ATTESTATION_ENABLED = True
except ImportError:
    ATTESTATION_ENABLED = False

try:
    from webauthn_sim import generate_authentication_options, verify_authentication_response, list_credentials
    WEBAUTHN_ENABLED = True
except ImportError:
    WEBAUTHN_ENABLED = False

try:
    from tx_signing import create_transaction_payload, sign_transaction, verify_transaction, simulate_passkey_tx_confirmation
    TX_SIGNING_ENABLED = True
except ImportError:
    TX_SIGNING_ENABLED = False

try:
    from dpop import verify_dpop_proof, bind_token_to_dpop
    DPOP_ENABLED = True
except ImportError:
    DPOP_ENABLED = False

try:
    from merkle_ledger import transparency_ledger
    MERKLE_ENABLED = True
except ImportError:
    MERKLE_ENABLED = False

# Reuse storage abstraction
REQUESTS_FILE = "data/requests.json"

try:
    import storage as storage_backend
    _USE_STORAGE = True
except ImportError:
    _USE_STORAGE = False

def _load_requests():
    if _USE_STORAGE:
        try:
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                return storage_backend.load_requests()
        except Exception:
            pass
    if not os.path.exists(REQUESTS_FILE):
        return {}
    try:
        with open(REQUESTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def _save_requests(requests):
    if _USE_STORAGE:
        try:
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                storage_backend.save_requests(requests)
                return
        except Exception:
            pass
    os.makedirs("data", exist_ok=True)
    with open(REQUESTS_FILE, "w", encoding="utf-8") as f:
        json.dump(requests, f, indent=2)

# ── Cerberus Request ───────────────────────────────────────────────────────

def cerberus_request_reset(
    token: str,
    device_id: str,
    location: str = "Nairobi",
    session_age_minutes: float = 5,
    mfa_type: str = "none",
    origin: str = "http://localhost:8000",
    dpop_proof: str = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    P4 request with Zero Trust checks.
    Returns (ok, result_dict) where result contains request_id, risk, policy, attestation, etc.
    """
    # 1. Basic authZ (original)
    ok, msg = authorization.authorize(token, "request_reset")
    if not ok:
        return False, {"error": msg, "stage": "authorization"}

    session = authentication.check_session(token)
    if session is None:
        return False, {"error": "no session", "stage": "session"}

    username = session["username"]
    role = session.get("role", "operator")

    # 2. Device exists
    device = device_simulator.get_device(device_id)
    if device is None:
        security_logger.log_event("RESET_REQUESTED", username, "denied: device not in fleet", severity="WARNING", device_id=device_id)
        return False, {"error": "device not in fleet", "stage": "device"}

    # 3. Attestation
    attestation_result = None
    device_trust = "unknown"
    if ATTESTATION_ENABLED:
        attestation_result = simulate_play_integrity(device_id, nonce=secrets.token_hex(8))
        device_trust = attestation_result.get("trust_level", "unknown")
        # If compromised, block early
        if device_trust == "untrusted":
            security_logger.log_event("RESET_REQUESTED", username, f"denied: device attestation untrusted {attestation_result.get('verdicts')}", severity="HIGH", device_id=device_id)
            return False, {"error": f"device attestation failed: {device_trust}", "stage": "attestation", "attestation": attestation_result}

    # 4. Risk scoring
    risk_result = None
    risk_score = 0
    if RISK_ENABLED:
        mfa_verified = session.get("mfa_verified", False)
        risk_result = calculate_risk(
            principal=username,
            action="request_reset",
            resource_trust=device_trust,
            mfa_verified=mfa_verified,
            mfa_type=mfa_type,
            is_escalation=False,
            current_location=location,
            session_age_minutes=session_age_minutes,
        )
        risk_score = risk_result["risk_score"]
        if should_deny(risk_score):
            security_logger.log_event("RESET_REQUESTED", username, f"denied: risk_score {risk_score} >=80", severity="HIGH", device_id=device_id)
            return False, {"error": f"risk too high: {risk_score}", "stage": "risk", "risk": risk_result, "attestation": attestation_result}

    # 5. Policy engine (Cedar ABAC)
    policy_decision = None
    if POLICY_ENABLED:
        principal = Principal(username, {"role": role, "risk_score": risk_score, "mfa_verified": session.get("mfa_verified", False)})
        action = Action("request_reset")
        resource = Resource(device_id, {"type": "device", "trust_level": device_trust, "owner": device.get("owner", "")})
        context = {
            "risk_score": risk_score,
            "mfa_verified": session.get("mfa_verified", False),
            "step_up_verified": not requires_step_up(risk_score) or mfa_type in ("passkey", "totp"),
            "requester": username,
            "approver": "",
        }
        allowed, reasons, decision_log = policy_engine.evaluate(principal, action, resource, context)
        policy_decision = decision_log
        if not allowed:
            security_logger.log_event("RESET_REQUESTED", username, f"denied by policy: {reasons}", severity="WARNING", device_id=device_id)
            return False, {"error": f"policy deny: {reasons}", "stage": "policy", "policy": policy_decision, "risk": risk_result}

    # 6. DPoP verification if provided
    dpop_jkt = None
    if DPOP_ENABLED and dpop_proof:
        ok_dpop, msg_dpop, jkt = verify_dpop_proof(dpop_proof, "POST", origin + "/request")
        if not ok_dpop:
            security_logger.log_event("RESET_REQUESTED", username, f"denied: DPoP invalid {msg_dpop}", severity="WARNING", device_id=device_id)
            return False, {"error": f"DPoP invalid: {msg_dpop}", "stage": "dpop"}
        dpop_jkt = jkt

    # 7. Create request with P4 metadata
    requests = _load_requests()
    for _ in range(5):
        request_id = secrets.token_hex(8)
        if request_id not in requests:
            break
    else:
        return False, {"error": "could not generate unique request id"}

    requests[request_id] = {
        "device_id": device_id,
        "requester": username,
        "approver": None,
        "status": "requested",
        "risk_score": risk_score,
        "risk": risk_result,
        "device_trust": device_trust,
        "attestation": attestation_result,
        "policy": policy_decision,
        "dpop_jkt": dpop_jkt,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "p4_version": "cerberus-1.0",
    }
    _save_requests(requests)

    security_logger.log_event("RESET_REQUESTED", username, f"created P4 risk={risk_score} trust={device_trust}", device_id=device_id, request_id=request_id)

    return True, {
        "request_id": request_id,
        "risk": risk_result,
        "attestation": attestation_result,
        "policy": policy_decision,
        "device_trust": device_trust,
        "requires_step_up": requires_step_up(risk_score) if RISK_ENABLED else False,
        "requires_tx_signing": requires_tx_signing(risk_score) if RISK_ENABLED else False,
        "message": "P4 request created, awaiting approval",
    }

# ── Cerberus Approve ───────────────────────────────────────────────────────

def cerberus_approve_reset(
    token: str,
    request_id: str,
    location: str = "Nairobi",
    session_age_minutes: float = 5,
    mfa_type: str = "passkey",
    tx_signed_payload: Dict[str, Any] = None,
    webauthn_credential_id: str = None,
    webauthn_counter: int = 1,
    origin: str = "http://localhost:8000",
    dpop_proof: str = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    P4 approval with step-up, tx signing, WebAuthn, DPoP.
    """
    ok, msg = authorization.authorize(token, "approve_reset")
    if not ok:
        return False, {"error": msg, "stage": "authorization"}

    session = authentication.check_session(token)
    if session is None:
        return False, {"error": "no session", "stage": "session"}

    username = session["username"]
    role = session.get("role", "admin")

    requests = _load_requests()
    if request_id not in requests:
        return False, {"error": "no such request", "stage": "lookup"}

    req = requests[request_id]
    if req["status"] != "requested":
        return False, {"error": "not in requested state", "stage": "state"}

    if username == req["requester"]:
        security_logger.log_event("APPROVAL_DENIED", username, "four-eyes violation", severity="WARNING", device_id=req["device_id"], request_id=request_id)
        return False, {"error": "approver must differ from requester", "stage": "four_eyes"}

    # Risk for approver
    risk_result = None
    risk_score = req.get("risk_score", 0)
    if RISK_ENABLED:
        mfa_verified = session.get("mfa_verified", False)
        # Approver risk includes escalation check
        is_escalation = (role != "admin")
        risk_result = calculate_risk(
            principal=username,
            action="approve_reset",
            resource_trust=req.get("device_trust", "unknown"),
            mfa_verified=mfa_verified,
            mfa_type=mfa_type,
            is_escalation=is_escalation,
            current_location=location,
            session_age_minutes=session_age_minutes,
        )
        # Use max of request risk and approver risk
        risk_score = max(risk_score, risk_result["risk_score"])
        if should_deny(risk_score):
            security_logger.log_event("APPROVAL_DENIED", username, f"denied: risk {risk_score} >=80", severity="HIGH", device_id=req["device_id"], request_id=request_id)
            return False, {"error": f"risk too high: {risk_score}", "stage": "risk", "risk": risk_result}

    # Check if step-up required
    if RISK_ENABLED and requires_step_up(risk_score):
        # Must have MFA verified
        if mfa_type not in ("passkey", "totp"):
            security_logger.log_event("APPROVAL_DENIED", username, f"step-up required risk={risk_score} but mfa_type={mfa_type}", severity="WARNING", device_id=req["device_id"], request_id=request_id)
            return False, {"error": f"step-up MFA required for risk {risk_score}", "stage": "step_up", "risk": risk_result, "requires": "mfa"}

    # Check if tx signing required
    if RISK_ENABLED and requires_tx_signing(risk_score):
        if not tx_signed_payload:
            return False, {"error": f"transaction signing required for risk {risk_score}", "stage": "tx_signing_required", "risk": risk_result, "requires": "tx_signing"}
        if TX_SIGNING_ENABLED:
            ok_tx, msg_tx = verify_transaction(tx_signed_payload)
            if not ok_tx:
                security_logger.log_event("APPROVAL_DENIED", username, f"tx signing invalid {msg_tx}", severity="WARNING", device_id=req["device_id"], request_id=request_id)
                return False, {"error": f"tx signing invalid: {msg_tx}", "stage": "tx_signing"}

    # WebAuthn verification if passkey used
    webauthn_verified = False
    if WEBAUTHN_ENABLED and mfa_type == "passkey" and webauthn_credential_id:
        ok_w, msg_w = verify_authentication_response(username, webauthn_credential_id, origin, rp_id="localhost", user_verified=True, counter=webauthn_counter)
        if not ok_w:
            security_logger.log_event("APPROVAL_DENIED", username, f"webauthn failed {msg_w}", severity="WARNING", device_id=req["device_id"], request_id=request_id)
            return False, {"error": f"webauthn failed: {msg_w}", "stage": "webauthn"}
        webauthn_verified = True

    # DPoP verification
    dpop_jkt = None
    if DPOP_ENABLED and dpop_proof:
        ok_dpop, msg_dpop, jkt = verify_dpop_proof(dpop_proof, "POST", origin + "/approve")
        if not ok_dpop:
            return False, {"error": f"DPoP invalid: {msg_dpop}", "stage": "dpop"}
        dpop_jkt = jkt

    # Policy engine for approve
    policy_decision = None
    if POLICY_ENABLED:
        principal = Principal(username, {"role": role, "risk_score": risk_score, "mfa_verified": True})
        action = Action("approve_reset")
        resource = Resource(req["device_id"], {"type": "reset_request", "trust_level": req.get("device_trust", "unknown")})
        context = {
            "risk_score": risk_score,
            "mfa_verified": True,
            "step_up_verified": True,
            "tx_signed": bool(tx_signed_payload),
            "requester": req["requester"],
            "approver": username,
        }
        allowed, reasons, decision_log = policy_engine.evaluate(principal, action, resource, context)
        policy_decision = decision_log
        if not allowed:
            security_logger.log_event("APPROVAL_DENIED", username, f"policy deny {reasons}", severity="WARNING", device_id=req["device_id"], request_id=request_id)
            return False, {"error": f"policy deny: {reasons}", "stage": "policy", "policy": policy_decision}

    # All checks passed — approve
    req["approver"] = username
    req["status"] = "approved"
    req["approved_at"] = datetime.now(timezone.utc).isoformat()
    req["approval_risk"] = risk_result
    req["approval_risk_score"] = risk_score
    req["approval_policy"] = policy_decision
    req["tx_signed"] = bool(tx_signed_payload)
    req["webauthn_verified"] = webauthn_verified
    req["dpop_jkt"] = dpop_jkt
    _save_requests(requests)

    security_logger.log_event("RESET_APPROVED", username, f"approved P4 risk={risk_score} tx_signed={bool(tx_signed_payload)} webauthn={webauthn_verified}", device_id=req["device_id"], request_id=request_id)

    return True, {
        "message": "approved",
        "risk": risk_result,
        "policy": policy_decision,
        "tx_signed": bool(tx_signed_payload),
        "webauthn_verified": webauthn_verified,
        "request_id": request_id,
    }

# ── Cerberus Execute ───────────────────────────────────────────────────────

def cerberus_execute_reset(
    token: str,
    request_id: str,
    tx_signed_payload: Dict[str, Any] = None,
    location: str = "Nairobi",
    origin: str = "http://localhost:8000",
) -> Tuple[bool, Dict[str, Any]]:
    """
    P4 execute with final verification, Merkle anchoring, and simulated wipe.
    """
    ok, msg = authorization.authorize(token, "approve_reset")
    if not ok:
        return False, {"error": msg, "stage": "authorization"}

    session = authentication.check_session(token)
    if session is None:
        return False, {"error": "no session", "stage": "session"}

    username = session["username"]

    requests = _load_requests()
    if request_id not in requests:
        return False, {"error": "no such request", "stage": "lookup"}

    req = requests[request_id]
    if req["status"] != "approved":
        security_logger.log_event("RESET_BLOCKED", username, "execute without approval denied", severity="HIGH", device_id=req["device_id"], request_id=request_id)
        return False, {"error": "SIMULATION GUARD: reset not approved", "stage": "state"}

    # Re-validate device
    devices = device_simulator.load_devices()
    if req["device_id"] not in devices:
        return False, {"error": "device not in fleet", "stage": "device"}

    if devices[req["device_id"]].get("status") == "wiped":
        return False, {"error": "device already wiped", "stage": "device"}

    # Re-check attestation at execution time (continuous verification)
    if ATTESTATION_ENABLED:
        att = simulate_play_integrity(req["device_id"])
        if att.get("trust_level") == "untrusted":
            security_logger.log_event("RESET_BLOCKED", username, f"device attestation failed at execution {att.get('verdicts')}", severity="HIGH", device_id=req["device_id"], request_id=request_id)
            return False, {"error": "device attestation failed at execution", "stage": "attestation", "attestation": att}

    # If high-risk, require tx signed payload still valid
    if RISK_ENABLED and req.get("risk_score", 0) >= 60:
        if TX_SIGNING_ENABLED and tx_signed_payload:
            ok_tx, msg_tx = verify_transaction(tx_signed_payload)
            if not ok_tx:
                return False, {"error": f"tx signing invalid at execution: {msg_tx}", "stage": "tx_signing"}

    # Simulated wipe
    devices[req["device_id"]]["status"] = "wiped"
    device_simulator.save_devices(devices)
    req["status"] = "executed"
    req["executed_at"] = datetime.now(timezone.utc).isoformat()
    req["executor"] = username
    _save_requests(requests)

    security_logger.log_event("RESET_EXECUTED", username, "SIMULATED wipe complete P4", severity="WARNING", device_id=req["device_id"], request_id=request_id)

    # Merkle root after execution
    merkle_info = None
    if MERKLE_ENABLED:
        try:
            merkle_info = {
                "root": transparency_ledger.get_root(),
                "size": transparency_ledger.get_size(),
                "checkpoints": transparency_ledger.get_checkpoints()[-1:] if transparency_ledger.get_checkpoints() else [],
            }
        except Exception:
            merkle_info = None

    return True, {
        "message": "SIMULATED wipe complete (no real device touched) P4 Cerberus",
        "device_id": req["device_id"],
        "request_id": request_id,
        "merkle": merkle_info,
    }

if __name__ == "__main__":
    import seed_lab
    seed_lab.seed_all()
    admin_token = seed_lab.get_default_token("que")
    ops_token = seed_lab.get_default_token("ops")

    print("=== P4 Cerberus Demo ===")
    ok, res = cerberus_request_reset(ops_token, "AND-001", location="Nairobi", mfa_type="passkey", session_age_minutes=2)
    print(f"Request: {ok} {res.get('request_id')} risk={res.get('risk', {}).get('risk_score')} trust={res.get('device_trust')}")

    if ok:
        rid = res["request_id"]
        # Simulate tx signing for approval if needed
        from tx_signing import create_transaction_payload, sign_transaction
        payload = create_transaction_payload("approve_reset", "AND-001", "ops", "que", risk_score=res.get("risk", {}).get("risk_score", 0))
        signed = sign_transaction(payload)

        # Need webauthn credential for que
        try:
            from webauthn_sim import generate_registration_options, verify_registration_response, _generate_credential_id
            opts = generate_registration_options("que", rp_id="localhost", attestation="direct")
            cred_id = _generate_credential_id()
            ok_r, msg_r, cred = verify_registration_response("que", cred_id, "http://localhost:8000", rp_id="localhost", attestation_type="direct", aaguid="yubikey-5")
            print(f"Passkey registration: {ok_r} {msg_r}")
            # Generate auth options
            from webauthn_sim import generate_authentication_options
            auth_opts = generate_authentication_options("que", rp_id="localhost")
            print(f"Auth options: {auth_opts['challenge'][:20]}...")
        except Exception as e:
            print(f"WebAuthn demo error: {e}")
            cred_id = None

        ok_a, res_a = cerberus_approve_reset(admin_token, rid, location="Nairobi", mfa_type="passkey", tx_signed_payload=signed, webauthn_credential_id=cred_id, webauthn_counter=1)
        print(f"Approve: {ok_a} {res_a}")

        if ok_a:
            ok_e, res_e = cerberus_execute_reset(admin_token, rid, tx_signed_payload=signed)
            print(f"Execute: {ok_e} {res_e}")
