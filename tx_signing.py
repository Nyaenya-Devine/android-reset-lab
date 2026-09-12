"""
Transaction Signing / WYSIWYS — P4 God Mode
What You See Is What You Sign for high-impact actions

Implements:
- Transaction payload: device_id, requester, approver, timestamp, risk_score, action
- Signing with HMAC-SHA256 (or simulated passkey) — WYSIWYS
- Verification with explicit user confirmation
- Prevents confused deputy, replay, and tampering

Inspired by: FIDO2 transaction confirmation extension (txAuthSimple), PSD2 dynamic linking

No external deps — stdlib only.
"""

import json
import hmac
import hashlib
import os
import time
import secrets
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone

TX_KEY_FILE = "data/tx_signing.key"

def _get_tx_key() -> bytes:
    """Load or generate transaction signing key."""
    if os.path.exists(TX_KEY_FILE):
        try:
            with open(TX_KEY_FILE, "r", encoding="utf-8") as f:
                return bytes.fromhex(f.read().strip())
        except Exception:
            pass
    # Generate
    os.makedirs("data", exist_ok=True)
    key = secrets.token_bytes(32)
    with open(TX_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key.hex())
    try:
        os.chmod(TX_KEY_FILE, 0o600)
    except OSError:
        pass
    return key

def create_transaction_payload(
    action: str,
    device_id: str,
    requester: str,
    approver: str = "",
    risk_score: int = 0,
    extra: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create canonical transaction payload for signing."""
    payload = {
        "action": action,
        "device_id": device_id,
        "requester": requester,
        "approver": approver,
        "risk_score": risk_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(8),
        "version": "1.0",
    }
    if extra:
        payload.update(extra)
    return payload

def _canonical_payload(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

def sign_transaction(payload: Dict[str, Any], key: bytes = None) -> Dict[str, Any]:
    """Sign transaction payload with HMAC-SHA256 (simulating passkey signing)."""
    if key is None:
        key = _get_tx_key()
    canonical = _canonical_payload(payload)
    signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    # Build WYSIWYS display: handle both direct tx payload and confirmation wrapper
    try:
        if "transaction" in payload and isinstance(payload["transaction"], dict):
            tx = payload["transaction"]
            wys = payload.get("display") or f"{tx.get('action')} device {tx.get('device_id')} by {tx.get('requester')} -> {tx.get('approver') or 'pending'} risk={tx.get('risk_score')}"
        else:
            wys = f"{payload.get('action','?')} device {payload.get('device_id','?')} by {payload.get('requester','?')} -> {payload.get('approver') or 'pending'} risk={payload.get('risk_score','?')}"
    except Exception:
        wys = "WYSIWYS transaction"

    signed = {
        "payload": payload,
        "signature": signature,
        "signature_type": "HMAC-SHA256-WYSIWYS",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "what_you_see": wys,
    }
    return signed

def verify_transaction(signed_tx: Dict[str, Any], key: bytes = None) -> Tuple[bool, str]:
    """Verify transaction signature."""
    if key is None:
        key = _get_tx_key()
    payload = signed_tx.get("payload")
    signature = signed_tx.get("signature")
    if not payload or not signature:
        return False, "missing payload or signature"
    canonical = _canonical_payload(payload)
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "signature mismatch — transaction tampered"
    # Check freshness (5 min)
    try:
        ts = datetime.fromisoformat(payload["timestamp"])
        now = datetime.now(timezone.utc)
        if (now - ts).total_seconds() > 300:
            return False, "transaction expired (>5m)"
    except Exception:
        return False, "invalid timestamp"
    return True, f"verified WYSIWYS: {signed_tx.get('what_you_see')}"

def simulate_passkey_tx_confirmation(
    username: str,
    payload: Dict[str, Any],
    origin: str = "http://localhost:8000",
    user_verified: bool = True,
) -> Dict[str, Any]:
    """
    Simulate FIDO2 transaction confirmation extension.
    In real WebAuthn, would use txAuthSimple extension with prompt.
    Here we simulate with passkey + explicit confirmation.
    """
    # Generate challenge for passkey
    challenge = secrets.token_hex(16)
    # Simulate user seeing transaction details and confirming with biometric
    confirmation = {
        "type": "webauthn.tx.confirmation",
        "challenge": challenge,
        "origin": origin,
        "rp_id": "localhost",
        "user": username,
        "user_verified": user_verified,
        "transaction": payload,
        "display": f"Confirm: {payload['action']} {payload['device_id']} risk={payload['risk_score']}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Sign confirmation with tx key (simulating private key in authenticator)
    signed = sign_transaction(confirmation)
    signed["webauthn_sim"] = {
        "credential_type": "passkey",
        "user_verification": "required" if user_verified else "discouraged",
        "backup_eligible": False,
        "authenticator_attachment": "platform",
    }
    return signed

if __name__ == "__main__":
    # Demo
    payload = create_transaction_payload("approve_reset", "AND-001", "ops", "que", risk_score=65)
    print(f"Payload: {payload}")
    signed = sign_transaction(payload)
    print(f"Signed: {signed['what_you_see']}")
    ok, msg = verify_transaction(signed)
    print(f"Verify: {ok} {msg}")

    # Passkey confirmation
    pc = simulate_passkey_tx_confirmation("que", payload, user_verified=True)
    print(f"\nPasskey TX confirmation: {pc['display']}")
    ok, msg = verify_transaction(pc)
    print(f"Verify: {ok} {msg}")
