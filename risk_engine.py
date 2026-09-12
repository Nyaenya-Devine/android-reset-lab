"""
Risk Engine — P4 God Mode
Adaptive risk scoring for Zero Trust, inspired by BeyondCorp + NIST 800-207

Factors:
- Velocity (requests/min)
- Impossible travel (geo)
- Device trust (attestation)
- Time anomaly (out-of-hours)
- Privilege escalation attempts
- Failed auths
- Session age, MFA strength
- Behavioral baseline

Produces risk_score 0-100, trust_level, step-up requirements.

No external deps — stdlib only.
"""

import time
import math
import os
import json
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta

# ── In-memory stores (would be Redis in prod) ─────────────────────────────

_velocity_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))  # principal -> timestamps
_geo_store: Dict[str, Tuple[str, float]] = {}  # principal -> (location, timestamp)
_failed_auth_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

# ── Risk Factors ───────────────────────────────────────────────────────────

def _velocity_score(principal: str, now: float) -> Tuple[int, str]:
    """Score based on requests per minute."""
    dq = _velocity_store[principal]
    # Clean old (>60s)
    while dq and dq[0] < now - 60:
        dq.popleft()
    count = len(dq)
    if count >= 20:
        return 40, f"velocity critical: {count}/min"
    if count >= 10:
        return 25, f"velocity high: {count}/min"
    if count >= 5:
        return 10, f"velocity medium: {count}/min"
    return 0, f"velocity low: {count}/min"

def _failed_auth_score(principal: str, now: float) -> Tuple[int, str]:
    dq = _failed_auth_store[principal]
    while dq and dq[0] < now - 600:  # 10 min window
        dq.popleft()
    count = len(dq)
    if count >= 5:
        return 30, f"failed auth critical: {count}/10m"
    if count >= 3:
        return 20, f"failed auth high: {count}/10m"
    if count >= 1:
        return 5, f"failed auth low: {count}/10m"
    return 0, "no failed auth"

def _time_anomaly_score(timestamp: float = None) -> Tuple[int, str]:
    """Out-of-hours detection."""
    if timestamp is None:
        timestamp = time.time()
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    hour = dt.hour
    # Approved 8-18 UTC (config.RESET_WINDOW)
    if 8 <= hour < 18:
        return 0, f"time normal: {hour}:00 UTC"
    if 0 <= hour < 6:
        return 20, f"time anomaly critical: {hour}:00 UTC (0-6)"
    return 10, f"time anomaly medium: {hour}:00 UTC out-of-hours"

def _device_trust_score(trust_level: str) -> Tuple[int, str]:
    mapping = {
        "trusted": (0, "device trusted"),
        "verified": (0, "device verified"),
        "unknown": (15, "device unknown"),
        "untrusted": (30, "device untrusted"),
        "compromised": (50, "device compromised"),
        "emulator": (40, "device emulator"),
        "rooted": (35, "device rooted"),
    }
    return mapping.get(trust_level, (15, f"device trust unknown: {trust_level}"))

def _mfa_score(mfa_verified: bool, mfa_type: str) -> Tuple[int, str]:
    if not mfa_verified:
        return 25, "MFA not verified"
    if mfa_type == "passkey":
        return -10, "MFA passkey (phishing-resistant) -10"
    if mfa_type == "totp":
        return 0, "MFA TOTP"
    if mfa_type == "none":
        return 25, "MFA none"
    return 0, f"MFA {mfa_type}"

def _privilege_escalation_score(is_escalation: bool) -> Tuple[int, str]:
    if is_escalation:
        return 40, "privilege escalation attempt"
    return 0, "no escalation"

def _impossible_travel_score(principal: str, current_location: str, now: float) -> Tuple[int, str]:
    """Simplified impossible travel: if location changes quickly."""
    if not current_location:
        return 0, "no location"
    prev = _geo_store.get(principal)
    if not prev:
        _geo_store[principal] = (current_location, now)
        return 0, f"first location: {current_location}"
    prev_loc, prev_time = prev
    if prev_loc == current_location:
        return 0, f"location stable: {current_location}"
    # If different location within 10 minutes, flag
    time_diff = now - prev_time
    if time_diff < 600:  # 10 min
        _geo_store[principal] = (current_location, now)
        return 30, f"impossible travel: {prev_loc} -> {current_location} in {int(time_diff)}s"
    _geo_store[principal] = (current_location, now)
    return 5, f"location change: {prev_loc} -> {current_location}"

def _session_age_score(session_age_minutes: float) -> Tuple[int, str]:
    if session_age_minutes > 120:
        return 15, f"session age high: {int(session_age_minutes)}m"
    if session_age_minutes > 60:
        return 5, f"session age medium: {int(session_age_minutes)}m"
    return 0, f"session age low: {int(session_age_minutes)}m"

# ── Main Risk Calculation ──────────────────────────────────────────────────

def calculate_risk(
    principal: str,
    action: str,
    resource_trust: str = "unknown",
    mfa_verified: bool = False,
    mfa_type: str = "none",
    is_escalation: bool = False,
    current_location: str = "",
    session_age_minutes: float = 0,
    timestamp: float = None,
    record_velocity: bool = True,
) -> Dict[str, Any]:
    """
    Calculate risk score 0-100.
    """
    now = time.time() if timestamp is None else timestamp

    if record_velocity:
        _velocity_store[principal].append(now)

    factors = []
    total = 0

    v_score, v_reason = _velocity_score(principal, now)
    factors.append({"factor": "velocity", "score": v_score, "reason": v_reason})
    total += v_score

    fa_score, fa_reason = _failed_auth_score(principal, now)
    factors.append({"factor": "failed_auth", "score": fa_score, "reason": fa_reason})
    total += fa_score

    t_score, t_reason = _time_anomaly_score(now)
    factors.append({"factor": "time_anomaly", "score": t_score, "reason": t_reason})
    total += t_score

    d_score, d_reason = _device_trust_score(resource_trust)
    factors.append({"factor": "device_trust", "score": d_score, "reason": d_reason})
    total += d_score

    m_score, m_reason = _mfa_score(mfa_verified, mfa_type)
    factors.append({"factor": "mfa", "score": m_score, "reason": m_reason})
    total += m_score

    esc_score, esc_reason = _privilege_escalation_score(is_escalation)
    factors.append({"factor": "privilege_escalation", "score": esc_score, "reason": esc_reason})
    total += esc_score

    travel_score, travel_reason = _impossible_travel_score(principal, current_location, now)
    factors.append({"factor": "impossible_travel", "score": travel_score, "reason": travel_reason})
    total += travel_score

    sess_score, sess_reason = _session_age_score(session_age_minutes)
    factors.append({"factor": "session_age", "score": sess_score, "reason": sess_reason})
    total += sess_score

    # Clamp 0-100
    risk_score = max(0, min(100, total))

    # Trust level inverse of risk
    if risk_score >= 80:
        trust_level = "untrusted"
        action_required = "deny"
    elif risk_score >= 60:
        trust_level = "low"
        action_required = "step_up_mfa+tx_signing"
    elif risk_score >= 30:
        trust_level = "medium"
        action_required = "step_up_mfa"
    else:
        trust_level = "high"
        action_required = "allow"

    return {
        "principal": principal,
        "action": action,
        "risk_score": risk_score,
        "trust_level": trust_level,
        "action_required": action_required,
        "factors": factors,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_factors": len(factors),
    }

def record_failed_auth(principal: str):
    _failed_auth_store[principal].append(time.time())

def clear_risk_state():
    _velocity_store.clear()
    _geo_store.clear()
    _failed_auth_store.clear()

# ── Adaptive Policy ────────────────────────────────────────────────────────

def requires_step_up(risk_score: int) -> bool:
    return risk_score >= 30

def requires_tx_signing(risk_score: int) -> bool:
    return risk_score >= 60

def should_deny(risk_score: int) -> bool:
    return risk_score >= 80

if __name__ == "__main__":
    clear_risk_state()
    r1 = calculate_risk("ops", "request_reset", resource_trust="trusted", mfa_verified=True, mfa_type="passkey", current_location="Nairobi", session_age_minutes=5)
    print(f"Low risk: {r1['risk_score']} {r1['trust_level']} {r1['action_required']}")
    r2 = calculate_risk("ops", "approve_reset", resource_trust="compromised", mfa_verified=False, is_escalation=True, current_location="Moscow", session_age_minutes=130)
    print(f"High risk: {r2['risk_score']} {r2['trust_level']} {r2['action_required']}")
    for f in r2["factors"]:
        print(f"  - {f['factor']}: {f['score']} {f['reason']}")
