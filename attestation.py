"""
Android Device Attestation Simulation — P4 God Mode
Simulates Play Integrity API + Hardware-backed Key Attestation

Implements:
- Play Integrity verdicts: MEETS_BASIC, MEETS_DEVICE, MEETS_STRONG
- Hardware attestation: attestationSecurityLevel (Software, TrustedEnvironment, StrongBox)
- Key attestation certificate chain simulation
- Device integrity signals: bootloader locked, patch level, emulator, rooted
- Device trust scoring

Inspired by real Android docs: hardware-backed keystore, StrongBox, Titan M, keybox.xml

No external deps — stdlib only.
"""

import hashlib
import json
import os
import time
import secrets
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
import base64

# ── Constants ──────────────────────────────────────────────────────────────

# Play Integrity verdicts
VERDICT_BASIC = "MEETS_BASIC_INTEGRITY"
VERDICT_DEVICE = "MEETS_DEVICE_INTEGRITY"
VERDICT_STRONG = "MEETS_STRONG_INTEGRITY"

# Attestation security levels (Android Keymaster)
LEVEL_SOFTWARE = 0  # Software
LEVEL_TEE = 1  # TrustedEnvironment (TEE)
LEVEL_STRONGBOX = 2  # StrongBox (Titan M, etc.)

LEVEL_NAMES = {
    LEVEL_SOFTWARE: "Software",
    LEVEL_TEE: "TrustedEnvironment",
    LEVEL_STRONGBOX: "StrongBox",
}

# ── Device Inventory with Attestation Signals ─────────────────────────────

# Simulated fleet with attestation properties
FLEET_ATTESTATION = {
    "AND-001": {
        "model": "Pixel 8 Pro",
        "bootloader_locked": True,
        "patch_level": "2026-08-05",
        "patch_recent": True,
        "hardware_backed": True,
        "strongbox": True,
        "tee": True,
        "emulator": False,
        "rooted": False,
        "play_services": True,
        "aaguid": "pixel-8",
        "keybox_valid": True,
    },
    "AND-002": {
        "model": "Samsung S24",
        "bootloader_locked": True,
        "patch_level": "2026-07-01",
        "patch_recent": True,
        "hardware_backed": True,
        "strongbox": False,
        "tee": True,
        "emulator": False,
        "rooted": False,
        "play_services": True,
        "aaguid": "titan-m",
        "keybox_valid": True,
    },
    "AND-003": {
        "model": "Pixel 6a",
        "bootloader_locked": False,
        "patch_level": "2025-01-15",
        "patch_recent": False,
        "hardware_backed": True,
        "strongbox": False,
        "tee": True,
        "emulator": False,
        "rooted": True,
        "play_services": True,
        "keybox_valid": False,
    },
    "AND-004": {
        "model": "Emulator",
        "bootloader_locked": False,
        "patch_level": "2026-08-01",
        "patch_recent": True,
        "hardware_backed": False,
        "strongbox": False,
        "tee": False,
        "emulator": True,
        "rooted": True,
        "play_services": False,
        "aaguid": "emulator",
        "keybox_valid": False,
    },
    "AND-005": {
        "model": "OnePlus 11",
        "bootloader_locked": True,
        "patch_level": "2024-03-01",
        "patch_recent": False,
        "hardware_backed": True,
        "strongbox": False,
        "tee": True,
        "emulator": False,
        "rooted": False,
        "play_services": True,
        "aaguid": "yubikey-5",
        "keybox_valid": True,
    },
    "AND-006": {
        "model": "GrapheneOS Pixel 8",
        "bootloader_locked": True,
        "patch_level": "2026-08-05",
        "patch_recent": True,
        "hardware_backed": True,
        "strongbox": True,
        "tee": True,
        "emulator": False,
        "rooted": False,
        "play_services": False,  # No GMS, uses hardware attestation directly
        "aaguid": "pixel-8",
        "keybox_valid": True,
        "custom_os": True,
    },
}

# ── Attestation Verification ───────────────────────────────────────────────

def _check_patch_recent(patch_level: str) -> bool:
    """Check if patch within last year."""
    try:
        patch_date = datetime.strptime(patch_level, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - patch_date).days <= 365
    except Exception:
        return False

def simulate_key_attestation(device_id: str) -> Dict[str, Any]:
    """
    Simulate hardware-backed key attestation certificate chain.
    Returns attestation result with security level and chain.
    """
    dev = FLEET_ATTESTATION.get(device_id)
    if not dev:
        return {
            "device_id": device_id,
            "error": "unknown device",
            "attestationSecurityLevel": LEVEL_SOFTWARE,
            "level_name": LEVEL_NAMES[LEVEL_SOFTWARE],
            "verified": False,
            "trust_score": 0,
        }

    # Determine security level
    if dev.get("strongbox"):
        level = LEVEL_STRONGBOX
    elif dev.get("tee"):
        level = LEVEL_TEE
    else:
        level = LEVEL_SOFTWARE

    # If emulator or rooted with unlocked bootloader, downgrade to Software
    if dev.get("emulator") or (dev.get("rooted") and not dev.get("bootloader_locked")):
        level = LEVEL_SOFTWARE

    # Simulate certificate chain
    # Root: Google Hardware Attestation Root (simulated)
    root_cert_sim = {
        "subject": "Google Hardware Attestation Root",
        "issuer": "Google Hardware Attestation Root",
        "serial": secrets.token_hex(8),
        "is_root": True,
        "public_key": "Google attestation root key (simulated)",
    }

    leaf_cert_sim = {
        "subject": f"Device {device_id} {dev['model']}",
        "issuer": root_cert_sim["subject"],
        "serial": secrets.token_hex(8),
        "attestationSecurityLevel": level,
        "level_name": LEVEL_NAMES[level],
        "bootloader_locked": dev.get("bootloader_locked"),
        "patch_level": dev.get("patch_level"),
        "patch_recent": _check_patch_recent(dev.get("patch_level", "")),
        "keybox_valid": dev.get("keybox_valid"),
        "emulator": dev.get("emulator"),
        "rooted": dev.get("rooted"),
    }

    # Verification logic
    verified = True
    reasons = []

    if not dev.get("keybox_valid"):
        verified = False
        reasons.append("keybox invalid or revoked")
    if dev.get("emulator"):
        verified = False
        reasons.append("emulator detected")
    if level == LEVEL_SOFTWARE and dev.get("hardware_backed"):
        # Fallback to software when hardware expected — suspicious
        reasons.append("fallback to software attestation when hardware expected")
        # Still could be verified as basic, but not strong

    trust_score = 100
    if not dev.get("bootloader_locked"):
        trust_score -= 40
        reasons.append("bootloader unlocked")
    if not _check_patch_recent(dev.get("patch_level", "")):
        trust_score -= 20
        reasons.append("patch not recent (>1 year)")
    if dev.get("rooted"):
        trust_score -= 30
        reasons.append("rooted")
    if dev.get("emulator"):
        trust_score -= 50
        reasons.append("emulator")
    if not dev.get("keybox_valid"):
        trust_score -= 40
    if level == LEVEL_STRONGBOX:
        trust_score += 10
    trust_score = max(0, min(100, trust_score))

    return {
        "device_id": device_id,
        "model": dev["model"],
        "attestationSecurityLevel": level,
        "level_name": LEVEL_NAMES[level],
        "certificate_chain": [leaf_cert_sim, root_cert_sim],
        "verified": verified,
        "trust_score": trust_score,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def simulate_play_integrity(device_id: str, nonce: str = None) -> Dict[str, Any]:
    """
    Simulate Play Integrity API verdicts.
    """
    if nonce is None:
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

    dev = FLEET_ATTESTATION.get(device_id)
    if not dev:
        return {
            "device_id": device_id,
            "nonce": nonce,
            "error": "unknown device",
            "verdicts": [],
            "meets_basic": False,
            "meets_device": False,
            "meets_strong": False,
            "trust_level": "unknown",
        }

    key_att = simulate_key_attestation(device_id)

    verdicts = []
    meets_basic = False
    meets_device = False
    meets_strong = False

    # Basic: must be able to produce valid attestation with valid key OR software fallback
    # For simulation: if not emulator, passes basic
    if not dev.get("emulator"):
        verdicts.append(VERDICT_BASIC)
        meets_basic = True

    # Device: HW attestation valid + bootloader locked + verified boot green
    if dev.get("bootloader_locked") and key_att["verified"] and key_att["attestationSecurityLevel"] >= LEVEL_TEE and not dev.get("emulator") and not dev.get("rooted"):
        verdicts.append(VERDICT_DEVICE)
        meets_device = True

    # Strong: Device + patch recent within 1 year + StrongBox or TEE + keybox valid + play services or hardware attestation
    if meets_device and _check_patch_recent(dev.get("patch_level", "")) and dev.get("keybox_valid") and key_att["attestationSecurityLevel"] >= LEVEL_TEE:
        # For Android 13+, strong also requires security patch recent across all partitions
        # For GrapheneOS without Play Services, strong can still pass via hardware attestation directly
        if dev.get("play_services") or dev.get("custom_os"):
            verdicts.append(VERDICT_STRONG)
            meets_strong = True

    # Trust level based on verdicts
    if meets_strong:
        trust_level = "trusted"
    elif meets_device:
        trust_level = "verified"
    elif meets_basic:
        trust_level = "basic"
    else:
        trust_level = "untrusted"

    return {
        "device_id": device_id,
        "model": dev["model"],
        "nonce": nonce,
        "verdicts": verdicts,
        "meets_basic": meets_basic,
        "meets_device": meets_device,
        "meets_strong": meets_strong,
        "trust_level": trust_level,
        "key_attestation": key_att,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "play_services": dev.get("play_services"),
        "note": "Simulation: real Play Integrity requires Google Play Services + server-side token verification with Google",
    }

def get_device_trust(device_id: str) -> str:
    """Get simplified trust level for risk engine."""
    pi = simulate_play_integrity(device_id)
    return pi.get("trust_level", "unknown")

def list_fleet_attestation() -> Dict[str, Dict[str, Any]]:
    """List all devices with attestation."""
    result = {}
    for device_id in FLEET_ATTESTATION:
        result[device_id] = simulate_play_integrity(device_id)
    return result

if __name__ == "__main__":
    for device_id in ["AND-001", "AND-003", "AND-004", "AND-006"]:
        pi = simulate_play_integrity(device_id)
        print(f"\n{device_id} {pi['model']}: {pi['verdicts']} trust={pi['trust_level']} score={pi['key_attestation']['trust_score']}")
        print(f"  Level: {pi['key_attestation']['level_name']}, Verified: {pi['key_attestation']['verified']}, Reasons: {pi['key_attestation']['reasons']}")
