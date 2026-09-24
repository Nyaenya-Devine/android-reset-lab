"""Deterministic safety guidance for simulated reset and sanitization scenarios.

This module never executes device commands. It classifies intent and assurance so
operators do not confuse troubleshooting, evidence handling, deprovisioning, and
media sanitization.
"""
from dataclasses import dataclass
from typing import Literal

Intent = Literal["troubleshoot", "redeploy", "lost", "investigation", "retire"]
Assurance = Literal["clear", "purge", "destroy"]


@dataclass(frozen=True)
class SanitizationScenario:
    intent: Intent
    encrypted_from_first_use: bool
    removable_media_present: bool
    evidence_hold: bool
    activation_lock_cleared: bool
    device_online: bool
    required_assurance: Assurance = "clear"


@dataclass(frozen=True)
class SanitizationDecision:
    outcome: Literal["BLOCK", "PRESERVE", "SIMULATE_RESET", "SANITIZE", "DESTROY"]
    rationale: str
    required_controls: tuple[str, ...]
    verification: tuple[str, ...]


def advise(scenario: SanitizationScenario) -> SanitizationDecision:
    base = ("record-device-identity", "dual-control", "tamper-evident-audit")

    if scenario.evidence_hold or scenario.intent == "investigation":
        return SanitizationDecision(
            "PRESERVE",
            "Potential evidence must not be altered by a reset or sanitization workflow.",
            base + ("isolate-network", "preserve-chain-of-custody", "forensic-authority"),
            ("custody-record-complete", "evidence-hash-or-seal-recorded"),
        )

    if scenario.required_assurance == "destroy":
        return SanitizationDecision(
            "DESTROY",
            "The requested assurance requires approved physical media destruction, not a factory reset.",
            base + ("approved-destruction-provider", "asset-disposition-approval"),
            ("certificate-of-destruction", "asset-register-closed"),
        )

    if scenario.removable_media_present:
        return SanitizationDecision(
            "BLOCK",
            "Removable media is outside the normal factory-reset boundary and must be handled separately.",
            base + ("remove-sim-and-media", "classify-removable-media"),
            ("media-accounted-for",),
        )

    if not scenario.activation_lock_cleared and scenario.intent in {"redeploy", "retire"}:
        return SanitizationDecision(
            "BLOCK",
            "Factory Reset Protection or activation lock could leave the device unusable for its next custodian.",
            base + ("clear-frp-or-activation-lock", "confirm-account-release"),
            ("setup-flow-not-owner-locked",),
        )

    if scenario.required_assurance == "purge" and not scenario.encrypted_from_first_use:
        return SanitizationDecision(
            "BLOCK",
            "Cryptographic erase cannot be relied on because encryption from first use is not established.",
            base + ("approved-purge-method", "escalate-to-asset-disposition"),
            ("independent-sanitization-verification",),
        )

    if scenario.intent == "troubleshoot":
        return SanitizationDecision(
            "SIMULATE_RESET",
            "Troubleshooting should prove the workflow without destroying user data.",
            base + ("backup-confirmed", "simulation-only"),
            ("device-state-unchanged", "workflow-evidence-recorded"),
        )

    controls = list(base)
    if scenario.intent == "lost" and not scenario.device_online:
        controls += ["queue-command-with-expiry", "revoke-access-now", "monitor-check-in"]
    else:
        controls += ["confirm-backup", "revoke-enterprise-access", "issue-bounded-command"]
    if scenario.required_assurance == "purge":
        controls += ["verify-hardware-backed-encryption", "cryptographic-erase"]

    return SanitizationDecision(
        "SANITIZE",
        "The scenario can proceed through the controlled simulation after prerequisite confirmation.",
        tuple(controls),
        ("command-acknowledged", "post-reset-enrollment-screen", "sanitization-record-signed"),
    )
