from sanitization_advisor import SanitizationScenario, advise


def scenario(**changes):
    values = dict(intent="retire", encrypted_from_first_use=True,
                  removable_media_present=False, evidence_hold=False,
                  activation_lock_cleared=True, device_online=True,
                  required_assurance="purge")
    values.update(changes)
    return SanitizationScenario(**values)


def test_evidence_hold_always_preserves():
    result = advise(scenario(evidence_hold=True))
    assert result.outcome == "PRESERVE"
    assert "preserve-chain-of-custody" in result.required_controls


def test_removable_media_blocks_factory_reset_path():
    result = advise(scenario(removable_media_present=True))
    assert result.outcome == "BLOCK"
    assert "media" in result.rationale.lower()


def test_activation_lock_blocks_redeployment():
    result = advise(scenario(intent="redeploy", activation_lock_cleared=False))
    assert result.outcome == "BLOCK"
    assert "clear-frp-or-activation-lock" in result.required_controls


def test_unproven_encryption_cannot_claim_purge():
    result = advise(scenario(encrypted_from_first_use=False))
    assert result.outcome == "BLOCK"
    assert "Cryptographic erase" in result.rationale


def test_destroy_is_not_misrepresented_as_reset():
    result = advise(scenario(required_assurance="destroy"))
    assert result.outcome == "DESTROY"
    assert "certificate-of-destruction" in result.verification


def test_offline_lost_device_reduces_access_before_eventual_command():
    result = advise(scenario(intent="lost", device_online=False, required_assurance="clear"))
    assert result.outcome == "SANITIZE"
    assert "revoke-access-now" in result.required_controls
    assert "queue-command-with-expiry" in result.required_controls


def test_troubleshooting_remains_non_destructive():
    result = advise(scenario(intent="troubleshoot", required_assurance="clear"))
    assert result.outcome == "SIMULATE_RESET"
    assert "device-state-unchanged" in result.verification
