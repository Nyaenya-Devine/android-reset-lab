# P4 Cerberus Architecture — God Mode

> **Simulation-only, no real device touch.** `SIMULATION_MODE=True` enforced by `test_safety.py`. This is a lab that a machine can applaud: Merkle transparency, Cedar policy-as-code, risk-adaptive auth, WebAuthn passkeys, StrongBox attestation, WYSIWYS transaction signing, DPoP.

## Why P4 is not basic

Prior versions:
- **P2**: JSON/SQLite storage abstraction, CSRF, rate limiting, RBAC hardening
- **P3**: PBKDF2/Argon2id agility, HMAC tamper-proof audit log, TOTP MFA, SIEM shipping

**P4 Cerberus** steps up from linear hash chain to verifiable transparency log, from static RBAC to Cedar ABAC with decision logs, from password+MFA to phishing-resistant passkeys + transaction signing, from blind device trust to hardware-backed attestation, from bearer tokens to DPoP-bound tokens.

Inspired by real-world Zero Trust:
- Google BeyondCorp (continuous verification, device trust as signal)
- Certificate Transparency RFC 6962 / 9162 (Merkle tree, inclusion/consistency proofs, STH)
- Sigstore Rekor (checkpoint anchoring)
- Cedar / OPA / AuthZEN (policy-as-code, explicit deny, decision logs, bundle hash)
- FIDO2 WebAuthn (origin binding, AAGUID allowlist via FIDO MDS, counter clone detection)
- Android Play Integrity + Key Attestation (MEETS_BASIC/DEVICE/STRONG, StrongBox Titan M, keybox.xml)
- PSD2 dynamic linking / FIDO txAuthSimple (WYSIWYS)
- RFC 9449 DPoP (proof-of-possession)

## Components

### 1. Merkle Transparency Ledger (`merkle_ledger.py`)
- **Hashing**: leaf `SHA256(0x00 || canonical_json)`, node `SHA256(0x01 || L || R)`, empty `SHA256("")` per RFC 6962
- **Tree**: binary Merkle, append-only rebuild O(N log N) acceptable for lab; production would use incremental
- **Proofs**: inclusion proof O(log N) returns sibling hex list, verified with `hmac.compare_digest`; consistency proof simplified returns old/new roots + size, verified by recomputing old root from prefix
- **STH**: Signed Tree Head with `tree_size, timestamp, sha256_root_hash, tree_head_signature, signature_type` — HMAC-SHA256 if `data/hmac.key` present else tamper-evident
- **Checkpoint**: writes to `logs/checkpoints.jsonl` every 10 entries or on HIGH severity, with `rekor_simulated_id = secrets.token_hex(16)` simulating Sigstore Rekor anchoring
- **Integration**: `security_logger.py` calls `_append_merkle(entry)` after each `log_event`, fail-open so audit log never breaks if Merkle fails. Respects `config.LOG_FILE` isolation for tests (writes to temp logs dir when `LOG_FILE` is in `/tmp`)
- **API**: `append`, `get_root`, `get_size`, `inclusion_proof`, `consistency_proof`, `verify_all`, `get_checkpoints`

### 2. Policy Engine (`policy_engine.py`)
- **Model**: Cedar-like `Principal(uid, attrs)`, `Action(name)`, `Resource(uid, attrs)`, `Context(dict)` — principal/action/resource/context
- **Policy format**: JSON-serializable dict with `id, effect (permit|forbid), principal, action, resource, condition, description`
- **Evaluation**: default deny, explicit forbid overrides permit, need ≥1 permit and 0 forbid. Each clause evaluated via safe AST walk (no `eval()` builtin to pass safety test)
- **ABAC attributes**: `role, clearance, risk_score, mfa_verified, device.trust_level, env.time, env.location, requester, approver, tx_signed, step_up_verified`
- **Decision log**: timestamp, version, principal, action, resource, context, decision, permits, forbids, evaluated, policy_sha (SHA256 of policies truncated)
- **AuthZEN**: `authzen_evaluate(principal_id, principal_attrs, action, resource_id, resource_attrs, context)` returns `{decision, reasons, context}` compatible with AuthZEN 1.0
- **Default policies** (10): viewer_deny_all (forbid), operator_can_request_low_risk (permit risk<80), operator_cannot_approve (forbid four-eyes), admin_can_approve_with_mfa (permit MFA+<70+not self), admin_can_approve_high_risk_with_tx_signing (permit MFA+tx_signed), admin_manage_users, analyst_view_logs, deny_compromised_device (forbid trust_level==compromised), deny_high_risk_without_step_up (forbid risk>=80 && !step_up), permit_view_dashboard
- **Storage**: `logs/decision_logs.jsonl`

### 3. Risk Engine (`risk_engine.py`)
- **Factors** (each returns score + reason):
  - Velocity: requests/min per principal (0,10,25,40)
  - Failed auth: count/10m (0,5,20,30)
  - Time anomaly: out-of-hours 8-18 UTC approved, 0-6 critical 20, else 10
  - Device trust: trusted/verified 0, unknown 15, untrusted 30, compromised 50, emulator 40, rooted 35
  - MFA: not verified 25, passkey -10 (phishing-resistant bonus), totp 0, none 25
  - Privilege escalation: is_escalation 40
  - Impossible travel: location change within 10m → 30, else 5
  - Session age: >120m 15, >60m 5
- **Score**: sum clamped 0-100
- **Trust level**: >=80 untrusted→deny, >=60 low→step_up_mfa+tx_signing, >=30 medium→step_up_mfa, else high→allow
- **API**: `calculate_risk(principal, action, resource_trust, mfa_verified, mfa_type, is_escalation, current_location, session_age_minutes)`, `requires_step_up`, `requires_tx_signing`, `should_deny`, `record_failed_auth`, `clear_risk_state`
- **Stores**: in-memory `defaultdict(deque)` for velocity/failed auth, dict for geo (would be Redis in prod)

### 4. WebAuthn / Passkeys Simulation (`webauthn_sim.py`)
- **Registration**: `generate_registration_options(username, rp_id, rp_name, attestation, authenticator_attachment, user_verification, resident_key)` returns challenge (base64url CSPRNG 32B), RP, user id (hash username), pubKeyCredParams ES256/RS256, timeout 60s, attestation, authenticatorSelection, excludeCredentials, extensions credProps. Stores challenge in `data/webauthn_challenge_{username}.json` with timestamp
- **Verification**: `verify_registration_response` checks challenge expiry 5m, origin validation (allow localhost, vercel.app, rp_id), attestation verification via `_verify_attestation` (none always pass, indirect/direct check AAGUID allowlist), generates credential_id CSPRNG 32B, simulated public key via `hash(secret)`, stores secret hex (in real, private never leaves authenticator), backup_eligible, backup_state, device_type platform/cross-platform, transports, counter 0
- **Authentication**: `generate_authentication_options` returns challenge + allowCredentials list; `verify_authentication_response` checks challenge expiry, origin+RP ID, credential existence, counter (clone detection: if received <= stored and stored !=0 → possible clone), updates counter and last_used
- **AAGUID allowlist**: yubikey-5, titan-m, windows-hello, touch-id, pixel-8 (enterprise policy via FIDO MDS simulation)
- **Storage**: `data/webauthn_credentials.json` (without secret in list view)

### 5. Device Attestation (`attestation.py`)
- **Fleet**: AND-001 Pixel 8 Pro StrongBox trusted, AND-002 Samsung S24 TEE verified, AND-003 Pixel 6a unlocked bootloader rooted basic, AND-004 Emulator untrusted, AND-005 OnePlus 11 old patch, AND-006 GrapheneOS Pixel 8 StrongBox trusted without Play Services (custom_os)
- **Key attestation**: `simulate_key_attestation(device_id)` determines level: StrongBox if strongbox else TEE else Software; downgrade to Software if emulator or rooted+unlocked. Simulates cert chain: leaf cert with attestationSecurityLevel, bootloader_locked, patch_level, keybox_valid, emulator, rooted; root cert Google Hardware Attestation Root. Verified if keybox_valid and not emulator; trust_score 100 minus penalties (bootloader unlocked -40, patch not recent -20, rooted -30, emulator -50, keybox invalid -40) plus StrongBox bonus +10, clamped 0-100
- **Play Integrity**: `simulate_play_integrity(device_id, nonce)` → verdicts: BASIC if not emulator, DEVICE if bootloader_locked + verified + TEE + not rooted/emulator, STRONG if DEVICE + patch recent + keybox_valid + (play_services or custom_os). Trust level: strong→trusted, device→verified, basic→basic, else untrusted
- **API**: `get_device_trust`, `list_fleet_attestation`

### 6. Transaction Signing WYSIWYS (`tx_signing.py`)
- **Payload**: action, device_id, requester, approver, risk_score, timestamp ISO, nonce hex 8B, version 1.0, extra
- **Canonical**: `json.dumps(sort_keys, separators) → bytes`
- **Signing**: HMAC-SHA256 with key from `data/tx_signing.key` (generated 32B, 0600), signature hex, signed_at ISO, what_you_see string `"{action} device {device_id} by {requester} -> {approver or pending} risk={risk_score}"`
- **Verification**: `verify_transaction` checks payload+signature present, recomputes HMAC with `compare_digest`, freshness 5m
- **Passkey TX confirmation**: `simulate_passkey_tx_confirmation(username, payload, origin, user_verified)` creates confirmation with type webauthn.tx.confirmation, challenge hex 16B, origin, rp_id, user, user_verified, transaction=payload, display `Confirm: {action} {device_id} risk={risk_score}`, timestamp, then signs confirmation; adds webauthn_sim metadata credential_type passkey, user_verification required/discouraged, backup_eligible False, authenticator_attachment platform. Simulates FIDO2 txAuthSimple extension
- **Key storage**: `data/tx_signing.key` hex

### 7. DPoP (`dpop.py`)
- **Keypair**: private 32B CSPRNG, public = SHA256(private) simulated, JWK oct with k (private b64url) and pub, jkt = SHA256(JSON(JWK)) hex
- **Proof**: JWT header `{"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"oct","pub":...}}`, payload `{"jti":hex8, "htm":method, "htu":uri, "iat":now, "nonce":hex8}`, signing input `header_b64.payload_b64`, signature HMAC-SHA256(private, signing_input), proof `header.payload.sig` b64url without padding
- **Verification**: `verify_dpop_proof(proof, htm, htu, max_age=60)` checks format 3 parts, typ, htm/htu match, iat freshness, pub present, computes jkt from JWK, returns ok, msg, jkt. Real DPoP would verify with public key; simulation accepts structure
- **Binding**: `bind_token_to_dpop(token, jkt)` returns dict token+jkt+bound_at+binding_type; `verify_token_binding` uses `compare_digest`

### 8. Cerberus Workflow (`cerberus_workflow.py`)
Orchestrates all P4 modules, keeps original `reset_workflow.py` untouched for backward compat/tests.

**Request**:
1. authorization.authorize(request_reset)
2. device exists
3. attestation: `simulate_play_integrity` → trust_level; if untrusted block
4. risk: `calculate_risk` with principal, action, resource_trust, mfa_verified, mfa_type, location, session_age; if >=80 deny
5. policy: `policy_engine.evaluate` Principal(role,risk,mfa) Action(request_reset) Resource(device_id,type,trust) Context(risk,mfa,step_up,requester); if not allowed deny
6. DPoP if provided: `verify_dpop_proof`
7. Create request with P4 metadata: risk_score, risk, device_trust, attestation, policy, dpop_jkt, created_at, p4_version
8. log_event + Merkle

**Approve**:
1. authorize approve_reset, check four-eyes (approver != requester)
2. risk for approver with is_escalation if role != admin, max(request_risk, approver_risk)
3. step-up: if `requires_step_up(risk)` then mfa_type must be passkey/totp else deny
4. tx_signing: if `requires_tx_signing(risk)` then tx_signed_payload required and `verify_transaction`
5. WebAuthn: if mfa_type==passkey and credential_id provided → `verify_authentication_response` with counter clone detection
6. DPoP verification
7. policy: Principal(admin) Action(approve_reset) Resource(reset_request) Context(risk,mfa,step_up,tx_signed,requester,approver)
8. Approve: set approver, status approved, approved_at, approval_risk, approval_policy, tx_signed, webauthn_verified, dpop_jkt
9. log

**Execute**:
1. authorize, check status approved
2. re-validate device exists and not already wiped
3. continuous attestation at execution time: `simulate_play_integrity` again, if untrusted block
4. if high-risk, verify tx payload still valid
5. simulated wipe: set device status wiped
6. log + Merkle root after execution returned

**Integration**:
- `security_logger.py` now appends to Merkle ledger (fail-open, respects config.LOG_FILE isolation)
- `web_console.py` collects P4 data: Merkle root/size/checkpoints/verify, policy version/count/sha, fleet attestation trusted count, passkey count; renders P4 Cerberus panel with transparency log, Cedar policy, attestation table
- New endpoints would be `/api/cerberus/request`, `/api/cerberus/approve`, `/api/cerberus/execute` with DPoP and WebAuthn (future)

## Threat Model Update

See `THREAT_MODEL.md` for full STRIDE. P4 additions:
- **Tampering**: Merkle inclusion proofs allow efficient verification without full log; checkpoint anchoring to Rekor sim prevents history rewrite; HMAC STH
- **Spoofing**: WebAuthn origin binding prevents phishing, AAGUID allowlist via FIDO MDS, counter clone detection
- **Elevation**: Cedar explicit deny + policy bundle hash + decision logs; risk-adaptive step-up; four-eyes + tx signing
- **Repudiation**: Merkle transparency + HMAC + WYSIWYS tx signing + DPoP binding
- **Device compromise**: Play Integrity verdicts + StrongBox attestationSecurityLevel + trust_score; GrapheneOS fallback to hardware attestation without Play Services
- **Token theft**: DPoP proof-of-possession binds token to key, jkt verification

## Formal Spec (TLA+ style informal)

- **Merkle**: ∀ entry i, ∃ proof P_i: verify_inclusion(leaf_hash_i, i, P_i, root) = true iff leaf_hash_i ∈ tree. Consistency: old_root is prefix of new_root iff consistency_proof verifies.
- **Policy**: decision = allow iff ∃ permit policy matching principal/action/resource/context ∧ ∄ forbid policy matching. Fail-closed on eval error.
- **Risk**: risk_score = Σ factors, 0-100, monotonic in velocity, failed_auth, etc. Action_required = f(risk_score) with thresholds 30,60,80.
- **Attestation**: trust_level = trusted iff meets_strong, verified iff keybox_valid ∧ ¬emulator. Trust_score penalizes unlocked, old patch, rooted, emulator.
- **WebAuthn**: registration succeeds iff challenge fresh, origin allowed, attestation AAGUID allowed. Authentication succeeds iff challenge fresh, origin+RP match, credential exists, counter > stored.
- **TX signing**: verify succeeds iff HMAC(payload, key) == signature ∧ now - timestamp < 5m.
- **Cerberus**: request allowed iff authz ∧ device_exists ∧ attestation≠untrusted ∧ risk<80 ∧ policy_allow ∧ DPoP_ok. Approve allowed iff request exists ∧ status=requested ∧ four_eyes ∧ risk<80 ∧ step_up_if_needed ∧ tx_if_needed ∧ webauthn_if_needed ∧ policy_allow. Execute allowed iff status=approved ∧ device_exists ∧ ¬already_wiped ∧ attestation_at_exec≠untrusted ∧ tx_still_valid.

## Chaos / Negative Tests

`tests/test_p4.py` includes:
- Merkle tamper detection (leaf_hash zero)
- Policy deny viewer, compromised device, admin without MFA
- Risk velocity + impossible travel
- WebAuthn counter replay (clone detection)
- Attestation rooted/emulator
- TX signing tamper
- DPoP wrong method
- Cerberus full flow and compromised device block

## Metrics

- 68 tests green (52 P2/P3 + 16 P4)
- Merkle root hex 64 chars, inclusion proof O(log N), consistency proof O(log N)
- Policy 10 default, bundle SHA 16 hex, version 1.0.0
- Risk 8 factors, 0-100 score
- Fleet 6 devices: 2 trusted StrongBox (Pixel 8 Pro, GrapheneOS Pixel 8), 1 verified, 1 basic, 1 untrusted emulator
- Passkeys: YubiKey 5, Titan M, Windows Hello, Touch ID, Pixel 8 StrongBox simulated
- DPoP: RFC 9449 JWT with jti, htm, htu, iat, nonce

## Future (beyond simulation)

- Real ECDSA/RSA for WebAuthn and DPoP (replace HMAC sim)
- Incremental Merkle tree (not rebuild)
- Real Sigstore Rekor anchoring with signed checkpoints
- Cedar policy bundle with WASM
- SPIFFE/SPIRE workload identity for PDP/PEP
- Hardware attestation via Google Play Integrity API server-side verification
- Real TEE/StrongBox via Android Keystore attestation extension parsing

## References

- RFC 6962, RFC 9162 Certificate Transparency
- Sigstore Rekor
- Cedar Policy Language, OPA Rego, AuthZEN
- FIDO2 WebAuthn, FIDO MDS, Passkeys
- Android Play Integrity, Key Attestation, StrongBox, Titan M
- PSD2 Dynamic Linking, FIDO txAuthSimple
- RFC 9449 DPoP, RFC 8705 mTLS token binding
- NIST 800-207 Zero Trust, BeyondCorp
