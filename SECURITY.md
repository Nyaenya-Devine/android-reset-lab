# SECURITY.md - Scope Statement & Honest Limitations

## What this project is
An educational, fully offline simulation of a Mobile Device Management (MDM)
reset workflow, built to learn defensive security concepts. It demonstrates
how to build controls, then proves they hold by attacking itself.

**Current hardening:** P0 (8 critical bugs fixed) + P1 (time-based lockout, rate limiting, precise detection) + P2 (persistent storage, CSRF, scanning) + P3 (Argon2id, HMAC-signed log, TOTP MFA sim, SIEM shipping)

## What this project will never do
- Reset, unlock, or modify a real Android device
- Access any real device, account, or network without authorization
- Delete, encrypt, or damage real files (writes go only to ./data and ./logs and optional data/lab.db and logs/siem.log)
- Bypass or weaken real authentication systems
- Provide working attack tooling against real targets

## Safety mechanisms enforced in code
- `config.SIMULATION_MODE` must stay True (enforced by tests/test_safety.py)
- `tests/test_safety.py` bans destructive calls in core lab (os.remove, subprocess, eval...) — demo files allowed for cleanup
- Every device "wipe" only changes a status field in local JSON/SQLite
- Web console binds to 127.0.0.1 only, with rate limiting (10 req/60s), CSRF token + SameSite Strict + HttpOnly
- Resets require two distinct accounts (dual control) — self-approval blocked
- Passwords: PBKDF2 100k + salt + `hmac.compare_digest` OR Argon2id (env LAB_HASH_ALGO=argon2) with PBKDF2 fallback, role whitelist, min length 8
- Sessions: 128-bit token, TTL 30m, CSRF token per session, MFA verified flag
- Audit log: hash-chained + optional HMAC-SHA256 tamper-proof (key in data/hmac.key, 0600) + timestamp spoof protection + optional SIEM shipping to stdout/file
- MFA: Optional TOTP RFC 6238 stdlib-only, 6-digit, 30s period, window=1 for clock skew

## Known Limitations — Honest Disclosure (P3)

**This is a simulation, not production MDM. Documented honestly for recruiters:**

1. **Audit log HMAC is file-based:** Hash chain is tamper-evident always. With HMAC key in `data/hmac.key` (0600), it becomes tamper-proof *if* attacker doesn't get key. But key is file-based, not KMS/HSM. Real SIEM needs KMS + WORM storage. Demo: `demo_ledger_attack.py` + `demo_p3_hardening.py` [2]. Production needs asymmetric signing + immutable storage.

2. **Storage:** Default JSON files are human-readable but no ACID. Optional SQLite backend (`LAB_STORAGE_BACKEND=sqlite`) adds WAL + atomicity but still file-based. Production needs proper DB with row-level locking + backups. Abstraction in `storage.py` allows switching.

3. **Rate limiting is in-memory:** `rate_limit_store` and `_auth_rate_limit_store` are per-process memory, reset on restart, not shared across workers. Production needs Redis.

4. **MFA is simulation:** TOTP secret stored plaintext in `data/users.json` (or SQLite), not encrypted. RFC 6238 stdlib-only, no QR provisioning server, no recovery codes. Production needs encrypted field + WebAuthn + device attestation. Demo: `demo_p3_hardening.py` [3]. Env `LAB_MFA_REQUIRED` controls enforcement.

5. **Session tokens in plaintext file:** `data/sessions.json` or SQLite stores tokens in plaintext. Web console uses HttpOnly Secure cookies, but API bearer tokens are not rotated.

6. **No breach check:** No HaveIBeenPwned k-anonymity.

7. **Detection is rule-based:** 6 rules, 100% on labelled data, 9 precise alerts (was 14). Real world needs ML baseline, no false positive measurement on clean data yet.

8. **Log shipping is best-effort:** `LAB_LOG_SHIP_STDOUT=true` prints JSON to stdout, `LAB_LOG_SHIP_FILE` appends to file. No queue, no retries, no Splunk HEC auth. Production needs reliable queue + batching. Demo: `demo_p3_hardening.py` [4].

9. **PBKDF2 100k default, Argon2id optional:** PBKDF2 OK for education, modern recommendation 310k+ or Argon2id. P3 adds Argon2id via `argon2-cffi` with env `LAB_HASH_ALGO=argon2` and PBKDF2 fallback if lib missing. Fallback is better than fail-closed but not as strong. Demo: `demo_p3_hardening.py` [1].

10. **CSRF per session, not per form:** Token per session, not rotated per request. Double-submit would be stronger.

11. **No encryption at rest:** Logs contain actor, device_id plaintext. Production needs field-level encryption for PII.

12. **Static fleet:** No dynamic inventory from real MDM.

13. **No account recovery:** No email reset, no admin unlock UI (only `unlock()` function).

14. **Argon2 fallback honest:** If `argon2-cffi` not installed and `LAB_HASH_ALGO=argon2`, we fallback to PBKDF2 and store `_argon2_fallback` flag. Production should fail-closed or require lib.

**Why document this?** Shows I understand difference between educational tamper-evident and production tamper-proof, and can articulate what would be needed for production.

## Threat Model

See `THREAT_MODEL.md` for assets, attackers, controls, detection, and mermaid diagram. Includes 13 attack types with demo scripts:
- `attacker_sim.py` (6 attacks)
- `demo_ledger_attack.py` (ledger tampering)
- `demo_self_approval.py` (four-eyes)
- `demo_p3_hardening.py` (Argon2id, HMAC, TOTP, SIEM)

## Dependency & Security Scanning

- **CodeQL:** `.github/workflows/codeql.yml` — weekly Python security scan
- **Dependabot:** `.github/dependabot.yml` — weekly pip + GitHub Actions updates
- **pip-audit:** `.github/workflows/security.yml` — dependency vulnerability scan
- **TruffleHog:** Secret scanning in CI
- **Safety tests:** AST scan bans destructive calls in core lab
- **Argon2:** Optional `argon2-cffi>=21.3.0` for modern hashing

## Responsible use

Keep adaptations simulated. Real device management belongs on authorized MDM platforms, under organizational policy and law. If you add real ADB/MDM integration, do it behind explicit flags, with authorization, and with audit + approval still enforced.
