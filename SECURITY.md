# SECURITY.md - Scope Statement & Honest Limitations

## What this project is
An educational, fully offline simulation of a Mobile Device Management (MDM)
reset workflow, built to learn defensive security concepts. It demonstrates
how to build controls, then proves they hold by attacking itself.

**Current hardening:** P0 (8 critical bugs fixed) + P1 (time-based lockout, rate limiting, precise detection) + P2 (persistent storage abstraction, CSRF, dependency scanning)

## What this project will never do
- Reset, unlock, or modify a real Android device
- Access any real device, account, or network without authorization
- Delete, encrypt, or damage real files (writes go only to ./data and ./logs and optional data/lab.db)
- Bypass or weaken real authentication systems
- Provide working attack tooling against real targets

## Safety mechanisms enforced in code
- `config.SIMULATION_MODE` must stay True (enforced by tests/test_safety.py)
- `tests/test_safety.py` bans destructive calls (os.remove, subprocess, eval...)
- Every device "wipe" only changes a status field in local JSON/SQLite
- Web console binds to 127.0.0.1 only, with rate limiting (10 req/60s), CSRF token + SameSite Strict + HttpOnly
- Resets require two distinct accounts (dual control) — self-approval blocked
- Passwords: PBKDF2 100k + salt + `hmac.compare_digest` constant-time, role whitelist, min length 8
- Sessions: 128-bit token, TTL 30m, CSRF token per session
- Audit log: hash-chained with timestamp spoof protection

## Known Limitations — Honest Disclosure (P2)

**This is a simulation, not production MDM. Documented honestly for recruiters:**

1. **Audit log is tamper-evident, not tamper-proof:** Hash chain detects modification at exact line (`verify_logs()`), but attacker with write access could delete entire log file. Real SIEM needs HMAC with secret key or asymmetric signing + WORM storage. Demo: `demo_ledger_attack.py`

2. **Storage:** Default JSON files are human-readable but no ACID. Optional SQLite backend (`LAB_STORAGE_BACKEND=sqlite`) adds WAL + atomicity but still file-based. Production needs proper DB with row-level locking + backups. New abstraction in `storage.py` allows switching.

3. **Rate limiting is in-memory:** `rate_limit_store` and `_auth_rate_limit_store` are per-process memory, reset on restart, not shared across workers. Production needs Redis.

4. **No MFA:** Only password + session token. No TOTP, WebAuthn, device attestation. Documented as next step.

5. **Session tokens in plaintext file:** `data/sessions.json` or SQLite stores tokens in plaintext. Web console uses HttpOnly Secure cookies, but API bearer tokens are not rotated.

6. **No breach check:** No HaveIBeenPwned k-anonymity.

7. **Detection is rule-based:** 6 rules, 100% on labelled data, 9 precise alerts (was 14). Real world needs ML baseline, no false positive measurement on clean data yet.

8. **No log shipping:** Logs stay local, not shipped to Splunk/SIEM, no retention.

9. **PBKDF2 100k:** OK for education, modern recommendation 310k+ or Argon2id (documented next step).

10. **CSRF per session, not per form:** Token per session, not rotated per request. Double-submit would be stronger.

11. **No encryption at rest:** Logs contain actor, device_id plaintext. Production needs field-level encryption for PII.

12. **Static fleet:** No dynamic inventory from real MDM.

13. **No account recovery:** No email reset, no admin unlock UI (only `unlock()` function).

**Why document this?** Shows I understand difference between educational tamper-evident and production tamper-proof, and can articulate what would be needed for production.

## Threat Model

See `THREAT_MODEL.md` for assets, attackers, controls, detection, and mermaid diagram. Includes 11 attack types with demo scripts:
- `attacker_sim.py` (6 attacks)
- `demo_ledger_attack.py` (ledger tampering)
- `demo_self_approval.py` (four-eyes)

## Dependency & Security Scanning

- **CodeQL:** `.github/workflows/codeql.yml` — weekly Python security scan
- **Dependabot:** `.github/dependabot.yml` — weekly pip + GitHub Actions updates
- **pip-audit:** `.github/workflows/security.yml` — dependency vulnerability scan
- **TruffleHog:** Secret scanning in CI
- **Safety tests:** AST scan bans destructive calls

## Responsible use

Keep adaptations simulated. Real device management belongs on authorized MDM platforms, under organizational policy and law. If you add real ADB/MDM integration, do it behind explicit flags, with authorization, and with audit + approval still enforced.
