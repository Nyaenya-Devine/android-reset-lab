# INTERVIEW_PREP.md — P3 Updated

## The 60-second demo (say this while showing)
1. "This is a simulated MDM reset lab - no real devices." (show README + SECURITY.md honest limits)
2. Run `attacker_sim.py` - "six simulated attacks fire into a hash-chained log with DAY/NIGHT timestamps."
3. Run `threat_detection.py` - "six correlation rules catch all six: 6/6 with 9 precise alerts (was 14)."
4. Run `reports.py` - "dashboard: severities, alerts, log integrity INTACT."
5. Run `demo_ledger_attack.py` - "I tamper with log, verify_logs points at exact broken line 2, restore → INTACT."
6. Run `demo_self_approval.py` - "Self-approval blocked with APPROVAL_DENIED, second admin allowed — four-eyes."
7. Run `demo_p3_hardening.py` - "P3: Argon2id login, HMAC-signed log tamper-proof, TOTP MFA, SIEM shipping to stdout."

## One-page summary bullets
- Full defensive pipeline in Python: PBKDF2/Argon2id + salt + TOTP MFA, RBAC default-deny, dual-control workflow, tamper-evident + HMAC tamper-proof logging, detection engineering with measured 6/6 coverage, SIEM shipping.
- 52 tests: 21 workflow + 5 detection + 2 safety + 19 negative/attack + 5 P3 (Argon2, HMAC, TOTP, SIEM)
- Storage: JSON + SQLite WAL + atomic writes, isolated per test via tmp_path
- Security: CSRF token + SameSite Strict + HttpOnly, IP rate limiting 10/60s web + 5/60s auth, XSS escaping + CSP
- Every feature mapped to MITRE ATT&CK and NIST 800-53, honest limitations documented (14 items)
- Safety as code: AST self-audit bans destructive calls in core lab; SIMULATION_MODE enforced by test; demo cleanup allowed

## Questions they will ask, and your answers
Q: Why salted hashes, not stored passwords?
A: A leak then never reveals passwords; salts make identical passwords hash differently and kill rainbow tables.

Q: Why PBKDF2 with 100k rounds and Argon2id option?
A: PBKDF2 deliberately slow so guessing is expensive; Argon2id is memory-hard, modern recommendation. I support both via LAB_HASH_ALGO=argon2 with PBKDF2 fallback if lib missing — shows graceful degradation.

Q: Why dual control?
A: Separation of duties (AC-5): no single account is a complete weapon. Self-approval blocked with test.

Q: How do you detect log tampering?
A: Hash chain (prev_hash + entry_hash) gives tamper-evident, points at exact broken line. With HMAC key in data/hmac.key (0600, kept separate), becomes tamper-proof — HMAC-SHA256 over entry, verified in verify_logs().

Q: What is a false positive; did you measure yours?
A: An alert on benign activity. Initial run gave 14 alerts with 5 false out_of_hours because tests ran at 07:53 outside 8-18 window. Fixed with controlled DAY=10:00 / NIGHT=03:00 timestamps → 9 precise alerts 1:1 mapping.

Q: What about MFA?
A: P3 adds TOTP RFC 6238 stdlib-only, 6-digit, 30s period, window=1 for clock skew. Secret stored plaintext in simulation (honest limitation), production needs encrypted field + HSM. Env LAB_MFA_REQUIRED controls enforcement, backward compat when false.

Q: How would you ship logs to SIEM?
A: P3 adds LAB_LOG_SHIP_STDOUT=true prints JSON to stdout for Splunk/SIEM collector, LAB_LOG_SHIP_FILE=logs/siem.log appends to file. Best-effort, production needs queue + retries + HEC auth.

Q: Is this hacking?
A: No - defensive simulation. SECURITY.md states exactly what it never does. SIMULATION_MODE=True enforced by test.

Q: Why honest limitations?
A: Shows production thinking — I document tamper-evident vs tamper-proof, in-memory rate limiting vs Redis, file-based HMAC vs KMS, plaintext TOTP secret vs encrypted, etc.

## P3 Demo Commands (for interview)
```bash
pytest -q  # 52 passed
LAB_STORAGE_BACKEND=sqlite pytest -q  # 52 passed sqlite
LAB_HASH_ALGO=argon2 python demo_p3_hardening.py  # Argon2id path
python demo_ledger_attack.py  # tamper detected at line 2
python demo_self_approval.py  # self-approval blocked
python demo_p3_hardening.py  # full P3
```
