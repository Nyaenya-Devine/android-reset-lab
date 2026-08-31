# INTERVIEW_PREP.md

## The 60-second demo (say this while showing)
1. "This is a simulated MDM reset lab - no real devices." (show README)
2. Run attacker_sim.py - "six simulated attacks fire into a hash-chained log."
3. Run threat_detection.py - "six correlation rules catch all six: 6/6."
4. Run reports.py - "dashboard: severities, alerts, log integrity INTACT."
5. Change one log word, run security_logger.py verify - "chain breaks at
   line 1. Undo, verify, INTACT."
6. "Every reset needs two different humans; the test suite proves the
   guard cannot be skipped."

## One-page summary bullets
- Full defensive pipeline in Python stdlib: PBKDF2+salt authn, RBAC default
  deny, dual-control workflow, tamper-evident logging, detection engineering
  with measured 6/6 coverage.
- Every feature mapped to MITRE ATT&CK and NIST 800-53.
- Safety as code: AST self-audit bans destructive calls; SIMULATION_MODE
  enforced by a test.

## Questions they will ask, and your answers
Q: Why salted hashes, not stored passwords?
A: A leak then never reveals passwords; salts make identical passwords hash
   differently and kill rainbow tables.

Q: Why PBKDF2 with 100k rounds?
A: Deliberately slow so guessing is expensive; standard, audited choice.

Q: Why dual control?
A: Separation of duties (AC-5): no single account is a complete weapon.

Q: How do you detect log tampering?
A: Hash chain; verify recomputes every fingerprint and points at the exact
   broken line.

Q: What is a false positive; did you measure yours?
A: An alert on benign activity. My labelled run gave 6/6 true positives and
   zero flags on clean events.

Q: What would you add next?
A: Session expiry, rate limiting on the console, argon2 option, shipping logs
   to a real SIEM, attacker_sim from Kali as a separate red host.

Q: Is this hacking?
A: No - defensive simulation. SECURITY.md states exactly what it never does.