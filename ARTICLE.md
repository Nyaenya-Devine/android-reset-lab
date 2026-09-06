# How I Fixed 15 Security Bugs in My Own MDM Lab and Cut False Positives 14→9 — Now 52 Tests with Argon2id, HMAC, TOTP, SIEM

> I built a simulated enterprise phone-wipe system, then attacked it. It caught 6/6 attacks but had 8 critical bugs and 5 false positives. Here's how I hardened it to 52 tests, 9 precise alerts, Argon2id, HMAC tamper-proof logs, TOTP MFA, and SIEM shipping.

**TL;DR:** `android-reset-lab` is a Python simulation (stdlib + optional argon2-cffi) of how banks safely wipe lost phones. No real devices touched. I implemented RBAC, dual-control (two humans required), hash-chained + HMAC audit logs, then red-teamed it. Initial version had 18 tests and 14 alerts with bugs. After P0+P1+P2+P3 hardening: 52 tests, 9 alerts (1:1 mapping), 0 critical bugs, P3 demos for Argon2id/HMAC/TOTP/SIEM.

🔗 **Repo:** https://github.com/Nyaenya-Devine/android-reset-lab  
📊 **Release v3.0:** https://github.com/Nyaenya-Devine/android-reset-lab/releases/tag/v3.0  
🎥 **Demo v2.0:** https://github.com/Nyaenya-Devine/android-reset-lab/releases/download/v2.0/android-reset-lab-demo.mp4

---

## The Problem: One Compromised Account Shouldn't Wipe All Phones

In real MDM (Mobile Device Management), a single IT admin account can factory-reset any company phone. If that account is phished, attacker wipes finance team's devices at 3am.

Enterprise controls that stop this:
- **Separation of duties:** Requester ≠ Approver (four-eyes)
- **RBAC default-deny:** Operator can request, only Admin can approve
- **Tamper-evident + tamper-proof logs:** Hash chain + HMAC-SHA256, verification breaks at exact line
- **Time fencing:** Resets outside 8am-6pm flagged
- **Lockout + MFA:** 3 fails → 15 min lock with auto-unlock + optional TOTP

I simulated all of this in Python with fake devices `AND-001`..`AND-006`.

## What I Built (30 sec)

```bash
git clone https://github.com/Nyaenya-Devine/android-reset-lab.git
pip install -r requirements.txt  # includes argon2-cffi optional
python seed_lab.py           # 3 fake users: que/admin, ops/operator, analyst
python attacker_sim.py       # 6 attacks → logs/security_log.jsonl
python threat_detection.py   # 6/6 detected, 9 precise alerts
pytest -q                    # 52 passed (json + sqlite)
python demo_ledger_attack.py    # tamper-evident: tamper detected at line 2
python demo_self_approval.py    # four-eyes: self-approval blocked
python demo_p3_hardening.py     # P3: Argon2id + HMAC tamper-proof + TOTP MFA + SIEM shipping
```

Workflow:
```
Login (PBKDF2/Argon2id + salt + hmac.compare_digest + optional TOTP) → Session (128-bit, 30m TTL, CSRF, MFA flag) → RBAC → Request (unique ID) → Second admin approves (four-eyes) → SIMULATED wipe (status field only) → Hash-chained + HMAC log + SIEM shipping → Detection → Dashboard
```

## The 6 Attacks (Red Team)

I wrote `attacker_sim.py` to fire:

1. **Brute force:** 4 wrong passwords for `ops`
2. **Out-of-hours:** Reset at 03:00 NIGHT (outside 8-18)
3. **Privilege escalation:** Operator tries to approve (should be Admin only)
4. **Unknown device:** Request `AND-999` not in fleet
5. **Replay:** Same request ID twice
6. **Unapproved execute:** Execute without approval → `RESET_BLOCKED`

Blue team `threat_detection.py` has 6 rules.

## What Was Wrong (Honest)

Initial version: 18 tests, 6/6 detection but **14 alerts** — 5 were false out-of-hours because I ran tests at 07:53 outside allowed window, and replay flagged both original + replay.

**Critical bugs found in review:**

1. **Audit actor bug:** `execute_reset` logged `req["approver"]` not executor. If Admin A approves and Admin B executes, log says A did it. Broke audit integrity.
2. **User enumeration:** `login()` returned "unknown user" vs "bad password" — attacker can enumerate users.
3. **Timing attack:** Used `==` for hash compare, not `hmac.compare_digest`.
4. **Shallow-copy bug:** `dict(FLEET)` shares inner dicts → wiping device mutated global `FLEET`, caused test flakiness.
5. **XSS:** Web console did `PAGE.replace("{msg}", msg)` no escaping.
6. **Password echo:** `input("pass: ")` echoes password.
7. **Reports crash:** `open("reports/dashboard.txt")` without `makedirs` → crash on clean clone.
8. **Timestamp spoofing:** `log_event(timestamp=...)` allowed anyone to forge timestamps.

**Repo hygiene:** 3.9MB video in git (bloats clone), screenshot with spaces, CI in `.pytest_cache`, duplicate test defs.

## How I Fixed It (P0)

```python
# Before (bug):
security_logger.log_event("RESET_EXECUTED", req["approver"], ...)

# After (fixed):
security_logger.log_event("RESET_EXECUTED", session["username"], ...)
```

- Generic messages: `"invalid credentials"` for both unknown user and bad password
- Constant-time: `hmac.compare_digest(expected, actual)`
- Deepcopy: `copy.deepcopy(FLEET)` not `dict(FLEET)`
- XSS: `html.escape(msg)` + CSP headers
- `getpass.getpass()` for password
- `os.makedirs("reports", exist_ok=True)`
- `_allow_custom_timestamp` flag — only simulation can set custom timestamp
- Centralized seeding in `seed_lab.py` with env var override
- Removed video from git → release asset, renamed screenshot → `dashboard.png`
- Added `requirements.txt`, `LICENSE`, proper CI

Result: 20 tests, 0 critical bugs.

## P1 Hardening — Cutting False Positives 14→9

**Problem:** Out-of-hours flagged 5 events but only 1 was real attack. Why? `attacker_sim` ran at 07:53 outside 8-18 window, so every `RESET_REQUESTED` at 07:53 was flagged.

**Fix:** Controlled timestamps:

```python
NIGHT = "2026-08-31T03:00:00+00:00"  # outside window → should flag
DAY = "2026-08-31T10:00:00+00:00"    # inside window → should NOT flag
```

**Detection improvements:**

- **Brute force:** Sliding window 10 min, not total count forever
- **Replay:** Only flag 2nd+ occurrence, not first
- **Out-of-hours:** Filter `outcome != "denied"` and use fleet set validation
- **Unknown device:** Check `device_id not in FLEET` set

**Rate limiting + lockout:**

```python
# Time-based lockout with auto-unlock
locked_until = now + timedelta(minutes=15)

# Web console IP rate limiting
rate_limit_store = defaultdict(deque)
if len(dq) >= 10: return 429
```

**Result:**
```
Before: brute_force 4, out_of_hours 5, replay 2 = 14 alerts
After:  brute_force 4, out_of_hours 1, replay 1 = 9 alerts (1:1 mapping)
```

## P2 Hardening — Slow, Necessary

- JSON + SQLite abstraction (`storage.py`) with WAL, atomic writes, migration via `LAB_STORAGE_BACKEND=sqlite`
- 19 negative/attack tests (SQLi, XSS, CSRF, rate limit, self-approval, ledger tamper)
- Auth rate limit 5 req/60s per IP/user + web 10 req/60s → 429 + `CSRF_BLOCKED` logging
- CSRF: hidden `csrf_token` field + `validate_csrf_token` + SameSite Strict + HttpOnly
- Scanning: CodeQL + Dependabot + pip-audit + TruffleHog
- Threat model: Mermaid flowchart with 11 attacks mapped to controls/detection/demo scripts
- Demos: `demo_ledger_attack.py` (tamper detected at line 2) + `demo_self_approval.py` (self-approval blocked)
- Honest limitations: 13 items documented

→ 47 tests

## P3 Hardening — Current (Simulation-Only Guard Kept)

**Argon2id with PBKDF2 fallback:**
```bash
LAB_HASH_ALGO=argon2 python demo_p3_hardening.py
```
- `argon2-cffi` optional, fallback to PBKDF2 if missing (better than fail-closed)
- User record stores `algo` field, login verifies based on stored algo
- Env `LAB_HASH_ALGO=argon2` enables memory-hard hashing

**HMAC Tamper-Proof Log:**
- Before: hash chain tamper-evident only
- Now: HMAC-SHA256 with key in `data/hmac.key` (0600) — tamper-proof if key kept separate from log
- `security_logger.generate_hmac_key()` + `verify_logs()` checks HMAC with `compare_digest`
- Demo: `demo_p3_hardening.py` [2] — without key EVIDENT, with key PROOF, tamper detected line 2

**TOTP MFA (stdlib-only):**
```python
secret = enable_totp("alice")
code = get_totp_code(secret)
login("alice", "pass", totp_code=code)
```
- RFC 6238, 6-digit, 30s period, window=1 for clock skew, no external deps
- `get_totp_uri()` for QR, `LAB_MFA_REQUIRED` flag controls enforcement
- Secret stored plaintext in simulation (honest limitation), production needs encrypted field

**SIEM Shipping:**
```bash
LAB_LOG_SHIP_STDOUT=true python security_logger.py  # JSON stdout for Splunk
LAB_LOG_SHIP_FILE=logs/siem.log python ...
```
- Best-effort print to stdout/file, production needs queue + retries + HEC auth

→ 52 tests (21 workflow + 5 detection + 2 safety + 19 negative + 5 P3), 15 attacks in threat model, 14 honest limitations

## Tests That Prove It

```python
def test_execute_logs_correct_actor():
    admin, ops = _tokens()
    ok, rid = request_reset(ops, "AND-004")
    approve_reset(admin, rid)
    admin2_token = start_session("t_admin2")
    execute_reset(admin2_token, rid)
    last = json.loads(open(LOG_FILE).readlines()[-1])
    assert last["actor"] == "t_admin2"  # was approver before, now executor

def test_hmac_signed_log():
    security_logger.generate_hmac_key()
    security_logger.log_event("TEST_HMAC", "bob", "with hmac")
    ok, count = security_logger.verify_logs()
    assert ok
    # Tamper
    entry["outcome"] = "hacked"
    ok, bad = security_logger.verify_logs()
    assert not ok and bad == 2

def test_totp_mfa_login_flow():
    secret = enable_totp("t_mfa")
    code = get_totp_code(secret)
    ok, _ = login("t_mfa", "StrongPass!123", totp_code=code)
    assert ok
```

52 tests now: workflow, detection, safety, negative/attack, P3 (Argon2, HMAC, TOTP, SIEM).

## What Recruiters Should See

**For SOC / Detection Engineer:**
- Wrote 6 detection rules with sliding windows, reduced false positives 14→9
- Built dashboard + JSON metrics + SIEM shipping stdout/file

**For AppSec:**
- Fixed OWASP: enumeration, timing attack, XSS, password echo
- Secure storage: PBKDF2 100k + Argon2id + salt, role whitelist, session TTL + CSRF + HMAC + TOTP MFA

**For Backend:**
- Stdlib-only + optional argon2, isolated tests with tmp_path + monkeypatch, fixed deepcopy bug
- Clean architecture: auth → RBAC → workflow → audit → detection → reporting
- CI: pytest + attack sim + log verify + CodeQL + pip-audit + TruffleHog

**Standards:** MITRE ATT&CK (T1110, T1078, T1134, T1070) + NIST 800-53 (IA-5, AC-7, AC-3, AC-5, AU-9, SI-4, IA-2 MFA) mapped, honest limitations documented

## Lessons

1. **Security controls need tests that attack them.** Happy path tests miss actor logging bugs.
2. **Timestamps matter.** 07:53 outside 8-18 window caused false positives — deterministic DAY/NIGHT fixed it.
3. **Shallow copy bites.** `dict(FLEET)` shares inner dicts — `deepcopy` needed.
4. **Repo hygiene is security.** 3.9MB video in git = slow clone, broken CI = no CI.
5. **Generic messages prevent enumeration.** "invalid credentials" > "unknown user".
6. **Document honest limitations.** Tamper-evident vs tamper-proof, in-memory rate limiting vs Redis, file-based HMAC vs KMS, plaintext TOTP secret vs encrypted — shows production thinking.

## Try It

```bash
git clone https://github.com/Nyaenya-Devine/android-reset-lab.git
pip install -r requirements.txt  # includes argon2-cffi optional
python seed_lab.py && python attacker_sim.py && python threat_detection.py && pytest -q  # 52 passed
python demo_ledger_attack.py    # tamper detected at line 2
python demo_self_approval.py    # self-approval blocked
python demo_p3_hardening.py     # Argon2id + HMAC + TOTP + SIEM
```

Full code: https://github.com/Nyaenya-Devine/android-reset-lab
Release v3.0: https://github.com/Nyaenya-Devine/android-reset-lab/releases/tag/v3.0

---

*Built by Devine Nyaenya Ngorwe — Nairobi, Kenya — Security-focused engineer who ships the proof alongside the code. Open to SOC, Detection, AppSec roles.*

#cybersecurity #python #rbac #detectionengineering #mitreattack #appsec #pytest #argon2 #hmac #totp #siem #defensivesecurity
