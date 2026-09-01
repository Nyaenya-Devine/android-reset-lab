# 🛡️ Android Reset Lab — Secure Device Management Simulation

> **One-line pitch:** I built a simulation of an enterprise MDM reset system that *prevents* single-person abuse through authentication, dual-control approval, and tamper-evident audit logs — then proved it works by attacking it myself (6/6 attacks detected).

[![Tests](https://github.com/Nyaenya-Devine/android-reset-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/Nyaenya-Devine/android-reset-lab/actions)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![Tests](https://img.shields.io/badge/tests-28%20passed-brightgreen)
![Detection](https://img.shields.io/badge/detection-6%2F6%20(100%25)-green)
![Security](https://img.shields.io/badge/security-simulation--only-green)
[![Release](https://img.shields.io/github/v/release/Nyaenya-Devine/android-reset-lab?label=release)](https://github.com/Nyaenya-Devine/android-reset-lab/releases/tag/v2.0)

**🎥 Demo Video:** [Download v2.0 Demo (3.9MB)](https://github.com/Nyaenya-Devine/android-reset-lab/releases/download/v2.0/android-reset-lab-demo.mp4) | **📊 Dashboard:** Below

![Dashboard](dashboard.png)

---

## 👩‍💼 For Recruiters — 30 Second Summary

**What is this?** A Python-only lab that simulates how companies like banks safely wipe lost/stolen phones. No real devices are touched — everything is fake data.

**Business problem solved:** Without controls, one compromised IT account can wipe all company phones. This lab enforces:
- **No single person can wipe a device** — needs 2 different humans (four-eyes)
- **No brute force** — account locks for 15 min after 3 fails, with auto-unlock
- **No secret tampering** — audit log is hash-chained; if someone edits it, verification breaks at exact line
- **No after-hours abuse** — resets outside 8am-6pm are flagged
- **No fake devices** — unknown device IDs are blocked

**Result:** I attacked my own system with 6 techniques (brute force, privilege escalation, replay, etc.) and my detection caught **6/6 with 9 precise alerts** (was 14 with false positives before hardening).

**Why hire me?** This shows I think like both attacker and defender, write tests for security controls, and clean up security bugs (fixed 15 issues: timing attacks, enumeration, XSS, actor logging bugs, etc.)

**Tech in 10 seconds:** Python stdlib only, PBKDF2 + salt + `hmac.compare_digest`, RBAC default-deny, session TTL, IP rate limiting, hash-chained JSONL logs, pytest with isolated tmp_path fixtures.

---

## 🎯 Key Achievements (Metrics)

| Metric | Before Hardening | After P0+P1 Hardening |
|--------|------------------|------------------------|
| **Tests** | 18 | **28** (+5 detection, +3 security) |
| **Detection** | 6/6 but 14 alerts (5 false out-of-hours, replay double-counted) | **6/6 with 9 alerts** (1:1 mapping, precise) |
| **Critical bugs** | 8 (actor logged as approver not executor, enumeration, timing attack, XSS, etc.) | **0 — all fixed with regression tests** |
| **Lockout** | Permanent DoS | **15 min auto-unlock** |
| **Rate limiting** | None | **10 req/60s IP-based, returns 429** |
| **Repo hygiene** | 3.9MB video in git, broken CI | **73KB repo, video as release asset, proper CI** |

---

## 🧠 Skills This Proves (Mapped to Job Descriptions)

**For SOC Analyst / Detection Engineer roles:**
- ✅ Wrote 6 detection rules (brute force with sliding time window, replay only 2nd occurrence, out-of-hours filtering)
- ✅ Reduced false positives 14 → 9 by fixing timestamp handling
- ✅ Built dashboard and JSON metrics

**For AppSec / Security Engineer roles:**
- ✅ Fixed OWASP-style bugs: user enumeration (generic messages), timing attack (`compare_digest`), XSS (`html.escape`), password echo (`getpass`)
- ✅ Implemented secure password storage (PBKDF2 100k + salt), role whitelist, password strength, session expiry
- ✅ Tamper-evident logging with hash chain verification

**For Python / Backend roles:**
- ✅ Stdlib-only, no dependencies except pytest
- ✅ Isolated tests with `tmp_path` + `monkeypatch` (no state leakage, fixed deepcopy bug)
- ✅ Clean architecture: auth → RBAC → workflow → audit → detection → reporting

**Standards:** Mapped to MITRE ATT&CK (T1110, T1078, T1134, T1070) and NIST 800-53 (IA-5, AC-7, AC-3, AC-5, AU-9, SI-4)

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[User Login] --> B{PBKDF2 + Salt + compare_digest}
    B -->|Fail| C[Increment failed, lock 15m after 3]
    B -->|Success| D[Session Token 128-bit TTL 30m]
    D --> E{RBAC Check default-deny}
    E -->|Deny| F[ACCESS_DENIED logged]
    E -->|Allow| G[Request Reset - Validate Device in Fleet]
    G --> H[Unique Request ID + Four-Eyes Check]
    H --> I{Second Admin Approves? requester != approver}
    I -->|No| J[APPROVAL_DENIED]
    I -->|Yes| K[SIMULATED Wipe - status field only]
    K --> L[Hash-Chained Audit Log prev_hash + entry_hash]
    L --> M[Threat Detection 6 Rules Time-Windowed]
    M --> N[Dashboard + Metrics]
```

**Data flow is 100% simulated:** `data/devices.json` status changes from `active` → `wiped`, never touches real hardware.

---

## ⚡ 30-Second Quick Start (For Recruiters to Try)

```bash
git clone https://github.com/Nyaenya-Devine/android-reset-lab.git
cd android-reset-lab
pip install -r requirements.txt
python seed_lab.py          # creates 3 fake users: que/admin, ops/operator, analyst
python attacker_sim.py      # fires 6 attacks into logs/security_log.jsonl
python threat_detection.py  # prints 6/6 detection
python reports.py           # prints dashboard
pytest -q                   # 28 passed
python web_console.py       # open http://127.0.0.1:8000 - try requesting reset
```

**Login for demo:** user `ops` / pass `OpsOps!123` (simulation-only, from `seed_lab.py`, override via `LAB_OPS_PASS` env var)

---

## 🎬 Demo Walkthrough (60 sec to say in interview)

1. "This is simulation-only MDM reset lab — no real devices" (show README + SECURITY.md)
2. Run `attacker_sim.py` — "6 simulated attacks fire into hash-chained log, DAY=10:00 within window, NIGHT=03:00 outside"
3. Run `threat_detection.py` — "6 rules catch all 6, now 9 precise alerts not 14"
4. Run `reports.py` — "Dashboard: severities, detection 6/6, log INTACT"
5. Edit one log word, run `security_logger.py verify` — "Chain breaks at line X, undo, INTACT"
6. "Every reset needs 2 different humans; test proves executor is logged correctly, not approver (was bug)"

---

## 🔍 Attack Simulation Results

| Attack | How Simulated | Detection Rule | Result |
|--------|---------------|----------------|--------|
| Brute force | 4 wrong passwords for ops | `LOGIN_FAILED` count ≥3 within 10 min sliding window | ✅ 4 events flagged |
| Out-of-hours | Reset at 03:00 NIGHT | `RESET_REQUESTED` hour not in 8-18 and outcome=created | ✅ 1 flagged (was 5 false) |
| Privilege escalation | Operator tries approve | `ACCESS_DENIED` | ✅ |
| Unknown device | Request AND-999 | Device not in FLEET set | ✅ |
| Replay | Same request ID twice | Only 2nd occurrence flagged (was both) | ✅ 1 flagged (was 2) |
| Unapproved execute | Execute without approval | `RESET_BLOCKED` | ✅ |

**Verified:** 6/6 categories, 9 total alerts (precise), log integrity INTACT.

---

## 🔐 Access Control

| Role | Request | Approve | Manage Users | View Logs |
|------|---------|---------|--------------|-----------|
| Viewer | ❌ | ❌ | ❌ | ❌ |
| Operator | ✅ | ❌ | ❌ | ❌ |
| Admin | ✅ | ✅ | ✅ | ❌ |
| Security Analyst | ❌ | ❌ | ❌ | ✅ |

Separation of duties: requester ≠ approver enforced in code + tested.

---

## 🛡️ Safety Boundary (Important for Recruiters)

```python
SIMULATION_MODE = True  # enforced by test
```

This project **never**:
- Touches real Android devices / ADB / MDM APIs
- Executes real wipe commands
- Deletes real files (writes only to `data/`, `logs/`, `reports/`)
- Contacts external networks

Safety tests (`test_safety.py`) AST-scan for banned calls (`subprocess`, `os.remove`, `eval`, etc.)

See `SECURITY.md` and `THREAT_MODEL.md` for full scope.

---

## 📁 Project Structure (Recruiter-Friendly)

```
├── authentication.py       # PBKDF2 + hmac.compare_digest, 15m lockout with auto-unlock
├── authorization.py        # RBAC default-deny + role whitelist
├── seed_lab.py             # Centralized seeding, env var override for creds
├── reset_workflow.py       # Four-eyes workflow, fixed actor logging, idempotency
├── security_logger.py      # Hash-chained JSONL, timestamp spoof protection
├── threat_detection.py     # P1: time-windowed, replay only 2nd+, filtered
├── web_console.py          # Loopback only, XSS fixed, IP rate limiting 10/60s
├── device_simulator.py     # Fake fleet AND-001..006, deepcopy fix
├── attacker_sim.py         # Red team with DAY/NIGHT controlled timestamps
├── tests/
│   ├── conftest.py         # Isolated tmp_path fixtures (professional)
│   ├── test_workflow.py    # 21 tests: auth, RBAC, dual-control, lockout auto-unlock
│   ├── test_detection.py   # 5 tests: replay, brute force window, rate limiting
│   └── test_safety.py      # 2 tests: no destructive calls, SIMULATION_MODE
├── dashboard.png           # Screenshot (no spaces, 44KB)
└── .github/workflows/tests.yml  # CI runs pytest + attack sim + verify
```

---

## 🧪 Testing

```bash
pip install -r requirements.txt
pytest -v  # 28 passed

# What tests prove:
# - Wrong password → "invalid credentials" (not "unknown user") — prevents enumeration
# - 3 fails → locked for 15m, auto-unlocks after time
# - Session expires after 30m, logout invalidates
# - Operator cannot approve, viewer cannot request
# - Self-approval blocked, execute without approval blocked
# - Device already wiped → blocked (idempotency)
# - Audit log tampering detected at exact line
# - Replay only 2nd occurrence flagged
# - Rate limiting blocks after 10 req/60s
```

---

## 📚 Standards Mapping (Educational, not certified)

| Feature | MITRE ATT&CK | NIST 800-53 |
|---------|--------------|-------------|
| Password hashing + lockout | T1110 Brute Force | IA-5, AC-7 |
| Session tokens | T1078 Valid Accounts | IA-11 |
| RBAC | T1134 Access Token Manipulation | AC-3, AC-6 |
| Dual control | — | AC-5 Separation of Duties |
| Hash-chained log | T1070 Indicator Removal | AU-9 Protection |
| Threat detection | Various | SI-4 Monitoring |
| Rate limiting | — | SC-5 Denial of Service Protection |

---

## 🚀 What I Fixed (P0+P1) — Shows Growth

**P0 (Critical bugs found in initial review):**
- Actor logged as approver not executor → fixed + regression test
- User enumeration + timing attack → generic messages + `compare_digest`
- XSS, password echo, reports crash, timestamp spoofing → fixed
- 3.9MB video in git → moved to release asset, repo 73KB

**P1 (Hardening to reduce false positives):**
- Permanent lockout → 15m auto-unlock with `locked_until`
- No rate limiting → IP sliding window 10/60s
- Detection 14 alerts with false positives → 9 precise alerts (1:1)
- Controlled timestamps DAY/NIGHT for deterministic results

---

## 📦 Release

**Latest:** [v2.0](https://github.com/Nyaenya-Devine/android-reset-lab/releases/tag/v2.0) — Includes demo video as asset:
- [android-reset-lab-demo.mp4](https://github.com/Nyaenya-Devine/android-reset-lab/releases/download/v2.0/android-reset-lab-demo.mp4)

**Install:**
```bash
pip install -r requirements.txt
python seed_lab.py
python attacker_sim.py && python threat_detection.py && python reports.py
```

---

## 👤 Author & Contact

**Nyaenya-Devine** — Defensive Security / Python / Detection Engineering

- GitHub: [@Nyaenya-Devine](https://github.com/Nyaenya-Devine)
- Project: [android-reset-lab](https://github.com/Nyaenya-Devine/android-reset-lab)
- Focus: Secure-by-design, testing security controls, red/blue team simulation

**Open to:** SOC Analyst, Detection Engineer, AppSec Engineer, Security Engineer (Junior) roles in Nairobi / Remote

---

## 📄 License & Ethics

MIT License — See `LICENSE`. This is **simulation-only** for education. All attacks run against fake local data. Real MDM belongs on authorized platforms under organizational policy and law.

**Verified:** 28 tests passing, 6/6 detection, log INTACT, 9 precise alerts.
