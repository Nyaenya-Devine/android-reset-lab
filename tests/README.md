# Android Reset Lab

A safe, fully simulated security lab that models how a real device-management
system identifies devices, authenticates users, authorizes actions, processes
factory-reset requests with dual control, detects attacks, and keeps a
tamper-evident audit log.

**Nothing in this project touches a real device, file, or network.**
See SECURITY.md for the full scope statement.

## What it demonstrates

- Salted password hashing (PBKDF2), session tokens, account lockout
- Role-based access control with default deny
- Dual-control (four-eyes) reset workflow with a simulation guard
- Hash-chained JSON Lines audit log with integrity verification
- Six attack detections with a measured detection rate
- A self-audit test that bans destructive code from the codebase

## Quick start

    pip install pytest
    python attacker_sim.py
    python threat_detection.py
    python reports.py
    python -m pytest tests -q
    python web_console.py        # then open http://127.0.0.1:8000

## Roles

| Role | Request reset | Approve reset | Manage users | View logs |
|---|---|---|---|---|
| viewer | no | no | no | no |
| operator | yes | no | no | no |
| admin | yes | yes | yes | no |
| security_analyst | no | no | no | yes |

## Detection results (latest labelled attack run)

| Attack | Rule | Caught |
|---|---|---|
| Brute force | repeated LOGIN_FAILED per actor | yes |
| Out-of-hours reset | timestamp outside 08:00-18:00 | yes |
| Privilege escalation | ACCESS_DENIED events | yes |
| Unknown device | request for device not in fleet | yes |
| Replay | duplicated request id | yes |
| Unapproved execute | RESET_BLOCKED by simulation guard | yes |

Detection rate: 6/6, zero misses on the labelled run.

## Standards mapping

| Feature | Real-world equivalent | MITRE ATT&CK | NIST 800-53 |
|---|---|---|---|
| Salted hashing + lockout | IAM password policy | T1110 | IA-5, AC-7 |
| Session tokens | SSO sessions | T1078 | IA-11 |
| RBAC matrix | least privilege | T1134 | AC-3, AC-6 |
| Dual control | separation of duties | T1531 | AC-5 |
| Hash-chained log | signed / WORM audit storage | T1070 | AU-9 |
| Six detections | SIEM correlation rules | various | SI-4 |
| Dashboard and report | SOC triage reporting | - | AU-6 |
| attacker_sim | purple-team exercise | - | CA-8 |
| Device fleet | MDM inventory (Intune, Workspace ONE) | T1485 | CM-8 |

## Architecture

    login -> session token -> authorize(role, action)
    request -> approve (second human) -> SIMULATED execute
    every step -> hash-chained audit log -> detections -> dashboard

## Disclaimer

Educational simulation for defensive-security learning.
No real device, account, file, or network is ever touched.