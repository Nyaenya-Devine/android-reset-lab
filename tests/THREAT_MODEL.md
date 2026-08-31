# THREAT_MODEL.md

## Assets
- Audit log integrity (evidence)
- Authorization decisions (who may reset)
- Device records (fleet inventory)

## Simulated attackers
- Outsider guessing credentials (brute force)
- Malicious insider with a valid low-privilege session
- Compromised admin trying to bypass dual control
- Actor with log write access trying to rewrite history

## Attacks modeled and controls
| # | Attack | Control | Detection |
|---|---|---|---|
| 1 | Brute force login | Lockout (AC-7) | brute_force rule |
| 2 | Out-of-hours reset | Policy window in config | out_of_hours rule |
| 3 | Privilege escalation | RBAC default deny | privilege_escalation rule |
| 4 | Ghost device request | Inventory validation | unknown_device rule |
| 5 | Replay of request id | Idempotency keys | replay rule |
| 6 | Unapproved execute | State machine guard | unapproved_execute rule |
| 7 | Log tampering | Hash chain | verify_logs |

## Out of scope (and why)
Real device exploits, FRP bypass, radio attacks: harmful and unlawful without
authorization. This lab teaches the defensive side instead.