# SECURITY.md - Scope Statement

## What this project is
An educational, fully offline simulation of a Mobile Device Management (MDM)
reset workflow, built to learn defensive security concepts.

## What this project will never do
- Reset, unlock, or modify a real Android device
- Access any real device, account, or network without authorization
- Delete, encrypt, or damage real files (writes go only to ./data and ./logs)
- Bypass or weaken real authentication systems
- Provide working attack tooling against real targets

## Safety mechanisms enforced in code
- config.SIMULATION_MODE must stay True (enforced by tests/test_safety.py)
- tests/test_safety.py bans destructive calls (os.remove, subprocess, eval...)
- Every device "wipe" only changes a status field in a local JSON file
- The web console binds to 127.0.0.1 only
- Resets require two distinct accounts (dual control)

## Responsible use
Keep adaptations simulated. Real device management belongs on authorized
MDM platforms, under organizational policy and law.