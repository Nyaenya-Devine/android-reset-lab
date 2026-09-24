# Android Reset Lab

A simulation-only security lab for authorizing, approving, recording, and verifying high-impact device reset and sanitization workflows.

> No real device commands are executed. The lab exists to test controls around irreversible operations without putting user data or evidence at risk.

## What it demonstrates

- Default-deny RBAC and time-limited sessions
- Distinct-requester dual control for reset approval
- Risk-adaptive step-up and transaction signing
- Device attestation and policy-as-code decisions
- Hash-chained, HMAC-protected and Merkle-verifiable audit evidence
- Detection for brute force, replay, privilege abuse and log tampering
- Safety classification across troubleshooting, redeployment, loss, investigation and retirement
- Clear separation between factory reset, cryptographic purge, evidence preservation and physical destruction

## Safety model

The sanitization advisor evaluates:

- operational intent
- evidence or legal hold
- encryption from first use
- removable media
- Factory Reset Protection or activation lock
- device connectivity
- required assurance: Clear, Purge or Destroy

It returns one of five deterministic outcomes:

`BLOCK` · `PRESERVE` · `SIMULATE_RESET` · `SANITIZE` · `DESTROY`

A factory reset is never presented as universal proof of sanitization. Investigation scenarios preserve evidence, removable media is handled separately, and Purge requires a defensible encryption or approved sanitization path.

## Run locally

```bash
python -m pip install -r requirements.txt
python seed_lab.py
python web_console.py
```

Open `http://localhost:8080`.

Seeded simulation accounts are defined in `seed_lab.py`. Change all credentials before using the lab outside an isolated local demonstration.

## Verify

```bash
python -m pytest -q
python -m compileall -q . -x '(.git|.venv|venv|__pycache__)'
python -m pip check
```

The safety test statically rejects destructive Python calls and keeps `SIMULATION_MODE` mandatory.

## Architecture

```text
Authentication → authorization → risk/policy decision
       → reset request → distinct approval → simulated execution
       → signed audit event → detection → verification/reporting
```

Important modules:

- `cerberus_workflow.py` — orchestrated request/approval/execution controls
- `sanitization_advisor.py` — deterministic intent and assurance guidance
- `policy_engine.py` — default-deny policy decisions
- `risk_engine.py` — contextual risk scoring
- `merkle_ledger.py` — transparency and inclusion evidence
- `security_logger.py` — tamper-evident security events
- `web_console.py` — simulation console

## Scope boundary

This project does not connect to ADB, Android Management API, carrier services, or real devices. A production system would additionally require durable storage, managed keys, independent identities, external approval delivery, device-vendor validation, legal retention controls, and verified media-sanitization procedures.

## Security

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do not include live credentials, personal information, or production device identifiers.

## License

See [LICENSE](LICENSE).
