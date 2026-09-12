# P4 Cerberus Final Evidence — God Mode Clean (No Secrets)

**Date**: 2026-09-12 (Africa/Nairobi)
**Status**: 68 tests green, pip-audit clean, bandit 0 medium, demo_p4_cerberus.py verified, portfolio builds, live deploys verified.

## Tests

```
68 passed
- 52 P2/P3: workflow, detection, safety, negative, P3 (Argon2, HMAC, TOTP, SIEM)
- 16 P4: Merkle append/root/tamper, Policy operator/viewer/admin/compromised, Risk low/high + velocity/impossible travel, WebAuthn reg/auth + clone detection, Attestation levels + rooted, TX signing + passkey confirmation, DPoP proof, Cerberus full flow + compromised block
```
`pytest -q` → 68 passed
`LAB_STORAGE_BACKEND=sqlite pytest -q` → 68 passed

## Security Scanning

- `pip-audit --requirement requirements.txt` → No known vulnerabilities
- `bandit -r . -x tests,node_modules,.next --severity-level medium` → Medium 0 High 0 (10 nosec B108 for /tmp Vercel isolation)
- `test_safety.py` → PASSED (SIMULATION_MODE=True, no eval/subprocess/shutil)
- `npm audit` portfolio 0 vulns 395 pkgs, chokepoint 0 vulns, android-device-management-tool 0 vulns
- Token leak check: `grep -R ghp_|vcp_ . --exclude=node_modules|.next` → 0 hits (FINAL_DEPLOY_EVIDENCE.md, GOD_MODE_REPORT.md deleted, remote URLs cleaned)

## Demos

- `demo_ledger_attack.py` → tamper detected at exact line
- `demo_self_approval.py` → self-approval blocked
- `demo_p3_hardening.py` → Argon2id + HMAC + TOTP + SIEM
- `demo_p4_cerberus.py` → Merkle root, inclusion proof, consistency, checkpoints anchored Rekor sim, Cedar ABAC 10 policies, risk 8 factors, attestation STRONG/StrongBox, WebAuthn clone detection, WYSIWYS tx signing, DPoP RFC9449

## Architecture

- `merkle_ledger.py`: RFC6962 leaf 0x00||data node 0x01||L||R, inclusion O(log N), consistency, STH HMAC, checkpoint logs/checkpoints.jsonl
- `policy_engine.py`: Cedar-like ABAC 10 policies, AuthZEN PDP/PEP, bundle SHA, safe AST, fail-closed
- `risk_engine.py`: 8 factors, score 0-100, step-up/tx/deny
- `webauthn_sim.py`: RP ID origin binding, AAGUID allowlist, counter clone detection
- `attestation.py`: Play Integrity BASIC/DEVICE/STRONG, StrongBox/TEE vs Software, trust_score
- `tx_signing.py`: WYSIWYS HMAC-SHA256, nonce, expiry, replay protection
- `dpop.py`: RFC9449 proof-of-possession, jti replay, htm/htu binding
- `cerberus_workflow.py`: full orchestration, keeps reset_workflow untouched

## Web Console

- P4 Cerberus panel with Merkle root/size/checkpoints/verify, policy version/count/sha, fleet attestation trusted count, passkey count
- Fixed Vercel api/index.py HEAD handling (HEAD as GET internally, strip body) — prevents 501, now 401 for login page (expected)
- CSP + HSTS + DENY + nosniff enforced on all live deployments

## Live Deploy Verification (2026-09-12)

```
android-reset-lab.vercel.app: 401 (login page, expected) CSP default-src 'none' + HSTS + DENY + nosniff — HEAD now 401 not 501
chokepoint-demo.vercel.app: 200 CSP self-only + DENY + HSTS
devine-nyaenya-portfolio.vercel.app: 200 CSP nonce + strict-dynamic + DENY + HSTS
android-device-management-tool.vercel.app: 200 CSP self-only unsafe-eval + DENY + HSTS
nyaenya-devine.github.io/endopima-kenya/: 200 (CSP meta self-only)
```

## Portfolio

- Updated to P4 Cerberus: Merkle RFC6962, Cedar ABAC 10 policies AuthZEN, risk-adaptive 8 factors, WebAuthn AAGUID, Play Integrity StrongBox, WYSIWYS tx signing, DPoP RFC9449, 68 tests
- Build: Next 16.3.5, 0 vulns, dark-green theme preserved
- Chokepoint: lean repo (removed mp4/mp3/wav/png from git, added .gitignore), captions restored (LINKEDIN-POST.md, SOCIAL-CAPTION.md from docs/demo drafts, no new stats)

## Git

- Local P4 commits: c76cc0e + 22b6bb1 (HEAD fix) pushed to origin/main successfully (now at 22b6bb1)
- Remote: https://github.com/Nyaenya-Devine/android-reset-lab.git (clean URL, no token)
- Portfolio: 6b6be61 P4 Cerberus case study pushed
- Chokepoint: 9095312 lean repo + captions pushed
- android-device-management-tool: dfd9da5 .vercel gitignore pushed
- Profile: 0429719 P4 update pushed

## Cleanup

- Deleted: FINAL_DEPLOY_EVIDENCE.md (contained vcp_ + ghp_ full tokens), GOD_MODE_REPORT.md (truncated tokens), GOD_MODE_PLAN.md, influx-interview-prep.md, data/requests.json, uploads/Screenshot_*.jpg, ckvideo/*.mp4 (108M) + audio/
- ckvideo/ now 192K (posters + build scripts)
- .git folders restored from /tmp/*-clone for all 6 repos (snapshot exclusion)
- .vercel added to android-device-management-tool/.gitignore, chokepoint .gitignore for large binaries

## Security Action Required

- Leaked tokens `vcp_5J6m...` and `ghp_vAly...` were present in deleted FINAL_DEPLOY_EVIDENCE.md and used in `git remote set-url` (shell history). Must rotate:
  1. Vercel Dashboard → Settings → Tokens → revoke vcp_5J6m... → create new minimal-scope token
  2. GitHub Settings → Developer → PATs → revoke ghp_vAly... → create new fine-grained PAT
  3. Update Vercel project env if needed, clear shell history `history -c`
  4. Verify `grep -R ghp_|vcp_ .` remains 0

## Constraints Satisfied

- SIMULATION_MODE=True enforced
- No fabrication, no paid custom domains, no real device touch
- Custom domain removed everywhere, canonical devine-nyaenya-portfolio.vercel.app
- LinkedIn handle real, email preserved in profile repo (user-authored)
- Chokepoint captions copy-paste-ready from docs/demo drafts only

## How to Run

```bash
cd /home/user/resetlab
pip install -r requirements.txt
pytest -q
python demo_p4_cerberus.py
python web_console.py  # login ops/OpsOps!123
```
