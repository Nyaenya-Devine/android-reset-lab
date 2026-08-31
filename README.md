Android Reset LabA safe, fully simulated cybersecurity lab demonstrating how a device-management system can protect sensitive factory-reset operations through authentication, authorization, dual control, attack detection, and tamper-evident auditing.Safety boundary: Nothing in this project touches a real device, account, file, or network. All device resets are simulated.What this project demonstratesAuthentication — salted PBKDF2 password hashing, session tokens, and account lockoutAuthorization — role-based access control with default-deny enforcementDual control — factory-reset requests require approval from a second authorized userSimulation guard — destructive operations cannot affect real devicesAudit logging — hash-chained JSON Lines logs with integrity verificationThreat detection — six simulated attack scenarios with measurable detection resultsSecurity testing — automated tests verify safety and workflow controlsReporting — detection metrics and a security dashboard for analysisSecurity workflowUser authentication
        ↓
Session token
        ↓
Role authorization
        ↓
Reset request
        ↓
Second-person approval
        ↓
SIMULATED execution
        ↓
Hash-chained audit log
        ↓
Threat detection
        ↓
Security dashboard
Attack simulation resultsThe included attacker_sim.py generates controlled attack scenarios against the simulated environment. No real exploitation is performed.Attack scenarioDetection ruleResultBrute forceRepeated LOGIN_FAILED eventsDetectedOut-of-hours resetReset outside allowed hoursDetectedPrivilege escalationACCESS_DENIED eventsDetectedUnknown deviceDevice not present in fleetDetectedReplayDuplicate request IDDetectedUnapproved executionRESET_BLOCKED simulation guardDetectedLatest labelled run: 6/6 detections — 100% detection rate, zero misses.This result represents the included labelled test scenarios; it is not a claim of real-world detection coverage.Access-control modelRoleRequest resetApprove resetManage usersView logsViewerNoNoNoNoOperatorYesNoNoNoAdminYesYesYesNoSecurity AnalystNoNoNoYesThe reset workflow follows separation of duties: the person requesting a reset cannot approve their own request.Standards mappingFeatureSecurity conceptMITRE ATT&CKNIST SP 800-53Password hashing + lockoutAuthentication controlsT1110IA-5, AC-7Session tokensSession/authentication securityT1078IA-11RBACLeast privilegeT1134AC-3, AC-6Dual controlSeparation of duties—AC-5Hash-chained audit logAudit protectionT1070AU-9Threat detectionsSecurity monitoringVariousSI-4Dashboard/reportingAudit review—AU-6Attack simulatorSecurity assessment exercise—CA-8Device inventoryConfiguration management—CM-8Standards mappings are intended as educational references rather than claims of formal compliance.Project structureandroid-reset-lab/
│
├── authentication.py       # Password hashing and authentication
├── authorization.py        # Role-based access control
├── approve_helper.py       # Approval workflow helpers
├── attacker_sim.py         # Controlled attack simulation
├── config.py               # Lab configuration
├── device_simulator.py     # Simulated device operations
├── reset_workflow.py       # Reset request/approval workflow
├── security_logger.py      # Hash-chained audit logging
├── threat_detection.py     # Attack detection rules
├── reports.py              # Security metrics and reports
├── web_console.py          # Local demonstration console
│
├── tests/
│   ├── test_safety.py      # Safety controls
│   └── test_workflow.py    # Workflow tests
│
├── docs/                   # Supporting documentation
├── SECURITY.md             # Security scope and safety boundary
├── THREAT_MODEL.md         # Threat model
└── INTERVIEW_PREP.md       # Project discussion/interview notes
Generated local files such as data/, logs/, reports/, scratch/, Python caches, and pytest caches are intentionally excluded from version control.Quick startInstall the test dependency:pip install pytest
Run the attack simulation:python attacker_sim.py
Run threat detection:python threat_detection.py
Generate reports:python reports.py
Run the automated tests:python -m pytest tests -q
Start the local demonstration console:python web_console.py
Then open:http://127.0.0.1:8000
The console is local-only and operates against the simulated environment.TestingThe project includes automated tests covering:destructive-operation safetyauthorization boundariesreset approval requirementsworkflow state transitionssimulation-only executionRun:python -m pytest tests -q
LimitationsThis project is intentionally a simulation, not an Android management product.It does not:communicate with Android devicesexecute real factory resetsmodify real device storagecontact external servicesperform real-world exploitationprovide production-grade MDM functionalityThe purpose is to demonstrate defensive security concepts such as authentication, authorization, separation of duties, attack detection, logging, and security testing.DisclaimerEducational simulation for defensive-security learning.No real device, account, file, or network is ever touched.