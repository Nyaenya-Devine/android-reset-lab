Android Reset LabA safe, fully simulated cybersecurity lab demonstrating how a device-management system can protect sensitive factory-reset operations through authentication, authorization, dual control, attack detection, and tamper-evident auditing.Safety boundary: Nothing in this project touches a real device, account, file, or external network. All device resets are simulated.What This Project DemonstratesAuthentication - salted PBKDF2 password hashing, session tokens, session expiration, and account lockoutAuthorization - role-based access control (RBAC) with default-deny enforcementDual control - reset requests require approval from a second authorized userSimulation guard - reset operations cannot affect real devicesAudit logging - hash-chained JSON Lines logs with integrity verificationThreat detection - six simulated attack scenarios with measurable detection resultsSecurity testing - automated tests verify safety and workflow controlsReporting - detection metrics and security analysisSecurity WorkflowUser authentication
&#x20;       |
&#x20;       v
Session token
&#x20;       |
&#x20;       v
Role authorization
&#x20;       |
&#x20;       v
Reset request
&#x20;       |
&#x20;       v
Second-person approval
&#x20;       |
&#x20;       v
SIMULATED execution
&#x20;       |
&#x20;       v
Hash-chained audit log
&#x20;       |
&#x20;       v
Threat detection
&#x20;       |
&#x20;       v
Security reporting
Attack Simulation ResultsThe included attacker\_sim.py generates six controlled attack scenarios against the simulated environment. No real exploitation is performed.Attack ScenarioDetection RuleResultBrute forceRepeated LOGIN\_FAILED eventsDetectedOut-of-hours resetReset outside allowed hoursDetectedPrivilege escalationACCESS\_DENIED eventsDetectedUnknown deviceDevice not present in fleetDetectedReplayDuplicate request IDDetectedUnapproved executionRESET\_BLOCKED simulation guardDetectedLatest Verified ResultDetection rate: 6/6 (100%)This result represents the six labelled scenarios included in the laboratory. It is not a claim of real-world detection coverage.Access-Control ModelRoleRequest ResetApprove ResetManage UsersView LogsViewerNoNoNoNoOperatorYesNoNoNoAdminYesYesYesNoSecurity AnalystNoNoNoYesThe reset workflow follows separation of duties: the person requesting a reset cannot approve their own request.Tamper-Evident Audit LoggingThe security logger maintains a hash-chained JSON Lines audit log.Each event contains:prev\_hash - hash of the previous evententry\_hash - SHA-256 hash of the current eventTimestampEvent typeSeverityActorDevice IDRequest IDOutcomeIf an existing event is modified, the calculated hash no longer matches the stored hash and the chain-integrity check detects the modification.This is an educational tamper-evident mechanism and should not be considered equivalent to cryptographic signing, immutable enterprise logging, or a production SIEM.Red-Team / Blue-Team DesignRed Teamattacker\_sim.py generates controlled scenarios representing:Brute-force authentication attemptsOut-of-hours reset activityPrivilege escalationRequests against unknown devicesReplay of a reset requestAttempted execution without approvalBlue Teamthreat\_detection.py analyzes the audit log and identifies the corresponding indicators.The current laboratory result is:6/6 attack categories detected
100% detection rate
Simulated Android Fleetdevice\_simulator.py contains a fictional device inventory.Example devices include:AND-001 - Pixel 7AND-003 - Pixel 6aAND-006 - Galaxy A54These are simulated records only.The project does not:Connect to Android devicesUse ADBExecute factory-reset commandsModify real device storageCommunicate with real device-management servicesA simulated reset only changes the status of a fictional device record.Safety ModelSafety is a core design requirement.The project uses:SIMULATION\_MODE = True
The laboratory also includes automated safety tests that inspect Python source code for prohibited destructive operations.The project deliberately avoids destructive mechanisms such as:Real device wipingReal factory-reset commandsADB-based device controlShell executionDestructive filesystem operationsExternal device-management APIsThe purpose is to demonstrate security controls without creating a tool capable of harming real devices.Automated TestingThe project includes automated tests covering:AuthenticationPassword rejectionAccount lockoutSession creationSession expirationSession invalidationRBAC permissionsDefault-deny authorizationReset approvalFour-eyes enforcementUnknown-device rejectionOperator restrictionsSimulated reset executionAudit-log integritySafety controlsCurrent verified result:18 passed
Run the tests with:python -m pytest tests -q
Project Structureandroid-reset-lab/
|
|-- authentication.py       # Password hashing and authentication
|-- authorization.py        # Role-based access control
|-- approve\_helper.py       # Approval workflow helpers
|-- attacker\_sim.py         # Controlled attack simulation
|-- config.py               # Lab configuration
|-- device\_simulator.py     # Simulated device operations
|-- reset\_workflow.py       # Reset request/approval workflow
|-- security\_logger.py      # Hash-chained audit logging
|-- threat\_detection.py     # Attack detection rules
|-- reports.py              # Security metrics and reports
|-- web\_console.py          # Local demonstration console
|
|-- tests/
|   |-- conftest.py         # Test-state isolation
|   |-- test\_safety.py      # Safety controls
|   `-- test\_workflow.py    # Workflow and security tests
|
|-- docs/                   # Supporting documentation
|-- SECURITY.md             # Security scope and safety boundary
|-- THREAT\_MODEL.md         # Threat model
`-- INTERVIEW\_PREP.md       # Project discussion/interview notes
Generated local files such as data/, logs/, reports/, scratch/, Python caches, and pytest caches are intentionally excluded from version control.Quick StartInstall the test dependency:pip install pytest
Run the simulated attack scenarios:python attacker\_sim.py
Run threat detection:python threat\_detection.py
Generate reports:python reports.py
Run the automated tests:python -m pytest tests -q
Start the local demonstration console:python web\_console.py
Then open:http://127.0.0.1:8000
The console is local-only and operates against the simulated environment.Security Concepts DemonstratedThis project provides practical experience with:Python security engineeringAuthenticationPassword hashingSession securityRole-Based Access ControlLeast privilegeSeparation of dutiesSecurity loggingHash chainingThreat detectionRed-team simulationBlue-team monitoringAutomated security testingSecure-by-design developmentStandards MappingThe following mappings are educational references, not claims of formal compliance.FeatureSecurity ConceptMITRE ATT\&CKNIST SP 800-53Password hashing and lockoutAuthentication controlsT1110IA-5, AC-7Session tokensAuthentication/session securityT1078IA-11RBACLeast privilegeT1134AC-3, AC-6Dual controlSeparation of duties-AC-5Hash-chained audit logAudit protectionT1070AU-9Threat detectionSecurity monitoringVariousSI-4ReportingAudit review-AU-6Attack simulatorSecurity assessment exercise-CA-8Device inventoryConfiguration management-CM-8LimitationsThis project is intentionally a simulation, not an Android management product.It does not:Communicate with Android devicesExecute real factory resetsModify real device storageContact external servicesPerform real-world exploitationProvide production-grade MDM functionalityThe purpose is to demonstrate defensive security concepts such as authentication, authorization, separation of duties, attack detection, logging, and security testing.Ethical and Safety NoticeThis project is intended for authorized educational and defensive cybersecurity learning.All attack scenarios operate against a fictional local environment.No real device, account, or external system is targeted.Future Defensive ImprovementsPossible future improvements include:Local security dashboard enhancementsMore detection rulesAlert severity scoringMFA simulationPassword-policy testingSIEM integration simulationCSV/PDF security reportsExpanded threat modellingImproved audit-log storageAdditional automated security testsThe project should remain simulation-only.Portfolio SummaryAndroid Reset Lab demonstrates practical defensive cybersecurity engineering by combining authentication, RBAC, separation of duties, secure workflow design, tamper-evident auditing, attack simulation, threat detection, and automated security testing in a controlled environment.The project demonstrates not only how security controls are implemented, but also how they can be deliberately tested from both red-team and blue-team perspectives.Verified laboratory results: 18 automated tests passing and 6/6 simulated attack categories detected.
