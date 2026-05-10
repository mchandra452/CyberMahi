# Microsoft Sentinel SOC Investigation Lab - Suspicious Login and Phishing Alert Analysis

## 1) Recruiter-Friendly Summary
A practical SOC Analyst Level 1 portfolio project simulating a realistic Microsoft Sentinel investigation. The case combines suspicious sign-ins and phishing telemetry to demonstrate triage, KQL investigation, MITRE ATT&CK mapping, escalation judgement, and concise analyst reporting.

## 2) Scenario
**Organisation (fictional):** Northbridge Financial Services  
**Case trigger:** user-reported phishing email + suspicious authentication alerts.

The SOC analyst investigates:
- repeated failed logins against one identity,
- successful login from an unusual geography,
- phishing email with fake Microsoft 365-themed login lure,
- potential credential compromise,
- whether incident escalation is justified.

## 3) Objectives
- Perform alert triage and entity validation.
- Use KQL to investigate identity + email evidence.
- Correlate events into a defensible timeline.
- Map findings to MITRE ATT&CK without overclaiming.
- Produce a recruiter-visible incident report and remediation plan.

## 4) Tools Used
- Microsoft Sentinel (workflow-aligned)
- Azure Log Analytics / KQL
- Simulated CSV datasets
- Markdown reporting artefacts

## 5) Skills Demonstrated
- SIEM monitoring and alert triage
- KQL query development and hunting
- Suspicious login and phishing analysis
- Incident prioritisation and escalation logic
- MITRE ATT&CK mapping and evidence-based reasoning
- Analyst communication (technical + stakeholder-friendly)

## 6) Lab Architecture
See `docs/architecture.md`.

## 7) Investigation Workflow
See `docs/soc-workflow.md`.

## 8) KQL Detection Examples
- `kql/suspicious-login-detection.kql`
- `kql/failed-login-bruteforce-detection.kql`
- `kql/phishing-indicators-detection.kql`
- `kql/impossible-travel-detection.kql`
- `kql/summary-hunting-queries.kql`

> **Environment note:** table schemas differ by connector and tenant. Update table/field names (`SigninLogs`, `EmailEvents`, `SecurityIncident`, `SecurityAlert`, `DeviceEvents`) to match your workspace.

## 9) MITRE ATT&CK Mapping
See `mitre-attack-mapping.md` for T1566, T1110, T1078 and cautious context notes for T1539/T1589/T1087.

## 10) Incident Timeline (Condensed)
| Time (UTC) | Event |
|---|---|
| 07:47 | Suspicious phishing email delivered and reported |
| 07:52-08:01 | Repeated failed sign-ins from same IP |
| 08:05 | Successful sign-in from same suspicious source |
| 08:09 | Correlated high-severity alert created |
| 08:25 | Incident opened and containment actions initiated |

Full timeline: `incident-report.md` and `sample-logs/incident-events-sample.csv`.

## 11) Remediation Actions
- Reset impacted credentials.
- Revoke active sessions/tokens.
- Validate MFA health and challenge method.
- Audit mailbox rules/forwarding.
- Block malicious indicators and monitor for recurrence.

## 12) Screenshots Placeholder
Capture checklist in `screenshots/README.md`.

## 13) What I Learned
- Why correlated identity + phishing signals increase confidence.
- How to distinguish suspicious patterns from expected user behaviour.
- How detection thresholds and baselines reduce false positives.
- How to produce a professional analyst narrative.

## 14) CV Bullet
Built a Microsoft Sentinel SOC investigation lab simulating suspicious-login and phishing-alert workflows, using KQL, Azure security logs, MITRE ATT&CK mapping, incident triage, and analyst-style reporting.

## 15) LinkedIn Post Draft
I’ve completed a Microsoft Sentinel SOC Investigation Lab focused on suspicious login and phishing alert analysis.

I used KQL to triage failed login bursts, unusual successful sign-ins, and phishing indicators, then built an incident timeline, mapped findings to MITRE ATT&CK, and wrote a structured analyst report.

I built this as a defensive portfolio project for SOC Analyst / Security Analyst applications. Feedback is welcome.


## 16) How to Run
### Option A: Offline (No Azure Cost) ✅ Recommended first run
1. Open this folder locally:
   ```bash
   cd sentinel-soc-investigation-lab
   ```
2. Run the built-in validator:
   ```bash
   python3 tests/validate_lab.py
   ```
3. Open the sample telemetry files in `sample-logs/` and compare fields to the KQL logic.
4. Read and step through each query in `kql/` in this order:
   - `failed-login-bruteforce-detection.kql`
   - `suspicious-login-detection.kql`
   - `phishing-indicators-detection.kql`
   - `summary-hunting-queries.kql`
5. Use `incident-report.md` and `reports/` as your analyst output template.

### Option B: Microsoft Sentinel Workspace
1. Create a Log Analytics Workspace and enable Microsoft Sentinel.
2. Ingest the sample CSVs as custom logs (or map to existing schema).
3. Run the KQL queries from `kql/` (adjust table/field names where needed).
4. Capture screenshots and update the incident report with your run findings.

## 17) Run and Test This Project
### Quick validation (offline)
Run the built-in validator to confirm file presence, CSV schema correctness, timestamp format, and safe-domain usage:

```bash
python3 tests/validate_lab.py
```

### Sentinel execution workflow
1. Import sample CSV data into custom Log Analytics tables (or map to your existing schema).
2. Open each query in `kql/` and adjust table/field names if required.
3. Execute detections, save results, and capture evidence screenshots.
4. Update `incident-report.md` with your run-specific findings.

## 18) Defensive Use Disclaimer
This repository is for defensive cybersecurity learning and job-portfolio use only. All logs are simulated. No malware, credential stealing tooling, or offensive attack instructions are included.
