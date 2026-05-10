# Demo Walkthrough (10-15 minutes)

## 1) Open with scenario (1 min)
Explain the fictional Northbridge case: phishing email + suspicious sign-in sequence.

## 2) Show sample telemetry (2 mins)
- `sample-logs/email-security-logs-sample.csv`
- `sample-logs/signin-logs-sample.csv`
- `sample-logs/incident-events-sample.csv`

## 3) Walk through detections (4 mins)
- failed login burst query
- suspicious location query
- phishing indicator query
- summary hunting query

## 4) Explain incident analysis (3 mins)
Use `incident-report.md` and `mitre-attack-mapping.md` to justify verdict and severity.

## 5) Close with remediation and lessons (2 mins)
Use `reports/remediation-plan.md` and `docs/lessons-learned.md`.

## Suggested interview close
"This project shows how I triage identity and email alerts together, validate evidence with KQL, and communicate a defensible escalation decision as an SOC L1 analyst."
