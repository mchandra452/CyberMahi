# Incident Report - Suspicious Login and Phishing Alert Investigation

## 1. Executive Summary
Northbridge Financial Services (fictional) experienced suspicious sign-in activity affecting one user shortly after a phishing-themed email was received and reported. Correlated evidence indicates a **likely credential phishing attempt with suspicious authentication activity**.

## 2. Incident Classification
- Incident Type: Suspected Account Compromise
- Severity: Medium-High
- Priority: P2 (identity containment required)
- Status: Escalated

## 3. Initial Alert
- Multiple failed authentications from one external IP.
- Successful login from unusual location for the same user.
- User-reported suspicious Microsoft 365-themed email.

## 4. Affected User
- `emma.wilson@northbridge-demo.local` (fictional identity)

## 5. Timeline of Events
| UTC Time | Source | Event |
|---|---|---|
| 07:47 | EmailEvents | Suspicious email with phishing-style URL delivered/reported |
| 07:52-08:01 | SigninLogs | 5 failed login attempts from `185.224.128.44` |
| 08:05 | SigninLogs | Successful login from same IP/location |
| 08:09 | SecurityAlert | Correlated high-severity alert generated |
| 08:25 | SecurityIncident | Incident opened and containment actions started |

## 6. Indicators of Compromise
- Repeated failed sign-ins from single source IP.
- Successful sign-in following failure burst.
- Location anomaly versus expected user pattern.
- Phishing-style URL and subject language.

## 7. Investigation Steps
1. Validate alert metadata and affected entity.
2. Analyse failure burst and success sequence in sign-in logs.
3. Pivot on IP address, app usage, and geography.
4. Validate phishing evidence in email telemetry.
5. Build a unified event timeline.
6. Assess impact and escalation requirement.

## 8. KQL Queries Used
- `kql/failed-login-bruteforce-detection.kql`
- `kql/suspicious-login-detection.kql`
- `kql/phishing-indicators-detection.kql`
- `kql/summary-hunting-queries.kql`
- `kql/impossible-travel-detection.kql`

## 9. MITRE ATT&CK Mapping
Mapped in `mitre-attack-mapping.md`:
- T1566 (Phishing)
- T1110 (Brute Force)
- T1078 (Valid Accounts)
- T1539 / T1589 / T1087 as cautious contextual possibilities only

## 10. Impact Assessment
Potential compromise of one user identity with possible mailbox and data access risk. No evidence of confirmed lateral movement in provided logs.

## 11. Containment Actions
- Force password reset for affected account.
- Revoke all active sessions/tokens.
- Validate and enforce strong MFA.
- Increase monitoring for follow-on sign-ins from suspicious sources.

## 12. Remediation Recommendations
- Audit inbox rules, forwarding settings, and delegated mailbox access.
- Block/report sender and phishing indicators.
- Tune detection rules for failure-burst-then-success correlation.
- Conduct targeted phishing awareness reinforcement.

## 13. Lessons Learned
- Cross-domain correlation (identity + email) improves triage speed.
- Baseline-aware logic is key to reducing travel-related false positives.
- Structured notes improve incident handover and defensibility.

## 14. Final Analyst Verdict
Likely credential phishing attempt with suspicious authentication activity.

Recommend password reset, MFA verification, session revocation, mailbox rule review, and user awareness follow-up.
