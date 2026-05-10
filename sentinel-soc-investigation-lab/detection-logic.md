# Detection Logic

## 1. Detection Objective
Detect potential credential phishing leading to suspicious account access by correlating identity and email telemetry.

## 2. Data Sources
- **SigninLogs**: success/failure patterns, location anomalies, risk context.
- **EmailEvents**: suspicious sender/domain/URL and threat verdict.
- **SecurityAlert / SecurityIncident**: correlated alert and lifecycle status.

## 3. Alert Logic
### A) Failed Login Threshold
- Condition: `>=5` failed sign-ins by same user/IP in `15 minutes`.
- Purpose: identify brute-force/password guessing style behaviour.

### B) Unusual Country Successful Login
- Condition: successful sign-in from location outside 14-day baseline.
- Purpose: catch potentially compromised valid account usage.

### C) Suspicious URL in Email
- Condition: phishing-themed subject/URL patterns or threat verdict = phishing.
- Purpose: detect likely credential-harvesting lure.

### D) Success After Failure Burst (High Confidence)
- Condition: successful login within 30 minutes of failure burst from same IP.
- Purpose: identify possible credential compromise sequence.

## 4. False Positives
- Legitimate user travel and roaming/VPN egress changes.
- Repeated password entry issues by genuine users.
- Security simulation campaigns resembling malicious phishing.
- Shared egress NAT causing mixed-user IP behaviours.

## 5. Tuning Recommendations
- Baseline trusted countries per user/team for prior 14-30 days.
- Maintain allowlist for validated corporate VPN IP ranges.
- Raise severity only when 2+ signals correlate.
- Use Identity Protection risk signals as a severity multiplier.

## 6. Escalation Criteria
Escalate to incident when any of the following occur:
1. Phishing evidence + unusual successful sign-in for same user.
2. Failure burst + immediate success from same source.
3. Additional indicators (new inbox rule, impossible travel, abnormal token/session behaviour).

## 7. Severity Rating Guidance
- **Medium:** single weak signal.
- **Medium-High:** two correlated suspicious signals.
- **High:** confirmed compromise evidence or post-authentication abuse.

## 8. Analyst Notes (Operational)
- Record query name, exact UTC timestamp, entity, and action.
- Note confidence level and alternative explanations.
- Clearly separate evidence from inference.
