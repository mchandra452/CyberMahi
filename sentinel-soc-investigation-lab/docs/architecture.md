# Lab Architecture

## Components
- Simulated data sources: sign-in, email security, incident events
- SIEM layer: Microsoft Sentinel (or offline KQL study)
- Investigation outputs: timeline, ATT&CK mapping, incident report

## Data Flow
1. Authentication and email events are ingested.
2. KQL queries detect suspicious patterns.
3. Alerts are correlated into incident context.
4. Analyst produces containment and remediation recommendations.
