# Offline analysis summary

## Scope

- Organisation: Northbridge Financial Services
- Scenario: `NFS-IDENTITY-001` - Identity Compromise and Cloud Persistence Investigation
- Synthetic telemetry: **true**
- Runtime: deterministic offline Python equivalents; KQL was not executed

## Result

- Incident: `INC-NFS-2025-001` - Identity Compromise and Cloud Persistence Investigation
- Risk score: **99/100**
  (high severity, high confidence)
- Linked detections: DET001, DET002, DET003, DET004, DET005, DET006, DET007, DET008, DET009
- Evidence window: 2025-02-18T08:55:00Z
  to 2025-02-18T09:52:00Z
- Synthetic regression metrics: TP 10,
  FP 1, FN 0,
  precision 0.9091, recall 1.0000

## Verdict

Escalate for priority human review as a suspected multi-stage identity incident. Human validation is required before containment.
Escalate for human-approved identity containment, consent review, mailbox rule removal, and endpoint scoping.

This result is generated from synthetic evidence and is not proof that the KQL executed
in Microsoft Sentinel.
