# Investigation report: INC-NFS-2025-001

## Executive summary

Deterministic synthetic telemetry for Northbridge Financial Services
produced 9 contributing findings across
7 signal categories. The offline incident
scored **99/100** with **high confidence**. This result
supports human review; it is not a claim that KQL executed in Microsoft Sentinel.

## Scope and provenance

- Organisation: Northbridge Financial Services
- Scenario: `NFS-IDENTITY-001` - Identity Compromise and Cloud Persistence Investigation
- Synthetic: **true**
- Evidence scope: only findings selected by configured entity, time-window, and duplicate controls
- Regression metrics: TP 10, FP 1,
  FN 0, precision 0.9091,
  recall 1.0000

## Incident classification

- Classification: suspected identity-led incident requiring validation
- Severity: high
- Confidence: high
- Evidence window: `2025-02-18T08:55:00Z` to
  `2025-02-18T09:52:00Z`

## Confidence assessment

- 9 unique detections across 7 independent signal categories
- Signals share the primary account and fall within a 4-hour correlation window
- Duplicate detection IDs contribute weight once

## Affected entities

| Entity type | Values |
|---|---|
| Account | analyst1@northbridge.example, finance1@northbridge.example, hr1@northbridge.example, ops1@northbridge.example |
| Application | Document Workflow Helper |
| ApplicationId | 00000000-0000-4000-8000-000000000501 |
| Domain | microsoft-auth-check.example, update-cdn.test |
| Host | NFS-LT-104, NFS-UNKNOWN-77 |
| IP | 203.0.113.50 |
| Mailbox | analyst1@northbridge.example |
| Process | powershell.exe, winword.exe |
| URL | https://microsoft-auth-check.example/review |

## Evidence summary

| Detection | Name | Severity | Confidence | Event IDs | Evidence |
|---|---|---|---|---|---|
| DET004 | Phishing-Link Indicators | medium | high | E-EMAIL-001 | Delivered message has display-name mismatch and safe suspicious URL domain microsoft-auth-check.example |
| DET001 | Password Spray Across Cloud Accounts | medium | high | E-AUTH-001, E-AUTH-002, E-AUTH-003, E-AUTH-004, E-AUTH-005, E-AUTH-006 | 6 failures against 4 accounts from 203.0.113.50 |
| DET002 | Successful Authentication After Failure Burst | high | high | E-AUTH-001, E-AUTH-002, E-AUTH-006, E-AUTH-007 | Successful sign-in followed 3 failures for analyst1@northbridge.example |
| DET003 | Unusual Authentication Context | medium | medium | E-AUTH-007 | Authentication context differs from baseline: new country, new device, elevated risk |
| DET005 | Suspicious OAuth Consent | high | medium | E-CLOUD-001 | First-seen application received high-impact scopes: Files.ReadWrite.All, Mail.ReadWrite, offline_access |
| DET006 | External Mail Forwarding Rule | high | high | E-CLOUD-002 | Mailbox forwarding was configured to external domain external-archive.example |
| DET007 | Cloud Download Anomaly | medium | medium | E-CLOUD-003, E-CLOUD-004, E-CLOUD-005, E-CLOUD-006, E-CLOUD-007, E-CLOUD-008, E-CLOUD-009, E-CLOUD-010, E-CLOUD-011 | 9 downloads exceed static daily baseline of 3 for analyst1@northbridge.example |
| DET008 | Office Application Spawning PowerShell | high | high | E-END-001 | Office parent created a PowerShell child; command line is inert and redacted |
| DET009 | New or Rare Domain DNS Activity | low | medium | E-DNS-001 | Domain update-cdn.test is new or rare for the device; novelty alone is not malicious |

## Chronological timeline

| Timestamp | Event ID | Source | User | Action | Result | Detections |
|---|---|---|---|---|---|---|
| 2025-02-18T08:55:00Z | E-EMAIL-001 | email | analyst1@northbridge.example | MessageDelivered | Delivered | DET004 |
| 2025-02-18T09:05:00Z | E-AUTH-001 | authentication | analyst1@northbridge.example | SignIn | Failure | DET001, DET002 |
| 2025-02-18T09:06:00Z | E-AUTH-002 | authentication | analyst1@northbridge.example | SignIn | Failure | DET001, DET002 |
| 2025-02-18T09:07:00Z | E-AUTH-003 | authentication | finance1@northbridge.example | SignIn | Failure | DET001 |
| 2025-02-18T09:08:00Z | E-AUTH-004 | authentication | hr1@northbridge.example | SignIn | Failure | DET001 |
| 2025-02-18T09:09:00Z | E-AUTH-005 | authentication | ops1@northbridge.example | SignIn | Failure | DET001 |
| 2025-02-18T09:10:00Z | E-AUTH-006 | authentication | analyst1@northbridge.example | SignIn | Failure | DET001, DET002 |
| 2025-02-18T09:12:00Z | E-AUTH-007 | authentication | analyst1@northbridge.example | SignIn | Success | DET002, DET003 |
| 2025-02-18T09:20:00Z | E-CLOUD-001 | cloud-app | analyst1@northbridge.example | ConsentGranted | Success | DET005 |
| 2025-02-18T09:28:00Z | E-CLOUD-002 | cloud-app | analyst1@northbridge.example | MailboxRuleCreated | Success | DET006 |
| 2025-02-18T09:35:00Z | E-CLOUD-003 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:36:00Z | E-CLOUD-004 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:37:00Z | E-CLOUD-005 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:38:00Z | E-CLOUD-006 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:39:00Z | E-CLOUD-007 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:40:00Z | E-CLOUD-008 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:41:00Z | E-CLOUD-009 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:42:00Z | E-CLOUD-010 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:43:00Z | E-CLOUD-011 | cloud-app | analyst1@northbridge.example | FileDownloaded | Success | DET007 |
| 2025-02-18T09:50:00Z | E-END-001 | endpoint-process | analyst1@northbridge.example | ProcessCreated | Success | DET008 |
| 2025-02-18T09:52:00Z | E-DNS-001 | dns | analyst1@northbridge.example | DnsQuery | Success | DET009 |

## Linked detections

DET001, DET002, DET003, DET004, DET005, DET006, DET007, DET008, DET009

## Analyst hypotheses

The leading hypothesis is a multi-stage identity-led incident because independent evidence spans authentication, cloud application, cloud storage, email, endpoint, mailbox, network. Correlation supports investigation, but does not establish malicious intent for every event.

## Alternative benign explanations

The linked rule metadata identifies these explanations for validation:

- Misconfigured applications
- shared egress
- service account failures
- User typing errors
- stale mobile credentials
- automated clients
- Corporate VPN
- travel
- mobile networks
- proxies
- short baselines
- Marketing redirects
- Safe Links rewriting
- delegated senders
- Approved administrator consent
- verified business applications
- deployment automation
- Approved business forwarding
- shared mailboxes
- administrative transport changes
- Backups
- migrations
- eDiscovery
- legal export
- short baseline
- Legitimate macros
- signed internal tools
- administrative automation
- Software updates
- CDNs
- newly onboarded SaaS
- sparse baseline

## ATT&CK mapping

| Detection | Technique | Status | Confidence | Evidence |
|---|---|---|---|---|
| DET001 | T1110.003 | observed | high | Multiple accounts receive failures from one source in a bounded window. |
| DET002 | T1078.004 | inferred | medium | A successful cloud authentication is preceded by a failure burst and supporting context. |
| DET003 | T1078.004 | inferred | medium | Valid cloud account use is inferred only when new context and elevated risk corroborate it. |
| DET004 | T1566.002 | observed | high | A delivered synthetic email contains a deceptive safe test link. |
| DET005 | T1098.003 | inferred | medium | A first-seen cloud application received high-impact delegated permissions from an unapproved synthetic actor. |
| DET006 | T1114.003 | observed | high | Synthetic audit evidence records an external forwarding rule. |
| DET007 | T1530 | inferred | medium | Anomalous downloads provide possible cloud collection evidence in the correlated chain. |
| DET008 | T1059.001 | observed | high | Endpoint telemetry directly records a PowerShell child process. |
| DET009 | Not mapped | not_mapped | Unspecified | A new or rare DNS name is not a specific adversary technique without process intent or follow-on network behaviour. |

Mappings above come from the linked YAML rule metadata and are included only where that
metadata supplies an evidence statement.

## Containment recommendations

- Primary recommendation: Escalate for human-approved identity containment, consent review, mailbox rule removal, and endpoint scoping.
- Escalate only when identity or contextual evidence corroborates the spray.
- Validate with the user and revoke sessions only under approved procedure.
- Challenge or contain the identity only after contextual validation.
- Quarantine only through approved mail-security procedure and scope recipients.
- Revoke unauthorised grants through human-approved change procedure.
- Preserve evidence and remove an unauthorised rule under approved procedure.
- Restrict access only after confirming unauthorised collection.
- Scope the host and isolate only under approved endpoint procedure.
- Do not block solely on novelty; escalate when independent signals corroborate it.

## Eradication and recovery recommendations

Remove only configuration confirmed as unauthorised, validate identity recovery and MFA,
restore approved access, and monitor the scoped entities for a documented observation period.

## Detection gaps

- Single-source logic does not fully cover distributed spraying.
- A success after failures is not independently proof of account compromise.
- Offline baselines are static and cannot establish impossible travel.
- Offline logic lacks live reputation, detonation, and click enrichment.
- Consent alone does not demonstrate token theft or malicious application use.
- Client and audit field shapes vary by connector and operation.
- Static baseline does not model seasonality or file sensitivity.
- The fixture command line is intentionally inert and redacted.
- Offline mode has no registration age, reputation, or global popularity enrichment.

## Final verdict

**Escalate for priority human review as a suspected multi-stage identity incident.** Human validation remains mandatory. The configured analyst action is:
Escalate for human-approved identity containment, consent review, mailbox rule removal, and endpoint scoping.

## Limitations

This report is generated from synthetic telemetry. Python equivalents test detection intent
but do not execute KQL. Live connector schemas, licences, ingestion, retention, baselines,
rule scheduling, and thresholds require tenant-specific validation and tuning.
