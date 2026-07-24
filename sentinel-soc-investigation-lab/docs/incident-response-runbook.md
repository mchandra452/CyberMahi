# Incident response runbook

## Triage questions

1. Which constituent detections are independently supported, and which may be duplicates?
2. Do the account, IP, device, application, mailbox, and URL entities agree across sources?
3. Is the event order plausible after accounting for ingestion delay and clock quality?
4. Can one approved change, VPN, migration, automation, or user action explain the evidence?
5. Which logs must be preserved before retention or response actions alter state?

## Investigation pivots

- **Identity validation:** confirm user activity, authentication methods, Conditional Access, risk, device registration, sessions, and adjacent accounts.
- **IP and device:** compare source history, VPN/egress ownership, device compliance, process ancestry, and other identities using the same entities.
- **Email:** inspect headers, delivery action, recipient scope, URL rewriting, click evidence, and post-delivery actions.
- **OAuth/application:** review actor, consent type, service principal, publisher, scopes, credentials, owners, and application sign-ins.
- **Mailbox:** identify user- versus admin-created rules, external targets, conditions, transport rules, and messages affected.
- **Cloud files:** review sensitivity, volume, client, source IP, destination evidence, backup/migration records, and legal activity.
- **Endpoint:** preserve process tree, command line, signer, document origin, hashes, network events, and relevant device timeline.
- **Scope:** find shared IPs, applications, URLs, domains, devices, recipients, and peer accounts across the same period.

## Escalation matrix

| Condition | Recommended action |
|---|---|
| Single low-confidence signal | Continue investigation |
| Known benign entity explains event | Document and close/tune |
| Success after spray plus new context | Escalate and contain identity |
| Suspicious OAuth consent | Review consent and revoke if unauthorised |
| External forwarding plus identity compromise | Escalate urgently |
| Endpoint and cloud signals correlate | Treat as multi-stage compromise |
| Evidence remains incomplete | State uncertainty and preserve telemetry |

## Containment decision points

Containment is not automatic. Follow organisational approvals, legal requirements, operational risk, and evidence-preservation procedures. Consider session revocation, credential reset, identity disablement, consent revocation, forwarding-rule removal, endpoint isolation, and mail remediation only when the evidence and local authority justify the action.

## Evidence preservation

Record query text and time range, export relevant result identifiers, preserve raw audit and endpoint events, note retention, hash exported files where procedure requires it, maintain analyst actions, and avoid changing tenant state before necessary evidence is captured.

## Recovery and closure

Restore approved access, validate MFA and device state, confirm unauthorised grants/rules are absent, monitor the identity and related entities, document residual uncertainty, record detection tuning, and obtain incident-owner approval. Close only when scope, containment, recovery, evidence, and follow-up owners are recorded.
