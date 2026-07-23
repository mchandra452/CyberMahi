# Microsoft Sentinel deployment guide

## Scope

This is a high-level, non-deploying guide. Perform all work in a personal or authorised lab, use change control, and never place secrets or tenant identifiers in the repository.

## 1. Analyst experience and workspace

Open Microsoft Sentinel through the Microsoft Defender portal and onboard or select the authorised Log Analytics workspace. Confirm region, retention, access roles, cost controls, and incident integration before enabling content. Microsoft documents the Defender portal as Sentinel's long-term experience and states that Azure-portal support ends after 31 March 2027: [Microsoft Sentinel in the Defender portal](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal).

## 2. Required connectors

Evaluate Entra ID sign-in and audit logs, Microsoft Defender XDR, Defender for Office 365, Defender for Endpoint, and Microsoft 365 audit sources. Availability, licensing, tables, and latency vary. Record the actual table and field coverage rather than assuming connector success.

## 3. Schema mapping

Run narrow discovery queries over a controlled time range. Map user, IP, device, application, URL, mailbox, process, result, risk, and operation fields. Adjust dynamic-property extraction to observed schemas. `DET010` reads upstream scheduled-rule custom details from the `SecurityAlert.ExtendedProperties` `"Custom Details"` bag and handles scalar or single-value-array fields; confirm that shape in the target workspace. Consider ASIM only after confirming the appropriate parser covers required fields.

## 4. Query testing

Paste one KQL file into Advanced Hunting or Logs, select an explicit historical period, verify syntax and performance, inspect benign and known test cases, and validate every projected field. Never claim a rule works from offline tests alone.

## 5. Analytics configuration

Configure frequency, lookback, threshold, alert grouping, suppression, custom details, and entity mappings from the rule metadata. For the upstream rules, preserve the projected fields needed by fusion and configure applicable custom-detail keys such as `DetectionId`, `User`, `IPAddress`, device, application, domain, mailbox, URL, and process fields. Account for ingestion delay and scheduling overlap. Deploy disabled or in a controlled validation mode before alerting analysts.

## 6. Incident settings and repository management

Confirm Defender XDR/Sentinel incident behaviour, duplicate handling, automation boundaries, ownership, and severity changes. Promote reviewed files through Git pull requests and CI. Microsoft's [repository connection guidance](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content) supports source-controlled custom content, but any deployment connection still requires explicit workspace/repository authorisation and local governance review.

## 7. Validation before enablement

Exercise malicious and benign lab cases, replay allowed synthetic events through an approved ingestion route if available, compare alerts with expected labels, inspect entities and timelines, measure query cost, and obtain an operational owner.

## 8. Cost, licensing, and cleanup

Review data ingestion, retention, Defender licensing, identity-risk availability, automation execution, and query costs. Disable test analytics, remove temporary ingestion resources, delete test watchlists, and follow the lab's resource-cleanup procedure when finished.
