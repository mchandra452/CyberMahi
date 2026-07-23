# Coverage and gaps

## Telemetry coverage

| Area | Fixture | Representative live source | Coverage boundary |
|---|---|---|---|
| Authentication | Sign-in failures/success/risk/context | Entra `SigninLogs` | No real Conditional Access policy evaluation |
| Email | Delivery, sender, URL | Defender for Office 365 | No click, detonation, or campaign clustering |
| OAuth | Consent actor, app, scopes | Entra `AuditLogs` | No live publisher/service-principal enrichment |
| Mailbox | Forwarding target and actor | Microsoft 365 audit | Operation field shapes require tenant validation |
| Cloud files | Download events and baseline | Microsoft 365 audit | No sensitivity labels or destination evidence |
| Endpoint | Process parent/child | Defender for Endpoint | Inert redacted command only; no memory evidence |
| DNS/network | Domain novelty and device | Defender for Endpoint network | No passive DNS, age, popularity, or reputation |

## ATT&CK coverage

Mappings are limited to T1566.002, T1110.003, T1078.004, T1098.003, T1114.003, T1059.001, and T1530 where fixture evidence supports observed or inferred behaviour. DET005 uses T1098.003 cautiously for the inferred additional cloud permission grant and explicitly does not claim token theft or token abuse. Domain novelty and incident fusion carry no technique assertion. The catalog is not a claim of broad ATT&CK coverage.

## Blind spots and assumptions

- No distributed password-spray aggregation across changing IPs.
- Static user and volume baselines do not model seasonality, role changes, or sparse identities.
- No token replay, session-cookie, MFA registration, inbox-rule execution, or data-egress proof.
- Identity strings are assumed to normalise consistently across sources.
- Event ordering assumes stable UTC fixture timestamps; real ingestion can arrive late.
- Fusion scores detection IDs once but does not yet cluster multiple compromised identities.

## Licensing and live dependencies

Microsoft Sentinel, Entra ID log retention, Defender for Office 365, Defender for Endpoint, Microsoft 365 audit, and identity risk features depend on tenant configuration and licensing. Query cost, retention, connector latency, and availability must be measured locally.

## Future engineering

Add distributed-spray correlation, ASIM parser validation, watchlist lifecycle tests, production baseline notebooks, publisher and domain enrichment, cross-identity clustering, analytics-template packaging, and live rule simulation in a dedicated lab tenant.
