# Attack path and evidence chain

```mermaid
sequenceDiagram
    participant Mail as Defender for Office 365
    participant ID as Entra ID
    participant Cloud as Microsoft 365 audit
    participant Host as Defender for Endpoint
    participant SOC as Sentinel / analyst
    Mail->>SOC: DET004 delivered deceptive test link
    ID->>SOC: DET001 password spray
    ID->>SOC: DET002 success after failures
    ID->>SOC: DET003 new risky context
    Cloud->>SOC: DET005 high-impact app consent
    Cloud->>SOC: DET006 external forwarding rule
    Cloud->>SOC: DET007 anomalous downloads
    Host->>SOC: DET008 Office to inert PowerShell evidence
    Host->>SOC: DET009 rare safe test domain
    SOC->>SOC: DET010 duplicate-aware identity fusion
    SOC-->>SOC: Human validation, containment decision, preservation
```

## Evidential interpretation

The sequence is a hypothesis supported by synthetic evidence, not an assertion that every step caused the next. Email delivery does not prove a click. Consent does not prove token theft. Download volume does not prove exfiltration. A rare domain is only a weak contextual signal. Confidence becomes high because several independent categories share the same account, device, source context, and bounded timeline.

## Benign controls

The same dataset contains approved VPN travel, repeated service-account failures, authorised administrator consent, and expected backup downloads. A newly adopted SaaS domain is intentionally reported as a benign false positive so the limits of novelty-only logic remain measurable.
