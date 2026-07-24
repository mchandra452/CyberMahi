# Threat hunting notebook

## Hunt 1: distributed spray pressure

**Hypothesis:** DET001 may miss a coordinated spray spread across documentation-range sources. Group failures by account set and authentication properties within a bounded period, then compare source diversity. Avoid publishing or testing password guesses.

## Hunt 2: consent followed by application use

**Hypothesis:** a first-seen consent becomes more significant when the service principal immediately accesses mail or files. Pivot from actor and application ID to sign-ins and audit activity. Consent alone is insufficient to assert token abuse.

## Hunt 3: forwarding impact

**Hypothesis:** the external rule affected messages after the risky session. Review rule conditions, rule execution evidence, message traces, and target ownership under authorised procedures.

## Hunt 4: cloud-to-endpoint relationship

**Hypothesis:** the endpoint event is related only if document origin, account, device, and timing overlap with email or cloud activity. Validate process ancestry and signing before treating PowerShell as malicious.

## Hunt 5: domain novelty enrichment

**Hypothesis:** the rare test domain gains confidence only when the initiating process and correlated identity chain agree. A newly adopted SaaS control should remain a measurable benign hit until an approval source or allowlist is available.

For each hunt, record query version, UTC range, data latency, result count, entity pivots, alternative explanations, evidence IDs, and decision. Promote a hunt to an analytic only after representative benign testing and an operational owner exist.
