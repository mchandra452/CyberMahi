# False-positive analysis

## Control results

| Control | Pressure on rule | Expected result | Rationale |
|---|---|---|---|
| Corporate VPN travel | DET003 geography novelty | Suppressed | Governed VPN IP reduces misleading travel context |
| Service account failures | DET001 failure volume | Suppressed | Known non-interactive identity and corporate egress |
| Approved administrator consent | DET005 high-impact scope | Suppressed | Actor and application are explicitly governed |
| Backup downloads | DET007 bulk activity | Suppressed | Dedicated process identity and high expected baseline |
| Newly adopted SaaS | DET009 new domain | Accepted benign FP | Novelty is observable, but offline reputation and approval enrichment are absent |

The accepted DET009 false positive is intentional and included in precision. It demonstrates why domain novelty must remain low severity and why process context, reputation, global prevalence, and SaaS onboarding records matter.

## Tuning guardrails

- Document the business owner and review date for each allowlist entry.
- Suppress a specific identity, application, source range, signer, or workflow—not an entire behaviour.
- Add a regression event before changing a threshold or exclusion.
- Measure missed required cases and prohibited control hits independently.
- Do not convert a weak signal into high severity solely to make the scenario more dramatic.
