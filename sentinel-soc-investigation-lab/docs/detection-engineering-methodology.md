# Detection engineering methodology

## Lifecycle

1. **Hypothesis:** describe an observable behaviour and the benign processes that can produce it. Avoid conclusions such as compromise when the signal only establishes novelty.
2. **Telemetry requirements:** identify table, connector, fields, retention, latency, identity fidelity, and licensing. Reject a rule when required fields are unreliable.
3. **Query development:** use explicit lookbacks, declared thresholds, bounded joins, stable entity output, and comments that explain logic and tuning.
4. **Test data:** encode malicious, benign, boundary, and duplicate cases with stable IDs and timestamps. Fixtures must remain safe and synthetic.
5. **Threshold selection:** begin with a documented rationale, inspect tenant distributions, and assess sensitivity across user and service populations.
6. **False-positive analysis:** attribute alerts to a process or owner before excluding them. Prefer governed watchlists and narrow conditions over broad suppression.
7. **Regression testing:** run Python equivalents against labelled fixtures and report TP, FP, FN, precision, and recall as fixture metrics only.
8. **Deployment:** map native fields, execute KQL over a controlled historical window, configure entities and custom details, then deploy disabled or low impact first.
9. **Monitoring:** measure alert volume, evidence completeness, latency, incident contribution, analyst disposition, and data-quality failures.
10. **Tuning:** review changes like code, with evidence, owner, expiry, and regression cases. Retest duplicate and benign controls.
11. **Retirement:** remove rules when telemetry disappears, logic is superseded, or operational value no longer justifies cost. Preserve the decision record.

## Offline versus Sentinel testing

The Python engine expresses the same behavioural hypotheses but does not parse KQL. It verifies deterministic input handling, threshold intent, suppressions, entity linkage, duplicate handling, metrics, and reporting. Native execution is still required to validate KQL syntax, table availability, dynamic-field shapes, ingestion delay, query cost, scheduling overlap, and alert grouping.

## Change evidence

Every detection change should include metadata updates, malicious and benign fixtures, unit coverage, expected-label review, generated evidence inspection, and documentation changes where risk or limitations shift.
