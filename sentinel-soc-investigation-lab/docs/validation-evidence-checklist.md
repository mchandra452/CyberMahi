# Sentinel live-validation evidence checklist

**Status: NOT EXECUTED.** This is a procedure and capture template, not proof of tenant testing. The repository's Python detectors only test synthetic offline intent; the KQL files have not been validated against real Microsoft tables.

## Controlled lab prerequisites

- [ ] Use an authorised Microsoft tenant/workspace with appropriate licence and approved test accounts
- [ ] Record tenant region, data retention, connector tables, and cost guardrails without committing tenant identifiers or credentials
- [ ] Select a single detection, for example `DET001-password-spray.kql`, for first validation
- [ ] Confirm the observed table schema, projected field names and data ingestion delay
- [ ] Avoid using real account credentials, customer records or attacker-controlled infrastructure

## Reproducible test record

| Field | Record |
| --- | --- |
| Date (UTC) | *Not tested* |
| Detection / commit SHA | *Not tested* |
| Tenant type (no identifiers) | *Not tested* |
| Connector(s) and licensing | *Not tested* |
| Query execution status | *Not tested* |
| Actual vs expected alert entities | *Not tested* |
| Query window / scheduling | *Not tested* |
| Benign control input | *Not tested* |
| Observed false positive | *Not tested* |
| Tuning change and reason | *Not tested* |
| Before / after results | *Not tested* |
| Query duration / ingestion cost | *Not tested* |
| Evidence files/screenshots (sanitised) | *Not tested* |

## Procedure

1. Run a small read-only schema exploration query using approved sample data.
2. Test the original detection and capture the query text, status and redacted output.
3. Test at least one authorised benign control and document why it should not alert.
4. If a false positive occurs, reproduce it, change only the necessary threshold/baseline, and rerun both positive and benign cases.
5. Record TP, FP, FN, TN where ground truth is available; do not invent measures for unlabelled live data.
6. Store sanitised before/after evidence and note remaining data gaps, licensing, cost, and limitations.
7. Remove lab resources according to tenant policy.

## Evidence review

A meaningful completed validation requires raw-but-sanitised query results, KQL version, timestamp, schema notes, an explicit tuning rationale and an independently repeatable test. Offline CI success must not be relabelled as Sentinel tenant validation.
