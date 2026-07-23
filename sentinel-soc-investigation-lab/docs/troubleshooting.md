# Troubleshooting

## Package cannot be imported

Run `python -m pip install -e ".[dev]"` from the repository root and confirm `python --version` is 3.11 or newer. If using a virtual environment, verify its interpreter is active.

## Validation reports an unsafe indicator

Use only `.example`, `.test`, or `.invalid` domains and IPv4 documentation networks listed in `config/safe-indicators.yml`. Do not weaken the validator to admit a convenient real indicator.

## A required detection is missed

Run `python -m soclab analyze`, inspect `artifacts/latest/findings.json`, compare event IDs with `data/labels/expected-findings.json`, and add or correct a focused regression case. Do not change labels simply to hide a detector defect.

## A benign control fires

Identify the detector and evidence event, verify the control's baseline/watchlist entry, and decide whether the hit is prohibited or an accepted measurable false positive. DET009 intentionally reports one newly adopted SaaS domain.

## No fused incident is produced

Fusion needs the primary account, a four-hour temporal window, and at least four independent categories. Review `config/detection-risk-model.yml`, finding entities, and detection categories. A single weak or duplicated signal should not be promoted.

## KQL fails in Sentinel

Offline tests do not execute KQL. Confirm the connector, table, field names, dynamic-property shape, portal time range, function availability, and permissions. Test subexpressions separately and update the documented schema mapping.

## Generated outputs differ

Verify source files and configuration are unchanged, delete `artifacts/latest/`, rerun analysis and report generation, and compare JSON with sorted keys. The engine adds no current-time value to evidence.
