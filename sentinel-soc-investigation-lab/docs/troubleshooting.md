# Troubleshooting

## Package cannot be imported

Run `./scripts/setup.sh` on Linux/macOS or `.\scripts\setup.ps1` on Windows from `sentinel-soc-investigation-lab/` (the lab root). The setup script requires Python 3.11 or newer and uses `.venv` directly, so activation is not required.

On Debian or Ubuntu, install the matching `python3-venv` package if virtual-environment creation is unavailable. If PowerShell blocks local scripts, run `Set-ExecutionPolicy -Scope Process Bypass` in that terminal and retry; this changes policy only for the current process.

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
