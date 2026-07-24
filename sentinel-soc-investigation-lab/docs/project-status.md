# Project status

## Verified offline

- Repository structure, safe indicators, JSONL syntax, stable event IDs, timestamps, rule metadata, KQL comments/projections, ATT&CK ID format, required documentation, secret patterns, and internal links.
- Ten Python-equivalent detection/fusion paths against deterministic synthetic telemetry.
- Four prohibited benign controls and one accepted novelty-only false positive.
- Duplicate-aware correlation, configurable scoring, deterministic JSON/CSV/Markdown evidence, and generated investigation report.
- Ruff, pytest, CLI exit-code, repository quality, and active monorepo-root GitHub Actions checks.

## Requires live validation

- KQL syntax and performance against actual Microsoft tables.
- Connector availability, schema extraction, entity mapping, ingestion delay, rule scheduling, alert grouping, and Defender XDR incident behaviour.
- Tenant baselines, watchlist governance, alert volume, cost, retention, operational ownership, and response approvals.

## Working versus simulated

The offline CLI, fixtures, metrics, fusion, and reports are working code. Microsoft security telemetry, tenant deployment, OAuth activity, endpoint evidence, and incident response are simulated. No production coverage or deployment is claimed.

## Verification

Install development dependencies, then run `ruff check .`, `pytest`, `python -m soclab validate`, `python -m soclab analyze`, `python -m soclab test-detections`, and `python -m soclab build-report`. Inspect every file under `artifacts/latest/` and compare the complete set with `artifacts/example/`.
