# AGENTS.md

Purpose: maintain a defensive Microsoft Sentinel detection-engineering and incident-fusion lab.

- Use only synthetic evidence, `.example`/`.test`/`.invalid` domains, and RFC documentation IP ranges.
- Never add real credentials, tenant/resource IDs, victim data, malicious infrastructure, payloads, persistence, evasion, or active scanning.
- Preserve the structure: `config/` holds policy, `data/` synthetic evidence, `detections/` KQL and metadata, `src/soclab/` the offline engine, `tests/` regression coverage, `docs/` engineering guidance, and `artifacts/example/` verified generated evidence.
- Keep KQL thresholds and time windows explicit; preserve rule metadata, entities, benign cases, limitations, and evidence-based ATT&CK mappings.
- Python tests validate offline intent only. Do not claim KQL execution, production deployment, guaranteed coverage, or tenant access.
- Keep documentation technical and concise. Do not add CV, LinkedIn, recruiter, interview-script, or classroom-project content.
- Before committing, run `ruff check .`, `pytest`, `python -m soclab validate`, `python -m soclab analyze`, `python -m soclab test-detections`, `python -m soclab build-report`, and `git diff --check`.
