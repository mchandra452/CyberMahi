# Contributing

Open a focused branch and describe the behavioural hypothesis, telemetry, benign alternatives, tuning, and limitations. Add safe fixtures and expected labels before changing detector logic. Keep rule metadata and KQL references aligned.

Install with `python -m pip install -e ".[dev]"`, then run Ruff, pytest, repository validation, analysis, detection regression, and report generation. Review generated evidence for deterministic content. Never contribute credentials, tenant identifiers, real victims, active indicators, payloads, or unsupported production claims.
