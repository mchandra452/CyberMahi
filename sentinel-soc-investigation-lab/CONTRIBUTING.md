# Contributing

Open a focused branch and describe the behavioural hypothesis, telemetry, benign alternatives, tuning, and limitations. Add safe fixtures and expected labels before changing detector logic. Keep rule metadata and KQL references aligned.

From the lab root, run `./scripts/setup.sh` on Linux/macOS or `.\scripts\setup.ps1` on Windows. The scripts create an isolated `.venv` and install `.[dev]`; no environment activation is required. Then use the platform's `run_offline` script to run validation, analysis, detection regression, report generation, and pytest. Run Ruff separately before opening a change. Review generated evidence for deterministic content. Never contribute credentials, tenant identifiers, real victims, active indicators, payloads, or unsupported production claims.
