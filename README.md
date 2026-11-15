# CyberMahi Security Engineering Labs

CyberMahi contains two defensive security labs that run locally with synthetic inputs.

| Project | Start here |
| --- | --- |
| Microsoft Sentinel | [Investigation report](sentinel-soc-investigation-lab/artifacts/example/investigation-report.md) · [Detection catalog](sentinel-soc-investigation-lab/docs/detection-catalog.md) |
| AgentShield | [Demo](projects/AgentShield-Lab/README.md#quick-start) · [Detection rules](projects/AgentShield-Lab/detection/detection_rules.json) |

## Microsoft Sentinel detection engineering lab

The [Sentinel detection engineering and incident fusion lab](sentinel-soc-investigation-lab/README.md) provides ten metadata-backed KQL detections, a deterministic Python analysis engine, malicious and benign regression scenarios, duplicate-aware incident fusion, and generated investigation evidence.

Python 3.11 or newer, Git, and internet access for the first dependency install are the only prerequisites for offline use. No Microsoft tenant or Azure subscription is required.

Linux/macOS:

```bash
git clone https://github.com/mchandra452/CyberMahi.git
cd CyberMahi/sentinel-soc-investigation-lab
./scripts/run_offline.sh
```

Windows PowerShell:

```powershell
git clone https://github.com/mchandra452/CyberMahi.git
Set-Location CyberMahi\sentinel-soc-investigation-lab
.\scripts\run_offline.ps1
```

The runner creates an isolated `.venv` on first use, installs the project, validates the repository, runs the synthetic analysis and regression suite, builds the report, and runs pytest. Generated evidence is written to `sentinel-soc-investigation-lab/artifacts/latest/`.

## AgentShield lab

The [AgentShield lab](projects/AgentShield-Lab/README.md) is an intentionally limited rule-based Python prototype: phrase matching, static risk labels, redacted alert logs and basic unit tests. It does not run or secure a real LLM agent.

## Evidence and limitations

| Project | Verified through local code and tests | Not established |
| --- | --- | --- |
| Sentinel | Synthetic telemetry analysis, incident correlation, test fixtures and CI | Live KQL execution, real connector mappings, production accuracy |
| AgentShield | Configured phrase matches, CLI logs, basic tests and privacy regression tests | Robust prompt-injection detection, actual AI agent/tool enforcement |

The Sentinel lab includes an [engineering decisions log](sentinel-soc-investigation-lab/docs/engineering-decisions.md) and [live-validation evidence checklist](sentinel-soc-investigation-lab/docs/validation-evidence-checklist.md). Test results and engineering limitations are reported separately from proposed future improvements.

All projects are designed for authorised, defensive testing. Review each project's security and limitations documentation before adapting it.
