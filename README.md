# CyberMahi Security Engineering Labs

CyberMahi contains defensive security engineering projects with reproducible local workflows, synthetic evidence, and automated checks.

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

The [AgentShield lab](projects/AgentShield-Lab/README.md) is a controlled AI security testing framework covering prompt injection, tool abuse, data exposure, insecure output handling, and denial-of-service-style prompt attacks.

All projects are designed for authorised, defensive testing. Review each project's security and limitations documentation before adapting it.
