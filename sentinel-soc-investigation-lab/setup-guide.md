# Setup Guide

## Option A: No Azure Cost / Offline Learning
1. Review sample logs in `sample-logs/`.
2. Read KQL files in `kql/` to understand logic patterns.
3. Follow `incident-report.md` and `reports/` to learn analyst reporting style.
4. Use `screenshots/README.md` as a checklist for future lab captures.

Best for: fast portfolio building without cloud spend.

## Option B: Microsoft Sentinel Lab
1. Create an Azure account.
2. Create a Log Analytics Workspace.
3. Enable Microsoft Sentinel on the workspace.
4. Ingest sample logs (custom tables) or connect safe demo data sources.
5. Run and adapt the KQL queries from `kql/`.
6. Capture screenshots of query outputs and incidents.
7. Document findings using the provided report templates.

Best for: hands-on Sentinel interface exposure.

## Cost Warning
Azure services may cost money. Use free credits carefully and delete resources when finished.
