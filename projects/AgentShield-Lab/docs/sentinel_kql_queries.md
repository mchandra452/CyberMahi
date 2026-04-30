# Microsoft Sentinel KQL Examples for AgentShield Lab

> **Note:** These are example KQL queries for lab-generated JSON alerts (for example, from `logs/generated_alerts.jsonl`).
> This project is **not** currently connected to a live Sentinel workspace.

## Assumptions
- Alerts are ingested into a custom table (example: `AgentShieldAlerts_CL`).
- Field suffixes follow common Sentinel custom log conventions (for example, `severity_s`, `rule_id_s`).

## 1) High severity AI security alerts
```kusto
AgentShieldAlerts_CL
| where severity_s == "High"
| project TimeGenerated, rule_id_s, rule_name_s, severity_s, risk_score_d, input_sample_s, recommended_action_s
| order by TimeGenerated desc
```

## 2) ASI-001 Instruction Override attempts
```kusto
AgentShieldAlerts_CL
| where rule_id_s == "ASI-001"
| summarize attempts=count() by rule_name_s, severity_s
| order by attempts desc
```

## 3) ASI-002 System Prompt Extraction attempts
```kusto
AgentShieldAlerts_CL
| where rule_id_s == "ASI-002"
| project TimeGenerated, input_sample_s, mapped_risk_s, recommended_action_s
| order by TimeGenerated desc
```

## 4) ASI-003 Unsafe Tool Request attempts
```kusto
AgentShieldAlerts_CL
| where rule_id_s == "ASI-003"
| summarize attempts=count(), max_risk=max(todouble(risk_score_d)) by severity_s
| order by attempts desc
```

## 5) Alert count by severity
```kusto
AgentShieldAlerts_CL
| summarize alerts=count() by severity_s
| order by alerts desc
```
