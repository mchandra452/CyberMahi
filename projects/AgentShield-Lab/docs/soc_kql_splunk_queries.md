# SOC Query Examples (KQL + Splunk)

## KQL (Microsoft Sentinel)
```kusto
let lookback = 7d;
AgentShieldAlerts_CL
| where TimeGenerated > ago(lookback)
| summarize alerts=count(), maxRisk=max(todouble(risk_score_d)) by severity_s, rule_id_s
| order by alerts desc
```

## KQL: high-risk prompt injection activity
```kusto
AgentShieldAlerts_CL
| where severity_s == "High" and mapped_risk_s has "Prompt Injection"
| project TimeGenerated, rule_id_s, input_sample_s, recommended_action_s
| order by TimeGenerated desc
```

## Splunk SPL
```spl
index=agentshield sourcetype=agentshield:alerts
| stats count max(risk_score) as max_risk by severity rule_id
| sort - count
```

## Splunk: detect burst behavior
```spl
index=agentshield sourcetype=agentshield:alerts
| bucket _time span=5m
| stats count by _time, rule_id
| where count > 5
| sort - _time
```
