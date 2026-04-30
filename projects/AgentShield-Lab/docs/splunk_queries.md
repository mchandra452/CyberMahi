# Splunk Query Examples for AgentShield Lab

> **Note:** These are example queries for lab-generated JSON alert logs (for example, `logs/generated_alerts.jsonl`).
> This project is **not** currently connected to a live Splunk environment.

## Assumptions
- Logs are onboarded as JSON events.
- Fields map to keys in the generated alerts (e.g., `severity`, `rule_id`, `risk_score`, `recommended_action`).

## 1) High severity AI security alerts
```spl
index=agentshield sourcetype=agentshield:alerts severity="High"
| table _time rule_id rule_name severity risk_score input_sample recommended_action
| sort - _time
```

## 2) ASI-001 Instruction Override attempts
```spl
index=agentshield sourcetype=agentshield:alerts rule_id="ASI-001"
| stats count as attempts by rule_name severity
```

## 3) ASI-002 System Prompt Extraction attempts
```spl
index=agentshield sourcetype=agentshield:alerts rule_id="ASI-002"
| table _time input_sample mapped_risk recommended_action
| sort - _time
```

## 4) ASI-003 Unsafe Tool Request attempts
```spl
index=agentshield sourcetype=agentshield:alerts rule_id="ASI-003"
| stats count values(recommended_action) as response_playbook by severity
```

## 5) Alert count by severity
```spl
index=agentshield sourcetype=agentshield:alerts
| stats count by severity
| sort - count
```
