"""Risk aggregation utilities for AgentShield Lab."""
from typing import Dict, List

SEVERITY_RANKING = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
}


def calculate_overall_risk(alerts: List[Dict]) -> Dict[str, int | str]:
    """Return overall alert summary with highest severity and highest risk score."""
    if not alerts:
        return {
            "total_alerts": 0,
            "highest_severity": "None",
            "highest_risk_score": 0,
        }

    highest_severity = "Low"
    highest_risk_score = 0

    for alert in alerts:
        severity = alert.get("severity", "Low")
        if SEVERITY_RANKING.get(severity, 0) > SEVERITY_RANKING.get(highest_severity, 0):
            highest_severity = severity

        risk_score = int(alert.get("risk_score", 0))
        if risk_score > highest_risk_score:
            highest_risk_score = risk_score

    return {
        "total_alerts": len(alerts),
        "highest_severity": highest_severity,
        "highest_risk_score": highest_risk_score,
    }
