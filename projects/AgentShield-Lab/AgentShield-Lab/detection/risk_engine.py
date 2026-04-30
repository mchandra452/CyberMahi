"""Risk aggregation utilities for AgentShield Lab."""
from typing import List, Dict, Any

SEVERITY_LEVELS = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
}


def aggregate_risk(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate risk across multiple alerts.

    Returns a dictionary with overall severity and average risk score.
    """
    if not alerts:
        return {"overall_severity": "Low", "overall_risk_score": 0}

    # Determine highest severity level
    max_level = max(SEVERITY_LEVELS.get(a.get("severity", "Low"), 1) for a in alerts)
    overall_severity = next((sev for sev, lvl in SEVERITY_LEVELS.items() if lvl == max_level), "Low")

    # Compute average risk score
    avg_score = sum(a.get("risk_score", 0) for a in alerts) / len(alerts)
    return {"overall_severity": overall_severity, "overall_risk_score": avg_score}
