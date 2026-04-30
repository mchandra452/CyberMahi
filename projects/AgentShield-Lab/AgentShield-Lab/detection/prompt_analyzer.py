import os
import json
from typing import List, Dict, Any

# Load detection rules from JSON file
_rules_path = os.path.join(os.path.dirname(__file__), "detection_rules.json")
with open(_rules_path, "r", encoding="utf-8") as f:
    _rules_data = json.load(f)

RULES: List[Dict[str, Any]] = _rules_data.get("rules", [])


def analyze_prompt(prompt: str) -> List[Dict[str, Any]]:
    """Analyze a user prompt against configured detection rules.

    Args:
        prompt: The user prompt to analyze.

    Returns:
        A list of alert dictionaries for each rule that matches.
    """
    alerts = []
    if not prompt:
        return alerts

    lower_prompt = prompt.lower()
    for rule in RULES:
        matched_patterns = [p for p in rule.get("patterns", []) if p.lower() in lower_prompt]
        if matched_patterns:
            alerts.append({
                "rule_id": rule.get("id"),
                "rule_name": rule.get("name"),
                "severity": rule.get("severity"),
                "risk_score": rule.get("risk_score"),
                "matched_patterns": matched_patterns,
                "mapped_risk": rule.get("mapped_risk"),
                "recommended_action": rule.get("recommended_action"),
            })
    return alerts


if __name__ == "__main__":
    # Example usage for manual testing
    test_prompt = input("Enter a prompt to analyze: ")
    results = analyze_prompt(test_prompt)
    if results:
        print("Alerts:")
        for alert in results:
            print(alert)
    else:
        print("No issues detected.")
