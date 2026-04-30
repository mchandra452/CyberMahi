from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from detection.risk_engine import calculate_overall_risk


def write_markdown_report(report_path: Path, prompts_scanned: int, alerts: List[Dict]) -> Path:
    """Write a SOC-friendly markdown report and return its path."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    summary = calculate_overall_risk(alerts)
    rule_ids = sorted({a.get("rule_id", "Unknown") for a in alerts}) if alerts else []
    actions = sorted({a.get("recommended_action", "Review activity") for a in alerts}) if alerts else []

    lines = [
        "# AgentShield Demo Report",
        "",
        f"- **Generated at (UTC):** {datetime.now(timezone.utc).isoformat()}",
        f"- **Prompts scanned:** {prompts_scanned}",
        f"- **Alerts generated:** {summary['total_alerts']}",
        f"- **Highest severity:** {summary['highest_severity']}",
        "",
        "## Rule IDs Triggered",
    ]

    if rule_ids:
        lines.extend([f"- `{rid}`" for rid in rule_ids])
    else:
        lines.append("- None")

    lines.extend(["", "## Recommended Actions"])
    if actions:
        lines.extend([f"- {action}" for action in actions])
    else:
        lines.append("- No action required.")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path
