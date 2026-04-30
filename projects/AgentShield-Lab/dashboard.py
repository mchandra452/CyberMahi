"""Optional Streamlit dashboard for AgentShield Lab."""
import json
from pathlib import Path

import streamlit as st

from main import analyze_prompt, load_rules

st.set_page_config(page_title="AgentShield Dashboard", layout="wide")
st.title("AgentShield Lab Dashboard (Optional)")

st.caption("Analyze prompts using local detection rules and review generated alerts.")

prompt = st.text_area("Enter a prompt to analyze", height=120)
run_analysis = st.button("Analyze Prompt")

if run_analysis:
    rules = load_rules()
    alerts = analyze_prompt(prompt, rules)

    if not alerts:
        st.success("No suspicious activity detected.")
    else:
        st.error(f"Matched {len(alerts)} rule(s).")

        rows = [
            {
                "rule_id": alert.get("rule_id"),
                "rule_name": alert.get("rule_name"),
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score"),
            }
            for alert in alerts
        ]
        st.subheader("Matched Rules")
        st.table(rows)

        st.subheader("Generated Alerts (JSON)")
        st.code(json.dumps(alerts, indent=2), language="json")

st.divider()
st.subheader("Recent Generated Alerts from logs/generated_alerts.jsonl")

log_path = Path("logs/generated_alerts.jsonl")
if not log_path.exists():
    st.info("No local alert log found yet. Run `python main.py --demo` first.")
else:
    records = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))

    if not records:
        st.info("Alert log file is present but currently empty.")
    else:
        st.dataframe(records[-50:], use_container_width=True)
