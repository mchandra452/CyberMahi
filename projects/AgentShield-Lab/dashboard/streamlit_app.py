import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="AgentShield Dashboard", layout="wide")
st.title("AgentShield Alert Dashboard")

log_path = st.text_input("Alert log path", "logs/generated_alerts.jsonl")
path = Path(log_path)

if not path.exists():
    st.warning("No log file found yet. Run `python main.py --demo` first.")
    st.stop()

records = []
with open(path, "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()
        if line:
            records.append(json.loads(line))

if not records:
    st.info("Log file is empty.")
    st.stop()

df = pd.DataFrame(records)
st.metric("Total Alerts", len(df))

c1, c2 = st.columns(2)
with c1:
    st.subheader("Severity")
    st.bar_chart(df["severity"].value_counts())
with c2:
    st.subheader("Top Rules")
    st.bar_chart(df["rule_id"].value_counts().head(10))

st.subheader("Recent Alerts")
st.dataframe(df.sort_values("timestamp", ascending=False).head(100), use_container_width=True)
