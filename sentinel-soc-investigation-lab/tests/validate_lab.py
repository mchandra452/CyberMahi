#!/usr/bin/env python3
"""Basic validation checks for the Sentinel SOC lab content."""

from __future__ import annotations
import csv
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md",
    "setup-guide.md",
    "incident-report.md",
    "detection-logic.md",
    "mitre-attack-mapping.md",
    "project-summary.md",
    "kql/suspicious-login-detection.kql",
    "kql/phishing-indicators-detection.kql",
    "kql/failed-login-bruteforce-detection.kql",
    "kql/impossible-travel-detection.kql",
    "kql/summary-hunting-queries.kql",
]

CSV_SCHEMAS = {
    "sample-logs/signin-logs-sample.csv": [
        "Timestamp","UserPrincipalName","IPAddress","Location","ResultType","ResultDescription",
        "AppDisplayName","DeviceDetail","RiskLevel","ConditionalAccessStatus",
    ],
    "sample-logs/email-security-logs-sample.csv": [
        "Timestamp","Recipient","Sender","SenderDomain","Subject","URL","AttachmentName",
        "ThreatType","DeliveryAction","DetectionSource",
    ],
    "sample-logs/incident-events-sample.csv": [
        "Timestamp","EventID","Source","User","IPAddress","EventDescription","Severity","InvestigationNote",
    ],
}

SAFE_DOMAINS = {"example.com", "phishing-demo.local", "northbridge-demo.local"}

def err(msg: str) -> None:
    print(f"[FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def validate_required_files() -> bool:
    passed = True
    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            err(f"missing required file: {rel}")
            passed = False
    if passed:
        ok("all required files exist")
    return passed


def validate_csvs() -> bool:
    passed = True
    for rel, headers in CSV_SCHEMAS.items():
        p = ROOT / rel
        with p.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames != headers:
                err(f"schema mismatch in {rel}: got {reader.fieldnames}")
                passed = False
                continue
            rows = list(reader)
            if not rows:
                err(f"no data rows in {rel}")
                passed = False
                continue
            for i, row in enumerate(rows, start=2):
                try:
                    datetime.fromisoformat(row["Timestamp"].replace("Z", "+00:00"))
                except Exception:
                    err(f"invalid ISO timestamp in {rel}:{i} => {row['Timestamp']}")
                    passed = False
    if passed:
        ok("csv schemas and timestamps validated")
    return passed


def validate_safe_domains() -> bool:
    p = ROOT / "sample-logs/email-security-logs-sample.csv"
    passed = True
    with p.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):
            domain = row["SenderDomain"].strip().lower()
            if domain not in SAFE_DOMAINS:
                err(f"unsafe/non-whitelisted sender domain at {p}:{i} => {domain}")
                passed = False
    if passed:
        ok("email sender domains restricted to safe placeholders")
    return passed


if __name__ == "__main__":
    checks = [validate_required_files(), validate_csvs(), validate_safe_domains()]
    if all(checks):
        print("\nValidation complete: all checks passed.")
        sys.exit(0)
    print("\nValidation complete: one or more checks failed.")
    sys.exit(1)
