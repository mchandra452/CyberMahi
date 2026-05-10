#!/usr/bin/env python3
"""Validation checks for the Sentinel SOC lab content."""

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
    "docs/project-status.md",
    "docs/troubleshooting.md",
    "docs/escalation-decision-tree.md",
    "docs/false-positive-handling.md",
    "docs/demo-walkthrough.md",
    "kql/suspicious-login-detection.kql",
    "kql/phishing-indicators-detection.kql",
    "kql/failed-login-bruteforce-detection.kql",
    "kql/impossible-travel-detection.kql",
    "kql/summary-hunting-queries.kql",
]

REQUIRED_FOLDERS = ["kql", "sample-logs", "docs", "reports", "screenshots", "tests"]

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
KQL_FILES = [
    "kql/suspicious-login-detection.kql",
    "kql/phishing-indicators-detection.kql",
    "kql/failed-login-bruteforce-detection.kql",
    "kql/impossible-travel-detection.kql",
    "kql/summary-hunting-queries.kql",
]


def err(msg: str) -> None:
    print(f"[FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def validate_required_files_and_folders() -> bool:
    passed = True
    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            err(f"missing required file: {rel}")
            passed = False
    for rel in REQUIRED_FOLDERS:
        if not (ROOT / rel).is_dir():
            err(f"missing required folder: {rel}")
            passed = False
    if passed:
        ok("required files and folders exist")
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
            if len(rows) < 3:
                err(f"expected at least 3 data rows in {rel}, got {len(rows)}")
                passed = False
            for i, row in enumerate(rows, start=2):
                try:
                    datetime.fromisoformat(row["Timestamp"].replace("Z", "+00:00"))
                except Exception:
                    err(f"invalid ISO timestamp in {rel}:{i} => {row['Timestamp']}")
                    passed = False
    if passed:
        ok("csv schemas, row counts, and timestamps validated")
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


def validate_kql_comments() -> bool:
    passed = True
    for rel in KQL_FILES:
        txt = (ROOT / rel).read_text(encoding="utf-8")
        if "//" not in txt:
            err(f"kql file missing comments: {rel}")
            passed = False
    if passed:
        ok("all KQL files contain comments")
    return passed


if __name__ == "__main__":
    checks = [
        validate_required_files_and_folders(),
        validate_csvs(),
        validate_safe_domains(),
        validate_kql_comments(),
    ]
    if all(checks):
        print("\nValidation complete: all checks passed.")
        sys.exit(0)
    print("\nValidation complete: one or more checks failed.")
    sys.exit(1)
