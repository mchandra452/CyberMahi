from __future__ import annotations

import csv
import hashlib
import json

import soclab.cli as cli
from soclab.cli import (
    command_analyze,
    command_build_report,
    command_test_detections,
    command_validate,
)
from soclab.config import ConfigurationError, load_yaml


def hashes(root):
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "artifacts/latest").glob("*"))
        if path.is_file()
    }


def test_cli_commands_return_success(root):
    assert command_validate(root) == 0
    assert command_analyze(root) == 0
    assert command_test_detections(root) == 0
    assert command_build_report(root) == 0


def test_generated_output_is_deterministic(root):
    command_analyze(root)
    command_build_report(root)
    first = hashes(root)
    command_analyze(root)
    command_build_report(root)
    assert hashes(root) == first


def test_stale_latest_files_are_removed(root):
    output = root / "artifacts/latest"
    output.mkdir(parents=True, exist_ok=True)
    stale = output / "stale-output.txt"
    stale.write_text("obsolete", encoding="utf-8")
    command_analyze(root)
    assert not stale.exists()


def test_generated_incident_artifacts_use_only_contributing_evidence(root):
    command_build_report(root)
    output = root / "artifacts/latest"
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    fusion = next(finding for finding in findings if finding["DetectionId"] == "DET010")
    assert "E-DNS-001" in fusion["EventIds"]
    assert "E-DNS-002" not in fusion["EventIds"]
    assert fusion["Synthetic"] is True
    assert fusion["Scope"] == "incident_fusion"
    accepted_false_positive = next(
        finding for finding in findings if "E-DNS-002" in finding["EventIds"]
    )
    assert accepted_false_positive["Scope"] == "standalone_detection_regression"

    incident = json.loads((output / "incident.json").read_text(encoding="utf-8"))
    assert incident["Synthetic"] is True
    assert incident["Scope"] == "offline_incident_fusion"
    with (output / "timeline.csv").open(encoding="utf-8", newline="") as handle:
        timeline = list(csv.DictReader(handle))
    assert timeline
    assert "E-DNS-002" not in {row["EventId"] for row in timeline}
    assert all(row["Synthetic"] == "true" for row in timeline)
    assert all(row["Scope"] == "correlated_incident_evidence" for row in timeline)


def test_report_is_derived_from_evidence_config_and_rule_metadata(root):
    command_build_report(root)
    output = root / "artifacts/latest"
    report = (output / "investigation-report.md").read_text(encoding="utf-8")
    incident = json.loads((output / "incident.json").read_text(encoding="utf-8"))
    assert "Northbridge Financial Services" in report
    assert "E-EMAIL-001" in report
    assert "E-DNS-001" in report
    assert "E-DNS-002" not in report
    assert incident["RecommendedAnalystAction"] in report
    assert "## Confidence assessment" in report
    for rationale in incident["Rationale"]:
        assert rationale in report
    for entity_type in incident["Entities"]:
        assert f"| {entity_type} |" in report
    for detection_id in incident["LinkedDetections"]:
        metadata = load_yaml(root / "detections/rules" / f"{detection_id}.yml")
        for mapping in metadata["attack"]:
            if "technique" in mapping:
                assert mapping["technique"] in report
            else:
                assert mapping["mapping_status"] in report
                assert mapping["rationale"] in report


def test_cli_main_returns_success_and_handles_expected_failure(root, monkeypatch, capsys):
    monkeypatch.setattr(cli, "repository_root", lambda: root)
    assert cli.main(["validate"]) == 0

    def fail_to_find_root():
        raise ConfigurationError("test root failure")

    monkeypatch.setattr(cli, "repository_root", fail_to_find_root)
    assert cli.main(["validate"]) == 1
    assert "ERROR: test root failure" in capsys.readouterr().err


def test_no_empty_engineering_files(root):
    checked = [
        *root.glob("*.md"),
        *(root / "docs").glob("*.md"),
        *(root / "detections/kql").glob("*.kql"),
        *(root / "detections/rules").glob("*.yml"),
        *(root / "src/soclab").glob("*.py"),
    ]
    assert checked
    assert all(path.read_text(encoding="utf-8").strip() for path in checked)


def test_password_spray_kql_preserves_every_target_account(root):
    query = (root / "detections/kql/DET001-password-spray.kql").read_text(encoding="utf-8")
    assert "mv-expand User=Users" in query
    assert "Users[0]" not in query


def test_fusion_kql_reads_security_alert_custom_details_from_extended_properties(root):
    query = (root / "detections/kql/DET010-identity-incident-fusion.kql").read_text(
        encoding="utf-8"
    )
    assert "parse_json(ExtendedProperties)" in query
    assert 'AlertProperties["Custom Details"]' in query


def test_windows_runner_propagates_native_failures(root):
    script = (root / "scripts/run_offline.ps1").read_text(encoding="utf-8")
    assert script.count("$LASTEXITCODE -ne 0") == 5


def test_portfolio_marketing_terms_do_not_reappear(root):
    terms = (
        "".join(("linked", "in")) + " post",
        " ".join(("cv", "bullet")),
        " ".join(("recruiter", "pitch")),
        " ".join(("feedback", "is welcome")),
        " ".join(("college", "project")),
    )
    for path in [root / "README.md", *(root / "docs").glob("*.md")]:
        text = path.read_text(encoding="utf-8").lower()
        assert not any(term in text for term in terms), path
