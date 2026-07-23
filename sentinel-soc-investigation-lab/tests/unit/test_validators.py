from __future__ import annotations

import json
import shutil
from ipaddress import ip_network

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from soclab.config import load_lab_config, load_risk_model, load_yaml
from soclab.telemetry import TelemetryError, event_from_record, load_events, parse_timestamp
from soclab.validators import (
    RFC_DOCUMENTATION_NETWORKS,
    _is_safe_ip,
    _load_rule_schema,
    _normalize_yaml_for_json,
    _validate_links_and_content,
    _validate_reference_incident,
    _validate_risk_controls,
    _validate_telemetry,
    _validate_text_indicators,
    validate_repository,
)


def test_configuration_loads(root):
    assert load_lab_config(root)["scenario"]["id"] == "NFS-IDENTITY-001"
    assert load_risk_model(root)["detection_weights"]["DET006"] == 15


def test_telemetry_is_stable_and_well_formed(root):
    events = load_events(root)
    assert len(events) >= 60
    assert len({event.event_id for event in events}) == len(events)
    assert sum(event.is_malicious for event in events) >= 20
    assert sum(not event.is_malicious for event in events) >= 20


def test_timestamp_validation():
    assert parse_timestamp("2025-02-18T09:00:00Z").tzinfo is not None
    with pytest.raises(TelemetryError):
        parse_timestamp("not-a-time")
    with pytest.raises(TelemetryError, match="UTC offset"):
        parse_timestamp("2025-02-18T09:00:00")
    with pytest.raises(TelemetryError, match="must use UTC"):
        parse_timestamp("2025-02-18T09:00:00+01:00")


def test_safe_indicator_validation():
    assert _is_safe_ip("192.0.2.1")
    assert _is_safe_ip("198.51.100.254")
    assert not _is_safe_ip("8.8.8.8")


def test_minimal_telemetry_fixture_has_all_typed_common_fields(root):
    source = root / "tests/fixtures/minimal-telemetry/authentication.jsonl"
    record = json.loads(source.read_text(encoding="utf-8"))
    event = event_from_record(record, source, 1)
    assert event.event_id == "E-MIN-001"
    assert event.timestamp.utcoffset() is not None

    record["IsMalicious"] = "false"
    with pytest.raises(TelemetryError, match="IsMalicious must be a boolean"):
        event_from_record(record, source, 1)


def test_telemetry_requires_every_named_source_file(root, tmp_path):
    telemetry_dir = tmp_path / "data/telemetry"
    telemetry_dir.mkdir(parents=True)
    shutil.copyfile(
        root / "tests/fixtures/minimal-telemetry/authentication.jsonl",
        telemetry_dir / "authentication.jsonl",
    )
    errors: list[str] = []
    _validate_telemetry(
        tmp_path,
        {
            "scenario": {"id": "MINIMAL-SYNTHETIC"},
            "telemetry": {"minimum_events": 60},
        },
        (".example", ".test", ".invalid"),
        RFC_DOCUMENTATION_NETWORKS,
        errors,
    )
    assert any("missing required telemetry files" in error for error in errors)


def test_rule_schema_normalizes_yaml_dates_and_rejects_incomplete_guidance(root):
    schema_errors: list[str] = []
    schema = _load_rule_schema(root, schema_errors)
    assert schema_errors == []
    assert schema is not None
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    loaded = load_yaml(root / "detections/rules/DET001.yml")
    rule = _normalize_yaml_for_json(loaded)
    assert isinstance(rule["date_created"], str)
    assert list(validator.iter_errors(rule)) == []

    rule["severity_rationale"] = ""
    rule["attack"] = []
    rule["test_cases"][0]["event_ids"] = []
    messages = [error.message for error in validator.iter_errors(rule)]
    assert sum("should be non-empty" in message for message in messages) >= 3


def test_risk_model_rejects_incomplete_categories_and_incoherent_limits(root, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    risk_text = (root / "config/detection-risk-model.yml").read_text(encoding="utf-8")
    invalid = (
        risk_text.replace(
            "primary_entity: analyst1@northbridge.example",
            "primary_entity: different-user@northbridge.example",
        )
        .replace("  DET009: network\n", "")
        .replace("  high_confidence_categories: 6", "  high_confidence_categories: 99")
        .replace("  high_confidence_detections: 7", "  high_confidence_detections: 99")
        .replace("  maximum_score: 100", "  maximum_score: 50")
    )
    (config_dir / "detection-risk-model.yml").write_text(invalid, encoding="utf-8")
    errors: list[str] = []
    _validate_risk_controls(
        tmp_path,
        load_lab_config(root),
        RFC_DOCUMENTATION_NETWORKS,
        errors,
    )
    assert any("primary_entity must match" in error for error in errors)
    assert any("detection_categories coverage mismatch" in error for error in errors)
    assert any("high_confidence_categories exceeds" in error for error in errors)
    assert any("high_confidence_detections must be between" in error for error in errors)
    assert any("0 < medium < high <= maximum_score" in error for error in errors)


def test_reference_incident_cannot_be_detection_input(root):
    source = root / "data/telemetry/incidents.jsonl"
    record = json.loads(source.read_text(encoding="utf-8"))
    record["DetectionInput"] = True
    event = event_from_record(record, source, 1)
    errors: list[str] = []
    _validate_reference_incident([event], load_lab_config(root), errors)
    assert errors == ["E-INC-001 DetectionInput must be false"]


def test_indicator_scan_rejects_unconfigured_ip_url_and_email(tmp_path):
    errors: list[str] = []
    configured_networks = tuple(
        ip_network(value)
        for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    )
    _validate_text_indicators(
        tmp_path / "unsafe.kql",
        'let ResponseIP = "8.8.8.8"; let Url = "https://unsafe.example.com/a"; '
        'let User = "person@example.com";',
        (".example", ".test", ".invalid"),
        configured_networks,
        errors,
        scan_domain_assignments=True,
    )
    assert any("8.8.8.8" in error for error in errors)
    assert any("unsafe.example.com" in error for error in errors)
    assert any("person@example.com" not in error and "example.com" in error for error in errors)


def test_markdown_scan_covers_nested_project_documents(tmp_path):
    nested = tmp_path / "nested/deeper"
    nested.mkdir(parents=True)
    (nested / "broken.md").write_text("[missing](not-there.md)\n", encoding="utf-8")
    errors: list[str] = []
    _validate_links_and_content(tmp_path, errors)
    assert len(errors) == 1
    assert errors[0].endswith("broken.md has broken internal link: not-there.md")


def test_labels_are_valid_json(root):
    labels = json.loads((root / "data/labels/expected-findings.json").read_text(encoding="utf-8"))
    assert sorted(labels["detections"]) == [f"DET{number:03d}" for number in range(1, 11)]


def test_labels_match_rule_test_evidence(root):
    labels = json.loads((root / "data/labels/expected-findings.json").read_text(encoding="utf-8"))
    for detection_id, expected in labels["detections"].items():
        rule = load_yaml(root / "detections/rules" / f"{detection_id}.yml")
        malicious_rule_cases = {
            frozenset(case["event_ids"])
            for case in rule["test_cases"]
            if case["type"] == "malicious"
        }
        labelled_required_cases = {
            frozenset(case["event_ids"]) for case in expected["required_cases"]
        }
        assert labelled_required_cases == malicious_rule_cases

        benign_rule_ids = {
            event_id
            for case in rule["test_cases"]
            if case["type"] == "benign"
            for event_id in case["event_ids"]
        }
        labelled_benign_ids = set(expected.get("benign_event_ids", [])) | set(
            expected["prohibited_false_positive_event_ids"]
        )
        labelled_benign_ids.update(
            event_id
            for case in expected.get("benign_cases", [])
            for event_id in case["event_ids"]
        )
        assert labelled_benign_ids == benign_rule_ids


def test_repository_validator_passes(root):
    assert validate_repository(root) == []
