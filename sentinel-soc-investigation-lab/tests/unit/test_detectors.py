from __future__ import annotations

import json

from soclab.config import load_yaml
from soclab.detectors import run_detectors
from soclab.telemetry import load_events


def context(root):
    return {
        "baselines": json.loads(
            (root / "data/baselines/user-baselines.json").read_text(encoding="utf-8")
        )["users"],
        "known_benign": json.loads(
            (root / "data/baselines/known-benign-entities.json").read_text(encoding="utf-8")
        ),
        "safe_indicators": load_yaml(root / "config/safe-indicators.yml"),
    }


def test_every_base_detector_returns_expected_case(root):
    findings = run_detectors(load_events(root), context(root))
    assert {finding.detection_id for finding in findings} == {
        f"DET{number:03d}" for number in range(1, 10)
    }


def test_required_and_control_event_membership(root):
    findings = run_detectors(load_events(root), context(root))
    by_id = {
        detection_id: set() for detection_id in (f"DET{number:03d}" for number in range(1, 10))
    }
    for finding in findings:
        by_id[finding.detection_id].update(finding.event_ids)
    assert "E-AUTH-007" in by_id["DET002"]
    assert "E-AUTH-013" not in by_id["DET003"]
    assert "E-CLOUD-020" not in by_id["DET005"]
    assert "E-CLOUD-021" not in by_id["DET007"]
    assert "E-DNS-002" in by_id["DET009"]  # intentionally accepted false positive


def test_findings_have_analyst_fields(root):
    for finding in run_detectors(load_events(root), context(root)):
        payload = finding.to_dict()
        assert payload["FindingId"].startswith("F-DET")
        assert payload["EventIds"]
        assert payload["Entities"]
        assert payload["Evidence"]


def test_specialised_entities_are_extracted(root):
    findings = run_detectors(load_events(root), context(root))
    by_detection = {finding.detection_id: finding for finding in findings}
    assert {
        detection_id: set(finding.entities)
        for detection_id, finding in by_detection.items()
    } == {
        "DET001": {"Account", "IP"},
        "DET002": {"Account", "IP"},
        "DET003": {"Account", "Host", "IP"},
        "DET004": {"Account", "Domain", "URL"},
        "DET005": {"Account", "Application", "ApplicationId", "IP"},
        "DET006": {"Account", "IP", "Mailbox"},
        "DET007": {"Account", "IP"},
        "DET008": {"Account", "Host", "Process"},
        "DET009": {"Account", "Domain", "Host"},
    }
    assert by_detection["DET004"].entities["URL"] == (
        "https://microsoft-auth-check.example/review",
    )
    assert by_detection["DET005"].entities["ApplicationId"]
    assert by_detection["DET005"].entities["Application"] == (
        "Document Workflow Helper",
    )
    assert {"winword.exe", "powershell.exe"} <= set(
        by_detection["DET008"].entities["Process"]
    )
    assert by_detection["DET008"].entities["Host"] == ("NFS-LT-104",)
