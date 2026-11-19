from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from soclab.config import load_yaml
from soclab.detectors import detect_download_anomaly, run_detectors
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


@pytest.fixture
def user_download(root):
    return next(
        event
        for event in load_events(root)
        if event.action == "FileDownloaded" and event.user == "analyst1@northbridge.example"
    )


@pytest.mark.parametrize(
    ("last_offset", "expected_count"),
    [
        (timedelta(days=1) - timedelta(microseconds=1), 1),
        (timedelta(days=1), 0),
        (timedelta(days=1, microseconds=1), 0),
    ],
)
def test_download_threshold_uses_a_bounded_day(root, user_download, last_offset, expected_count):
    sample = user_download
    offsets = [timedelta(hours=index) for index in range(8)] + [last_offset]
    events = [
        replace(sample, event_id=f"TEST-DOWNLOAD-{index}", timestamp=sample.timestamp + offset)
        for index, offset in enumerate(offsets)
    ]
    findings = detect_download_anomaly(list(reversed(events)), context(root))
    assert len(findings) == expected_count
    if findings:
        assert set(findings[0].event_ids) == {event.event_id for event in events}


def test_downloads_spread_across_days_do_not_trigger(root, user_download):
    sample = user_download
    events = [
        replace(
            sample,
            event_id=f"TEST-DAILY-{index}",
            timestamp=sample.timestamp + timedelta(days=index),
        )
        for index in range(9)
    ]
    assert detect_download_anomaly(events, context(root)) == []


def test_download_burst_is_found_after_sparse_older_events(root, user_download):
    sample = user_download
    older = [
        replace(
            sample,
            event_id=f"TEST-OLDER-{index}",
            timestamp=sample.timestamp + timedelta(days=index),
        )
        for index in range(3)
    ]
    burst = [
        replace(
            sample,
            event_id=f"TEST-BURST-{index}",
            timestamp=sample.timestamp + timedelta(days=4, minutes=index),
        )
        for index in range(9)
    ]
    findings = detect_download_anomaly(list(reversed([*older, *burst])), context(root))
    assert len(findings) == 1
    assert set(findings[0].event_ids) == {event.event_id for event in burst}


@pytest.mark.parametrize(
    "other_context",
    [
        {"user": "another-user@northbridge.example"},
        {"scenario_id": "TEST-ANOTHER-SCENARIO"},
    ],
)
def test_download_count_keeps_users_and_scenarios_separate(root, user_download, other_context):
    sample = user_download
    first = [replace(sample, event_id=f"TEST-FIRST-{index}") for index in range(5)]
    second = [
        replace(sample, event_id=f"TEST-SECOND-{index}", **other_context)
        for index in range(5)
    ]
    assert detect_download_anomaly([*first, *second], context(root)) == []
