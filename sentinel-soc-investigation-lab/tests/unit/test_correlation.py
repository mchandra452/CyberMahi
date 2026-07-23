from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from soclab.config import load_lab_config, load_risk_model
from soclab.correlation import correlate
from soclab.models import Finding


def finding(
    detection_id: str,
    category: str,
    minute: int,
    user: str = "analyst1@northbridge.example",
    ip_value: str = "203.0.113.50",
) -> Finding:
    return Finding(
        finding_id=f"F-{detection_id}-{minute}",
        detection_id=detection_id,
        name=detection_id,
        timestamp=datetime(2025, 2, 18, 9, minute, tzinfo=UTC),
        severity="medium",
        confidence="medium",
        category=category,
        event_ids=(f"E-{detection_id}-{minute}",),
        entities={"Account": (user,), "IP": (ip_value,)},
        evidence="test evidence",
    )


def test_one_weak_signal_does_not_create_incident(root):
    assert (
        correlate(
            [finding("DET009", "network", 1)],
            load_risk_model(root),
            load_lab_config(root),
        )
        is None
    )


def test_duplicate_detection_does_not_inflate_score(root):
    model = load_risk_model(root)
    base = [
        finding("DET002", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET008", "endpoint", 4),
    ]
    config = load_lab_config(root)
    first = correlate(base, model, config)
    duplicated = correlate([*base, finding("DET008", "endpoint", 5)], model, config)
    assert first is not None and duplicated is not None
    assert first.incident.risk_score == duplicated.incident.risk_score
    assert [item.detection_id for item in duplicated.contributing_findings].count("DET008") == 1


def test_multiple_independent_categories_increase_confidence(root):
    model = load_risk_model(root)
    findings = [
        finding("DET001", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET006", "mailbox", 4),
        finding("DET007", "cloud_storage", 5),
        finding("DET008", "endpoint", 6),
        finding("DET009", "network", 7),
    ]
    result = correlate(findings, model, load_lab_config(root))
    assert result is not None
    assert result.incident.confidence == "high"
    assert result.incident.risk_score >= model["thresholds"]["high"]


def test_known_vpn_reduces_score_and_confidence(root):
    model = load_risk_model(root)
    categories = (
        ("DET001", "authentication"),
        ("DET004", "email"),
        ("DET005", "cloud_application"),
        ("DET006", "mailbox"),
        ("DET007", "cloud_storage"),
        ("DET008", "endpoint"),
        ("DET009", "network"),
    )
    normal = correlate(
        [
            finding(detection_id, category, index)
            for index, (detection_id, category) in enumerate(categories, 1)
        ],
        model,
        load_lab_config(root),
    )
    vpn = correlate(
        [
            finding(detection_id, category, index, ip_value="198.51.100.10")
            for index, (detection_id, category) in enumerate(categories, 1)
        ],
        model,
        load_lab_config(root),
    )
    assert normal is not None and vpn is not None
    assert vpn.incident.risk_score == normal.incident.risk_score - 20
    assert normal.incident.confidence == "high" and vpn.incident.confidence == "medium"


def test_high_impact_cloud_signals_raise_priority(root):
    model = load_risk_model(root)
    common = [
        finding("DET001", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET008", "endpoint", 3),
    ]
    config = load_lab_config(root)
    low_impact = correlate([*common, finding("DET009", "network", 4)], model, config)
    oauth = correlate([*common, finding("DET005", "cloud_application", 4)], model, config)
    mailbox = correlate([*common, finding("DET006", "mailbox", 4)], model, config)
    assert low_impact is not None and oauth is not None and mailbox is not None
    assert (
        mailbox.incident.risk_score
        > oauth.incident.risk_score
        > low_impact.incident.risk_score
    )


def test_correlation_excludes_out_of_window_and_unrelated_findings(root):
    model = load_risk_model(root)
    config = load_lab_config(root)
    base = [
        finding("DET002", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET008", "endpoint", 4),
    ]
    out_of_window = replace(
        finding("DET009", "network", 5),
        finding_id="F-DET009-LATE",
        timestamp=base[0].timestamp + timedelta(hours=5),
    )
    unrelated = finding(
        "DET006",
        "mailbox",
        6,
        user="sales1@northbridge.example",
    )
    result = correlate([*base, out_of_window, unrelated], model, config)
    assert result is not None
    assert {item.finding_id for item in result.contributing_findings}.isdisjoint(
        {out_of_window.finding_id, unrelated.finding_id}
    )
    assert all(
        result.incident.first_seen <= item.timestamp <= result.incident.last_seen
        for item in result.contributing_findings
    )


def test_score_cap_and_confidence_thresholds_come_from_model(root):
    model = deepcopy(load_risk_model(root))
    model["thresholds"]["maximum_score"] = 55
    model["thresholds"]["high_confidence_categories"] = 7
    model["thresholds"]["high_confidence_detections"] = 8
    findings = [
        finding("DET001", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET006", "mailbox", 4),
        finding("DET007", "cloud_storage", 5),
        finding("DET008", "endpoint", 6),
        finding("DET009", "network", 7),
    ]
    result = correlate(findings, model, load_lab_config(root))
    assert result is not None
    assert result.incident.risk_score == 55
    assert result.incident.confidence == "medium"

    model["thresholds"]["high_confidence_detections"] = 7
    result = correlate(findings, model, load_lab_config(root))
    assert result is not None
    assert result.incident.confidence == "high"


def test_independent_categories_come_from_risk_model(root):
    model = deepcopy(load_risk_model(root))
    model["detection_categories"] = {
        detection_id: "authentication" for detection_id in model["detection_weights"]
    }
    findings = [
        finding("DET001", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET008", "endpoint", 4),
    ]
    assert correlate(findings, model, load_lab_config(root)) is None


def test_incident_identity_and_title_come_from_lab_config(root):
    config = deepcopy(load_lab_config(root))
    config["scenario"].update(
        {
            "id": "TEST-SCENARIO-042",
            "incident_id": "INC-TEST-042",
            "name": "Configured synthetic investigation",
        }
    )
    findings = [
        finding("DET001", "authentication", 1),
        finding("DET004", "email", 2),
        finding("DET005", "cloud_application", 3),
        finding("DET008", "endpoint", 4),
    ]
    result = correlate(findings, load_risk_model(root), config)
    assert result is not None
    assert result.incident.incident_id == "INC-TEST-042"
    assert result.incident.title == "Configured synthetic investigation"

    del config["scenario"]["incident_id"]
    result = correlate(findings, load_risk_model(root), config)
    assert result is not None
    assert result.incident.incident_id == "INC-TEST-SCENARIO-042"
