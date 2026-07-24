from __future__ import annotations

from datetime import UTC, datetime

from soclab.cli import execute_analysis
from soclab.metrics import calculate_metrics
from soclab.models import Finding


def test_metrics_are_honest_and_pass(root):
    _, _, metrics = execute_analysis(root, write=False)
    overall = metrics["overall"]
    assert overall == {
        "true_positives": 10,
        "false_positives": 1,
        "false_negatives": 0,
        "precision": 0.9091,
        "recall": 1.0,
    }
    assert metrics["passed"] is True
    assert metrics["prohibited_false_positive_hits"] == []
    assert metrics["synthetic"] is True


def metric_finding(event_ids: tuple[str, ...]) -> Finding:
    return Finding(
        finding_id="F-DET001-TEST",
        detection_id="DET001",
        name="test",
        timestamp=datetime(2025, 2, 18, tzinfo=UTC),
        severity="medium",
        confidence="medium",
        category="authentication",
        event_ids=event_ids,
        entities={"Account": ("analyst1@northbridge.example",)},
        evidence="test",
    )


def test_required_case_requires_complete_event_set():
    labels = {
        "detections": {
            "DET001": {
                "required_cases": [{"event_ids": ["E-1", "E-2"]}],
                "benign_event_ids": [],
                "prohibited_false_positive_event_ids": [],
            }
        }
    }
    metrics = calculate_metrics([metric_finding(("E-1",))], labels)
    assert metrics["overall"]["true_positives"] == 0
    assert metrics["overall"]["false_negatives"] == 1


def test_false_positives_are_counted_as_complete_cases():
    labels = {
        "detections": {
            "DET001": {
                "required_cases": [],
                "benign_cases": [{"event_ids": ["B-1", "B-2"]}],
                "prohibited_false_positive_event_ids": [],
            }
        }
    }
    partial = calculate_metrics([metric_finding(("B-1",))], labels)
    complete = calculate_metrics([metric_finding(("B-1", "B-2"))], labels)
    assert partial["overall"]["false_positives"] == 0
    assert complete["overall"]["false_positives"] == 1
