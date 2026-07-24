"""Synthetic fixture regression metrics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soclab.models import Finding


def load_labels(root: Path) -> dict[str, Any]:
    return json.loads(
        (root / "data" / "labels" / "expected-findings.json").read_text(encoding="utf-8")
    )


def _case_event_sets(
    expected: dict[str, Any], cases_key: str, event_ids_key: str
) -> list[set[str]]:
    """Return case event sets while supporting legacy singleton benign labels."""

    if cases_key in expected:
        return [
            {str(event_id) for event_id in case.get("event_ids", [])}
            for case in expected.get(cases_key, [])
            if case.get("event_ids")
        ]
    return [{str(event_id)} for event_id in expected.get(event_ids_key, [])]


def calculate_metrics(findings: list[Finding], labels: dict[str, Any]) -> dict[str, Any]:
    by_detection: dict[str, list[Finding]] = {}
    for finding in findings:
        by_detection.setdefault(finding.detection_id, []).append(finding)
    per_detection: dict[str, Any] = {}
    total_tp = total_fp = total_fn = 0
    prohibited_hits: list[str] = []
    for detection_id, expected in sorted(labels["detections"].items()):
        actual_event_sets = [set(item.event_ids) for item in by_detection.get(detection_id, [])]
        required_cases = _case_event_sets(expected, "required_cases", "required_event_ids")
        benign_cases = _case_event_sets(expected, "benign_cases", "benign_event_ids")
        prohibited_ids = set(expected.get("prohibited_false_positive_event_ids", []))
        # A required case is detected only when one finding contains its complete evidence set.
        tp = sum(any(case <= actual for actual in actual_event_sets) for case in required_cases)
        fn = len(required_cases) - tp
        # False positives use the same case-level semantics as true positives.
        fp = sum(any(case <= actual for actual in actual_event_sets) for case in benign_cases)
        prohibited = sorted(
            {event_id for actual in actual_event_sets for event_id in actual & prohibited_ids}
        )
        prohibited_hits.extend(f"{detection_id}:{event_id}" for event_id in prohibited)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_detection[detection_id] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn
    overall_precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0.0
    return {
        "synthetic": True,
        "scope": (
            "Synthetic regression fixtures only; not a claim of production detection performance."
        ),
        "overall": {
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision": round(overall_precision, 4),
            "recall": round(overall_recall, 4),
        },
        "per_detection": per_detection,
        "prohibited_false_positive_hits": prohibited_hits,
        "passed": total_fn == 0 and not prohibited_hits,
    }
