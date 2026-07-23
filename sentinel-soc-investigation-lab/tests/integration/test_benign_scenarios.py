from __future__ import annotations

import json

from soclab.config import load_yaml
from soclab.detectors import run_detectors
from soclab.telemetry import load_events


def test_four_governed_benign_controls_do_not_alert(root):
    context = {
        "baselines": json.loads(
            (root / "data/baselines/user-baselines.json").read_text(encoding="utf-8")
        )["users"],
        "known_benign": json.loads(
            (root / "data/baselines/known-benign-entities.json").read_text(encoding="utf-8")
        ),
        "safe_indicators": load_yaml(root / "config/safe-indicators.yml"),
    }
    findings = run_detectors(load_events(root), context)
    triggered = {event_id for finding in findings for event_id in finding.event_ids}
    controls = {
        "E-AUTH-013",
        "E-AUTH-014",
        "E-CLOUD-020",
        "E-CLOUD-021",
    }
    assert triggered.isdisjoint(controls)
