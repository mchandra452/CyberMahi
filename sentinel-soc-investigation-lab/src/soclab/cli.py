"""Command-line interface for validation, analysis, regression, and reporting."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from soclab.config import (
    ConfigurationError,
    analysis_output_directory,
    load_lab_config,
    load_risk_model,
    load_yaml,
    repository_root,
)
from soclab.correlation import correlate
from soclab.detectors import run_detectors
from soclab.metrics import calculate_metrics, load_labels
from soclab.models import CorrelationResult, Event, Finding, Incident
from soclab.reporting import build_investigation_report, write_analysis_artifacts
from soclab.telemetry import TelemetryError, load_events
from soclab.validators import ValidationFailure, require_valid_repository


def _context(root: Path) -> dict[str, Any]:
    return {
        "baselines": json.loads(
            (root / "data" / "baselines" / "user-baselines.json").read_text(encoding="utf-8")
        )["users"],
        "known_benign": json.loads(
            (root / "data" / "baselines" / "known-benign-entities.json").read_text(encoding="utf-8")
        ),
        "safe_indicators": load_yaml(root / "config" / "safe-indicators.yml"),
    }


def _fusion_finding(correlation: CorrelationResult) -> Finding:
    incident = correlation.incident
    event_ids = tuple(
        sorted(
            {
                event_id
                for finding in correlation.contributing_findings
                for event_id in finding.event_ids
            }
        )
    )
    return Finding(
        finding_id="F-DET010-0001",
        detection_id="DET010",
        name="Identity-Led Incident Fusion",
        timestamp=incident.last_seen,
        severity=incident.severity,
        confidence=incident.confidence,
        category="incident_fusion",
        event_ids=event_ids,
        entities=incident.entities,
        evidence=(
            f"Correlated {len(incident.linked_detections)} unique detections "
            f"into risk score {incident.risk_score}"
        ),
    )


def _run_analysis(
    root: Path, write: bool = True
) -> tuple[list[Event], list[Finding], CorrelationResult, dict[str, Any], dict[str, Any]]:
    lab_config = load_lab_config(root)
    events = load_events(root)
    base_findings = run_detectors(events, _context(root))
    correlation = correlate(base_findings, load_risk_model(root), lab_config)
    if correlation is None:
        raise ValidationFailure("No incident met the configured fusion threshold")
    findings = [*base_findings, _fusion_finding(correlation)]
    metrics = calculate_metrics(findings, load_labels(root))
    if write:
        write_analysis_artifacts(root, events, findings, correlation, metrics, lab_config)
    return events, findings, correlation, metrics, lab_config


def execute_analysis(
    root: Path, write: bool = True
) -> tuple[list[Finding], Incident, dict[str, Any]]:
    """Run analysis while preserving the public tuple used by the regression tests."""

    _, findings, correlation, metrics, _ = _run_analysis(root, write)
    return findings, correlation.incident, metrics


def command_validate(root: Path) -> int:
    require_valid_repository(root)
    print("PASS: repository structure, metadata, telemetry, indicators, links, and safety checks")
    return 0


def command_analyze(root: Path) -> int:
    findings, incident, metrics = execute_analysis(root)
    print(
        f"PASS: wrote {len(findings)} findings and incident {incident.incident_id} "
        f"(risk {incident.risk_score})"
    )
    print(f"Synthetic metrics: {metrics['overall']}")
    return 0


def command_test_detections(root: Path) -> int:
    _, _, metrics = execute_analysis(root)
    overall = metrics["overall"]
    print(
        f"Synthetic regression: TP={overall['true_positives']} "
        f"FP={overall['false_positives']} FN={overall['false_negatives']} "
        f"precision={overall['precision']:.4f} recall={overall['recall']:.4f}"
    )
    if not metrics["passed"]:
        print(
            "FAIL: required finding missed or prohibited false positive triggered", file=sys.stderr
        )
        return 1
    print("PASS: all required cases detected; no prohibited benign controls triggered")
    return 0


def command_build_report(root: Path) -> int:
    events, _, correlation, metrics, lab_config = _run_analysis(root)
    path = build_investigation_report(root, events, correlation, metrics, lab_config)
    print(f"PASS: wrote {path.relative_to(root)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soclab", description="Offline Sentinel detection-engineering regression lab"
    )
    parser.add_argument(
        "command", choices=("validate", "analyze", "test-detections", "build-report")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = repository_root()
        return {
            "validate": command_validate,
            "analyze": command_analyze,
            "test-detections": command_test_detections,
            "build-report": command_build_report,
        }[args.command](root)
    except (
        ConfigurationError,
        TelemetryError,
        ValidationFailure,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def copy_latest_to_example(root: Path) -> None:
    """Replace the committed deterministic example with the latest verified output."""
    latest = analysis_output_directory(root, load_lab_config(root))
    example = root / "artifacts" / "example"
    if example.exists():
        shutil.rmtree(example)
    shutil.copytree(latest, example)


if __name__ == "__main__":
    raise SystemExit(main())
