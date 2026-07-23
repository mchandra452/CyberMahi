"""Deterministic evidence and investigation report generation."""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Any

from soclab.config import analysis_output_directory, load_yaml
from soclab.models import CorrelationResult, Event, Finding, Incident


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _iso_timestamp(event_time: Any) -> str:
    return event_time.isoformat().replace("+00:00", "Z")


def _clean_output_directory(output: Path) -> None:
    """Remove stale generated files from the already validated output directory."""

    output.mkdir(parents=True, exist_ok=True)
    for path in sorted(output.iterdir()):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def _finding_payload(
    finding: Finding, contributing_ids: set[str], synthetic: bool
) -> dict[str, Any]:
    if finding.detection_id == "DET010":
        scope = "incident_fusion"
    elif finding.finding_id in contributing_ids:
        scope = "correlated_incident_evidence"
    else:
        scope = "standalone_detection_regression"
    return {**finding.to_dict(), "Synthetic": synthetic, "Scope": scope}


def _event_detection_map(findings: tuple[Finding, ...]) -> dict[str, tuple[str, ...]]:
    mapped: dict[str, set[str]] = {}
    for finding in findings:
        for event_id in finding.event_ids:
            mapped.setdefault(event_id, set()).add(finding.detection_id)
    return {event_id: tuple(sorted(detections)) for event_id, detections in mapped.items()}


def _contributing_events(
    events: list[Event], findings: tuple[Finding, ...]
) -> tuple[list[Event], dict[str, tuple[str, ...]]]:
    detection_map = _event_detection_map(findings)
    selected = sorted(
        (event for event in events if event.event_id in detection_map),
        key=lambda event: (event.timestamp, event.event_id),
    )
    return selected, detection_map


def _verdict(incident: Incident) -> str:
    if incident.severity == "high" and incident.confidence == "high":
        return "Escalate for priority human review as a suspected multi-stage identity incident."
    if incident.severity == "high" or incident.confidence == "high":
        return "Escalate for human review because the correlated evidence warrants priority triage."
    return "Continue scoped investigation before deciding whether containment is justified."


def write_analysis_artifacts(
    root: Path,
    events: list[Event],
    findings: list[Finding],
    correlation: CorrelationResult,
    metrics: dict[str, Any],
    lab_config: dict[str, Any],
) -> Path:
    output = analysis_output_directory(root, lab_config)
    _clean_output_directory(output)
    incident = correlation.incident
    synthetic = bool(lab_config.get("scenario", {}).get("synthetic", True))
    contributing_ids = {finding.finding_id for finding in correlation.contributing_findings}
    finding_payloads = [
        _finding_payload(finding, contributing_ids, synthetic) for finding in findings
    ]
    incident_payload = {
        **incident.to_dict(),
        "Synthetic": synthetic,
        "Scope": "offline_incident_fusion",
    }
    metric_payload = {
        **metrics,
        "synthetic": synthetic,
        "scope": metrics.get(
            "scope",
            "Synthetic regression fixtures; not production detection performance.",
        ),
    }
    _write_json(output / "findings.json", finding_payloads)
    _write_json(output / "incident.json", incident_payload)
    _write_json(output / "metrics.json", metric_payload)

    selected_events, detection_map = _contributing_events(
        events, correlation.contributing_findings
    )
    with (output / "timeline.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "Timestamp",
                "EventId",
                "ScenarioId",
                "SourceType",
                "User",
                "IPAddress",
                "DeviceId",
                "Application",
                "Action",
                "Result",
                "Detections",
                "Synthetic",
                "Scope",
            ]
        )
        for event in selected_events:
            writer.writerow(
                [
                    _iso_timestamp(event.timestamp),
                    event.event_id,
                    event.scenario_id,
                    event.source_type,
                    event.user,
                    event.ip_address,
                    event.device_id,
                    event.application,
                    event.action,
                    event.result,
                    ";".join(detection_map[event.event_id]),
                    str(synthetic).lower(),
                    "correlated_incident_evidence",
                ]
            )

    overall = metrics["overall"]
    project = lab_config.get("project", {})
    scenario = lab_config.get("scenario", {})
    summary = f"""# Offline analysis summary

## Scope

- Organisation: {project.get("organisation", "Unspecified")}
- Scenario: `{scenario.get("id", "Unspecified")}` - {incident.title}
- Synthetic telemetry: **{str(synthetic).lower()}**
- Runtime: deterministic offline Python equivalents; KQL was not executed

## Result

- Incident: `{incident.incident_id}` - {incident.title}
- Risk score: **{incident.risk_score}/100**
  ({incident.severity} severity, {incident.confidence} confidence)
- Linked detections: {", ".join(incident.linked_detections)}
- Evidence window: {_iso_timestamp(incident.first_seen)}
  to {_iso_timestamp(incident.last_seen)}
- Synthetic regression metrics: TP {overall["true_positives"]},
  FP {overall["false_positives"]}, FN {overall["false_negatives"]},
  precision {overall["precision"]:.4f}, recall {overall["recall"]:.4f}

## Verdict

{_verdict(incident)} Human validation is required before containment.
{incident.recommended_action}

This result is generated from synthetic evidence and is not proof that the KQL executed
in Microsoft Sentinel.
"""
    (output / "analysis-summary.md").write_text(summary, encoding="utf-8")
    return output


def _markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _load_rule_metadata(root: Path, detection_ids: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for detection_id in detection_ids:
        metadata[detection_id] = load_yaml(root / "detections" / "rules" / f"{detection_id}.yml")
    return metadata


def _unique_metadata_values(
    metadata: dict[str, dict[str, Any]], key: str
) -> list[str]:
    values: list[str] = []
    for detection_id in sorted(metadata):
        raw_values = metadata[detection_id].get(key, [])
        if isinstance(raw_values, str):
            raw_values = [raw_values]
        for value in raw_values:
            text = str(value)
            if text and text not in values:
                values.append(text)
    return values


def _bullet_list(values: list[str], fallback: str) -> str:
    return "\n".join(f"- {_markdown(value)}" for value in values) if values else f"- {fallback}"


def _hypothesis(incident: Incident, findings: tuple[Finding, ...]) -> str:
    categories = sorted({finding.category.replace("_", " ") for finding in findings})
    category_text = ", ".join(categories)
    if incident.confidence == "high" and len(categories) >= 6:
        return (
            "The leading hypothesis is a multi-stage identity-led incident because independent "
            f"evidence spans {category_text}. Correlation supports investigation, but does not "
            "establish malicious intent for every event."
        )
    if len(categories) >= 4:
        return (
            f"The evidence spans {category_text} and supports an identity-led incident "
            "hypothesis. Additional enrichment is needed before attributing intent."
        )
    return (
        f"The evidence currently spans {category_text}. Treat the correlation as a triage lead "
        "until another independent source corroborates it."
    )


def build_investigation_report(
    root: Path,
    events: list[Event],
    correlation: CorrelationResult,
    metrics: dict[str, Any],
    lab_config: dict[str, Any],
) -> Path:
    output = analysis_output_directory(root, lab_config)
    output.mkdir(parents=True, exist_ok=True)
    incident = correlation.incident
    findings = correlation.contributing_findings
    metadata = _load_rule_metadata(root, incident.linked_detections)
    project = lab_config.get("project", {})
    scenario = lab_config.get("scenario", {})
    synthetic = bool(scenario.get("synthetic", True))
    overall = metrics["overall"]

    entity_rows = "\n".join(
        f"| {_markdown(entity_type)} | {_markdown(', '.join(values))} |"
        for entity_type, values in sorted(incident.entities.items())
    )
    evidence_rows = "\n".join(
        f"| {finding.detection_id} | {_markdown(finding.name)} | {finding.severity} | "
        f"{finding.confidence} | {_markdown(', '.join(finding.event_ids))} | "
        f"{_markdown(finding.evidence)} |"
        for finding in findings
    )
    selected_events, detection_map = _contributing_events(events, findings)
    timeline_rows = "\n".join(
        f"| {_iso_timestamp(event.timestamp)} | {event.event_id} | {event.source_type} | "
        f"{_markdown(event.user or '-')} | {_markdown(event.action or '-')} | "
        f"{_markdown(event.result or '-')} | {', '.join(detection_map[event.event_id])} |"
        for event in selected_events
    )

    attack_rows: list[str] = []
    for detection_id in sorted(metadata):
        for mapping in metadata[detection_id].get("attack", []):
            technique = mapping.get("technique", "Not mapped")
            status = mapping.get("status", mapping.get("mapping_status", "Unspecified"))
            evidence = mapping.get("evidence", mapping.get("rationale", "No evidence statement"))
            attack_rows.append(
                f"| {detection_id} | {_markdown(technique)} | "
                f"{_markdown(status)} | "
                f"{_markdown(mapping.get('confidence', 'Unspecified'))} | "
                f"{_markdown(evidence)} |"
            )
    attack_content = "\n".join(attack_rows) or (
        "No evidence-based ATT&CK technique is asserted by the linked rule metadata."
    )
    if attack_rows:
        attack_content = (
            "| Detection | Technique | Status | Confidence | Evidence |\n"
            "|---|---|---|---|---|\n" + attack_content
        )

    false_positives = _unique_metadata_values(metadata, "false_positives")
    response_actions = _unique_metadata_values(metadata, "response_actions")
    detection_gaps = _unique_metadata_values(metadata, "limitations")
    report = f"""# Investigation report: {incident.incident_id}

## Executive summary

Deterministic synthetic telemetry for {project.get("organisation", "the configured organisation")}
produced {len(findings)} contributing findings across
{len({finding.category for finding in findings})} signal categories. The offline incident
scored **{incident.risk_score}/100** with **{incident.confidence} confidence**. This result
supports human review; it is not a claim that KQL executed in Microsoft Sentinel.

## Scope and provenance

- Organisation: {project.get("organisation", "Unspecified")}
- Scenario: `{scenario.get("id", "Unspecified")}` - {incident.title}
- Synthetic: **{str(synthetic).lower()}**
- Evidence scope: only findings selected by configured entity, time-window, and duplicate controls
- Regression metrics: TP {overall["true_positives"]}, FP {overall["false_positives"]},
  FN {overall["false_negatives"]}, precision {overall["precision"]:.4f},
  recall {overall["recall"]:.4f}

## Incident classification

- Classification: suspected identity-led incident requiring validation
- Severity: {incident.severity}
- Confidence: {incident.confidence}
- Evidence window: `{_iso_timestamp(incident.first_seen)}` to
  `{_iso_timestamp(incident.last_seen)}`

## Confidence assessment

{_bullet_list(list(incident.rationale), "No correlation rationale was supplied.")}

## Affected entities

| Entity type | Values |
|---|---|
{entity_rows}

## Evidence summary

| Detection | Name | Severity | Confidence | Event IDs | Evidence |
|---|---|---|---|---|---|
{evidence_rows}

## Chronological timeline

| Timestamp | Event ID | Source | User | Action | Result | Detections |
|---|---|---|---|---|---|---|
{timeline_rows}

## Linked detections

{", ".join(incident.linked_detections)}

## Analyst hypotheses

{_hypothesis(incident, findings)}

## Alternative benign explanations

The linked rule metadata identifies these explanations for validation:

{_bullet_list(false_positives, "No rule-specific benign explanation was supplied.")}

## ATT&CK mapping

{attack_content}

Mappings above come from the linked YAML rule metadata and are included only where that
metadata supplies an evidence statement.

## Containment recommendations

- Primary recommendation: {_markdown(incident.recommended_action)}
{_bullet_list(response_actions, "Follow the organisation's approved incident procedure.")}

## Eradication and recovery recommendations

Remove only configuration confirmed as unauthorised, validate identity recovery and MFA,
restore approved access, and monitor the scoped entities for a documented observation period.

## Detection gaps

{_bullet_list(detection_gaps, "No rule-specific limitation was supplied.")}

## Final verdict

**{_verdict(incident)}** Human validation remains mandatory. The configured analyst action is:
{_markdown(incident.recommended_action)}

## Limitations

This report is generated from synthetic telemetry. Python equivalents test detection intent
but do not execute KQL. Live connector schemas, licences, ingestion, retention, baselines,
rule scheduling, and thresholds require tenant-specific validation and tuning.
"""
    path = output / "investigation-report.md"
    path.write_text(report, encoding="utf-8")
    return path
