"""Identity-led, duplicate-aware incident correlation."""

from __future__ import annotations

from datetime import timedelta

from soclab.config import ConfigurationError
from soclab.models import CorrelationResult, Finding, Incident


def correlate(
    findings: list[Finding], model: dict, lab_config: dict
) -> CorrelationResult | None:
    if not findings:
        return None
    scenario = lab_config.get("scenario", {})
    primary_user = str(scenario.get("primary_user") or model.get("primary_entity", ""))
    controls = model.get("controls", {})
    require_entity_overlap = bool(controls.get("require_entity_overlap", True))
    duplicate_control = str(controls.get("duplicate_detection_contribution", "once"))
    if duplicate_control != "once":
        raise ConfigurationError("duplicate_detection_contribution must be 'once'")
    window_hours = float(
        controls.get(
            "correlation_window_hours",
            lab_config.get("analysis", {}).get("correlation_window_hours", 4),
        )
    )
    if window_hours <= 0:
        raise ConfigurationError("correlation_window_hours must be greater than zero")

    ordered = sorted(findings, key=lambda item: (item.timestamp, item.finding_id))
    anchors = [
        finding for finding in ordered if primary_user in finding.entities.get("Account", ())
    ]
    if not anchors:
        return None

    window = timedelta(hours=window_hours)
    thresholds = model.get("thresholds", {})
    min_categories = int(thresholds.get("minimum_independent_categories", 4))
    maximum_score = int(thresholds.get("maximum_score", 100))
    configured_categories = model.get("detection_categories", {})
    weights = model["detection_weights"]
    category_bonus_weight = int(model.get("category_bonus", 3))
    known_vpn_ips = set(controls.get("known_vpn_ips", []))
    vpn_adjustment = int(controls.get("known_vpn_confidence_adjustment", -20))

    def categories_for(selected: list[Finding]) -> set[str]:
        return {
            str(configured_categories.get(finding.detection_id, finding.category))
            for finding in selected
        }

    def score_for(selected: list[Finding], categories: set[str]) -> int:
        raw_score = sum(int(weights.get(finding.detection_id, 0)) for finding in selected)
        bonus = max(0, len(categories) - min_categories) * category_bonus_weight
        score = min(maximum_score, raw_score + bonus)
        observed_ips = {
            ip_value for finding in selected for ip_value in finding.entities.get("IP", ())
        }
        if observed_ips & known_vpn_ips:
            score = max(0, score + vpn_adjustment)
        return score

    candidates: list[tuple[tuple[int, int, int], list[Finding]]] = []
    for anchor in anchors:
        window_findings = [
            finding
            for finding in ordered
            if anchor.timestamp <= finding.timestamp <= anchor.timestamp + window
            and (
                not require_entity_overlap
                or primary_user in finding.entities.get("Account", ())
            )
        ]
        unique_by_detection: dict[str, Finding] = {}
        for finding in window_findings:
            unique_by_detection.setdefault(finding.detection_id, finding)
        unique = list(unique_by_detection.values())
        categories = categories_for(unique)
        if len(categories) < min_categories:
            continue
        rank = (score_for(unique, categories), len(categories), len(unique))
        candidates.append((rank, unique))
    if not candidates:
        return None
    # Rank by evidence strength; stable input ordering resolves ties toward the earliest window.
    _, unique = max(candidates, key=lambda item: item[0])
    categories = categories_for(unique)
    score = score_for(unique, categories)
    observed_ips = {ip_value for finding in unique for ip_value in finding.entities.get("IP", ())}
    vpn_overlap = observed_ips & known_vpn_ips
    high = int(thresholds.get("high", 70))
    medium = int(thresholds.get("medium", 40))
    severity = "high" if score >= high else "medium" if score >= medium else "low"
    high_confidence_categories = int(thresholds.get("high_confidence_categories", 6))
    high_confidence_detections = int(thresholds.get("high_confidence_detections", 7))
    confidence = (
        "high"
        if len(categories) >= high_confidence_categories
        and len(unique) >= high_confidence_detections
        else "medium"
    )
    if vpn_overlap:
        confidence = "medium" if confidence == "high" else "low"
    entities: dict[str, set[str]] = {}
    for finding in unique:
        for entity_type, values in finding.entities.items():
            entities.setdefault(entity_type, set()).update(values)
    ordered_detections = tuple(sorted(finding.detection_id for finding in unique))
    rationale_items = [
        f"{len(ordered_detections)} unique detections across "
        f"{len(categories)} independent signal categories",
        f"Signals share the primary account and fall within a {window_hours:g}-hour "
        "correlation window",
        "Duplicate detection IDs contribute weight once",
    ]
    if vpn_overlap:
        rationale_items.append("Known corporate VPN context reduces score and confidence")
    scenario_id = str(scenario.get("id") or "SCENARIO")
    incident_id = str(scenario.get("incident_id") or f"INC-{scenario_id}")
    incident = Incident(
        incident_id=incident_id,
        title=str(scenario.get("name") or "Identity-led incident investigation"),
        risk_score=score,
        confidence=confidence,
        severity=severity,
        linked_detections=ordered_detections,
        entities={key: tuple(sorted(values)) for key, values in sorted(entities.items())},
        first_seen=min(finding.timestamp for finding in unique),
        last_seen=max(finding.timestamp for finding in unique),
        recommended_action=(
            "Escalate for human-approved identity containment, consent review, "
            "mailbox rule removal, and endpoint scoping."
        ),
        rationale=tuple(rationale_items),
    )
    return CorrelationResult(
        incident=incident,
        contributing_findings=tuple(unique),
    )
