"""Internal, source-independent data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    event_id: str
    scenario_id: str
    timestamp: datetime
    source_type: str
    user: str = ""
    ip_address: str = ""
    device_id: str = ""
    application: str = ""
    action: str = ""
    result: str = ""
    location: str = ""
    risk_level: str = "none"
    is_malicious: bool = False
    expected_detections: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    detection_id: str
    name: str
    timestamp: datetime
    severity: str
    confidence: str
    category: str
    event_ids: tuple[str, ...]
    entities: dict[str, tuple[str, ...]]
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "FindingId": self.finding_id,
            "DetectionId": self.detection_id,
            "Name": self.name,
            "Timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "Severity": self.severity,
            "Confidence": self.confidence,
            "Category": self.category,
            "EventIds": list(self.event_ids),
            "Entities": {key: list(values) for key, values in sorted(self.entities.items())},
            "Evidence": self.evidence,
        }


@dataclass(frozen=True)
class Incident:
    incident_id: str
    title: str
    risk_score: int
    confidence: str
    severity: str
    linked_detections: tuple[str, ...]
    entities: dict[str, tuple[str, ...]]
    first_seen: datetime
    last_seen: datetime
    recommended_action: str
    rationale: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "IncidentId": self.incident_id,
            "Title": self.title,
            "RiskScore": self.risk_score,
            "Confidence": self.confidence,
            "Severity": self.severity,
            "LinkedDetections": list(self.linked_detections),
            "Entities": {key: list(values) for key, values in sorted(self.entities.items())},
            "FirstSeen": self.first_seen.isoformat().replace("+00:00", "Z"),
            "LastSeen": self.last_seen.isoformat().replace("+00:00", "Z"),
            "RecommendedAnalystAction": self.recommended_action,
            "Rationale": list(self.rationale),
        }


@dataclass(frozen=True)
class CorrelationResult:
    """An incident and the exact base findings that contributed to it."""

    incident: Incident
    contributing_findings: tuple[Finding, ...]
