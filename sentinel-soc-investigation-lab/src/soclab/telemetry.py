"""Load and normalize deterministic JSON Lines telemetry."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from soclab.models import Event

COMMON_FIELDS = {
    "EventId",
    "ScenarioId",
    "Timestamp",
    "SourceType",
    "User",
    "IPAddress",
    "DeviceId",
    "Application",
    "Action",
    "Result",
    "Location",
    "RiskLevel",
    "IsMalicious",
    "ExpectedDetections",
}
STRING_FIELDS = COMMON_FIELDS - {"IsMalicious", "ExpectedDetections"}
SOURCE_TYPES_BY_FILENAME = {
    "authentication.jsonl": "authentication",
    "cloud-app.jsonl": "cloud-app",
    "dns.jsonl": "dns",
    "email.jsonl": "email",
    "endpoint-process.jsonl": "endpoint-process",
    "incidents.jsonl": "incident",
}


class TelemetryError(ValueError):
    """Raised for malformed synthetic telemetry."""


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise TelemetryError(f"Invalid ISO-8601 timestamp: {value!r}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TelemetryError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TelemetryError(f"Timestamp must include a UTC offset: {value!r}")
    if parsed.utcoffset().total_seconds() != 0:
        raise TelemetryError(f"Timestamp must use UTC (Z or +00:00): {value!r}")
    return parsed


def event_from_record(record: dict[str, Any], source: Path, line_number: int) -> Event:
    missing = COMMON_FIELDS - record.keys()
    if missing:
        raise TelemetryError(f"{source}:{line_number} missing fields: {', '.join(sorted(missing))}")
    invalid_string_fields = sorted(
        field for field in STRING_FIELDS if not isinstance(record[field], str)
    )
    if invalid_string_fields:
        raise TelemetryError(
            f"{source}:{line_number} fields must be strings: "
            f"{', '.join(invalid_string_fields)}"
        )
    for field in ("EventId", "ScenarioId", "Timestamp", "SourceType"):
        if not record[field].strip():
            raise TelemetryError(f"{source}:{line_number} {field} must not be empty")
    if not isinstance(record["IsMalicious"], bool):
        raise TelemetryError(f"{source}:{line_number} IsMalicious must be a boolean")
    expected = record["ExpectedDetections"]
    if not isinstance(expected, list):
        raise TelemetryError(f"{source}:{line_number} ExpectedDetections must be a list")
    if any(not isinstance(item, str) or not item for item in expected):
        raise TelemetryError(
            f"{source}:{line_number} ExpectedDetections entries must be non-empty strings"
        )
    if len(expected) != len(set(expected)):
        raise TelemetryError(
            f"{source}:{line_number} ExpectedDetections must not contain duplicates"
        )
    expected_source_type = SOURCE_TYPES_BY_FILENAME.get(source.name)
    if expected_source_type and record["SourceType"] != expected_source_type:
        raise TelemetryError(
            f"{source}:{line_number} SourceType must be {expected_source_type!r}"
        )
    return Event(
        event_id=record["EventId"],
        scenario_id=record["ScenarioId"],
        timestamp=parse_timestamp(record["Timestamp"]),
        source_type=record["SourceType"],
        user=record["User"],
        ip_address=record["IPAddress"],
        device_id=record["DeviceId"],
        application=record["Application"],
        action=record["Action"],
        result=record["Result"],
        location=record["Location"],
        risk_level=record["RiskLevel"],
        is_malicious=record["IsMalicious"],
        expected_detections=tuple(expected),
        attributes={key: value for key, value in record.items() if key not in COMMON_FIELDS},
    )


def load_events(root: Path) -> list[Event]:
    telemetry_dir = root / "data" / "telemetry"
    events: list[Event] = []
    for path in sorted(telemetry_dir.glob("*.jsonl")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TelemetryError(f"{path}:{line_number} invalid JSON: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise TelemetryError(f"{path}:{line_number} must contain a JSON object")
            events.append(event_from_record(record, path, line_number))
    if not events:
        raise TelemetryError(f"No telemetry found under {telemetry_dir}")
    id_counts = Counter(event.event_id for event in events)
    duplicates = sorted(event_id for event_id, count in id_counts.items() if count > 1)
    if duplicates:
        raise TelemetryError(f"Duplicate EventId values: {', '.join(duplicates)}")
    return sorted(events, key=lambda event: (event.timestamp, event.event_id))
