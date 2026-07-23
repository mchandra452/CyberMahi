"""Repository, telemetry, indicator, metadata, and documentation validation."""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from ipaddress import IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from soclab.config import (
    ConfigurationError,
    load_lab_config,
    load_risk_model,
    load_yaml,
)
from soclab.models import Event
from soclab.telemetry import SOURCE_TYPES_BY_FILENAME, TelemetryError, load_events

DETECTION_IDS = frozenset(f"DET{number:03d}" for number in range(1, 11))
WEIGHTED_DETECTION_IDS = DETECTION_IDS - {"DET010"}
REQUIRED_RULE_FIELDS = {
    "id",
    "name",
    "status",
    "description",
    "author",
    "date_created",
    "date_modified",
    "severity",
    "severity_rationale",
    "confidence",
    "confidence_rationale",
    "data_sources",
    "query_file",
    "query_frequency",
    "query_period",
    "trigger_operator",
    "trigger_threshold",
    "entity_mappings",
    "attack",
    "false_positives",
    "tuning",
    "investigation_steps",
    "response_actions",
    "test_cases",
    "limitations",
}
REQUIRED_DOCS = {
    "architecture.md",
    "attack-path.md",
    "detection-catalog.md",
    "detection-engineering-methodology.md",
    "incident-response-runbook.md",
    "investigation-report.md",
    "threat-hunting-notebook.md",
    "false-positive-analysis.md",
    "coverage-and-gaps.md",
    "engineering-decisions.md",
    "sentinel-deployment.md",
    "troubleshooting.md",
    "project-status.md",
    "automation-design.md",
}
REQUIRED_ROOT = {
    ".gitattributes",
    "README.md",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "Makefile",
    "SECURITY.md",
    "pyproject.toml",
    ".gitignore",
    "config/detection-risk-model.yml",
    "config/lab.yml",
    "config/safe-indicators.yml",
    "data/baselines/known-benign-entities.json",
    "data/baselines/user-baselines.json",
    "data/labels/expected-findings.json",
    "detections/schemas/detection-rule.schema.json",
    "scripts/run_offline.ps1",
    "scripts/run_offline.sh",
}
REQUIRED_TELEMETRY_FILES = frozenset(SOURCE_TYPES_BY_FILENAME)
PROHIBITED_DOC_TERMS = (
    "linkedin post",
    "cv bullet",
    "recruiter pitch",
    "feedback is welcome",
    "college project",
)
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DETECTION_ID_DECLARATION_RE = re.compile(
    r'^\s*let\s+DetectionId\s*=\s*"([^"]+)"\s*;', re.MULTILINE
)
MARKDOWN_LINK_RE = re.compile(
    r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+['\"][^)]*['\"])?\s*\)"
)
IPV4_LITERAL_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
)
HOSTNAME_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
QUOTED_VALUE_RE = re.compile(r"['\"]([^'\"]+)['\"]")
SECRET_PATTERNS = (
    re.compile(
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9_\-/+=]{20,}"
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
RESERVED_DOMAIN_SUFFIXES = frozenset({".example", ".test", ".invalid"})
RFC_DOCUMENTATION_NETWORKS = tuple(
    ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
MARKDOWN_SCAN_EXCLUSIONS = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "venv"}
)


class ValidationFailure(ValueError):
    """Raised when repository acceptance checks fail."""


def _is_within(path: Path, parent: Path) -> bool:
    resolved = path.resolve()
    expected_parent = parent.resolve()
    return resolved == expected_parent or expected_parent in resolved.parents


def _validate_structure(root: Path, errors: list[str]) -> None:
    for relative in sorted(REQUIRED_ROOT):
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")
    for doc in sorted(REQUIRED_DOCS):
        if not (root / "docs" / doc).is_file():
            errors.append(f"missing required document: docs/{doc}")
    for directory in (
        "config",
        "data/telemetry",
        "data/baselines",
        "data/labels",
        "detections/kql",
        "detections/rules",
        "detections/schemas",
        "src/soclab",
        "tests/unit",
        "tests/integration",
        "tests/fixtures/minimal-telemetry",
        "scripts",
        "artifacts",
    ):
        if not (root / directory).is_dir():
            errors.append(f"missing required directory: {directory}")

    monorepo_workflow = root.parent / ".github" / "workflows" / "sentinel-soclab-ci.yml"
    if (root.parent / ".git").exists():
        if not monorepo_workflow.is_file():
            errors.append(
                "missing required monorepo workflow: .github/workflows/sentinel-soclab-ci.yml"
            )
    else:
        standalone_workflows = (
            root / ".github" / "workflows" / "ci.yml",
            root / ".github" / "workflows" / "sentinel-soclab-ci.yml",
        )
        if not any(path.is_file() for path in standalone_workflows):
            errors.append(
                "missing required standalone workflow: .github/workflows/ci.yml "
                "or .github/workflows/sentinel-soclab-ci.yml"
            )


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_exact_keys(
    actual: set[str], expected: frozenset[str], label: str, errors: list[str]
) -> None:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        errors.append(f"{label} coverage mismatch: missing={missing}, extra={extra}")


def _load_safe_policy(
    root: Path, errors: list[str]
) -> tuple[tuple[str, ...], tuple[IPv4Network, ...]]:
    try:
        policy = load_yaml(root / "config" / "safe-indicators.yml")
    except ConfigurationError as exc:
        errors.append(str(exc))
        return (), ()

    if not isinstance(policy.get("policy"), str) or not policy["policy"].strip():
        errors.append("config/safe-indicators.yml policy must be a non-empty string")

    suffix_values = policy.get("allowed_domain_suffixes")
    suffixes: list[str] = []
    if not isinstance(suffix_values, list) or not suffix_values:
        errors.append("config/safe-indicators.yml requires allowed_domain_suffixes")
    else:
        for value in suffix_values:
            if not isinstance(value, str) or value not in RESERVED_DOMAIN_SUFFIXES:
                errors.append(
                    "config/safe-indicators.yml contains a non-reserved domain suffix: "
                    f"{value!r}"
                )
            elif value not in suffixes:
                suffixes.append(value)

    range_values = policy.get("allowed_ipv4_ranges")
    networks: list[IPv4Network] = []
    if not isinstance(range_values, list) or not range_values:
        errors.append("config/safe-indicators.yml requires allowed_ipv4_ranges")
    else:
        for value in range_values:
            try:
                parsed = ip_network(value, strict=True) if isinstance(value, str) else None
            except ValueError:
                parsed = None
            if not isinstance(parsed, IPv4Network):
                errors.append(
                    f"config/safe-indicators.yml has invalid IPv4 range: {value!r}"
                )
                continue
            if not any(
                parsed.subnet_of(documentation)
                for documentation in RFC_DOCUMENTATION_NETWORKS
            ):
                errors.append(
                    "config/safe-indicators.yml range is outside RFC documentation space: "
                    f"{value}"
                )
                continue
            if parsed not in networks:
                networks.append(parsed)

    suspicious_domains = policy.get("suspicious_domains")
    if not isinstance(suspicious_domains, list) or not suspicious_domains:
        errors.append("config/safe-indicators.yml requires suspicious_domains")
    else:
        for value in suspicious_domains:
            if not isinstance(value, str) or not _is_safe_domain(value, tuple(suffixes)):
                errors.append(
                    "config/safe-indicators.yml has unsafe suspicious domain: " f"{value!r}"
                )

    sample_hashes = policy.get("sample_hashes")
    if not isinstance(sample_hashes, list) or not sample_hashes:
        errors.append("config/safe-indicators.yml requires sample_hashes")
    else:
        for value in sample_hashes:
            if (
                not isinstance(value, str)
                or "SAMPLE" not in value.upper()
                or "NOT-A-REAL" not in value.upper()
            ):
                errors.append(
                    "config/safe-indicators.yml sample hashes must be explicitly marked as samples"
                )

    return tuple(suffixes), tuple(networks)


def _validate_lab_controls(root: Path, errors: list[str]) -> dict[str, Any]:
    try:
        lab = load_lab_config(root)
    except ConfigurationError as exc:
        errors.append(str(exc))
        return {}

    project = lab.get("project")
    if not isinstance(project, dict) or project.get("defensive_only") is not True:
        errors.append("config/lab.yml project.defensive_only must be true")
    scenario = lab.get("scenario")
    if not isinstance(scenario, dict):
        errors.append("config/lab.yml scenario must be a mapping")
    else:
        if scenario.get("synthetic") is not True:
            errors.append("config/lab.yml scenario.synthetic must be true")
        for key in ("id", "incident_id", "name", "primary_user"):
            if not isinstance(scenario.get(key), str) or not scenario[key].strip():
                errors.append(f"config/lab.yml scenario.{key} must be a non-empty string")

    telemetry = lab.get("telemetry")
    if not isinstance(telemetry, dict):
        errors.append("config/lab.yml telemetry must be a mapping")
    else:
        if telemetry.get("format") != "jsonl":
            errors.append("config/lab.yml telemetry.format must be jsonl")
        minimum_events = telemetry.get("minimum_events")
        if (
            not isinstance(minimum_events, int)
            or isinstance(minimum_events, bool)
            or minimum_events < 60
        ):
            errors.append("config/lab.yml telemetry.minimum_events must be an integer >= 60")
        if telemetry.get("timezone") != "UTC":
            errors.append("config/lab.yml telemetry.timezone must be UTC")

    analysis = lab.get("analysis")
    if not isinstance(analysis, dict):
        errors.append("config/lab.yml analysis must be a mapping")
    else:
        window = analysis.get("correlation_window_hours")
        if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
            errors.append(
                "config/lab.yml analysis.correlation_window_hours must be a positive integer"
            )
        if analysis.get("deterministic") is not True:
            errors.append("config/lab.yml analysis.deterministic must be true")
        output = analysis.get("output_directory")
        if not isinstance(output, str) or not output.strip():
            errors.append("config/lab.yml analysis.output_directory must be a relative path")
        elif Path(output).is_absolute() or not _is_within(root / output, root):
            errors.append("config/lab.yml analysis.output_directory must remain inside the project")
    return lab


def _validate_risk_controls(
    root: Path, lab: dict[str, Any], networks: tuple[IPv4Network, ...], errors: list[str]
) -> dict[str, Any]:
    try:
        model = load_risk_model(root)
    except ConfigurationError as exc:
        errors.append(str(exc))
        return {}

    if not isinstance(model.get("version"), int) or isinstance(model.get("version"), bool):
        errors.append("config/detection-risk-model.yml version must be an integer")
    if not isinstance(model.get("primary_entity"), str) or not model["primary_entity"].strip():
        errors.append("config/detection-risk-model.yml primary_entity must be a non-empty string")
    scenario = lab.get("scenario")
    lab_primary_user = scenario.get("primary_user") if isinstance(scenario, dict) else None
    if lab_primary_user is not None and model.get("primary_entity") != lab_primary_user:
        errors.append("risk-model primary_entity must match config/lab.yml scenario.primary_user")
    if not isinstance(model.get("description"), str) or not model["description"].strip():
        errors.append("config/detection-risk-model.yml description must be a non-empty string")

    weights = model.get("detection_weights")
    if isinstance(weights, dict):
        _validate_exact_keys(
            {str(key) for key in weights},
            WEIGHTED_DETECTION_IDS,
            "risk-model detection_weights",
            errors,
        )
        for detection_id, weight in weights.items():
            if not _is_number(weight) or weight <= 0:
                errors.append(
                    f"risk-model weight for {detection_id} must be a positive number"
                )
    else:
        errors.append("config/detection-risk-model.yml requires detection_weights")

    categories = model.get("detection_categories")
    distinct_categories: set[str] = set()
    if isinstance(categories, dict):
        _validate_exact_keys(
            {str(key) for key in categories},
            WEIGHTED_DETECTION_IDS,
            "risk-model detection_categories",
            errors,
        )
        for detection_id, category in categories.items():
            if not isinstance(category, str) or not category.strip():
                errors.append(
                    f"risk-model category for {detection_id} must be a non-empty string"
                )
            else:
                distinct_categories.add(category)
    else:
        errors.append("risk-model detection_categories must be a mapping")

    category_bonus = model.get("category_bonus")
    if (
        not isinstance(category_bonus, int)
        or isinstance(category_bonus, bool)
        or category_bonus < 0
    ):
        errors.append("risk-model category_bonus must be a non-negative integer")

    thresholds = model.get("thresholds")
    if not isinstance(thresholds, dict):
        errors.append("risk-model thresholds must be a mapping")
    else:
        category_count = thresholds.get("minimum_independent_categories")
        if (
            not isinstance(category_count, int)
            or isinstance(category_count, bool)
            or category_count < 2
        ):
            errors.append("risk-model minimum_independent_categories must be an integer >= 2")
        elif distinct_categories and category_count > len(distinct_categories):
            errors.append(
                "risk-model minimum_independent_categories exceeds configured categories"
            )
        high_confidence_categories = thresholds.get("high_confidence_categories")
        if (
            not isinstance(high_confidence_categories, int)
            or isinstance(high_confidence_categories, bool)
            or high_confidence_categories < 2
        ):
            errors.append("risk-model high_confidence_categories must be an integer >= 2")
        elif (
            isinstance(category_count, int)
            and not isinstance(category_count, bool)
            and high_confidence_categories < category_count
        ):
            errors.append(
                "risk-model high_confidence_categories must be >= "
                "minimum_independent_categories"
            )
        elif distinct_categories and high_confidence_categories > len(distinct_categories):
            errors.append("risk-model high_confidence_categories exceeds configured categories")
        high_confidence_detections = thresholds.get("high_confidence_detections")
        if (
            not isinstance(high_confidence_detections, int)
            or isinstance(high_confidence_detections, bool)
            or not 2 <= high_confidence_detections <= len(WEIGHTED_DETECTION_IDS)
        ):
            errors.append(
                "risk-model high_confidence_detections must be between 2 and the number "
                "of weighted detections"
            )
        elif (
            isinstance(high_confidence_categories, int)
            and not isinstance(high_confidence_categories, bool)
            and high_confidence_detections < high_confidence_categories
        ):
            errors.append(
                "risk-model high_confidence_detections must be >= high_confidence_categories"
            )
        medium = thresholds.get("medium")
        high = thresholds.get("high")
        maximum_score = thresholds.get("maximum_score")
        if not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (medium, high, maximum_score)
        ) or not 0 < medium < high <= maximum_score:
            errors.append(
                "risk-model score thresholds must be integers satisfying "
                "0 < medium < high <= maximum_score"
            )

    controls = model.get("controls")
    if not isinstance(controls, dict):
        errors.append("risk-model controls must be a mapping")
    else:
        if controls.get("duplicate_detection_contribution") != "once":
            errors.append("risk-model duplicate_detection_contribution must be once")
        if controls.get("require_entity_overlap") is not True:
            errors.append("risk-model require_entity_overlap must be true")
        adjustment = controls.get("known_vpn_confidence_adjustment")
        if not _is_number(adjustment) or adjustment > 0:
            errors.append("risk-model known_vpn_confidence_adjustment must be <= 0")
        control_window = controls.get("correlation_window_hours")
        if (
            not isinstance(control_window, int)
            or isinstance(control_window, bool)
            or control_window <= 0
        ):
            errors.append("risk-model correlation_window_hours must be a positive integer")
        lab_window = (
            lab.get("analysis", {}).get("correlation_window_hours")
            if isinstance(lab.get("analysis"), dict)
            else None
        )
        if lab_window is not None and control_window != lab_window:
            errors.append("risk-model and lab correlation_window_hours must match")
        known_vpn_ips = controls.get("known_vpn_ips")
        if not isinstance(known_vpn_ips, list) or not known_vpn_ips:
            errors.append("risk-model known_vpn_ips must be a non-empty list")
        else:
            for value in known_vpn_ips:
                if not isinstance(value, str) or not _is_safe_ip(value, networks):
                    errors.append(f"risk-model known_vpn_ips contains unsafe IP: {value!r}")
    return model


def _validate_configuration(
    root: Path, errors: list[str]
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...], tuple[IPv4Network, ...]]:
    suffixes, networks = _load_safe_policy(root, errors)
    lab = _validate_lab_controls(root, errors)
    risk_model = _validate_risk_controls(root, lab, networks, errors)
    for path in sorted((root / "config").glob("*.yml")):
        _validate_text_indicators(
            path, path.read_text(encoding="utf-8"), suffixes, networks, errors
        )
    for path in sorted((root / "data" / "baselines").glob("*.json")):
        _validate_text_indicators(
            path, path.read_text(encoding="utf-8"), suffixes, networks, errors
        )
    return lab, risk_model, suffixes, networks


def _json_default(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _normalize_yaml_for_json(value: dict[str, Any]) -> dict[str, Any]:
    """Round-trip YAML values through JSON so schema validation sees JSON-compatible types."""

    normalized = json.loads(json.dumps(value, default=_json_default))
    if not isinstance(normalized, dict):  # Defensive; load_yaml already guarantees a mapping.
        raise TypeError("normalized YAML document must be an object")
    return normalized


def _load_rule_schema(root: Path, errors: list[str]) -> dict[str, Any] | None:
    path = root / "detections" / "schemas" / "detection-rule.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        errors.append(f"unable to read {path.relative_to(root)}: {exc}")
        return None
    except json.JSONDecodeError as exc:
        errors.append(f"invalid detection rule schema JSON: {exc.msg}")
        return None
    if not isinstance(schema, dict):
        errors.append("detection rule schema must be a JSON object")
        return None
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        errors.append(f"invalid Draft 2020-12 detection rule schema: {exc.message}")
        return None
    return schema


def _schema_error_path(error: Any) -> str:
    components = [str(component) for component in error.absolute_path]
    return "$" if not components else "$." + ".".join(components)


def _attack_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        str(item["technique"])
        for item in value
        if isinstance(item, dict) and "technique" in item
    ]


def _validate_rule_test_events(
    rule: dict[str, Any], path: Path, root: Path, events: dict[str, Event], errors: list[str]
) -> None:
    detection_id = str(rule.get("id", ""))
    tests = rule.get("test_cases")
    if not isinstance(tests, list):
        return
    for index, test in enumerate(tests):
        if not isinstance(test, dict):
            continue
        event_ids = test.get("event_ids")
        if not isinstance(event_ids, list):
            continue
        missing = sorted(
            event_id
            for event_id in event_ids
            if isinstance(event_id, str) and event_id not in events
        )
        if missing:
            errors.append(
                f"{path.relative_to(root)} test_cases[{index}] references missing events: {missing}"
            )
        resolved = [events[event_id] for event_id in event_ids if event_id in events]
        kind = test.get("type")
        expected_malicious = kind == "malicious"
        mismatched = sorted(
            event.event_id for event in resolved if event.is_malicious is not expected_malicious
        )
        if kind in {"malicious", "benign"} and mismatched:
            errors.append(
                f"{path.relative_to(root)} test_cases[{index}] type {kind!r} conflicts with "
                f"event labels: {mismatched}"
            )
        if detection_id != "DET010" and expected_malicious and resolved and not any(
            detection_id in event.expected_detections for event in resolved
        ):
            errors.append(
                f"{path.relative_to(root)} malicious test_cases[{index}] has no event labelled "
                f"for {detection_id}"
            )


def _validate_rules(
    root: Path, events: dict[str, Event], suffixes: tuple[str, ...],
    networks: tuple[IPv4Network, ...], errors: list[str]
) -> None:
    rule_paths = sorted((root / "detections" / "rules").glob("*.yml"))
    expected_stems = DETECTION_IDS
    _validate_exact_keys(
        {path.stem for path in rule_paths}, expected_stems, "detection rule files", errors
    )
    schema = _load_rule_schema(root, errors)
    schema_validator = (
        Draft202012Validator(schema, format_checker=FormatChecker()) if schema else None
    )
    ids: list[str] = []
    referenced_queries: set[str] = set()
    for path in rule_paths:
        try:
            loaded_rule = load_yaml(path)
            rule = _normalize_yaml_for_json(loaded_rule)
        except (ConfigurationError, TypeError) as exc:
            errors.append(str(exc))
            continue
        missing = REQUIRED_RULE_FIELDS - rule.keys()
        if missing:
            errors.append(f"{path.relative_to(root)} missing fields: {', '.join(sorted(missing))}")
        if schema_validator:
            schema_errors = sorted(
                schema_validator.iter_errors(rule),
                key=lambda item: tuple(str(component) for component in item.absolute_path),
            )
            for schema_error in schema_errors:
                errors.append(
                    f"{path.relative_to(root)} schema error at "
                    f"{_schema_error_path(schema_error)}: {schema_error.message}"
                )

        detection_id = str(rule.get("id", ""))
        ids.append(detection_id)
        if path.stem != detection_id:
            errors.append(
                f"{path.relative_to(root)} filename does not match metadata ID {detection_id!r}"
            )
        query_file = rule.get("query_file")
        if isinstance(query_file, str) and query_file:
            referenced_queries.add(query_file)
            query_path = root / query_file
            if not _is_within(query_path, root / "detections" / "kql"):
                errors.append(f"{path.relative_to(root)} query_file escapes detections/kql")
            elif not query_path.is_file():
                errors.append(f"{path.relative_to(root)} references missing query: {query_file}")
            else:
                query = query_path.read_text(encoding="utf-8")
                for token in ("//", "let ", "project ", "DetectionId", "Timestamp", "Evidence"):
                    if token not in query:
                        errors.append(
                            f"{query_path.relative_to(root)} missing required KQL token: {token}"
                        )
                declarations = DETECTION_ID_DECLARATION_RE.findall(query)
                if declarations != [detection_id]:
                    errors.append(
                        f"{query_path.relative_to(root)} DetectionId declaration must match "
                        f"{detection_id}; found {declarations}"
                    )
                _validate_text_indicators(
                    query_path, query, suffixes, networks, errors, scan_domain_assignments=True
                )
        else:
            errors.append(f"{path.relative_to(root)} has invalid query_file")

        _validate_rule_test_events(rule, path, root, events, errors)
        for attack_id in _attack_ids(rule.get("attack")):
            if not ATTACK_RE.fullmatch(attack_id):
                errors.append(f"{path.relative_to(root)} has invalid ATT&CK ID: {attack_id}")
        created = rule.get("date_created")
        modified = rule.get("date_modified")
        if isinstance(created, str) and isinstance(modified, str) and modified < created:
            errors.append(f"{path.relative_to(root)} date_modified precedes date_created")

    _validate_exact_keys(set(ids), DETECTION_IDS, "detection metadata IDs", errors)
    if len(ids) != len(set(ids)):
        errors.append("detection rule IDs are not unique")
    query_paths = {
        str(path.relative_to(root)).replace("\\", "/")
        for path in (root / "detections" / "kql").glob("*.kql")
    }
    if query_paths != referenced_queries:
        unreferenced = sorted(query_paths - referenced_queries)
        missing = sorted(referenced_queries - query_paths)
        errors.append(
            f"KQL/rule reference mismatch: unreferenced={unreferenced}, missing={missing}"
        )


def _is_safe_ip(
    value: str, networks: tuple[IPv4Network, ...] = RFC_DOCUMENTATION_NETWORKS
) -> bool:
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return parsed.version == 4 and any(parsed in network for network in networks)


def _is_safe_domain(value: str, suffixes: tuple[str, ...]) -> bool:
    normalized = value.rstrip(".").lower()
    return bool(normalized) and any(normalized.endswith(suffix) for suffix in suffixes)


def _validate_host(
    host: str, context: str, suffixes: tuple[str, ...], networks: tuple[IPv4Network, ...],
    errors: list[str]
) -> None:
    normalized = host.strip("[]").rstrip(".")
    try:
        parsed = ip_address(normalized)
    except ValueError:
        if not _is_safe_domain(normalized, suffixes):
            errors.append(f"{context} uses domain outside configured reserved suffixes: {host}")
    else:
        if parsed.version != 4 or not _is_safe_ip(normalized, networks):
            errors.append(f"{context} uses IP outside configured documentation ranges: {host}")


def _validate_text_indicators(
    path: Path,
    text: str,
    suffixes: tuple[str, ...],
    networks: tuple[IPv4Network, ...],
    errors: list[str],
    *,
    scan_domain_assignments: bool = False,
) -> None:
    context = str(path)
    seen: set[tuple[str, str]] = set()
    for match in IPV4_LITERAL_RE.finditer(text):
        value = match.group(0)
        key = ("ip", value)
        if key not in seen and not _is_safe_ip(value, networks):
            errors.append(f"{context} uses IP outside configured documentation ranges: {value}")
        seen.add(key)
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:")
        host = urlparse(value).hostname
        key = ("url", value)
        if key not in seen:
            if not host:
                errors.append(f"{context} contains an invalid URL: {value}")
            else:
                _validate_host(host, context, suffixes, networks, errors)
        seen.add(key)
    for match in EMAIL_RE.finditer(text):
        value = match.group(0)
        key = ("email", value)
        if key not in seen:
            _validate_host(value.rsplit("@", 1)[1], context, suffixes, networks, errors)
        seen.add(key)
    if scan_domain_assignments:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "domain" not in line.casefold():
                continue
            for candidate in QUOTED_VALUE_RE.findall(line):
                if HOSTNAME_RE.fullmatch(candidate):
                    key = ("domain", candidate)
                    if key not in seen:
                        _validate_host(
                            candidate,
                            f"{context}:{line_number}",
                            suffixes,
                            networks,
                            errors,
                        )
                    seen.add(key)


def _validate_event_indicators(
    event: Event,
    suffixes: tuple[str, ...],
    networks: tuple[IPv4Network, ...],
    errors: list[str],
) -> None:
    values: dict[str, Any] = {
        "ScenarioId": event.scenario_id,
        "SourceType": event.source_type,
        "User": event.user,
        "IPAddress": event.ip_address,
        "DeviceId": event.device_id,
        "Application": event.application,
        "Action": event.action,
        "Result": event.result,
        "Location": event.location,
        "RiskLevel": event.risk_level,
        **event.attributes,
    }

    def inspect(key: str, value: Any) -> None:
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                inspect(str(nested_key), nested_value)
            return
        if isinstance(value, list):
            for nested_value in value:
                inspect(key, nested_value)
            return
        if not isinstance(value, str) or not value:
            return
        context = f"{event.event_id}.{key}"
        _validate_text_indicators(Path(context), value, suffixes, networks, errors)
        if key.casefold().endswith("domain"):
            _validate_host(value, context, suffixes, networks, errors)

    for key, value in values.items():
        inspect(key, value)


def _validate_telemetry(
    root: Path,
    lab: dict[str, Any],
    suffixes: tuple[str, ...],
    networks: tuple[IPv4Network, ...],
    errors: list[str],
) -> dict[str, Event]:
    telemetry_dir = root / "data" / "telemetry"
    actual_files = {path.name for path in telemetry_dir.glob("*.jsonl")}
    missing_files = sorted(REQUIRED_TELEMETRY_FILES - actual_files)
    if missing_files:
        errors.append(f"missing required telemetry files: {missing_files}")
    for filename in sorted(REQUIRED_TELEMETRY_FILES & actual_files):
        path = telemetry_dir / filename
        if not any(line.strip() for line in path.read_text(encoding="utf-8").splitlines()):
            errors.append(f"required telemetry file is empty: data/telemetry/{filename}")
    try:
        events = load_events(root)
    except TelemetryError as exc:
        errors.append(str(exc))
        return {}

    configured_minimum = (
        lab.get("telemetry", {}).get("minimum_events", 60)
        if isinstance(lab.get("telemetry"), dict)
        else 60
    )
    minimum_events = configured_minimum if isinstance(configured_minimum, int) else 60
    if len(events) < minimum_events:
        errors.append(f"telemetry requires at least {minimum_events} events, found {len(events)}")
    scenario_id = (
        lab.get("scenario", {}).get("id") if isinstance(lab.get("scenario"), dict) else None
    )
    malicious = sum(event.is_malicious for event in events)
    primary_malicious = sum(
        event.is_malicious and event.scenario_id == scenario_id for event in events
    )
    benign = len(events) - malicious
    if primary_malicious < 20 or benign < 20:
        errors.append(
            "telemetry labels require >=20 malicious primary-scenario and >=20 benign events, "
            f"found {primary_malicious}/{benign}"
        )
    scenarios = {event.scenario_id for event in events}
    required_controls = {"BENIGN-VPN", "BENIGN-SVC", "BENIGN-CONSENT", "BENIGN-BACKUP"}
    if not required_controls <= scenarios:
        errors.append(
            f"missing benign control scenarios: {', '.join(sorted(required_controls - scenarios))}"
        )
    for event in events:
        _validate_event_indicators(event, suffixes, networks, errors)
        invalid = set(event.expected_detections) - DETECTION_IDS
        if invalid:
            errors.append(f"{event.event_id} has invalid expected detections: {sorted(invalid)}")
        if "Synthetic" in event.attributes and event.attributes["Synthetic"] is not True:
            errors.append(f"{event.event_id} Synthetic must be true when present")
    _validate_reference_incident(events, lab, errors)
    return {event.event_id: event for event in events}


def _validate_reference_incident(
    events: list[Event], lab: dict[str, Any], errors: list[str]
) -> None:
    incident_events = [event for event in events if event.source_type == "incident"]
    if len(incident_events) != 1:
        errors.append(
            f"telemetry requires exactly one reference-only incident record, found "
            f"{len(incident_events)}"
        )
        return
    event = incident_events[0]
    scenario = lab.get("scenario") if isinstance(lab.get("scenario"), dict) else {}
    incident_id = scenario.get("incident_id")
    if event.attributes.get("IncidentId") != incident_id:
        errors.append(f"{event.event_id} IncidentId must match config/lab.yml scenario.incident_id")
    if event.attributes.get("RecordRole") != "synthetic_reference_only":
        errors.append(f"{event.event_id} RecordRole must be synthetic_reference_only")
    if event.attributes.get("DetectionInput") is not False:
        errors.append(f"{event.event_id} DetectionInput must be false")
    if event.attributes.get("Synthetic") is not True:
        errors.append(f"{event.event_id} Synthetic must be true")
    if event.is_malicious or event.expected_detections:
        errors.append(
            f"{event.event_id} reference-only record must be benign and have no expected detections"
        )
    if scenario:
        if event.scenario_id != scenario.get("id"):
            errors.append(f"{event.event_id} ScenarioId must match config/lab.yml scenario.id")
        if event.user != scenario.get("primary_user"):
            errors.append(f"{event.event_id} User must match config/lab.yml scenario.primary_user")


def _json_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{label} must be a list")
        return []
    invalid = [item for item in value if not isinstance(item, str) or not item]
    if invalid:
        errors.append(f"{label} entries must be non-empty strings")
    return [item for item in value if isinstance(item, str) and item]


def _label_cases(
    value: Any, label: str, errors: list[str], *, required: bool
) -> list[set[str]]:
    if not isinstance(value, list) or (required and not value):
        qualifier = "a non-empty list" if required else "a list"
        errors.append(f"{label} must be {qualifier}")
        return []
    cases: list[set[str]] = []
    for index, case in enumerate(value):
        case_label = f"{label}[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{case_label} must be an object")
            continue
        if not isinstance(case.get("name"), str) or not case["name"].strip():
            errors.append(f"{case_label}.name must be a non-empty string")
        event_ids = _json_list(case.get("event_ids"), f"{case_label}.event_ids", errors)
        if not event_ids:
            errors.append(f"{case_label}.event_ids must not be empty")
        cases.append(set(event_ids))
    return cases


def _rule_test_event_sets(
    root: Path, detection_id: str, test_type: str
) -> set[frozenset[str]]:
    rule = load_yaml(root / "detections" / "rules" / f"{detection_id}.yml")
    tests = rule.get("test_cases", [])
    if not isinstance(tests, list):
        return set()
    return {
        frozenset(str(event_id) for event_id in test.get("event_ids", []))
        for test in tests
        if isinstance(test, dict)
        and test.get("type") == test_type
        and isinstance(test.get("event_ids"), list)
    }


def _validate_labels(
    root: Path, events: dict[str, Event], risk_model: dict[str, Any], errors: list[str]
) -> None:
    path = root / "data" / "labels" / "expected-findings.json"
    try:
        labels = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        errors.append(f"unable to read data/labels/expected-findings.json: {exc}")
        return
    except json.JSONDecodeError as exc:
        errors.append(f"invalid expected-findings.json: {exc.msg}")
        return
    if not isinstance(labels, dict):
        errors.append("expected-findings.json must contain an object")
        return
    if not isinstance(labels.get("description"), str) or not labels["description"].strip():
        errors.append("expected-findings.json description must be a non-empty string")
    detections = labels.get("detections")
    if not isinstance(detections, dict):
        errors.append("expected-findings.json detections must be an object")
        return
    _validate_exact_keys(set(detections), DETECTION_IDS, "expected-findings detections", errors)
    for detection_id, entry in detections.items():
        label = f"expected-findings {detection_id}"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be an object")
            continue
        required_cases = _label_cases(
            entry.get("required_cases"), f"{label}.required_cases", errors, required=True
        )
        referenced: set[str] = set()
        for case_event_ids in required_cases:
            referenced.update(case_event_ids)
            if detection_id != "DET010" and case_event_ids and not any(
                event_id in events
                and detection_id in events[event_id].expected_detections
                for event_id in case_event_ids
            ):
                errors.append(
                    f"{label}.required_cases has no event labelled for {detection_id}"
                )
        required_non_malicious = sorted(
            event_id
            for case_event_ids in required_cases
            for event_id in case_event_ids
            if event_id in events and not events[event_id].is_malicious
        )
        if required_non_malicious:
            errors.append(
                f"{label}.required_cases uses benign events: {required_non_malicious}"
            )

        if "benign_cases" in entry:
            if "benign_event_ids" in entry:
                errors.append(f"{label} cannot define both benign_cases and benign_event_ids")
            benign_cases = _label_cases(
                entry.get("benign_cases"), f"{label}.benign_cases", errors, required=True
            )
            benign_ids = sorted({event_id for case in benign_cases for event_id in case})
        else:
            benign_ids = _json_list(
                entry.get("benign_event_ids"), f"{label}.benign_event_ids", errors
            )
        prohibited_ids = _json_list(
            entry.get("prohibited_false_positive_event_ids"),
            f"{label}.prohibited_false_positive_event_ids",
            errors,
        )
        referenced.update(benign_ids)
        referenced.update(prohibited_ids)
        missing = sorted(referenced - events.keys())
        if missing:
            errors.append(f"{label} references missing telemetry events: {missing}")
        non_benign = sorted(
            event_id
            for event_id in {*benign_ids, *prohibited_ids}
            if event_id in events and events[event_id].is_malicious
        )
        if non_benign:
            errors.append(f"{label} benign/prohibited cases use malicious events: {non_benign}")
        overlap = sorted(set(benign_ids) & set(prohibited_ids))
        if overlap:
            errors.append(f"{label} benign and prohibited event IDs overlap: {overlap}")

        expected_malicious = _rule_test_event_sets(root, detection_id, "malicious")
        labelled_malicious = {frozenset(case) for case in required_cases}
        if labelled_malicious != expected_malicious:
            errors.append(
                f"{label} required cases do not match the rule malicious test cases"
            )
        expected_benign_ids = set().union(
            *(set(case) for case in _rule_test_event_sets(root, detection_id, "benign"))
        )
        labelled_benign_ids = set(benign_ids) | set(prohibited_ids)
        if labelled_benign_ids != expected_benign_ids:
            errors.append(
                f"{label} benign/prohibited evidence does not match the rule benign test cases"
            )

    weights = risk_model.get("detection_weights")
    if isinstance(weights, dict):
        _validate_exact_keys(
            {str(key) for key in weights},
            WEIGHTED_DETECTION_IDS,
            "risk-model detection_weights",
            errors,
        )


def _validate_links_and_content(root: Path, errors: list[str]) -> None:
    markdown_paths = sorted(
        path
        for path in root.rglob("*.md")
        if not MARKDOWN_SCAN_EXCLUSIONS.intersection(path.relative_to(root).parts)
        and not any(part.endswith(".egg-info") for part in path.relative_to(root).parts)
    )
    for path in markdown_paths:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for term in PROHIBITED_DOC_TERMS:
            if term in lowered:
                errors.append(
                    f"{path.relative_to(root)} contains prohibited portfolio term: {term}"
                )
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = unquote(match.group(1) or match.group(2) or "").strip()
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            file_target = target.split("#", 1)[0].split("?", 1)[0]
            if not file_target:
                continue
            resolved = (
                root / file_target.lstrip("/")
                if file_target.startswith("/")
                else path.parent / file_target
            ).resolve()
            if not _is_within(resolved, root) or not resolved.exists():
                errors.append(f"{path.relative_to(root)} has broken internal link: {target}")


def _validate_secrets(root: Path, errors: list[str]) -> None:
    scan_suffixes = {".py", ".yml", ".yaml", ".json", ".jsonl", ".kql", ".md", ".toml"}
    for path in root.rglob("*"):
        relative_parts = path.relative_to(root).parts
        if (
            not path.is_file()
            or path.suffix.lower() not in scan_suffixes
            or ".git" in relative_parts
            or ".venv" in relative_parts
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            errors.append(
                f"possible secret pattern detected in {path.relative_to(root)} (value suppressed)"
            )


def validate_repository(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    _validate_structure(root, errors)
    lab, risk_model, suffixes, networks = _validate_configuration(root, errors)
    events = _validate_telemetry(root, lab, suffixes, networks, errors)
    _validate_rules(root, events, suffixes, networks, errors)
    _validate_labels(root, events, risk_model, errors)
    _validate_links_and_content(root, errors)
    _validate_secrets(root, errors)
    return errors


def require_valid_repository(root: Path) -> None:
    errors = validate_repository(root)
    if errors:
        raise ValidationFailure("Repository validation failed:\n- " + "\n- ".join(errors))
