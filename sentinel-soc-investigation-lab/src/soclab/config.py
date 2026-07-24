"""Configuration loading with clear errors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ConfigurationError(ValueError):
    """Raised when repository configuration is invalid."""


def repository_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "config" / "lab.yml").exists():
            return candidate
    raise ConfigurationError(
        "Could not locate repository root containing pyproject.toml and config/lab.yml"
    )


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to load {path}: {exc}") from exc
    if not isinstance(content, dict):
        raise ConfigurationError(f"Expected a mapping in {path}")
    return content


def load_lab_config(root: Path) -> dict[str, Any]:
    config = load_yaml(root / "config" / "lab.yml")
    for key in ("project", "scenario", "telemetry", "analysis"):
        if key not in config:
            raise ConfigurationError(f"config/lab.yml is missing required key: {key}")
    return config


def analysis_output_directory(root: Path, config: dict[str, Any]) -> Path:
    """Resolve the configured artifact directory and keep cleanup inside the repository."""

    configured = config.get("analysis", {}).get("output_directory")
    if not isinstance(configured, str) or not configured.strip():
        raise ConfigurationError("config/lab.yml analysis.output_directory must be a path")
    root = root.resolve()
    artifacts_root = (root / "artifacts").resolve()
    output = (root / configured).resolve()
    if output == artifacts_root or artifacts_root not in output.parents:
        raise ConfigurationError("analysis.output_directory must be below the artifacts directory")
    return output


def load_risk_model(root: Path) -> dict[str, Any]:
    model = load_yaml(root / "config" / "detection-risk-model.yml")
    if not isinstance(model.get("detection_weights"), dict):
        raise ConfigurationError("Risk model requires detection_weights")
    return model
