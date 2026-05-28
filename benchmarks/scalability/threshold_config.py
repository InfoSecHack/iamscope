from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from benchmarks.common import load_json

SCHEMA_VERSION = "0.1"
CONFIG_TYPE = "iamscope_threshold_config"
ALLOWED_MODES = {"report_only", "advisory"}
ALLOWED_REPORT_TYPES = {
    "synthetic_scalability_baseline_comparison",
    "frozen_corpus_baseline_comparison",
}
ALLOWED_TARGET_TYPES = {"fixture", "case", "batch"}
ALLOWED_COMPARISON_TYPES = {
    "max_absolute_delta",
    "max_relative_delta",
    "equals",
    "changed_or_unchanged",
    "must_be_available",
    "may_be_unavailable",
}
FORBIDDEN_FIELDS = {
    "composite_score",
    "overall_score",
    "grade",
    "ranking",
    "pass_rate",
    "production_readiness",
    "broad_pass_fail",
    "severity",
}
RUNTIME_METRICS = {"wall_clock_runtime_ms", "artifact_load_time_ms"}
TOP_LEVEL_REQUIRED_FIELDS = {
    "schema_version",
    "config_type",
    "mode",
    "report_type",
    "thresholds",
}
TOP_LEVEL_ALLOWED_FIELDS = {
    *TOP_LEVEL_REQUIRED_FIELDS,
    "caveats",
    "notes",
}
ENTRY_REQUIRED_FIELDS = {
    "target_type",
    "metric",
    "comparison_type",
    "rationale",
    "caveat",
}
ENTRY_ALLOWED_FIELDS = {
    *ENTRY_REQUIRED_FIELDS,
    "target_name",
    "selector",
    "expected",
    "delta_limit",
    "runtime_context_note",
}


def load_threshold_config(path: str | Path) -> dict[str, Any]:
    threshold_config_path = Path(path)
    if not threshold_config_path.exists():
        raise ValueError(f"threshold config path does not exist: {threshold_config_path}")
    if not threshold_config_path.is_file():
        raise ValueError(f"threshold config path is not a file: {threshold_config_path}")
    try:
        payload = load_json(threshold_config_path)
    except JSONDecodeError as exc:
        raise ValueError(f"threshold config is malformed JSON: {threshold_config_path}") from exc
    return validate_threshold_config(payload)


def validate_threshold_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("threshold config must be a JSON object")
    _reject_forbidden_fields(config)
    _require_fields(config, TOP_LEVEL_REQUIRED_FIELDS, context="threshold config")
    _reject_unknown_fields(config, TOP_LEVEL_ALLOWED_FIELDS, context="threshold config")
    _validate_top_level(config)
    thresholds = config["thresholds"]
    if not isinstance(thresholds, list):
        raise ValueError("threshold config field 'thresholds' must be a list")
    for index, entry in enumerate(thresholds):
        _validate_threshold_entry(entry, index=index)
    return config


def _validate_top_level(config: dict[str, Any]) -> None:
    if config["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported threshold config schema_version: {config['schema_version']!r}")
    if config["config_type"] != CONFIG_TYPE:
        raise ValueError(f"threshold config config_type must be {CONFIG_TYPE!r}")
    if config["mode"] not in ALLOWED_MODES:
        raise ValueError(f"unsupported threshold config mode: {config['mode']!r}")
    if config["report_type"] not in ALLOWED_REPORT_TYPES:
        raise ValueError(f"unsupported threshold config report_type: {config['report_type']!r}")


def _validate_threshold_entry(entry: Any, *, index: int) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"threshold entry {index} must be an object")
    _require_fields(entry, ENTRY_REQUIRED_FIELDS, context=f"threshold entry {index}")
    _reject_unknown_fields(entry, ENTRY_ALLOWED_FIELDS, context=f"threshold entry {index}")
    if not _has_target_selector(entry):
        raise ValueError(f"threshold entry {index} must include target_name or selector")
    if entry["target_type"] not in ALLOWED_TARGET_TYPES:
        raise ValueError(f"threshold entry {index} has unsupported target_type: {entry['target_type']!r}")
    if not _non_empty_string(entry["metric"]):
        raise ValueError(f"threshold entry {index} field 'metric' must be a non-empty string")
    comparison_type = entry["comparison_type"]
    if comparison_type not in ALLOWED_COMPARISON_TYPES:
        raise ValueError(f"threshold entry {index} has unsupported comparison_type: {comparison_type!r}")
    if not _non_empty_string(entry["rationale"]):
        raise ValueError(f"threshold entry {index} field 'rationale' must be a non-empty string")
    if not _non_empty_string(entry["caveat"]):
        raise ValueError(f"threshold entry {index} field 'caveat' must be a non-empty string")
    _validate_value_requirement(entry, index=index)
    if entry["metric"] in RUNTIME_METRICS and not _has_runtime_context(entry):
        raise ValueError(f"threshold entry {index} runtime metric requires machine/context caveat")


def _validate_value_requirement(entry: dict[str, Any], *, index: int) -> None:
    comparison_type = entry["comparison_type"]
    if comparison_type in {"max_absolute_delta", "max_relative_delta"}:
        if "delta_limit" not in entry:
            raise ValueError(f"threshold entry {index} comparison_type {comparison_type!r} requires delta_limit")
        if not _available_number(entry["delta_limit"]):
            raise ValueError(f"threshold entry {index} field 'delta_limit' must be a number")
    if comparison_type == "equals" and "expected" not in entry:
        raise ValueError(f"threshold entry {index} comparison_type 'equals' requires expected")
    if comparison_type == "changed_or_unchanged":
        if entry.get("expected") not in {"changed", "unchanged"}:
            raise ValueError(
                f"threshold entry {index} comparison_type 'changed_or_unchanged' requires expected "
                "'changed' or 'unchanged'"
            )


def _reject_forbidden_fields(value: Any, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_FIELDS:
                raise ValueError(f"forbidden threshold config field at {path}.{key}: {key}")
            _reject_forbidden_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_fields(child, path=f"{path}[{index}]")


def _require_fields(payload: dict[str, Any], required_fields: set[str], *, context: str) -> None:
    missing = sorted(field for field in required_fields if field not in payload)
    if missing:
        raise ValueError(f"{context} missing required field(s): {', '.join(missing)}")


def _reject_unknown_fields(payload: dict[str, Any], allowed_fields: set[str], *, context: str) -> None:
    unknown = sorted(field for field in payload if field not in allowed_fields)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")


def _has_target_selector(entry: dict[str, Any]) -> bool:
    return _non_empty_string(entry.get("target_name")) or entry.get("selector") not in (None, "")


def _has_runtime_context(entry: dict[str, Any]) -> bool:
    context_text = " ".join(
        str(entry.get(field, "")).lower()
        for field in ("caveat", "runtime_context_note")
        if entry.get(field) is not None
    )
    return "machine" in context_text or "context" in context_text


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _available_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)
