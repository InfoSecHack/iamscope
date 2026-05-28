from __future__ import annotations

from typing import Any

from benchmarks.common import (
    ALLOWED_AUTHORITIES,
    ALLOWED_CONFIDENCE,
    ALLOWED_DEFECT_CLASSES,
    MANIFEST_VERSION,
    load_json,
)


def _require_keys(payload: dict[str, Any], required: list[str], label: str) -> list[str]:
    return [f"{label} missing required field: {key}" for key in required if key not in payload]


def validate_case_manifest(payload: dict[str, Any]) -> list[str]:
    errors = _require_keys(
        payload,
        [
            "manifest_type",
            "schema_version",
            "case_id",
            "family",
            "tier",
            "purpose",
            "claim_surface",
            "benchmark_proves",
            "benchmark_does_not_prove",
            "unknowns_remaining",
            "environment",
            "ground_truth",
            "honesty_ground_truth",
            "semantic_assertions",
            "artifacts_required",
            "scoring_expectations",
        ],
        "case manifest",
    )
    if payload.get("manifest_type") != "benchmark_case_manifest":
        errors.append("case manifest has invalid manifest_type")
    if payload.get("schema_version") != MANIFEST_VERSION:
        errors.append("case manifest has unsupported schema_version")
    if not isinstance(payload.get("semantic_assertions"), list) or not payload.get("semantic_assertions"):
        errors.append("case manifest semantic_assertions must be a non-empty list")
    supported_types = {
        "finding_count",
        "blocker_present",
        "check_state_present",
        "scenario_node_count",
        "scenario_edge_count",
        "scenario_constraint_count",
        "scenario_edge_constraint_count",
    }
    assertion_required_keys = {
        "finding_count": ["pattern_id", "verdict"],
        "blocker_present": ["pattern_id", "verdict", "kind"],
        "check_state_present": ["pattern_id", "verdict", "check_name", "check_state"],
        "scenario_node_count": ["node_type"],
        "scenario_edge_count": ["edge_type"],
        "scenario_constraint_count": ["constraint_type"],
        "scenario_edge_constraint_count": ["edge_type", "constraint_type"],
    }
    for assertion in payload.get("semantic_assertions", []):
        if not isinstance(assertion, dict):
            errors.append("case manifest semantic_assertion must be an object")
            continue
        assertion_type = assertion.get("type")
        errors.extend(
            _require_keys(
                assertion,
                [
                    "assertion_id",
                    "type",
                    "op",
                    "expected_value",
                    "defect_class_on_fail",
                    "confidence",
                    "authority",
                ],
                "semantic assertion",
            )
        )
        if assertion_type not in supported_types:
            errors.append(f"semantic assertion {assertion.get('assertion_id')} has unsupported type")
        else:
            errors.extend(
                _require_keys(
                    assertion,
                    assertion_required_keys[assertion_type],
                    "semantic assertion",
                )
            )
        if assertion.get("defect_class_on_fail") not in ALLOWED_DEFECT_CLASSES:
            errors.append(f"semantic assertion {assertion.get('assertion_id')} has invalid defect_class_on_fail")
        if assertion.get("confidence") not in ALLOWED_CONFIDENCE:
            errors.append(f"semantic assertion {assertion.get('assertion_id')} has invalid confidence")
        if assertion.get("authority") not in ALLOWED_AUTHORITIES:
            errors.append(f"semantic assertion {assertion.get('assertion_id')} has invalid authority")
    return errors


def validate_run_manifest(payload: dict[str, Any]) -> list[str]:
    errors = _require_keys(
        payload,
        [
            "manifest_type",
            "schema_version",
            "run_id",
            "case_id",
            "tool_name",
            "git_sha",
            "started_at",
            "ended_at",
            "authority",
            "confidence",
            "benchmark_date",
            "environment",
            "artifacts",
            "artifact_status",
            "context",
            "tool_claims",
        ],
        "run manifest",
    )
    if payload.get("manifest_type") != "benchmark_run_manifest":
        errors.append("run manifest has invalid manifest_type")
    if payload.get("schema_version") != MANIFEST_VERSION:
        errors.append("run manifest has unsupported schema_version")
    if payload.get("authority") not in ALLOWED_AUTHORITIES:
        errors.append("run manifest has invalid authority")
    if payload.get("confidence") not in ALLOWED_CONFIDENCE:
        errors.append("run manifest has invalid confidence")
    if payload.get("git_sha") is not None and not isinstance(payload.get("git_sha"), str):
        errors.append("run manifest git_sha must be a string or null")
    if payload.get("started_at") is not None and not isinstance(payload.get("started_at"), str):
        errors.append("run manifest started_at must be a string or null")
    if payload.get("ended_at") is not None and not isinstance(payload.get("ended_at"), str):
        errors.append("run manifest ended_at must be a string or null")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("run manifest artifacts must be an object")
    return errors


def validate_corpus_change_manifest(payload: dict[str, Any]) -> list[str]:
    return _require_keys(
        payload,
        [
            "manifest_type",
            "schema_version",
            "change_id",
            "summary",
            "cases_added",
            "cases_changed",
            "cases_removed",
            "reason",
        ],
        "corpus change manifest",
    )


def validate_gate_manifest(payload: dict[str, Any]) -> list[str]:
    errors = _require_keys(payload, ["manifest_type", "schema_version", "gates", "human_review"], "gate manifest")
    if payload.get("manifest_type") != "promotion_gate_manifest":
        errors.append("gate manifest has invalid manifest_type")
    if payload.get("schema_version") != MANIFEST_VERSION:
        errors.append("gate manifest has unsupported schema_version")
    gates = payload.get("gates")
    if not isinstance(gates, list) or not gates:
        errors.append("gate manifest gates must be a non-empty list")
    else:
        for gate in gates:
            if not isinstance(gate, dict):
                errors.append("gate manifest gate must be an object")
                continue
            errors.extend(_require_keys(gate, ["gate_id", "description", "blocks_on", "severity"], "gate rule"))
            for defect_class in gate.get("blocks_on", []):
                if defect_class not in ALLOWED_DEFECT_CLASSES:
                    errors.append(f"gate rule {gate.get('gate_id')} has invalid defect class {defect_class}")
    return errors


def validate_json_file(path: str) -> list[str]:
    payload = load_json(path)
    manifest_type = payload.get("manifest_type")
    if manifest_type == "benchmark_case_manifest":
        return validate_case_manifest(payload)
    if manifest_type == "benchmark_run_manifest":
        return validate_run_manifest(payload)
    if manifest_type == "benchmark_corpus_change_manifest":
        return validate_corpus_change_manifest(payload)
    if manifest_type == "promotion_gate_manifest":
        return validate_gate_manifest(payload)
    return [f"unknown manifest_type: {manifest_type}"]
