from __future__ import annotations

import argparse
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from benchmarks.common import load_json
from benchmarks.runtime.report_safety import reject_forbidden_report_keys

SCHEMA_VERSION = "controlled-sts-validation-report/v1"
REPORT_TYPE = "controlled_sts_validation_report"
PREDICTED_ACTION = "sts:AssumeRole"
PROBE_TYPE = "sts_assume_role"
ALLOWED_PREDICTED_OUTCOMES = {"assumed", "denied", "inconclusive"}
ALLOWED_OBSERVED_OUTCOMES = {
    "assumed",
    "denied",
    "inconclusive",
    "configuration_error",
    "unexpected_account",
    "skipped_safety_guard",
}
ALLOWED_OUTCOME_CLASSIFICATIONS = {
    "corroborated",
    "refuted",
    "inconclusive",
    "environment_mismatch",
    "probe_harness_issue",
    "evidence_gap",
    "tool_bug_candidate",
    "model_limitation",
}
REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "report_type",
    "validation_id",
    "created_at",
    "environment_label",
    "input_bundle_reference",
    "finding_reference",
    "predicted_behavior",
    "runtime_probe",
    "observed_behavior",
    "outcome_classification",
    "evidence_summary",
    "caveats",
    "non_claims",
    "artifact_safety_status",
}
ALLOWED_TOP_LEVEL_FIELDS = REQUIRED_TOP_LEVEL_FIELDS
REQUIRED_FINDING_REFERENCE_FIELDS = {
    "source_principal_arn",
    "target_role_arn",
    "expected_account_id",
    "reasoner_or_finding_type",
    "prediction_source",
}
ALLOWED_FINDING_REFERENCE_FIELDS = {
    *REQUIRED_FINDING_REFERENCE_FIELDS,
    "finding_id",
    "path_id",
    "source_document",
    "source_bundle",
}
REQUIRED_PREDICTED_BEHAVIOR_FIELDS = {
    "predicted_action",
    "predicted_outcome",
    "prediction_basis",
    "prediction_caveats",
}
ALLOWED_PREDICTED_BEHAVIOR_FIELDS = REQUIRED_PREDICTED_BEHAVIOR_FIELDS
REQUIRED_RUNTIME_PROBE_FIELDS = {
    "probe_id",
    "probe_type",
    "mode",
    "operator_confirmation_used",
    "live_aws_used",
    "aws_calls_made",
    "sts_assume_role_called",
    "downstream_actions_performed",
    "credentials_obtained",
    "output_paths",
    "safe_error_category",
}
ALLOWED_RUNTIME_PROBE_FIELDS = REQUIRED_RUNTIME_PROBE_FIELDS
REQUIRED_OBSERVED_BEHAVIOR_FIELDS = {
    "observed_outcome",
    "result_classification",
    "sanitized_reasons",
}
ALLOWED_OBSERVED_BEHAVIOR_FIELDS = {
    *REQUIRED_OBSERVED_BEHAVIOR_FIELDS,
    "observed_account_id",
    "no_raw_credentials",
    "no_raw_aws_errors",
}
REQUIRED_ARTIFACT_SAFETY_FIELDS = {
    "raw_artifacts_committed",
    "credentials_committed",
    "tmp_outputs_committed",
    "downstream_actions",
    "sanitized_summary_only",
    "reviewer_checked",
}
ALLOWED_ARTIFACT_SAFETY_FIELDS = {
    *REQUIRED_ARTIFACT_SAFETY_FIELDS,
    "raw_aws_logs_committed",
    "terraform_artifacts_committed",
    "credential_shaped_fields_present",
    "separate_summary_review_required",
}
FORBIDDEN_KEY_TERMS = {
    "accesskeyid",
    "secretaccesskey",
    "sessiontoken",
    "credentials",
    "credential",
    "secret",
    "token",
    "composite_score",
    "overall_score",
    "pass_fail",
    "pass",
    "fail",
    "vulnerable",
    "exploited",
    "production_ready",
    "benchmark_passed",
}
ALLOWED_SAFE_KEYS = {
    "credentials_obtained",
    "credentials_committed",
    "credential_shaped_fields_present",
    "no_raw_credentials",
}
REQUIRED_NON_CLAIM_MARKERS = {
    "production readiness": ("production readiness",),
    "broad IAMScope correctness": ("broad iamscope correctness", "broad correctness"),
    "arbitrary enterprise graph correctness": ("arbitrary enterprise graph correctness",),
    "broad runtime exploitability": ("broad runtime exploitability", "broad exploitability"),
    "downstream authorization proof": ("downstream authorization proof", "downstream authorization"),
    "resource-policy Deny support": ("resource-policy deny", "resource policy deny"),
    "finding-level reachability": ("finding-level reachability", "finding level reachability"),
}


def validate_report_from_path(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path)
    report = _load_report(path)
    return validate_report(report, report_path=path)


def validate_report(report: dict[str, Any], *, report_path: str | Path | None = None) -> dict[str, Any]:
    _validate_top_level(report)
    _validate_finding_reference(report["finding_reference"])
    _validate_predicted_behavior(report["predicted_behavior"])
    _validate_runtime_probe(report["runtime_probe"])
    _validate_observed_behavior(report["observed_behavior"])
    _validate_outcome_classification(report["outcome_classification"])
    _validate_summary_lists(report)
    _validate_artifact_safety(report["artifact_safety_status"])
    return _summary(report, report_path=report_path)


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"controlled STS validation report path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"controlled STS validation report path is not a file: {path}")
    try:
        payload = load_json(path)
    except JSONDecodeError as exc:
        raise ValueError(f"controlled STS validation report is malformed JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("controlled STS validation report must be a JSON object")
    return payload


def _validate_top_level(report: dict[str, Any]) -> None:
    _reject_forbidden_keys(report)
    _require_fields(report, REQUIRED_TOP_LEVEL_FIELDS, context="controlled STS validation report")
    _reject_unknown_fields(report, ALLOWED_TOP_LEVEL_FIELDS, context="controlled STS validation report")
    if report["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {report['schema_version']!r}")
    if report["report_type"] != REPORT_TYPE:
        raise ValueError(f"report_type must be {REPORT_TYPE!r}")
    for forbidden_scope_field in ("findings", "finding_references", "paths", "path_references", "reports"):
        if forbidden_scope_field in report:
            raise ValueError(f"controlled STS validation report must contain one finding/path only: {forbidden_scope_field}")


def _validate_finding_reference(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("finding_reference must be an object")
    _require_fields(value, REQUIRED_FINDING_REFERENCE_FIELDS, context="finding_reference")
    _reject_unknown_fields(value, ALLOWED_FINDING_REFERENCE_FIELDS, context="finding_reference")
    if ("finding_id" not in value) and ("path_id" not in value):
        raise ValueError("finding_reference requires finding_id or path_id")
    for field in REQUIRED_FINDING_REFERENCE_FIELDS:
        _require_non_empty_string(value.get(field), f"finding_reference.{field}")
    if "finding_id" in value:
        _require_non_empty_string(value.get("finding_id"), "finding_reference.finding_id")
    if "path_id" in value:
        _require_non_empty_string(value.get("path_id"), "finding_reference.path_id")


def _validate_predicted_behavior(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("predicted_behavior must be an object")
    _require_fields(value, REQUIRED_PREDICTED_BEHAVIOR_FIELDS, context="predicted_behavior")
    _reject_unknown_fields(value, ALLOWED_PREDICTED_BEHAVIOR_FIELDS, context="predicted_behavior")
    if value["predicted_action"] != PREDICTED_ACTION:
        raise ValueError(f"predicted_behavior.predicted_action must be {PREDICTED_ACTION!r}")
    if value["predicted_outcome"] not in ALLOWED_PREDICTED_OUTCOMES:
        raise ValueError("predicted_behavior.predicted_outcome must be assumed, denied, or inconclusive")
    _require_non_empty_string(value.get("prediction_basis"), "predicted_behavior.prediction_basis")
    _require_string_list(value.get("prediction_caveats"), "predicted_behavior.prediction_caveats")


def _validate_runtime_probe(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("runtime_probe must be an object")
    _require_fields(value, REQUIRED_RUNTIME_PROBE_FIELDS, context="runtime_probe")
    _reject_unknown_fields(value, ALLOWED_RUNTIME_PROBE_FIELDS, context="runtime_probe")
    _require_non_empty_string(value.get("probe_id"), "runtime_probe.probe_id")
    if value["probe_type"] != PROBE_TYPE:
        raise ValueError(f"runtime_probe.probe_type must be {PROBE_TYPE!r}")
    _require_non_empty_string(value.get("mode"), "runtime_probe.mode")
    for field in (
        "operator_confirmation_used",
        "live_aws_used",
        "aws_calls_made",
        "sts_assume_role_called",
        "credentials_obtained",
    ):
        if not isinstance(value.get(field), bool):
            raise ValueError(f"runtime_probe.{field} must be a boolean")
    if value["downstream_actions_performed"] is not False:
        raise ValueError("runtime_probe.downstream_actions_performed must be false")
    if not isinstance(value.get("output_paths"), dict):
        raise ValueError("runtime_probe.output_paths must be an object")
    _require_non_empty_string(value.get("safe_error_category"), "runtime_probe.safe_error_category")


def _validate_observed_behavior(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("observed_behavior must be an object")
    _require_fields(value, REQUIRED_OBSERVED_BEHAVIOR_FIELDS, context="observed_behavior")
    _reject_unknown_fields(value, ALLOWED_OBSERVED_BEHAVIOR_FIELDS, context="observed_behavior")
    if value["observed_outcome"] not in ALLOWED_OBSERVED_OUTCOMES:
        raise ValueError(f"unsupported observed_behavior.observed_outcome: {value['observed_outcome']!r}")
    _require_non_empty_string(value.get("result_classification"), "observed_behavior.result_classification")
    _require_string_list(value.get("sanitized_reasons"), "observed_behavior.sanitized_reasons")
    if "no_raw_credentials" in value and value["no_raw_credentials"] is not True:
        raise ValueError("observed_behavior.no_raw_credentials must be true when supplied")
    if "no_raw_aws_errors" in value and value["no_raw_aws_errors"] is not True:
        raise ValueError("observed_behavior.no_raw_aws_errors must be true when supplied")


def _validate_outcome_classification(value: Any) -> None:
    if value not in ALLOWED_OUTCOME_CLASSIFICATIONS:
        raise ValueError(f"unsupported outcome_classification: {value!r}")


def _validate_summary_lists(report: dict[str, Any]) -> None:
    if not isinstance(report["evidence_summary"], dict):
        raise ValueError("evidence_summary must be an object")
    _require_string_list(report.get("caveats"), "caveats")
    non_claims = report.get("non_claims")
    _require_string_list(non_claims, "non_claims")
    joined = "\n".join(str(item).lower() for item in non_claims)
    missing = [
        label for label, markers in REQUIRED_NON_CLAIM_MARKERS.items() if not any(marker in joined for marker in markers)
    ]
    if missing:
        raise ValueError(f"non_claims missing required coverage: {', '.join(missing)}")


def _validate_artifact_safety(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("artifact_safety_status must be an object")
    _require_fields(value, REQUIRED_ARTIFACT_SAFETY_FIELDS, context="artifact_safety_status")
    _reject_unknown_fields(value, ALLOWED_ARTIFACT_SAFETY_FIELDS, context="artifact_safety_status")
    for field in ("raw_artifacts_committed", "credentials_committed", "tmp_outputs_committed", "downstream_actions"):
        if value[field] is not False:
            raise ValueError(f"artifact_safety_status.{field} must be false")
    if value["sanitized_summary_only"] is not True:
        raise ValueError("artifact_safety_status.sanitized_summary_only must be true")
    if not isinstance(value["reviewer_checked"], bool):
        raise ValueError("artifact_safety_status.reviewer_checked must be a boolean")
    for optional_false_field in (
        "raw_aws_logs_committed",
        "terraform_artifacts_committed",
        "credential_shaped_fields_present",
    ):
        if optional_false_field in value and value[optional_false_field] is not False:
            raise ValueError(f"artifact_safety_status.{optional_false_field} must be false when supplied")


def _reject_forbidden_keys(value: Any, *, path: str = "$") -> None:
    reject_forbidden_report_keys(
        value,
        forbidden_key_terms=FORBIDDEN_KEY_TERMS,
        allowed_safe_keys=ALLOWED_SAFE_KEYS,
        report_label="controlled STS validation report",
        path=path,
    )


def _require_fields(payload: dict[str, Any], required_fields: set[str], *, context: str) -> None:
    missing = sorted(field for field in required_fields if field not in payload)
    if missing:
        raise ValueError(f"{context} missing required field(s): {', '.join(missing)}")


def _reject_unknown_fields(payload: dict[str, Any], allowed_fields: set[str], *, context: str) -> None:
    unknown = sorted(field for field in payload if field not in allowed_fields)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")


def _require_non_empty_string(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")


def _require_string_list(value: Any, field: str) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field} must contain only non-empty strings")


def _summary(report: dict[str, Any], *, report_path: str | Path | None) -> dict[str, Any]:
    finding_reference = report["finding_reference"]
    runtime_probe = report["runtime_probe"]
    return {
        "report_type": "controlled_sts_validation_report_validation",
        "valid": True,
        "report_path": str(report_path) if report_path is not None else "in_memory",
        "validated_report_type": report["report_type"],
        "schema_version": report["schema_version"],
        "validation_id": report["validation_id"],
        "environment_label": report["environment_label"],
        "finding_or_path_id": finding_reference.get("finding_id") or finding_reference.get("path_id"),
        "probe_id": runtime_probe["probe_id"],
        "outcome_classification": report["outcome_classification"],
        "observed_outcome": report["observed_behavior"]["observed_outcome"],
        "credentials_obtained": runtime_probe["credentials_obtained"],
        "downstream_actions_performed": runtime_probe["downstream_actions_performed"],
        "artifact_safety_status": {
            "raw_artifacts_committed": report["artifact_safety_status"]["raw_artifacts_committed"],
            "credentials_committed": report["artifact_safety_status"]["credentials_committed"],
            "tmp_outputs_committed": report["artifact_safety_status"]["tmp_outputs_committed"],
            "sanitized_summary_only": report["artifact_safety_status"]["sanitized_summary_only"],
            "reviewer_checked": report["artifact_safety_status"]["reviewer_checked"],
        },
        "caveats": [
            "shape_validation_only: this validator checks report JSON shape and safety boundaries only",
            "no_aws_calls: this validator does not call AWS or STS AssumeRole",
            "no_runtime_validation: this validator does not perform controlled validation execution",
            "no_composite_score: this validator does not emit aggregate scoring",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate one controlled STS validation report JSON without calling AWS."
    )
    parser.add_argument("--report", required=True, type=Path, help="Controlled STS validation report JSON file.")
    args = parser.parse_args(argv)

    try:
        summary = validate_report_from_path(args.report)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
