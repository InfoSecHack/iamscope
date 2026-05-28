from __future__ import annotations

import argparse
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from benchmarks.common import load_json
from benchmarks.runtime.report_safety import reject_forbidden_report_keys

REPORT_TYPE = "controlled_identity_deny_validation_report"
VALIDATION_SUMMARY_TYPE = "controlled_identity_deny_validation_report_validation"
ALLOWED_PREDICTED_OUTCOMES = {"denied", "allowed", "suppressed", "inconclusive"}
ALLOWED_METHOD_TYPES = {
    "static_policy_corroboration",
    "iam_simulation",
    "harmless_active_read",
    "no_active_check",
}
ALLOWED_OBSERVED_OUTCOMES = {
    "denied",
    "allowed",
    "suppressed",
    "inconclusive",
    "configuration_error",
    "unsupported_method",
    "environment_mismatch",
}
ALLOWED_OUTCOME_CLASSIFICATIONS = {
    "corroborated",
    "refuted",
    "inconclusive",
    "environment_mismatch",
    "evidence_gap",
    "probe_harness_issue",
    "tool_bug_candidate",
    "model_limitation",
    "unsupported_method",
}
ALLOWED_ALLOW_SOURCE_TYPES = {
    "identity_policy",
    "group_policy",
    "role_policy",
    "boundary_context",
    "unknown",
}
ALLOWED_DENY_SOURCE_TYPES = {
    "identity_policy",
    "group_policy",
    "role_policy",
    "permission_boundary",
    "session_policy",
    "unknown",
}
REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "report_type",
    "validation_id",
    "created_at",
    "environment_label",
    "input_bundle_reference",
    "finding_reference",
    "source_principal_arn",
    "candidate_action",
    "candidate_resource",
    "allow_basis",
    "deny_basis",
    "condition_context",
    "predicted_behavior",
    "evidence_method",
    "observed_or_static_evidence",
    "outcome_classification",
    "evidence_summary",
    "caveats",
    "non_claims",
    "artifact_safety_status",
}
ALLOWED_TOP_LEVEL_FIELDS = REQUIRED_TOP_LEVEL_FIELDS
REQUIRED_FINDING_REFERENCE_FIELDS = {
    "reasoner_or_finding_type",
    "prediction_source",
}
ALLOWED_FINDING_REFERENCE_FIELDS = {
    *REQUIRED_FINDING_REFERENCE_FIELDS,
    "finding_id",
    "path_id",
    "validation_layer_id",
    "source_document",
    "source_bundle",
}
REQUIRED_ALLOW_BASIS_FIELDS = {
    "allow_present",
    "allow_source_type",
    "allow_statement_summary",
    "allowed_action_match",
    "allowed_resource_match",
    "allow_condition_context",
    "caveats",
}
ALLOWED_ALLOW_BASIS_FIELDS = REQUIRED_ALLOW_BASIS_FIELDS
REQUIRED_DENY_BASIS_FIELDS = {
    "deny_present",
    "deny_source_type",
    "deny_statement_summary",
    "denied_action_match",
    "denied_resource_match",
    "deny_condition_context",
    "explicit_deny_applies",
    "caveats",
}
ALLOWED_DENY_BASIS_FIELDS = REQUIRED_DENY_BASIS_FIELDS
REQUIRED_PREDICTED_BEHAVIOR_FIELDS = {
    "predicted_action",
    "predicted_resource",
    "predicted_outcome",
    "prediction_basis",
    "prediction_caveats",
}
ALLOWED_PREDICTED_BEHAVIOR_FIELDS = REQUIRED_PREDICTED_BEHAVIOR_FIELDS
REQUIRED_EVIDENCE_METHOD_FIELDS = {
    "method_type",
    "live_aws_used",
    "aws_calls_made",
    "active_action_called",
    "destructive_action_called",
    "resource_modified",
    "output_paths",
    "safe_error_category",
}
ALLOWED_EVIDENCE_METHOD_FIELDS = REQUIRED_EVIDENCE_METHOD_FIELDS
REQUIRED_OBSERVED_OR_STATIC_EVIDENCE_FIELDS = {
    "observed_outcome",
    "static_allow_summary",
    "static_deny_summary",
    "condition_evaluation_summary",
    "sanitized_reasons",
}
ALLOWED_OBSERVED_OR_STATIC_EVIDENCE_FIELDS = {
    *REQUIRED_OBSERVED_OR_STATIC_EVIDENCE_FIELDS,
    "no_raw_credentials",
    "no_raw_aws_errors",
}
REQUIRED_ARTIFACT_SAFETY_FIELDS = {
    "raw_artifacts_committed",
    "credentials_committed",
    "tmp_outputs_committed",
    "destructive_actions",
    "resource_modifications",
    "sanitized_summary_only",
    "reviewer_checked",
}
ALLOWED_ARTIFACT_SAFETY_FIELDS = REQUIRED_ARTIFACT_SAFETY_FIELDS
FORBIDDEN_KEY_TERMS = {
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "credentials",
    "credential",
    "secret",
    "token",
    "raw_aws_log",
    "raw_error",
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
    "credentials_committed",
    "no_raw_credentials",
    "sanitized_reasons",
    "safe_error_category",
    "allow_statement_summary",
    "deny_statement_summary",
    "condition_evaluation_summary",
}
REQUIRED_NON_CLAIM_MARKERS = {
    "production readiness": ("production readiness",),
    "broad IAMScope correctness": ("broad iamscope correctness", "broad correctness"),
    "generic Deny correctness": ("generic deny correctness",),
    "resource-policy Deny support": ("resource-policy deny", "resource policy deny"),
    "SCP Deny support": ("scp deny",),
    "broad runtime exploitability": ("broad runtime exploitability", "broad exploitability"),
    "downstream authorization proof": ("downstream authorization proof", "downstream authorization"),
    "all-findings-verified claim": ("all-findings-verified", "all findings verified"),
    "real-world scalability": ("real-world scalability", "real world scalability"),
}
FORBIDDEN_MULTI_SCOPE_FIELDS = {
    "sources",
    "source_principals",
    "candidate_actions",
    "candidate_resources",
    "deny_bases",
    "denies",
    "reports",
    "findings",
    "paths",
}


def validate_report_from_path(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path)
    report = _load_report(path)
    return validate_report(report, report_path=path)


def validate_report(report: dict[str, Any], *, report_path: str | Path | None = None) -> dict[str, Any]:
    _validate_top_level(report)
    _validate_finding_reference(report["finding_reference"])
    _validate_allow_basis(report["allow_basis"])
    _validate_deny_basis(report["deny_basis"])
    _validate_condition_context(report["condition_context"])
    _validate_predicted_behavior(report["predicted_behavior"], report)
    _validate_evidence_method(report["evidence_method"])
    _validate_observed_or_static_evidence(report["observed_or_static_evidence"])
    _validate_outcome_classification(report["outcome_classification"])
    _validate_summary_lists(report)
    _validate_artifact_safety(report["artifact_safety_status"])
    return _summary(report, report_path=report_path)


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"controlled identity Deny validation report path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"controlled identity Deny validation report path is not a file: {path}")
    try:
        payload = load_json(path)
    except JSONDecodeError as exc:
        raise ValueError(f"controlled identity Deny validation report is malformed JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("controlled identity Deny validation report must be a JSON object")
    return payload


def _validate_top_level(report: dict[str, Any]) -> None:
    _reject_forbidden_keys(report)
    _require_fields(report, REQUIRED_TOP_LEVEL_FIELDS, context="controlled identity Deny validation report")
    _reject_unknown_fields(report, ALLOWED_TOP_LEVEL_FIELDS, context="controlled identity Deny validation report")
    _require_non_empty_string(report.get("schema_version"), "schema_version")
    if report["report_type"] != REPORT_TYPE:
        raise ValueError(f"report_type must be {REPORT_TYPE!r}")
    _require_non_empty_string(report.get("validation_id"), "validation_id")
    _require_non_empty_string(report.get("created_at"), "created_at")
    _require_non_empty_string(report.get("environment_label"), "environment_label")
    _require_non_empty_string(report.get("source_principal_arn"), "source_principal_arn")
    _require_non_empty_string(report.get("candidate_action"), "candidate_action")
    _require_non_empty_string(report.get("candidate_resource"), "candidate_resource")
    for forbidden_scope_field in FORBIDDEN_MULTI_SCOPE_FIELDS:
        if forbidden_scope_field in report:
            raise ValueError(
                "controlled identity Deny validation report must contain one source/action/resource/Deny only: "
                f"{forbidden_scope_field}"
            )


def _validate_finding_reference(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("finding_reference must be an object")
    _require_fields(value, REQUIRED_FINDING_REFERENCE_FIELDS, context="finding_reference")
    _reject_unknown_fields(value, ALLOWED_FINDING_REFERENCE_FIELDS, context="finding_reference")
    if not any(value.get(field) for field in ("finding_id", "path_id", "validation_layer_id")):
        raise ValueError("finding_reference requires finding_id, path_id, or validation_layer_id")
    if not any(value.get(field) for field in ("source_document", "source_bundle")):
        raise ValueError("finding_reference requires source_document or source_bundle")
    for field in REQUIRED_FINDING_REFERENCE_FIELDS:
        _require_non_empty_string(value.get(field), f"finding_reference.{field}")
    for field in ("finding_id", "path_id", "validation_layer_id", "source_document", "source_bundle"):
        if field in value and value[field] is not None:
            _require_non_empty_string(value[field], f"finding_reference.{field}")


def _validate_allow_basis(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("allow_basis must be an object")
    _require_fields(value, REQUIRED_ALLOW_BASIS_FIELDS, context="allow_basis")
    _reject_unknown_fields(value, ALLOWED_ALLOW_BASIS_FIELDS, context="allow_basis")
    if not isinstance(value["allow_present"], bool):
        raise ValueError("allow_basis.allow_present must be a boolean")
    if value["allow_source_type"] not in ALLOWED_ALLOW_SOURCE_TYPES:
        raise ValueError(f"unsupported allow_basis.allow_source_type: {value['allow_source_type']!r}")
    for field in ("allowed_action_match", "allowed_resource_match"):
        if not isinstance(value[field], bool):
            raise ValueError(f"allow_basis.{field} must be a boolean")
    _require_non_empty_string(value.get("allow_statement_summary"), "allow_basis.allow_statement_summary")
    _require_non_empty_string(value.get("allow_condition_context"), "allow_basis.allow_condition_context")
    _require_string_list(value.get("caveats"), "allow_basis.caveats")


def _validate_deny_basis(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("deny_basis must be an object")
    _require_fields(value, REQUIRED_DENY_BASIS_FIELDS, context="deny_basis")
    _reject_unknown_fields(value, ALLOWED_DENY_BASIS_FIELDS, context="deny_basis")
    if not isinstance(value["deny_present"], bool):
        raise ValueError("deny_basis.deny_present must be a boolean")
    if value["deny_source_type"] not in ALLOWED_DENY_SOURCE_TYPES:
        raise ValueError(f"unsupported deny_basis.deny_source_type: {value['deny_source_type']!r}")
    for field in ("denied_action_match", "denied_resource_match", "explicit_deny_applies"):
        if not isinstance(value[field], bool):
            raise ValueError(f"deny_basis.{field} must be a boolean")
    _require_non_empty_string(value.get("deny_statement_summary"), "deny_basis.deny_statement_summary")
    _require_non_empty_string(value.get("deny_condition_context"), "deny_basis.deny_condition_context")
    _require_string_list(value.get("caveats"), "deny_basis.caveats")
    if value["deny_present"] is not True:
        raise ValueError("deny_basis.deny_present must be true for this report type")


def _validate_condition_context(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("condition_context must be an object")


def _validate_predicted_behavior(value: Any, report: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise ValueError("predicted_behavior must be an object")
    _require_fields(value, REQUIRED_PREDICTED_BEHAVIOR_FIELDS, context="predicted_behavior")
    _reject_unknown_fields(value, ALLOWED_PREDICTED_BEHAVIOR_FIELDS, context="predicted_behavior")
    if value["predicted_outcome"] not in ALLOWED_PREDICTED_OUTCOMES:
        raise ValueError(f"unsupported predicted_behavior.predicted_outcome: {value['predicted_outcome']!r}")
    _require_non_empty_string(value.get("predicted_action"), "predicted_behavior.predicted_action")
    _require_non_empty_string(value.get("predicted_resource"), "predicted_behavior.predicted_resource")
    _require_non_empty_string(value.get("prediction_basis"), "predicted_behavior.prediction_basis")
    _require_string_list(value.get("prediction_caveats"), "predicted_behavior.prediction_caveats")
    if value["predicted_action"] != report["candidate_action"]:
        raise ValueError("predicted_behavior.predicted_action must match candidate_action")
    if value["predicted_resource"] != report["candidate_resource"]:
        raise ValueError("predicted_behavior.predicted_resource must match candidate_resource")


def _validate_evidence_method(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("evidence_method must be an object")
    _require_fields(value, REQUIRED_EVIDENCE_METHOD_FIELDS, context="evidence_method")
    _reject_unknown_fields(value, ALLOWED_EVIDENCE_METHOD_FIELDS, context="evidence_method")
    method_type = value["method_type"]
    if method_type not in ALLOWED_METHOD_TYPES:
        raise ValueError(f"unsupported evidence_method.method_type: {method_type!r}")
    for field in (
        "live_aws_used",
        "aws_calls_made",
        "active_action_called",
        "destructive_action_called",
        "resource_modified",
    ):
        if not isinstance(value[field], bool):
            raise ValueError(f"evidence_method.{field} must be a boolean")
    if value["destructive_action_called"] is not False:
        raise ValueError("evidence_method.destructive_action_called must be false")
    if value["resource_modified"] is not False:
        raise ValueError("evidence_method.resource_modified must be false")
    if method_type in {"static_policy_corroboration", "no_active_check"}:
        for field in ("live_aws_used", "aws_calls_made", "active_action_called"):
            if value[field] is not False:
                raise ValueError(f"evidence_method.{field} must be false for {method_type}")
    if method_type == "iam_simulation" and value["active_action_called"] is not False:
        raise ValueError("evidence_method.active_action_called must be false for iam_simulation")
    if value["active_action_called"] is True and method_type != "harmless_active_read":
        raise ValueError("evidence_method.active_action_called=true requires harmless_active_read")
    if value["live_aws_used"] is True and method_type not in {"iam_simulation", "harmless_active_read"}:
        raise ValueError("evidence_method.live_aws_used=true requires iam_simulation or harmless_active_read")
    if value["aws_calls_made"] is True and method_type not in {"iam_simulation", "harmless_active_read"}:
        raise ValueError("evidence_method.aws_calls_made=true requires iam_simulation or harmless_active_read")
    if value["active_action_called"] is True and (value["live_aws_used"] is not True or value["aws_calls_made"] is not True):
        raise ValueError("evidence_method.active_action_called=true requires live_aws_used=true and aws_calls_made=true")
    if not isinstance(value["output_paths"], list):
        raise ValueError("evidence_method.output_paths must be a list")
    if any(not isinstance(path, str) or not path.strip() for path in value["output_paths"]):
        raise ValueError("evidence_method.output_paths must contain only non-empty strings")
    if value["safe_error_category"] is not None:
        _require_non_empty_string(value["safe_error_category"], "evidence_method.safe_error_category")


def _validate_observed_or_static_evidence(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("observed_or_static_evidence must be an object")
    _require_fields(
        value,
        REQUIRED_OBSERVED_OR_STATIC_EVIDENCE_FIELDS,
        context="observed_or_static_evidence",
    )
    _reject_unknown_fields(
        value,
        ALLOWED_OBSERVED_OR_STATIC_EVIDENCE_FIELDS,
        context="observed_or_static_evidence",
    )
    if value["observed_outcome"] not in ALLOWED_OBSERVED_OUTCOMES:
        raise ValueError(f"unsupported observed_or_static_evidence.observed_outcome: {value['observed_outcome']!r}")
    _require_non_empty_string(value.get("static_allow_summary"), "observed_or_static_evidence.static_allow_summary")
    _require_non_empty_string(value.get("static_deny_summary"), "observed_or_static_evidence.static_deny_summary")
    _require_non_empty_string(
        value.get("condition_evaluation_summary"),
        "observed_or_static_evidence.condition_evaluation_summary",
    )
    _require_string_list(value.get("sanitized_reasons"), "observed_or_static_evidence.sanitized_reasons")
    if "no_raw_credentials" in value and value["no_raw_credentials"] is not True:
        raise ValueError("observed_or_static_evidence.no_raw_credentials must be true when supplied")
    if "no_raw_aws_errors" in value and value["no_raw_aws_errors"] is not True:
        raise ValueError("observed_or_static_evidence.no_raw_aws_errors must be true when supplied")


def _validate_outcome_classification(value: Any) -> None:
    if value not in ALLOWED_OUTCOME_CLASSIFICATIONS:
        raise ValueError(f"unsupported outcome_classification: {value!r}")


def _validate_summary_lists(report: dict[str, Any]) -> None:
    _require_non_empty_string(report.get("evidence_summary"), "evidence_summary")
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
    for field in (
        "raw_artifacts_committed",
        "credentials_committed",
        "tmp_outputs_committed",
        "destructive_actions",
        "resource_modifications",
    ):
        if value[field] is not False:
            raise ValueError(f"artifact_safety_status.{field} must be false")
    if value["sanitized_summary_only"] is not True:
        raise ValueError("artifact_safety_status.sanitized_summary_only must be true")
    if not isinstance(value["reviewer_checked"], bool):
        raise ValueError("artifact_safety_status.reviewer_checked must be a boolean")


def _reject_forbidden_keys(value: Any, *, path: str = "$") -> None:
    reject_forbidden_report_keys(
        value,
        forbidden_key_terms=FORBIDDEN_KEY_TERMS,
        allowed_safe_keys=ALLOWED_SAFE_KEYS,
        report_label="controlled identity Deny validation report",
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
    evidence_method = report["evidence_method"]
    return {
        "report_type": VALIDATION_SUMMARY_TYPE,
        "valid": True,
        "report_path": str(report_path) if report_path is not None else "in_memory",
        "validated_report_type": report["report_type"],
        "schema_version": report["schema_version"],
        "validation_id": report["validation_id"],
        "environment_label": report["environment_label"],
        "finding_or_path_id": finding_reference.get("finding_id")
        or finding_reference.get("path_id")
        or finding_reference.get("validation_layer_id"),
        "source_principal_arn": report["source_principal_arn"],
        "candidate_action": report["candidate_action"],
        "candidate_resource": report["candidate_resource"],
        "method_type": evidence_method["method_type"],
        "outcome_classification": report["outcome_classification"],
        "observed_outcome": report["observed_or_static_evidence"]["observed_outcome"],
        "live_aws_used": evidence_method["live_aws_used"],
        "aws_calls_made": evidence_method["aws_calls_made"],
        "active_action_called": evidence_method["active_action_called"],
        "destructive_action_called": evidence_method["destructive_action_called"],
        "resource_modified": evidence_method["resource_modified"],
        "artifact_safety_status": {
            "raw_artifacts_committed": report["artifact_safety_status"]["raw_artifacts_committed"],
            "credentials_committed": report["artifact_safety_status"]["credentials_committed"],
            "tmp_outputs_committed": report["artifact_safety_status"]["tmp_outputs_committed"],
            "destructive_actions": report["artifact_safety_status"]["destructive_actions"],
            "resource_modifications": report["artifact_safety_status"]["resource_modifications"],
            "sanitized_summary_only": report["artifact_safety_status"]["sanitized_summary_only"],
            "reviewer_checked": report["artifact_safety_status"]["reviewer_checked"],
        },
        "caveats": [
            "shape_validation_only: this validator checks report JSON shape and safety boundaries only",
            "no_aws_calls: this validator does not call AWS, STS, iam:PassRole, or Lambda APIs",
            "no_active_validation: this validator does not perform active validation or modify resources",
            "no_generic_deny_correctness: this validator does not prove generic Deny correctness",
            "no_composite_score: this validator does not emit aggregate scoring",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate one controlled identity Deny validation report JSON without calling AWS."
    )
    parser.add_argument("--report", required=True, type=Path, help="Controlled identity Deny validation report JSON file.")
    args = parser.parse_args(argv)

    try:
        summary = validate_report_from_path(args.report)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
