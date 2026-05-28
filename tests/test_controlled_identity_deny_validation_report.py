from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_identity_deny_validation_report import validate_report


def _base_report(
    *,
    predicted_outcome: str = "suppressed",
    observed_outcome: str = "suppressed",
    method_type: str = "static_policy_corroboration",
    outcome_classification: str = "corroborated",
) -> dict[str, Any]:
    return {
        "schema_version": "2026-05-identity-deny-v1",
        "report_type": "controlled_identity_deny_validation_report",
        "validation_id": "controlled-identity-deny-test-001",
        "created_at": "2026-05-26T00:00:00Z",
        "environment_label": "controlled-identity-deny-test-lab",
        "input_bundle_reference": "sanitized-identity-deny-bundle",
        "finding_reference": {
            "validation_layer_id": "validation-layer-identity-deny-test-001",
            "reasoner_or_finding_type": "identity_deny_suppression",
            "prediction_source": "selected sanitized IAMScope identity Deny summary",
            "source_document": "docs/example/sanitized-identity-deny-selection.md",
        },
        "source_principal_arn": "arn:aws:iam::123456789012:user/example-source",
        "candidate_action": "iam:AddUserToGroup",
        "candidate_resource": "arn:aws:iam::123456789012:group/example-admins",
        "allow_basis": {
            "allow_present": True,
            "allow_source_type": "identity_policy",
            "allow_statement_summary": "sanitized Allow statement summary",
            "allowed_action_match": True,
            "allowed_resource_match": True,
            "allow_condition_context": "no relevant Allow condition in sanitized summary",
            "caveats": ["static sanitized summary only"],
        },
        "deny_basis": {
            "deny_present": True,
            "deny_source_type": "identity_policy",
            "deny_statement_summary": "sanitized explicit Deny statement summary",
            "denied_action_match": True,
            "denied_resource_match": True,
            "deny_condition_context": "no relevant Deny condition in sanitized summary",
            "explicit_deny_applies": True,
            "caveats": ["static sanitized summary only"],
        },
        "condition_context": {
            "context_keys_required": [],
            "context_values_supplied": {},
            "condition_caveats": [],
        },
        "predicted_behavior": {
            "predicted_action": "iam:AddUserToGroup",
            "predicted_resource": "arn:aws:iam::123456789012:group/example-admins",
            "predicted_outcome": predicted_outcome,
            "prediction_basis": "explicit identity Deny suppresses structurally allowed action",
            "prediction_caveats": ["selected case only", "controlled test environment only"],
        },
        "evidence_method": {
            "method_type": method_type,
            "live_aws_used": False,
            "aws_calls_made": False,
            "active_action_called": False,
            "destructive_action_called": False,
            "resource_modified": False,
            "output_paths": [],
            "safe_error_category": None,
        },
        "observed_or_static_evidence": {
            "observed_outcome": observed_outcome,
            "static_allow_summary": "Allow side matches the selected action and resource in sanitized metadata.",
            "static_deny_summary": "Explicit identity Deny matches the selected action and resource.",
            "condition_evaluation_summary": "No unsatisfied Deny condition in sanitized summary.",
            "sanitized_reasons": ["allow_matches", "explicit_identity_deny_applies"],
            "no_raw_credentials": True,
            "no_raw_aws_errors": True,
        },
        "outcome_classification": outcome_classification,
        "evidence_summary": "Static sanitized evidence corroborates one selected identity Deny suppression case.",
        "caveats": [
            "one selected source/action/resource only",
            "static evidence only",
            "no active validation",
        ],
        "non_claims": [
            "no production readiness",
            "no broad IAMScope correctness",
            "no generic Deny correctness",
            "no resource-policy Deny support",
            "no SCP Deny support",
            "no broad runtime exploitability",
            "no downstream authorization proof",
            "no all-findings-verified claim",
            "no real-world scalability",
        ],
        "artifact_safety_status": {
            "raw_artifacts_committed": False,
            "credentials_committed": False,
            "tmp_outputs_committed": False,
            "destructive_actions": False,
            "resource_modifications": False,
            "sanitized_summary_only": True,
            "reviewer_checked": True,
        },
    }


def _assert_rejected(report: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        validate_report(report)


def _copy_report() -> dict[str, Any]:
    return copy.deepcopy(_base_report())


def test_valid_minimal_corrobated_denied_suppressed_static_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="suppressed", observed_outcome="suppressed"))

    assert summary["valid"] is True
    assert summary["outcome_classification"] == "corroborated"
    assert summary["observed_outcome"] == "suppressed"
    assert summary["method_type"] == "static_policy_corroboration"
    assert summary["live_aws_used"] is False
    assert summary["aws_calls_made"] is False
    assert summary["active_action_called"] is False


def test_valid_minimal_denied_static_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="denied", observed_outcome="denied"))

    assert summary["valid"] is True
    assert summary["observed_outcome"] == "denied"


def test_valid_minimal_inconclusive_no_active_check_report() -> None:
    summary = validate_report(
        _base_report(
            predicted_outcome="inconclusive",
            observed_outcome="inconclusive",
            method_type="no_active_check",
            outcome_classification="inconclusive",
        )
    )

    assert summary["valid"] is True
    assert summary["method_type"] == "no_active_check"
    assert summary["live_aws_used"] is False


def test_missing_required_top_level_field_rejected() -> None:
    report = _copy_report()
    del report["validation_id"]

    _assert_rejected(report, "missing required field")


def test_wrong_report_type_rejected() -> None:
    report = _copy_report()
    report["report_type"] = "wrong"

    _assert_rejected(report, "report_type")


def test_missing_native_id_and_validation_layer_id_rejected() -> None:
    report = _copy_report()
    report["finding_reference"].pop("validation_layer_id")

    _assert_rejected(report, "finding_id, path_id, or validation_layer_id")


def test_missing_deny_basis_rejected() -> None:
    report = _copy_report()
    del report["deny_basis"]

    _assert_rejected(report, "missing required field")


def test_invalid_predicted_outcome_rejected() -> None:
    report = _copy_report()
    report["predicted_behavior"]["predicted_outcome"] = "vulnerable"

    _assert_rejected(report, "predicted_outcome")


def test_invalid_method_type_rejected() -> None:
    report = _copy_report()
    report["evidence_method"]["method_type"] = "live_probe"

    _assert_rejected(report, "method_type")


def test_invalid_observed_outcome_rejected() -> None:
    report = _copy_report()
    report["observed_or_static_evidence"]["observed_outcome"] = "vulnerable"

    _assert_rejected(report, "observed_outcome")


def test_invalid_outcome_classification_rejected() -> None:
    report = _copy_report()
    report["outcome_classification"] = "pass"

    _assert_rejected(report, "unsupported outcome_classification")


@pytest.mark.parametrize(
    "field_name",
    [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "credentials",
        "credential",
        "raw_credentials",
        "aws_session_token",
        "secret_value",
        "access_key_id",
    ],
)
def test_forbidden_credential_shaped_field_rejected(field_name: str) -> None:
    report = _copy_report()
    report["observed_or_static_evidence"][field_name] = "unsafe"

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


def test_nested_forbidden_field_rejected_recursively() -> None:
    report = _copy_report()
    report["condition_context"]["nested"] = [{"secret_value": "unsafe"}]

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


@pytest.mark.parametrize("field_name", ["raw_aws_log", "raw_error"])
def test_raw_aws_log_and_raw_error_rejected(field_name: str) -> None:
    report = _copy_report()
    report["observed_or_static_evidence"][field_name] = "unsafe"

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


def test_safe_metadata_exception_fields_allowed() -> None:
    summary = validate_report(_base_report())

    assert summary["valid"] is True
    assert summary["artifact_safety_status"]["credentials_committed"] is False


@pytest.mark.parametrize("field_name", ["composite_score", "overall_score"])
def test_composite_score_rejected(field_name: str) -> None:
    report = _copy_report()
    report[field_name] = 1

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


@pytest.mark.parametrize("field_name", ["pass_fail", "pass", "fail", "benchmark_passed"])
def test_pass_fail_style_field_rejected(field_name: str) -> None:
    report = _copy_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


@pytest.mark.parametrize("field_name", ["vulnerable", "exploited", "production_ready"])
def test_overclaim_field_rejected(field_name: str) -> None:
    report = _copy_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled identity Deny validation report field")


def test_destructive_action_called_true_rejected() -> None:
    report = _copy_report()
    report["evidence_method"]["destructive_action_called"] = True

    _assert_rejected(report, "destructive_action_called must be false")


def test_resource_modified_true_rejected() -> None:
    report = _copy_report()
    report["evidence_method"]["resource_modified"] = True

    _assert_rejected(report, "resource_modified must be false")


def test_static_method_with_aws_calls_made_true_rejected() -> None:
    report = _copy_report()
    report["evidence_method"]["aws_calls_made"] = True

    _assert_rejected(report, "aws_calls_made must be false")


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("raw_artifacts_committed", True),
        ("credentials_committed", True),
        ("tmp_outputs_committed", True),
        ("destructive_actions", True),
        ("resource_modifications", True),
        ("sanitized_summary_only", False),
    ],
)
def test_artifact_safety_flags_unsafe_rejected(field_name: str, value: bool) -> None:
    report = _copy_report()
    report["artifact_safety_status"][field_name] = value

    _assert_rejected(report, field_name)


def test_missing_non_claims_rejected() -> None:
    report = _copy_report()
    report["non_claims"] = ["no production readiness"]

    _assert_rejected(report, "non_claims missing required coverage")


def test_validator_script_works_on_temp_json_file(tmp_path: Path) -> None:
    report_path = tmp_path / "controlled-identity-deny-report.json"
    report_path.write_text(json.dumps(_base_report()), encoding="utf-8")

    result = subprocess.run(
        ["bash", "scripts/validate_controlled_identity_deny_validation_report.sh", "--report", str(report_path)],
        check=True,
        text=True,
        capture_output=True,
    )

    summary = json.loads(result.stdout)
    assert summary["valid"] is True
    assert summary["report_path"] == str(report_path)
    assert summary["caveats"][1] == "no_aws_calls: this validator does not call AWS, STS, iam:PassRole, or Lambda APIs"


def test_validator_makes_no_aws_calls_and_requires_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    summary = validate_report(_base_report())

    assert summary["valid"] is True
    assert summary["live_aws_used"] is False
    assert summary["aws_calls_made"] is False
    assert summary["active_action_called"] is False


def test_validator_has_no_aws_dependency() -> None:
    import benchmarks.runtime.controlled_identity_deny_validation_report as validator

    module_names = set(validator.__dict__)
    assert "boto3" not in module_names
    assert "botocore" not in module_names
