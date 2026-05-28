from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_passrole_validation_report import validate_report


def _base_report(*, predicted_outcome: str = "allowed", observed_outcome: str = "allowed") -> dict[str, Any]:
    return {
        "schema_version": "controlled-passrole-validation-report/v0",
        "report_type": "controlled_passrole_validation_report",
        "validation_id": "controlled-passrole-test-001",
        "created_at": "2026-05-19T00:00:00Z",
        "environment_label": "controlled-passrole-test-lab",
        "input_bundle_reference": "frozen-sanitized-passrole-bundle",
        "finding_reference": {
            "validation_layer_id": "validation-layer-passrole-test-001",
            "source_principal_arn": "arn:aws:iam::123456789012:user/example-source",
            "target_role_arn": "arn:aws:iam::123456789012:role/example-service-role",
            "service_principal": "lambda.amazonaws.com",
            "expected_account_id": "123456789012",
            "reasoner_or_finding_type": "passrole_lambda",
            "prediction_source": "selected sanitized IAMScope PassRole summary",
            "source_document": "docs/example/sanitized-passrole-selection.md",
            "source_bundle": "frozen-sanitized-passrole-bundle",
        },
        "predicted_behavior": {
            "predicted_action": "iam:PassRole",
            "predicted_service_principal": "lambda.amazonaws.com",
            "predicted_target_role_arn": "arn:aws:iam::123456789012:role/example-service-role",
            "predicted_outcome": predicted_outcome,
            "prediction_basis": "sanitized permission and trust summary",
            "prediction_caveats": ["selected path only", "controlled test environment only"],
        },
        "evidence_method": {
            "method_type": "static_policy_trust_corroboration",
            "live_aws_used": False,
            "aws_calls_made": False,
            "iam_passrole_called": False,
            "service_launch_attempted": False,
            "downstream_actions_performed": False,
            "output_paths": [],
            "safe_error_category": "none",
        },
        "observed_evidence": {
            "source_permission_evidence": "sanitized source-side iam:PassRole permission summary",
            "target_trust_evidence": "sanitized target role trust summary",
            "service_principal_match": "matched",
            "condition_context": "no modeled condition context required for this static test",
            "observed_outcome": observed_outcome,
            "sanitized_reasons": ["source_permission_matches", "target_trust_matches"],
            "no_raw_credentials": True,
            "no_raw_aws_errors": True,
        },
        "outcome_classification": "corroborated",
        "evidence_summary": "Static sanitized evidence corroborates one selected PassRole prediction.",
        "caveats": [
            "one selected finding/path only",
            "one controlled environment only",
            "no service launch",
            "no downstream AWS actions",
        ],
        "non_claims": [
            "no production readiness",
            "no broad IAMScope correctness",
            "no arbitrary enterprise graph correctness",
            "no broad runtime exploitability",
            "no downstream service execution proof",
            "no downstream authorization proof",
        ],
        "artifact_safety_status": {
            "raw_artifacts_committed": False,
            "credentials_committed": False,
            "tmp_outputs_committed": False,
            "downstream_actions": False,
            "service_launch_attempted": False,
            "sanitized_summary_only": True,
            "reviewer_checked": True,
        },
    }


def _assert_rejected(report: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        validate_report(report)


def test_valid_minimal_corrobated_allowed_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="allowed", observed_outcome="allowed"))

    assert summary["valid"] is True
    assert summary["outcome_classification"] == "corroborated"
    assert summary["method_type"] == "static_policy_trust_corroboration"
    assert summary["iam_passrole_called"] is False
    assert summary["service_launch_attempted"] is False
    assert summary["downstream_actions_performed"] is False


def test_valid_minimal_corrobated_denied_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="denied", observed_outcome="denied"))

    assert summary["valid"] is True
    assert summary["observed_outcome"] == "denied"
    assert summary["iam_passrole_called"] is False


def test_missing_required_top_level_field_rejected() -> None:
    report = _base_report()
    del report["validation_id"]

    _assert_rejected(report, "missing required field")


def test_wrong_report_type_rejected() -> None:
    report = _base_report()
    report["report_type"] = "wrong"

    _assert_rejected(report, "report_type")


def test_missing_native_id_and_validation_layer_id_rejected() -> None:
    report = _base_report()
    report["finding_reference"].pop("validation_layer_id")

    _assert_rejected(report, "finding_id, path_id, or validation_layer_id")


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
        "accesskeyid",
        "secretaccesskey",
        "sessiontoken",
    ],
)
def test_forbidden_credential_shaped_field_rejected(field_name: str) -> None:
    report = _base_report()
    report["observed_evidence"][field_name] = "unsafe"

    _assert_rejected(report, "forbidden controlled PassRole validation report field")


def test_nested_forbidden_field_rejected_recursively() -> None:
    report = _base_report()
    report["condition_context"] = {"nested": [{"secret_value": "unsafe"}]}

    _assert_rejected(report, "forbidden controlled PassRole validation report field")


def test_credentials_committed_safe_artifact_boolean_field_allowed() -> None:
    summary = validate_report(_base_report())

    assert summary["artifact_safety_status"]["credentials_committed"] is False


def test_no_raw_credentials_safe_metadata_field_allowed() -> None:
    summary = validate_report(_base_report())

    assert summary["valid"] is True


@pytest.mark.parametrize("field_name", ["composite_score", "overall_score"])
def test_composite_score_rejected(field_name: str) -> None:
    report = _base_report()
    report[field_name] = 1

    _assert_rejected(report, "forbidden controlled PassRole validation report field")


@pytest.mark.parametrize("field_name", ["pass_fail", "pass", "fail", "benchmark_passed"])
def test_pass_fail_style_field_rejected(field_name: str) -> None:
    report = _base_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled PassRole validation report field")


@pytest.mark.parametrize("field_name", ["vulnerable", "exploited", "production_ready"])
def test_overclaim_field_rejected(field_name: str) -> None:
    report = _base_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled PassRole validation report field")


def test_invalid_outcome_classification_rejected() -> None:
    report = _base_report()
    report["outcome_classification"] = "pass"

    _assert_rejected(report, "unsupported outcome_classification")


def test_iam_passrole_called_true_rejected() -> None:
    report = _base_report()
    report["evidence_method"]["iam_passrole_called"] = True

    _assert_rejected(report, "iam_passrole_called must be false")


def test_service_launch_attempted_true_rejected() -> None:
    report = _base_report()
    report["evidence_method"]["service_launch_attempted"] = True

    _assert_rejected(report, "service_launch_attempted must be false")


def test_downstream_actions_performed_true_rejected() -> None:
    report = _base_report()
    report["evidence_method"]["downstream_actions_performed"] = True

    _assert_rejected(report, "downstream_actions_performed must be false")


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("raw_artifacts_committed", True),
        ("credentials_committed", True),
        ("tmp_outputs_committed", True),
        ("downstream_actions", True),
        ("service_launch_attempted", True),
        ("sanitized_summary_only", False),
    ],
)
def test_artifact_safety_flags_unsafe_rejected(field_name: str, value: bool) -> None:
    report = _base_report()
    report["artifact_safety_status"][field_name] = value

    _assert_rejected(report, field_name)


def test_missing_non_claims_rejected() -> None:
    report = _base_report()
    report["non_claims"] = ["no production readiness"]

    _assert_rejected(report, "non_claims missing required coverage")


def test_invalid_observed_outcome_rejected() -> None:
    report = _base_report()
    report["observed_evidence"]["observed_outcome"] = "vulnerable"

    _assert_rejected(report, "observed_outcome")


def test_validator_script_works_on_temp_json_file(tmp_path: Path) -> None:
    report_path = tmp_path / "controlled-passrole-report.json"
    report_path.write_text(json.dumps(_base_report()), encoding="utf-8")

    result = subprocess.run(
        ["bash", "scripts/validate_controlled_passrole_validation_report.sh", "--report", str(report_path)],
        check=True,
        text=True,
        capture_output=True,
    )

    summary = json.loads(result.stdout)
    assert summary["valid"] is True
    assert summary["report_path"] == str(report_path)
    assert summary["caveats"][1] == "no_aws_calls: this validator does not call AWS, iam:PassRole, or STS AssumeRole"


def test_validator_makes_no_aws_calls_and_requires_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    summary = validate_report(_base_report())

    assert summary["valid"] is True
    assert summary["iam_passrole_called"] is False
    assert summary["service_launch_attempted"] is False


def test_validator_has_no_aws_dependency() -> None:
    import benchmarks.runtime.controlled_passrole_validation_report as validator

    module_names = set(validator.__dict__)
    assert "boto3" not in module_names
    assert "botocore" not in module_names
