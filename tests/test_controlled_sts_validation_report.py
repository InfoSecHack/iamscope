from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_sts_validation_report import validate_report


def _base_report(*, predicted_outcome: str = "assumed", observed_outcome: str = "assumed") -> dict[str, Any]:
    credentials_obtained = observed_outcome == "assumed"
    return {
        "schema_version": "controlled-sts-validation-report/v1",
        "report_type": "controlled_sts_validation_report",
        "validation_id": "controlled-sts-test-001",
        "created_at": "2026-05-16T00:00:00Z",
        "environment_label": "controlled-test-lab",
        "input_bundle_reference": "frozen-sanitized-bundle",
        "finding_reference": {
            "path_id": "path-001",
            "source_principal_arn": "arn:aws:iam::123456\u003789012:user/example-source",
            "target_role_arn": "arn:aws:iam::123456\u003789012:role/example-target-role",
            "expected_account_id": "123456\u003789012",
            "reasoner_or_finding_type": "sts_assume_role_path",
            "prediction_source": "selected sanitized IAMScope finding summary",
            "source_bundle": "frozen-sanitized-bundle",
        },
        "predicted_behavior": {
            "predicted_action": "sts:AssumeRole",
            "predicted_outcome": predicted_outcome,
            "prediction_basis": "sanitized trust and permission summary",
            "prediction_caveats": ["selected path only", "controlled test environment only"],
        },
        "runtime_probe": {
            "probe_id": "sts-probe-001",
            "probe_type": "sts_assume_role",
            "mode": "live_probe",
            "operator_confirmation_used": True,
            "live_aws_used": True,
            "aws_calls_made": True,
            "sts_assume_role_called": True,
            "downstream_actions_performed": False,
            "credentials_obtained": credentials_obtained,
            "output_paths": {
                "json": "/tmp/example-controlled-sts-validation.json",
                "markdown": "/tmp/example-controlled-sts-validation.md",
            },
            "safe_error_category": "none" if credentials_obtained else "access_denied",
        },
        "observed_behavior": {
            "observed_outcome": observed_outcome,
            "observed_account_id": "123456\u003789012",
            "result_classification": observed_outcome,
            "sanitized_reasons": ["safe summary only"],
            "no_raw_credentials": True,
            "no_raw_aws_errors": True,
        },
        "outcome_classification": "corroborated",
        "evidence_summary": {
            "sanitized_inputs": "one selected source principal and one target role",
            "runtime_observation": f"one STS AssumeRole attempt was {observed_outcome}",
            "manual_context_review": "safe trust and permission context summary",
        },
        "caveats": [
            "one selected finding/path only",
            "one controlled environment only",
            "no downstream AWS actions",
        ],
        "non_claims": [
            "no production readiness",
            "no broad IAMScope correctness",
            "no arbitrary enterprise graph correctness",
            "no broad runtime exploitability",
            "no downstream authorization proof",
            "no resource-policy Deny support unless explicitly in scope",
            "no finding-level reachability unless explicitly in scope",
        ],
        "artifact_safety_status": {
            "raw_artifacts_committed": False,
            "credentials_committed": False,
            "tmp_outputs_committed": False,
            "downstream_actions": False,
            "sanitized_summary_only": True,
            "reviewer_checked": True,
        },
    }


def _assert_rejected(report: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        validate_report(report)


def test_valid_minimal_corrobated_assumed_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="assumed", observed_outcome="assumed"))

    assert summary["valid"] is True
    assert summary["outcome_classification"] == "corroborated"
    assert summary["credentials_obtained"] is True
    assert summary["downstream_actions_performed"] is False


def test_valid_minimal_corrobated_denied_report() -> None:
    summary = validate_report(_base_report(predicted_outcome="denied", observed_outcome="denied"))

    assert summary["valid"] is True
    assert summary["observed_outcome"] == "denied"
    assert summary["credentials_obtained"] is False


def test_missing_required_top_level_field_rejected() -> None:
    report = _base_report()
    del report["validation_id"]

    _assert_rejected(report, "missing required field")


def test_wrong_report_type_rejected() -> None:
    report = _base_report()
    report["report_type"] = "wrong"

    _assert_rejected(report, "report_type")


def test_multiple_finding_references_rejected() -> None:
    report = _base_report()
    report["finding_reference"] = [report["finding_reference"]]

    _assert_rejected(report, "finding_reference must be an object")


@pytest.mark.parametrize(
    "field_name",
    [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "credentials",
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
    report["runtime_probe"][field_name] = "unsafe"

    _assert_rejected(report, "forbidden controlled STS validation report field")


def test_nested_forbidden_field_rejected_recursively() -> None:
    report = _base_report()
    report["runtime_probe"]["output_paths"]["nested"] = [{"secret_value": "unsafe"}]

    _assert_rejected(report, "forbidden controlled STS validation report field")


def test_credentials_obtained_safe_boolean_field_allowed() -> None:
    summary = validate_report(_base_report())

    assert summary["credentials_obtained"] is True


def test_credentials_committed_safe_artifact_boolean_field_allowed() -> None:
    summary = validate_report(_base_report())

    assert summary["artifact_safety_status"]["credentials_committed"] is False


def test_composite_score_rejected() -> None:
    report = _base_report()
    report["composite_score"] = 1

    _assert_rejected(report, "forbidden controlled STS validation report field")


@pytest.mark.parametrize("field_name", ["pass_fail", "pass", "fail", "composite_score"])
def test_pass_fail_style_field_rejected(field_name: str) -> None:
    report = _base_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled STS validation report field")


@pytest.mark.parametrize("field_name", ["vulnerable", "exploited", "production_ready", "benchmark_passed"])
def test_overclaim_field_rejected(field_name: str) -> None:
    report = _base_report()
    report[field_name] = True

    _assert_rejected(report, "forbidden controlled STS validation report field")


def test_invalid_outcome_classification_rejected() -> None:
    report = _base_report()
    report["outcome_classification"] = "pass"

    _assert_rejected(report, "unsupported outcome_classification")


def test_downstream_actions_performed_true_rejected() -> None:
    report = _base_report()
    report["runtime_probe"]["downstream_actions_performed"] = True

    _assert_rejected(report, "downstream_actions_performed must be false")


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("raw_artifacts_committed", True),
        ("credentials_committed", True),
        ("tmp_outputs_committed", True),
        ("downstream_actions", True),
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
    report["observed_behavior"]["observed_outcome"] = "vulnerable"

    _assert_rejected(report, "observed_outcome")


def test_validator_script_works_on_temp_json_file(tmp_path: Path) -> None:
    report_path = tmp_path / "controlled-sts-report.json"
    report_path.write_text(json.dumps(_base_report()), encoding="utf-8")

    result = subprocess.run(
        ["bash", "scripts/validate_controlled_sts_validation_report.sh", "--report", str(report_path)],
        check=True,
        text=True,
        capture_output=True,
    )

    summary = json.loads(result.stdout)
    assert summary["valid"] is True
    assert summary["report_path"] == str(report_path)
    assert summary["caveats"][1] == "no_aws_calls: this validator does not call AWS or STS AssumeRole"


def test_validator_has_no_aws_dependency() -> None:
    import benchmarks.runtime.controlled_sts_validation_report as validator

    module_names = set(validator.__dict__)
    assert "boto3" not in module_names
    assert "botocore" not in module_names
