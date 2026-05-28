from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_passrole_validation_report import validate_report
from benchmarks.runtime.controlled_passrole_validation_report_generator import build_report, write_report

SUPPORTED_CASE_EXPECTATIONS = {
    "corroborated_allowed_static": ("allowed", "allowed", "corroborated"),
    "corroborated_denied_static": ("denied", "denied", "corroborated"),
    "inconclusive_static": ("inconclusive", "inconclusive", "inconclusive"),
}


def _walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        keys = list(value)
        for child in value.values():
            keys.extend(_walk_keys(child))
        return keys
    if isinstance(value, list):
        keys: list[str] = []
        for child in value:
            keys.extend(_walk_keys(child))
        return keys
    return []


@pytest.mark.parametrize("case", sorted(SUPPORTED_CASE_EXPECTATIONS))
def test_static_report_generation_cases(case: str) -> None:
    predicted_outcome, observed_outcome, outcome_classification = SUPPORTED_CASE_EXPECTATIONS[case]

    report = build_report(case)

    assert report["report_type"] == "controlled_passrole_validation_report"
    assert report["validation_id"] == f"controlled-passrole-{case}-summary-001"
    assert report["predicted_behavior"]["predicted_outcome"] == predicted_outcome
    assert report["observed_evidence"]["observed_outcome"] == observed_outcome
    assert report["outcome_classification"] == outcome_classification
    assert report["evidence_method"]["method_type"] == "static_policy_trust_corroboration"
    assert report["evidence_method"]["iam_passrole_called"] is False
    assert report["evidence_method"]["service_launch_attempted"] is False
    assert report["evidence_method"]["downstream_actions_performed"] is False


@pytest.mark.parametrize("case", sorted(SUPPORTED_CASE_EXPECTATIONS))
def test_generated_report_passes_validator(case: str, tmp_path: Path) -> None:
    output_path = tmp_path / f"{case}-controlled-passrole-validation-report.json"

    generation_summary = write_report(case=case, json_out=output_path)
    report = json.loads(output_path.read_text(encoding="utf-8"))
    validation_summary = validate_report(report)

    assert generation_summary["generated"] is True
    assert generation_summary["case"] == case
    assert generation_summary["validated_before_write"] is True
    assert validation_summary["valid"] is True
    assert validation_summary["outcome_classification"] == SUPPORTED_CASE_EXPECTATIONS[case][2]


def test_unknown_case_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported controlled PassRole validation report case"):
        build_report("unknown")


def test_missing_json_out_rejected_by_script() -> None:
    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_passrole_validation_report.sh",
            "--case",
            "corroborated_allowed_static",
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert "--json-out" in result.stderr


def test_repo_local_output_rejected_by_default() -> None:
    repo_output_path = Path.cwd() / "controlled-passrole-validation-report.generated.json"

    with pytest.raises(
        ValueError, match="refusing to write controlled PassRole validation report inside the repository"
    ):
        write_report(case="corroborated_allowed_static", json_out=repo_output_path, repo_root=Path.cwd())

    assert not repo_output_path.exists()


def test_generated_report_has_no_credential_or_scoring_fields() -> None:
    report = build_report("corroborated_allowed_static")
    keys = set(_walk_keys(report))

    assert "AccessKeyId" not in keys
    assert "SecretAccessKey" not in keys
    assert "SessionToken" not in keys
    assert "raw_credentials" not in keys
    assert "aws_session_token" not in keys
    assert "secret_value" not in keys
    assert "access_key_id" not in keys
    assert "composite_score" not in keys
    assert "pass_fail" not in keys
    assert "vulnerable" not in keys
    assert "exploited" not in keys
    assert "production_ready" not in keys


@pytest.mark.parametrize("case", sorted(SUPPORTED_CASE_EXPECTATIONS))
def test_generated_report_runtime_action_flags_are_false(case: str) -> None:
    report = build_report(case)

    assert report["evidence_method"]["iam_passrole_called"] is False
    assert report["evidence_method"]["service_launch_attempted"] is False
    assert report["evidence_method"]["downstream_actions_performed"] is False
    assert report["artifact_safety_status"]["service_launch_attempted"] is False
    assert report["artifact_safety_status"]["downstream_actions"] is False


def test_script_execution_with_tmp_output_path(tmp_path: Path) -> None:
    output_path = tmp_path / "controlled-passrole-denied-validation-report.json"
    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_passrole_validation_report.sh",
            "--case",
            "corroborated_denied_static",
            "--json-out",
            str(output_path),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    generation_summary = json.loads(result.stdout)
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert generation_summary["generated"] is True
    assert generation_summary["case"] == "corroborated_denied_static"
    assert generation_summary["validated_before_write"] is True
    assert validate_report(report)["valid"] is True


def test_generator_requires_no_aws_credentials(tmp_path: Path) -> None:
    output_path = tmp_path / "controlled-passrole-inconclusive-validation-report.json"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}

    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_passrole_validation_report.sh",
            "--case",
            "inconclusive_static",
            "--json-out",
            str(output_path),
        ],
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )

    assert json.loads(result.stdout)["generated"] is True
    assert output_path.exists()


def test_generator_has_no_boto3_import_or_aws_call_path() -> None:
    import benchmarks.runtime.controlled_passrole_validation_report_generator as generator

    module_source = Path(generator.__file__).read_text(encoding="utf-8")
    assert "boto3" not in module_source
    assert "botocore" not in module_source
    assert ".client(" not in module_source
    assert "pass_role(" not in module_source
    assert "assume_role(" not in module_source
