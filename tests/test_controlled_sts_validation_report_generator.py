from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_sts_validation_report import validate_report
from benchmarks.runtime.controlled_sts_validation_report_generator import build_report, write_report


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


def test_denied_case_report_generation() -> None:
    report = build_report("denied")

    assert report["finding_reference"]["source_principal_arn"] == "arn:aws:iam::516525145310:user/iamscope-admin"
    assert report["finding_reference"]["target_role_arn"] == "arn:aws:iam::516525145310:role/arf-rt-DevRole"
    assert report["predicted_behavior"]["predicted_outcome"] == "denied"
    assert report["observed_behavior"]["observed_outcome"] == "denied"
    assert report["outcome_classification"] == "corroborated"
    assert report["runtime_probe"]["credentials_obtained"] is False
    assert report["runtime_probe"]["downstream_actions_performed"] is False


def test_assumed_case_report_generation() -> None:
    report = build_report("assumed")

    assert (
        report["finding_reference"]["source_principal_arn"] == "arn:aws:iam::516525145310:user/iamscope-positive-source"
    )
    assert (
        report["finding_reference"]["target_role_arn"] == "arn:aws:iam::516525145310:role/iamscope-positive-target-role"
    )
    assert report["predicted_behavior"]["predicted_outcome"] == "assumed"
    assert report["observed_behavior"]["observed_outcome"] == "assumed"
    assert report["outcome_classification"] == "corroborated"
    assert report["runtime_probe"]["credentials_obtained"] is True
    assert report["runtime_probe"]["downstream_actions_performed"] is False


@pytest.mark.parametrize("case", ["denied", "assumed"])
def test_generated_report_passes_validator(case: str, tmp_path: Path) -> None:
    output_path = tmp_path / f"{case}-controlled-sts-validation-report.json"

    generation_summary = write_report(case=case, json_out=output_path)
    report = json.loads(output_path.read_text(encoding="utf-8"))
    validation_summary = validate_report(report)

    assert generation_summary["generated"] is True
    assert generation_summary["case"] == case
    assert generation_summary["validated_before_write"] is True
    assert validation_summary["valid"] is True
    assert validation_summary["outcome_classification"] == "corroborated"


def test_unknown_case_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported controlled STS validation report case"):
        build_report("unknown")


def test_output_path_required_for_script() -> None:
    result = subprocess.run(
        ["bash", "scripts/generate_controlled_sts_validation_report.sh", "--case", "denied"],
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert "--json-out" in result.stderr


def test_assumed_report_has_no_raw_credential_or_scoring_fields() -> None:
    report = build_report("assumed")
    serialized = json.dumps(report).lower()
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
    assert "accesskeyid" not in serialized
    assert "secretaccesskey" not in serialized
    assert "sessiontoken" not in serialized


def test_safe_credential_booleans_remain_present() -> None:
    report = build_report("assumed")

    assert report["runtime_probe"]["credentials_obtained"] is True
    assert report["artifact_safety_status"]["credentials_committed"] is False
    assert report["artifact_safety_status"]["credential_shaped_fields_present"] is False
    assert report["observed_behavior"]["no_raw_credentials"] is True


def test_repo_local_output_rejected_by_default(tmp_path: Path) -> None:
    repo_output_path = Path.cwd() / "controlled-sts-validation-report.generated.json"

    with pytest.raises(ValueError, match="refusing to write controlled STS validation report inside the repository"):
        write_report(case="denied", json_out=repo_output_path, repo_root=Path.cwd())

    assert not repo_output_path.exists()


def test_script_execution_with_tmp_output_path(tmp_path: Path) -> None:
    output_path = tmp_path / "controlled-sts-assumed-validation-report.json"
    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_sts_validation_report.sh",
            "--case",
            "assumed",
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
    assert generation_summary["case"] == "assumed"
    assert validate_report(report)["valid"] is True


def test_generator_requires_no_aws_credentials(tmp_path: Path) -> None:
    output_path = tmp_path / "controlled-sts-denied-validation-report.json"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}

    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_sts_validation_report.sh",
            "--case",
            "denied",
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
    import benchmarks.runtime.controlled_sts_validation_report_generator as generator

    module_source = Path(generator.__file__).read_text(encoding="utf-8")
    assert "boto3" not in module_source
    assert "botocore" not in module_source
    assert ".client(" not in module_source
    assert "assume_role(" not in module_source
