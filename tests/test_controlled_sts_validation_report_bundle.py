from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.controlled_sts_validation_report import validate_report_from_path
from benchmarks.runtime.controlled_sts_validation_report_bundle import (
    ARTIFACT_SAFETY_MANIFEST_FILENAME,
    ASSUMED_REPORT_FILENAME,
    BUNDLE_INDEX_FILENAME,
    DENIED_REPORT_FILENAME,
    VALIDATOR_SUMMARY_FILENAME,
    generate_bundle,
)

EXPECTED_FILES = {
    DENIED_REPORT_FILENAME,
    ASSUMED_REPORT_FILENAME,
    BUNDLE_INDEX_FILENAME,
    ARTIFACT_SAFETY_MANIFEST_FILENAME,
    VALIDATOR_SUMMARY_FILENAME,
}


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def test_bundle_generator_creates_expected_files_in_tmp_path(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"

    summary = generate_bundle(out_dir=out_dir)

    assert summary["generated"] is True
    assert set(summary["files"]) == EXPECTED_FILES
    assert {path.name for path in out_dir.iterdir()} == EXPECTED_FILES


def test_denied_report_exists_and_passes_validator(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    validation_summary = validate_report_from_path(out_dir / DENIED_REPORT_FILENAME)

    assert validation_summary["valid"] is True
    assert validation_summary["observed_outcome"] == "denied"
    assert validation_summary["outcome_classification"] == "corroborated"
    assert validation_summary["credentials_obtained"] is False


def test_assumed_report_exists_and_passes_validator(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    validation_summary = validate_report_from_path(out_dir / ASSUMED_REPORT_FILENAME)

    assert validation_summary["valid"] is True
    assert validation_summary["observed_outcome"] == "assumed"
    assert validation_summary["outcome_classification"] == "corroborated"
    assert validation_summary["credentials_obtained"] is True


def test_artifact_safety_manifest_fields_are_safe(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    manifest = _read_json(out_dir / ARTIFACT_SAFETY_MANIFEST_FILENAME)

    assert manifest["bundle_type"] == "controlled_sts_validation_report_bundle"
    assert manifest["raw_artifacts_included"] is False
    assert manifest["credentials_included"] is False
    assert manifest["tmp_proof_outputs_included"] is False
    assert manifest["raw_aws_logs_included"] is False
    assert manifest["terraform_state_included"] is False
    assert manifest["composite_score_included"] is False
    assert manifest["pass_fail_labels_included"] is False
    assert manifest["downstream_actions_claimed"] is False
    assert manifest["sanitized_summaries_only"] is True
    assert manifest["reports_validated"] is True


def test_bundle_index_includes_non_claims(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    index = (out_dir / BUNDLE_INDEX_FILENAME).read_text(encoding="utf-8")

    assert "No production-readiness claim." in index
    assert "No broad runtime exploitability claim." in index
    assert "No broad IAMScope correctness claim." in index
    assert "No composite score." in index
    assert "No pass/fail benchmark label." in index


def test_output_path_required_for_script() -> None:
    result = subprocess.run(
        ["bash", "scripts/generate_controlled_sts_validation_bundle.sh"],
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert "--out-dir" in result.stderr


def test_repo_local_output_path_rejected_by_default() -> None:
    repo_output_path = Path.cwd() / "controlled-sts-validation-bundle.generated"

    with pytest.raises(
        ValueError, match="refusing to write controlled STS validation report bundle inside the repository"
    ):
        generate_bundle(out_dir=repo_output_path, repo_root=Path.cwd())

    assert not repo_output_path.exists()


def test_generated_reports_are_not_committed_by_default(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    result = subprocess.run(["git", "status", "--short"], check=True, text=True, capture_output=True)

    assert str(out_dir) not in result.stdout
    assert DENIED_REPORT_FILENAME not in result.stdout
    assert ASSUMED_REPORT_FILENAME not in result.stdout


def test_script_execution_with_tmp_output_path(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_sts_validation_bundle.sh",
            "--out-dir",
            str(out_dir),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    summary = json.loads(result.stdout)

    assert summary["generated"] is True
    assert set(summary["files"]) == EXPECTED_FILES
    assert (out_dir / VALIDATOR_SUMMARY_FILENAME).exists()


def test_bundle_generator_requires_no_aws_credentials(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}

    result = subprocess.run(
        [
            "bash",
            "scripts/generate_controlled_sts_validation_bundle.sh",
            "--out-dir",
            str(out_dir),
        ],
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )

    assert json.loads(result.stdout)["generated"] is True
    assert (out_dir / ARTIFACT_SAFETY_MANIFEST_FILENAME).exists()


def test_bundle_generator_has_no_boto3_import_or_aws_call_path() -> None:
    import benchmarks.runtime.controlled_sts_validation_report_bundle as bundle

    module_source = Path(bundle.__file__).read_text(encoding="utf-8")
    assert "boto3" not in module_source
    assert "botocore" not in module_source
    assert ".client(" not in module_source
    assert "assume_role(" not in module_source


def test_no_composite_score_or_pass_fail_fields_in_bundle(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    json_keys: set[str] = set()
    for json_path in (
        out_dir / DENIED_REPORT_FILENAME,
        out_dir / ASSUMED_REPORT_FILENAME,
        out_dir / ARTIFACT_SAFETY_MANIFEST_FILENAME,
        out_dir / VALIDATOR_SUMMARY_FILENAME,
    ):
        json_keys.update(_walk_keys(_read_json(json_path)))

    assert "composite_score" not in json_keys
    assert "pass_fail" not in json_keys
    assert "composite_score_included" in json_keys
    assert "pass_fail_labels_included" in json_keys


def test_no_raw_credential_shaped_fields_in_bundle(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    generate_bundle(out_dir=out_dir)

    forbidden_keys = {
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "raw_credentials",
        "aws_session_token",
        "secret_value",
        "access_key_id",
    }
    allowed_safe_keys = {
        "credentials_obtained",
        "credentials_committed",
        "credential_shaped_fields_present",
        "no_raw_credentials",
        "credentials_included",
    }
    keys: set[str] = set()
    for json_path in (
        out_dir / DENIED_REPORT_FILENAME,
        out_dir / ASSUMED_REPORT_FILENAME,
        out_dir / ARTIFACT_SAFETY_MANIFEST_FILENAME,
        out_dir / VALIDATOR_SUMMARY_FILENAME,
    ):
        keys.update(_walk_keys(_read_json(json_path)))

    assert not (forbidden_keys & keys)
    assert allowed_safe_keys <= keys
