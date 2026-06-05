from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "compare_prod_like_oracle_findings.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location("compare_prod_like_oracle_findings", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _oracle_payload() -> dict[str, Any]:
    return {
        "oracle_rows": [
            {
                "oracle_row_id": "oracle-v-001",
                "expected_category": "validated",
                "pattern": "PassRole-to-Lambda allowed scoped role",
            },
            {
                "oracle_row_id": "oracle-b-001",
                "expected_category": "blocked",
                "pattern": "Boundary blocks PassRole-to-Lambda",
            },
            {
                "oracle_row_id": "oracle-i-001",
                "expected_category": "inconclusive",
                "pattern": "Wildcard resource scope unknown",
            },
            {
                "oracle_row_id": "oracle-v-006",
                "expected_category": "validated",
                "pattern": "Service-mediated role path",
            },
            {
                "oracle_row_id": "oracle-v-003",
                "expected_category": "validated",
                "pattern": "Direct AssumeRole allowed",
            },
            {
                "oracle_row_id": "oracle-u-001",
                "expected_category": "unsupported",
                "pattern": "Unsupported resource-policy Deny",
            },
        ]
    }


def _finding(
    *,
    finding_id: str,
    pattern_id: str,
    verdict: str,
    source_name: str,
    target_name: str,
    source_kind: str = "user",
    target_kind: str = "role",
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "pattern_id": pattern_id,
        "verdict": verdict,
        "source": {
            "provider_id": f"arn:aws:iam::000000000000:{source_kind}/{source_name}",
        },
        "target": {
            "provider_id": f"arn:aws:iam::000000000000:{target_kind}/{target_name}",
        },
    }


def _findings_payload() -> dict[str, Any]:
    return {
        "findings": [
            _finding(
                finding_id="finding-v001",
                pattern_id="passrole_lambda",
                verdict="validated",
                source_name="iamscope-prodlike-v1-ci-deployer",
                target_name="iamscope-prodlike-v1-lambda-exec-scoped",
            ),
            _finding(
                finding_id="finding-b001",
                pattern_id="passrole_lambda",
                verdict="blocked",
                source_name="iamscope-prodlike-v1-boundary-probe",
                target_name="iamscope-prodlike-v1-lambda-exec-boundary",
            ),
            _finding(
                finding_id="finding-i001",
                pattern_id="passrole_lambda",
                verdict="inconclusive",
                source_name="iamscope-prodlike-v1-uncertainty-resource-probe",
                target_name="iamscope-prodlike-v1-lambda-exec-scoped",
            ),
            _finding(
                finding_id="finding-environmental-extra",
                pattern_id="passrole_lambda",
                verdict="inconclusive",
                source_name="dev-account",
                target_name="iamscope-prodlike-v1-service-mediated-target",
            ),
            _finding(
                finding_id="finding-unmapped-sandbox-extra",
                pattern_id="passrole_lambda",
                verdict="inconclusive",
                source_name="iamscope-prodlike-v1-uncertainty-resource-probe",
                target_name="iamscope-prodlike-v1-service-mediated-target",
            ),
        ]
    }


def _row_by_id(result: dict[str, Any], row_id: str) -> dict[str, Any]:
    rows = {row["oracle_row_id"]: row for row in result["rows"]}
    return rows[row_id]


def test_comparison_classifies_matches_mismatch_missing_unsupported_and_not_comparable() -> None:
    module = _load_module()

    result = module.compare(_oracle_payload(), _findings_payload())

    assert _row_by_id(result, "oracle-v-001")["comparison_category"] == "oracle_match"
    assert _row_by_id(result, "oracle-b-001")["comparison_category"] == "oracle_match"
    assert _row_by_id(result, "oracle-i-001")["comparison_category"] == "oracle_match"
    assert _row_by_id(result, "oracle-i-001")["emitted_verdict"] == "inconclusive"
    assert _row_by_id(result, "oracle-v-006")["comparison_category"] == "oracle_missing"
    assert _row_by_id(result, "oracle-v-003")["comparison_category"] == "not_currently_live_comparable"
    assert _row_by_id(result, "oracle-u-001")["comparison_category"] == "unsupported_static_only"

    assert result["oracle_row_count"] == 6
    assert result["emitted_finding_count"] == 5
    assert result["sandbox_source_finding_count"] == 4
    assert result["environmental_extra_count"] == 1
    assert result["unmapped_sandbox_extra_count"] == 1
    assert result["comparison_category_counts"]["environmental_extra"] == 1
    assert result["comparison_category_counts"]["unmapped_sandbox_extra"] == 1
    assert result["comparison_category_counts"]["oracle_match"] == 3
    assert "oracle_mismatch" not in result["comparison_category_counts"]
    assert result["comparison_category_counts"]["oracle_missing"] == 1
    assert result["comparison_category_counts"]["unsupported_static_only"] == 1
    assert result["comparison_category_counts"]["not_currently_live_comparable"] == 1


def test_environmental_extra_uses_sanitized_source_and_target_names_only() -> None:
    module = _load_module()

    result = module.compare(_oracle_payload(), _findings_payload())

    extras = result["environmental_extras"]
    assert len(extras) == 1
    assert extras[0]["comparison_category"] == "environmental_extra"
    assert extras[0]["extra_type"] == "non_sandbox_source_targets_sandbox_role"
    assert extras[0]["source_name"] == "dev-account"
    assert extras[0]["target_name"] == "iamscope-prodlike-v1-service-mediated-target"

    unmapped = result["unmapped_sandbox_extras"]
    assert len(unmapped) == 1
    assert unmapped[0]["comparison_category"] == "unmapped_sandbox_extra"
    assert unmapped[0]["extra_type"] == "sandbox_source_has_no_deterministic_oracle_mapping"
    assert unmapped[0]["source_name"] == "iamscope-prodlike-v1-uncertainty-resource-probe"
    assert unmapped[0]["target_name"] == "iamscope-prodlike-v1-service-mediated-target"
    assert unmapped[0]["triage_note"] == (
        "extra wildcard resource-scope path from oracle-i-001 split source; "
        "review or remap only after a fresh live run confirms it remains intended"
    )


def test_output_json_contains_no_raw_account_ids_or_iam_arns(tmp_path: Path) -> None:
    module = _load_module()

    result = module.compare(_oracle_payload(), _findings_payload())
    out_dir = tmp_path / "comparison"
    module.write_outputs(result, out_dir)

    output_text = (out_dir / "comparison.json").read_text(encoding="utf-8")
    assert not re.search(r"\b[0-9]{12}\b", output_text)
    assert "arn:aws:iam::" not in output_text


def test_summary_contains_non_claims_without_machine_score_or_pass_fail_fields(tmp_path: Path) -> None:
    module = _load_module()

    result = module.compare(_oracle_payload(), _findings_payload())
    module.write_outputs(result, tmp_path / "comparison")
    summary = (tmp_path / "comparison" / "comparison-summary.md").read_text(encoding="utf-8")

    assert "no composite benchmark score" in summary
    assert "no pass/fail benchmark label" in summary
    assert "oracle-i-001" in summary
    assert "iamscope-prodlike-v1-uncertainty-resource-probe" in summary
    assert "extra wildcard resource-scope path from oracle-i-001 split source" in summary
    assert "composite_score" not in summary
    assert "benchmark_passed" not in summary
    assert "pass_fail" not in summary


def test_script_refuses_output_inside_repository_tree() -> None:
    module = _load_module()

    result = module.compare(_oracle_payload(), _findings_payload())
    with pytest.raises(SystemExit, match="refusing to write"):
        module.write_outputs(result, REPO_ROOT / "prodlike-comparison-output")


def test_cli_writes_expected_outputs_to_temp_directory(tmp_path: Path) -> None:
    module = _load_module()
    oracle = tmp_path / "oracle_rows.json"
    findings = tmp_path / "findings.json"
    out_dir = tmp_path / "out"
    oracle.write_text(json.dumps(_oracle_payload()), encoding="utf-8")
    findings.write_text(json.dumps(_findings_payload()), encoding="utf-8")

    assert module.main(["--oracle", str(oracle), "--findings", str(findings), "--out", str(out_dir)]) == 0
    assert (out_dir / "comparison-summary.md").is_file()
    assert (out_dir / "comparison.json").is_file()


def test_comparator_does_not_import_live_aws_or_terraform_clients() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()

    assert "boto3" not in source
    assert "terraform " not in source
    assert "subprocess" not in source
    assert "lambda:invokefunction" not in source
    assert "iam:passrole" not in source
