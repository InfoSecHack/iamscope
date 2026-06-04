from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.run_public_demo_review import CLAIM_BOUNDARY, REPO_ROOT, CheckResult, run_public_demo_review

RUNNER = REPO_ROOT / "scripts" / "run_public_demo_review.py"


def _passing_checks(output_dir: Path) -> list[CheckResult]:
    (output_dir / "path-overcounting-uncertainty-groups.json").write_text("{}\n", encoding="utf-8")
    return [
        CheckResult("focused_live_binding_tests", "python -m pytest -q ...", 0, "", ""),
        CheckResult("account_id_hygiene_scan", "grep account ids", 0, "", "", True),
        CheckResult("iam_arn_hygiene_scan", "grep iam arns", 0, "", "", True),
        CheckResult("artifact_hygiene_scan", "find artifacts", 0, "", "", True),
        CheckResult(
            "path_overcounting_uncertainty_grouping", "python scripts/group_inconclusive_uncertainty.py ...", 0, "", ""
        ),
    ]


def test_runner_refuses_repo_output_paths() -> None:
    with pytest.raises(ValueError, match="repository tree"):
        run_public_demo_review(REPO_ROOT / "public-demo-review-output", check_runner=_passing_checks)


def test_runner_writes_summary_and_manifest(tmp_path: Path) -> None:
    manifest = run_public_demo_review(tmp_path, check_runner=_passing_checks)

    summary_path = tmp_path / "summary.md"
    manifest_path = tmp_path / "manifest.json"
    assert summary_path.is_file()
    assert manifest_path.is_file()

    payload = json.loads(manifest_path.read_text())
    assert payload == manifest
    assert payload["schema_version"] == "public_demo_review_manifest.v1"
    assert payload["local_only"] is True
    assert payload["live_aws_used"] is False
    assert payload["aws_calls_made"] == 0
    assert "summary.md" in payload["output_files_generated"]
    assert "manifest.json" in payload["output_files_generated"]
    assert "passrole-lambda-replay-subset/replay-subset-summary.md" in payload["output_files_generated"]
    assert "passrole-lambda-replay-subset/replay-subset-manifest.json" in payload["output_files_generated"]
    assert "passrole-lambda-replay-subset/generated-findings.json" in payload["output_files_generated"]
    assert (tmp_path / "passrole-lambda-replay-subset" / "replay-subset-summary.md").is_file()
    assert (tmp_path / "passrole-lambda-replay-subset" / "replay-subset-manifest.json").is_file()
    assert (tmp_path / "passrole-lambda-replay-subset" / "generated-findings.json").is_file()


def test_summary_includes_claim_boundary_passrole_summaries_and_non_claims(tmp_path: Path) -> None:
    run_public_demo_review(tmp_path, check_runner=_passing_checks)
    summary = (tmp_path / "summary.md").read_text()

    assert CLAIM_BOUNDARY in summary
    assert "selected local `validated` finding matched live AWS `lambda:CreateFunction` success" in summary
    assert "live AWS returned `access_denied`" in summary
    assert "local IAMScope emitted no selected validated `passrole_lambda` finding" in summary
    assert "no broad IAMScope correctness" in summary
    assert "no exploitability proof" in summary
    assert "no Lambda invocation behavior" in summary
    assert "no composite benchmark score" in summary
    assert "no pass/fail benchmark label" in summary


def test_summary_includes_complex_synthetic_benchmark_section(tmp_path: Path) -> None:
    run_public_demo_review(tmp_path, check_runner=_passing_checks)
    summary = (tmp_path / "summary.md").read_text()

    assert "## Complex synthetic benchmark" in summary
    assert "Local-only frozen synthetic oracle: true" in summary
    assert "Naive path-shaped candidates: 42" in summary
    assert "Findings: 18" in summary
    assert "`validated`: 4" in summary
    assert "`blocked`: 5" in summary
    assert "`precondition_only`: 3" in summary
    assert "`inconclusive`: 6" in summary
    assert "`shared_passrole_target_resource_scope_unknown`: 3" in summary
    assert "`shared_cross_account_trust_condition_unknown`: 2" in summary
    assert "`shared_boundary_or_session_policy_context_missing`: 1" in summary
    assert "Generation mode: `frozen_synthetic_oracle`" in summary
    assert "Generated/replayed by IAMScope: false" in summary
    assert "This is not generated/replayed by IAMScope." in summary
    assert "This is not a composite score or pass/fail benchmark label." in summary


def test_summary_includes_narrow_passrole_lambda_replay_subset(tmp_path: Path) -> None:
    run_public_demo_review(tmp_path, check_runner=_passing_checks)
    summary = (tmp_path / "summary.md").read_text()

    assert "## Narrow PassRole-to-Lambda replay subset" in summary
    assert "replayed_selected_passrole_lambda_subset" in summary
    assert "input contract status: `replay_ready`" in summary
    assert "safe replay attempted: `true`" in summary
    assert "reasoners attempted: `passrole_lambda`" in summary
    assert "matched rows: 1" in summary
    assert "missing rows: 0" in summary
    assert "extra rows: 0" in summary
    assert "static-only rows: 1" in summary
    assert "live AWS used: `false`" in summary
    assert "AWS calls made: `0`" in summary
    assert "This does not prove replay-equivalence for the full complex synthetic benchmark." in summary


def test_manifest_includes_supported_claims_non_claims_and_checks(tmp_path: Path) -> None:
    manifest = run_public_demo_review(tmp_path, check_runner=_passing_checks)

    assert any("Local synthetic path-overcounting demo" in claim for claim in manifest["supported_claims"])
    assert any("Allowed PassRole-to-Lambda case" in claim for claim in manifest["supported_claims"])
    assert any("Denied missing-PassRole case" in claim for claim in manifest["supported_claims"])
    assert "no broad IAMScope correctness" in manifest["non_claims"]
    assert "no pass/fail benchmark label" in manifest["non_claims"]
    assert [check["name"] for check in manifest["commands_checks_run"]] == [
        "focused_live_binding_tests",
        "account_id_hygiene_scan",
        "iam_arn_hygiene_scan",
        "artifact_hygiene_scan",
        "path_overcounting_uncertainty_grouping",
    ]


def test_manifest_includes_complex_synthetic_benchmark_counts(tmp_path: Path) -> None:
    manifest = run_public_demo_review(tmp_path, check_runner=_passing_checks)
    complex_summary = manifest["complex_synthetic_benchmark"]

    assert complex_summary["fixture_id"] == "complex_shared_uncertainty_iam_benchmark_001"
    assert complex_summary["source_tool"] == "static_fixture_authoring"
    assert complex_summary["generation_mode"] == "frozen_synthetic_oracle"
    assert complex_summary["local_only"] is True
    assert complex_summary["live_aws_used"] is False
    assert complex_summary["aws_calls_made"] == 0
    assert complex_summary["generated_or_replayed_by_iamscope"] is False
    assert complex_summary["reasoners_run"] == []
    assert complex_summary["naive_candidate_count"] == 42
    assert complex_summary["finding_count"] == 18
    assert complex_summary["verdict_breakdown"] == {
        "validated": 4,
        "blocked": 5,
        "precondition_only": 3,
        "inconclusive": 6,
    }
    assert complex_summary["uncertainty_group_counts"] == {
        "shared_passrole_target_resource_scope_unknown": 3,
        "shared_cross_account_trust_condition_unknown": 2,
        "shared_boundary_or_session_policy_context_missing": 1,
    }
    assert complex_summary["report_only"] is True
    assert complex_summary["not_composite_score"] is True
    assert complex_summary["not_pass_fail_benchmark_label"] is True


def test_manifest_includes_narrow_passrole_lambda_replay_subset(tmp_path: Path) -> None:
    manifest = run_public_demo_review(tmp_path, check_runner=_passing_checks)
    subset = manifest["passrole_lambda_replay_subset"]

    assert subset["replay_subset_status"] == "replayed_selected_passrole_lambda_subset"
    assert subset["input_contract_status"] == "replay_ready"
    assert subset["safe_replay_attempted"] is True
    assert subset["reasoners_attempted"] == ["passrole_lambda"]
    assert subset["matched_row_count"] == 1
    assert subset["missing_row_count"] == 0
    assert subset["extra_row_count"] == 0
    assert subset["static_only_row_count"] == 1
    assert subset["generated_findings_output"] == "passrole-lambda-replay-subset/generated-findings.json"
    assert subset["local_only"] is True
    assert subset["live_aws_used"] is False
    assert subset["aws_calls_made"] == 0
    assert "no full complex benchmark replay-equivalence" in subset["non_claims"]
    assert "no composite benchmark score" in subset["non_claims"]
    assert "no pass/fail benchmark label" in subset["non_claims"]


def test_runner_fails_if_account_scan_produces_unexpected_output(tmp_path: Path) -> None:
    def checks(_: Path) -> list[CheckResult]:
        return [
            CheckResult(
                "account_id_hygiene_scan",
                "grep account ids",
                0,
                "docs/example.md:1:<unexpected-account-id>\n",
                "",
                True,
            )
        ]

    with pytest.raises(RuntimeError, match="account_id_hygiene_scan"):
        run_public_demo_review(tmp_path, check_runner=checks)

    assert (tmp_path / "summary.md").is_file()
    assert (tmp_path / "manifest.json").is_file()
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["commands_checks_run"][0]["passed"] is False


def test_runner_fails_if_artifact_scan_produces_unexpected_output(tmp_path: Path) -> None:
    def checks(_: Path) -> list[CheckResult]:
        return [CheckResult("artifact_hygiene_scan", "find artifacts", 0, "./result.json\n", "", True)]

    with pytest.raises(RuntimeError, match="artifact_hygiene_scan"):
        run_public_demo_review(tmp_path, check_runner=checks)


def test_runner_does_not_require_aws_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)

    manifest = run_public_demo_review(tmp_path, check_runner=_passing_checks)

    assert manifest["live_aws_used"] is False
    assert manifest["aws_calls_made"] == 0


def test_generated_outputs_are_not_committed() -> None:
    forbidden = {
        "summary.md",
        "manifest.json",
        "path-overcounting-uncertainty-groups.json",
        "replay-subset-summary.md",
        "replay-subset-manifest.json",
        "generated-findings.json",
    }
    fixture_dirs = [
        REPO_ROOT / "tests" / "fixtures" / "demo" / "path_overcounting_shared_uncertainty",
        REPO_ROOT / "tests" / "fixtures" / "demo" / "complex_replay_subset_passrole_lambda",
        REPO_ROOT / "tests" / "fixtures" / "live_binding" / "passrole_lambda_selected_finding",
        REPO_ROOT / "tests" / "fixtures" / "live_binding" / "passrole_lambda_denied_missing_passrole",
    ]

    for fixture_dir in fixture_dirs:
        assert forbidden.isdisjoint({path.name for path in fixture_dir.iterdir() if path.is_file()})


def test_cli_refuses_repo_output_path() -> None:
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--out", str(REPO_ROOT / "public-demo-review-output")],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "repository tree" in result.stderr
