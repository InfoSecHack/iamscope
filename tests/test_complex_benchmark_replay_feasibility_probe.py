from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.probe_complex_benchmark_replay_feasibility import REPO_ROOT, build_probe_result, run_probe

PROBE = REPO_ROOT / "scripts" / "probe_complex_benchmark_replay_feasibility.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo" / "complex_shared_uncertainty_iam_benchmark"
GENERATED_OUTPUTS = {
    "replay-feasibility-summary.md",
    "replay-feasibility-manifest.json",
}
REQUIRED_PATTERN_CATEGORIES = {
    "passrole_lambda",
    "passrole_ecs",
    "assume_role_chain",
    "cross_account_trust",
    "permission_boundary_blocked_path",
    "scp_blocked_path",
    "identity_deny_suppressed_path",
    "missing_iam_passrole_precondition",
    "missing_target_trust_precondition",
    "shared_uncertainty_grouping",
}


def test_probe_refuses_repo_output_paths() -> None:
    with pytest.raises(ValueError, match="repository tree"):
        run_probe(REPO_ROOT / "complex-replay-feasibility-output")


def test_probe_writes_summary_and_manifest(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    summary_path = tmp_path / "replay-feasibility-summary.md"
    manifest_path = tmp_path / "replay-feasibility-manifest.json"
    assert summary_path.is_file()
    assert manifest_path.is_file()
    assert json.loads(manifest_path.read_text()) == manifest


def test_manifest_preserves_not_proven_local_only_boundary(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    assert manifest["replay_equivalence_status"] == "not_proven"
    assert manifest["fixture_generation_mode"] == "frozen_synthetic_oracle"
    assert manifest["generated_or_replayed_by_iamscope"] is False
    assert manifest["reasoners_run_in_fixture"] == []
    assert manifest["input_contract_status"] == "not_replay_ready"
    assert manifest["safe_replay_attempted"] is False
    assert manifest["local_only"] is True
    assert manifest["live_aws_used"] is False
    assert manifest["aws_calls_made"] == 0
    assert manifest["output_files_generated"] == [
        "replay-feasibility-summary.md",
        "replay-feasibility-manifest.json",
    ]


def test_manifest_explains_input_contract_gaps(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)
    scenario_gaps = manifest["input_contract_gaps"]["scenario_json"]
    binding_gaps = manifest["input_contract_gaps"]["binding_metadata_json"]

    assert any("canonical_hash" in gap for gap in scenario_gaps)
    assert any("constraints array" in gap for gap in scenario_gaps)
    assert any("NodeRef objects" in gap for gap in scenario_gaps)
    assert any("sidecar list" in gap for gap in binding_gaps)


def test_manifest_includes_required_pattern_feasibility_rows(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)
    rows = {row["pattern_category"]: row for row in manifest["pattern_feasibility"]}

    assert set(rows) == REQUIRED_PATTERN_CATEGORIES
    assert rows["passrole_lambda"]["replayable_now"] == "partial"
    assert rows["passrole_ecs"]["replayable_now"] == "partial"
    assert rows["assume_role_chain"]["replayable_now"] == "partial"
    assert rows["cross_account_trust"]["replayable_now"] == "partial"
    assert rows["permission_boundary_blocked_path"]["replayable_now"] == "partial"
    assert rows["scp_blocked_path"]["replayable_now"] == "partial"
    assert rows["identity_deny_suppressed_path"]["replayable_now"] == "partial"
    assert rows["missing_iam_passrole_precondition"]["replayable_now"] == "no"
    assert rows["missing_iam_passrole_precondition"]["status"] == "static_only_expected_absence"
    assert rows["missing_target_trust_precondition"]["replayable_now"] == "no"
    assert rows["shared_uncertainty_grouping"]["status"] == "report_only_static_grouping"


def test_manifest_marks_static_only_and_unsupported_rows(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    assert any(row["kind"] == "finding" for row in manifest["static_only_rows"])
    assert any(row["kind"] == "naive_candidate_non_finding" for row in manifest["static_only_rows"])
    assert {row["category"] for row in manifest["unsupported_rows"]} == {
        "shared_uncertainty_grouping",
        "precondition_only_rows",
    }


def test_summary_states_required_boundaries(tmp_path: Path) -> None:
    run_probe(tmp_path)
    summary = (tmp_path / "replay-feasibility-summary.md").read_text()

    assert "Replay-equivalence is not yet proven." in summary
    assert "The complex synthetic benchmark remains a frozen synthetic oracle." in summary
    assert "The current fixture is not generated/replayed IAMScope output." in summary
    assert "Unsupported or static-only rows remain labeled as such." in summary
    assert "No composite benchmark score or pass/fail benchmark label is produced." in summary


def test_no_composite_score_or_pass_fail_manifest_fields(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)
    text = json.dumps(manifest).lower()

    assert "composite_score" not in text
    assert "benchmark_passed" not in text
    assert "pass/fail benchmark label" in text


def test_probe_does_not_require_aws_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)

    manifest = run_probe(tmp_path)

    assert manifest["live_aws_used"] is False
    assert manifest["aws_calls_made"] == 0


def test_no_generated_outputs_are_committed() -> None:
    committed = {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()}
    assert GENERATED_OUTPUTS.isdisjoint(committed)


def test_cli_writes_expected_outputs(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(PROBE), "--out", str(tmp_path)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Replay-equivalence status: not_proven" in result.stdout
    assert (tmp_path / "replay-feasibility-summary.md").is_file()
    assert (tmp_path / "replay-feasibility-manifest.json").is_file()


def test_build_probe_result_matches_fixture_oracle_counts() -> None:
    manifest = build_probe_result()

    assert manifest["fixture_id"] == "complex_shared_uncertainty_iam_benchmark_001"
    assert manifest["oracle_counts"]["naive_candidate_count"] == 42
    assert manifest["oracle_counts"]["finding_count"] == 18
    assert manifest["oracle_counts"]["verdict_breakdown"] == {
        "validated": 4,
        "blocked": 5,
        "precondition_only": 3,
        "inconclusive": 6,
    }
    assert manifest["oracle_counts"]["uncertainty_group_counts"] == {
        "shared_passrole_target_resource_scope_unknown": 3,
        "shared_cross_account_trust_condition_unknown": 2,
        "shared_boundary_or_session_policy_context_missing": 1,
    }
