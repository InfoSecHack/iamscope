from __future__ import annotations

import json
from pathlib import Path

from benchmarks.reporting.mutation_pairs import build_pair_report, write_pair_report


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_run(snapshot_dir: Path, run_name: str, case_id: str, *, passed: bool = True) -> Path:
    run_dir = snapshot_dir / "runs" / run_name
    run_dir.mkdir(parents=True)
    _write_json(
        run_dir / "run_manifest.json",
        {
            "case_id": case_id,
            "run_id": f"iamscope-benchmark-{run_name}",
        },
    )
    _write_json(
        run_dir / "scorer_result.json",
        {
            "case_id": case_id,
            "run_id": f"iamscope-benchmark-{run_name}",
            "passed": passed,
            "assertion_results": [
                {
                    "assertion_id": "example_assertion",
                    "type": "finding_count",
                    "passed": passed,
                    "op": "eq",
                    "expected_value": 1,
                    "actual_value": 1 if passed else 0,
                }
            ],
            "defects": [] if passed else [{"defect_class": "semantic_mismatch"}],
        },
    )
    _write_json(
        run_dir / "gate_result.json",
        {
            "artifact_sufficient": True,
            "defects": [] if passed else [{"defect_class": "semantic_mismatch"}],
            "gate_results": [],
            "human_review_required": True,
            "promotion_blocked": not passed,
        },
    )
    return run_dir


def test_pair_report_marks_complete_pair_passed(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test"
    _make_run(snapshot_dir, "env03-run", "env03_identity_deny_group_escalation")
    _make_run(snapshot_dir, "env16-run", "env16_identity_deny_removed_validated_group_escalation")

    report = build_pair_report(snapshot_dir)
    pair = next(item for item in report["pairs"] if item["pair_id"] == "env03_env16_identity_deny_removed")

    assert pair["pair_complete"] is True
    assert pair["pair_delta_passed"] is True
    assert pair["observed_control_present_summary"]["run_id"] == "iamscope-benchmark-env03-run"
    assert pair["observed_mutation_summary"]["run_id"] == "iamscope-benchmark-env16-run"
    assert "composite_score" not in report


def test_pair_report_marks_missing_cases_incomplete(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test-missing"
    _make_run(snapshot_dir, "env03-run", "env03_identity_deny_group_escalation")

    report = build_pair_report(snapshot_dir)
    pair = next(item for item in report["pairs"] if item["pair_id"] == "env03_env16_identity_deny_removed")

    assert pair["pair_complete"] is False
    assert pair["pair_delta_passed"] is False
    assert pair["missing_cases"] == ["env16_identity_deny_removed_validated_group_escalation"]
    assert pair["observed_mutation_summary"]["status"] == "missing"


def test_pair_report_writes_json_and_markdown_without_composite_score(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test-output"
    _make_run(snapshot_dir, "env20-run", "env20_ecs_passrole_validated")
    _make_run(snapshot_dir, "env21-run", "env21_ecs_passedtoservice_scoped_away_nonvalidated")

    json_out = tmp_path / "pair-report.json"
    markdown_out = tmp_path / "pair-report.md"
    write_pair_report(snapshot_dir=snapshot_dir, json_out=json_out, markdown_out=markdown_out)

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert payload["report_type"] == "benchmark_mutation_pair_report"
    assert "env20_env21_ecs_passedtoservice_scoped_away" in markdown
    assert "No composite score is emitted." in markdown
    assert "composite_score" not in json_out.read_text()
    assert "composite_score" not in markdown


def test_pair_report_includes_env22_env23_cross_account_trust_pair(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test-env23"
    _make_run(snapshot_dir, "env22-run", "env22_cross_account_validated_admin")
    _make_run(snapshot_dir, "env23-run", "env23_cross_account_trust_scoped_away_nonvalidated")

    report = build_pair_report(snapshot_dir)
    pair = next(item for item in report["pairs"] if item["pair_id"] == "env22_env23_cross_account_trust_scoped_away")

    assert report["pair_count"] == 10
    assert pair["control_family"] == "cross_account_trust"
    assert pair["pair_complete"] is True
    assert pair["pair_delta_passed"] is True
    assert pair["observed_control_present_summary"]["case_id"] == "env22_cross_account_validated_admin"
    assert pair["observed_mutation_summary"]["case_id"] == "env23_cross_account_trust_scoped_away_nonvalidated"


def test_pair_report_includes_env24_env25_s3_resource_policy_pair(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test-env25"
    _make_run(snapshot_dir, "env24-run", "env24_s3_resource_policy_allow")
    _make_run(snapshot_dir, "env25-run", "env25_s3_resource_policy_allow_scoped_away_nonvalidated")

    report = build_pair_report(snapshot_dir)
    pair = next(
        item for item in report["pairs"] if item["pair_id"] == "env24_env25_s3_resource_policy_allow_scoped_away"
    )

    assert report["pair_count"] == 10
    assert pair["control_family"] == "s3_resource_policy_allow"
    assert pair["pair_complete"] is True
    assert pair["pair_delta_passed"] is True
    assert pair["observed_control_present_summary"]["case_id"] == "env24_s3_resource_policy_allow"
    assert pair["observed_mutation_summary"]["case_id"] == "env25_s3_resource_policy_allow_scoped_away_nonvalidated"
    assert "generic resource-policy Deny support" in pair["evidence_boundary"]


def test_pair_report_includes_env26_env27_multihop_trust_scoped_away_pair(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "phase0-test-env27"
    _make_run(snapshot_dir, "env26-run", "env26_multihop_chain_validated_admin")
    _make_run(snapshot_dir, "env27-run", "env27_multihop_trust_scoped_away_nonvalidated")

    report = build_pair_report(snapshot_dir)
    pair = next(item for item in report["pairs"] if item["pair_id"] == "env26_env27_multihop_trust_scoped_away")

    assert report["pair_count"] == 10
    assert pair["control_family"] == "same_account_multihop_trust"
    assert pair["pair_complete"] is True
    assert pair["pair_delta_passed"] is True
    assert pair["observed_control_present_summary"]["case_id"] == "env26_multihop_chain_validated_admin"
    assert pair["observed_mutation_summary"]["case_id"] == "env27_multihop_trust_scoped_away_nonvalidated"
    assert "controlled same-account multihop" in pair["evidence_boundary"]
    assert "arbitrary enterprise graph correctness" in pair["evidence_boundary"]
