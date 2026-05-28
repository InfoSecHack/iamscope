from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.reporting.corpus_summary import summarize_corpus

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_evaluated_run(
    tmp_path: Path,
    name: str,
    *,
    case_id: str,
    family: str,
    score_passed: bool,
    promotion_blocked: bool,
    artifact_sufficient: bool,
    human_review_required: bool,
    defect_classes: list[str],
) -> Path:
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True)
    run_manifest = {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": name,
        "case_id": case_id,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "live_aws",
        "confidence": "high",
        "benchmark_date": "2026-04-24",
        "environment": f"acceptance/{family}",
        "tool_claims": [],
        "context": {"source_provider_id": "src", "target_provider_id": "dst"},
        "artifact_status": {"scenario_validation": "pass", "artifact_retention": "complete"},
        "artifacts": {
            "scenario_json": str(run_dir / "scenario.json"),
            "findings_json": str(run_dir / "findings.json"),
            "run_log": str(run_dir / "run.log"),
            "scenario_validate_txt": str(run_dir / "scenario_validate.txt"),
        },
    }
    scorer_result = {
        "case_id": case_id,
        "run_id": name,
        "passed": score_passed,
        "assertion_results": [],
        "defects": [
            {
                "defect_class": defect_class,
                "message": f"{defect_class} defect",
            }
            for defect_class in defect_classes
        ],
    }
    gate_result = {
        "artifact_sufficient": artifact_sufficient,
        "defects": [
            {
                "defect_class": defect_class,
                "message": f"{defect_class} defect",
            }
            for defect_class in defect_classes
        ],
        "gate_results": [],
        "human_review_required": human_review_required,
        "promotion_blocked": promotion_blocked,
    }
    _write_json(run_dir / "run_manifest.json", run_manifest)
    _write_json(run_dir / "scorer_result.json", scorer_result)
    _write_json(run_dir / "gate_result.json", gate_result)
    (run_dir / "report.md").write_text(
        f"# {case_id}\n\n## Directly Proven\n- Example\n\n## Only Implied\n- Example\n\n## Still Unknown\n- Example\n"
    )
    return run_dir


def test_summary_over_two_passing_runs(tmp_path: Path) -> None:
    run_a = _make_evaluated_run(
        tmp_path,
        "env03-run",
        case_id="env03_identity_deny_group_escalation",
        family="identity_deny",
        score_passed=True,
        promotion_blocked=False,
        artifact_sufficient=True,
        human_review_required=True,
        defect_classes=[],
    )
    run_b = _make_evaluated_run(
        tmp_path,
        "env05-run",
        case_id="env05_permission_boundary_blocked_chain",
        family="permission_boundary",
        score_passed=True,
        promotion_blocked=False,
        artifact_sufficient=True,
        human_review_required=True,
        defect_classes=[],
    )
    out_dir = tmp_path / "summary-out"
    result = summarize_corpus(runs_dir=None, run_dirs=[run_a, run_b], out_dir=out_dir, repo_root=REPO_ROOT)
    summary = load_json(result["corpus_summary_path"])
    decision = load_json(result["promotion_decision_path"])
    assert summary["aggregate"]["total_cases_evaluated"] == 2
    assert summary["aggregate"]["passes"] == 2
    assert summary["aggregate"]["failures"] == 0
    assert decision["decision"] == "hold_review"
    assert "composite_score" not in summary


def test_blocked_run_causes_corpus_promotion_block(tmp_path: Path) -> None:
    run_a = _make_evaluated_run(
        tmp_path,
        "env03-run-blocked",
        case_id="env03_identity_deny_group_escalation",
        family="identity_deny",
        score_passed=False,
        promotion_blocked=True,
        artifact_sufficient=True,
        human_review_required=True,
        defect_classes=["semantic_mismatch"],
    )
    out_dir = tmp_path / "blocked-summary"
    result = summarize_corpus(runs_dir=None, run_dirs=[run_a], out_dir=out_dir, repo_root=REPO_ROOT)
    decision = load_json(result["promotion_decision_path"])
    assert decision["decision"] == "block"
    assert decision["blocked_promotions"] == 1


def test_defect_counts_aggregate_correctly(tmp_path: Path) -> None:
    run_a = _make_evaluated_run(
        tmp_path,
        "env03-run-defects",
        case_id="env03_identity_deny_group_escalation",
        family="identity_deny",
        score_passed=False,
        promotion_blocked=True,
        artifact_sufficient=False,
        human_review_required=True,
        defect_classes=["artifact_insufficient", "semantic_mismatch"],
    )
    run_b = _make_evaluated_run(
        tmp_path,
        "env05-run-defects",
        case_id="env05_permission_boundary_blocked_chain",
        family="permission_boundary",
        score_passed=False,
        promotion_blocked=True,
        artifact_sufficient=True,
        human_review_required=True,
        defect_classes=["false_admin_claim"],
    )
    out_dir = tmp_path / "defect-summary"
    result = summarize_corpus(runs_dir=None, run_dirs=[run_a, run_b], out_dir=out_dir, repo_root=REPO_ROOT)
    summary = load_json(result["corpus_summary_path"])
    assert summary["aggregate"]["defect_counts_by_class"] == {
        "artifact_insufficient": 1,
        "false_admin_claim": 1,
        "semantic_mismatch": 1,
    }
    assert summary["aggregate"]["artifact_insufficient_count"] == 1


def test_report_contains_truth_sections(tmp_path: Path) -> None:
    run_a = _make_evaluated_run(
        tmp_path,
        "env06-run",
        case_id="env06_validated_admin_reachability",
        family="admin_reachability",
        score_passed=True,
        promotion_blocked=False,
        artifact_sufficient=True,
        human_review_required=True,
        defect_classes=[],
    )
    out_dir = tmp_path / "report-summary"
    result = summarize_corpus(runs_dir=None, run_dirs=[run_a], out_dir=out_dir, repo_root=REPO_ROOT)
    report = Path(result["corpus_report_path"]).read_text()
    assert "## Directly Proven" in report
    assert "## Only Implied" in report
    assert "## Still Unknown" in report
    assert "does not claim broad IAMScope correctness" in report
