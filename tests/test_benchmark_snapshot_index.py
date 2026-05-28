from __future__ import annotations

import json
from pathlib import Path

from benchmarks.reporting.snapshot_index import update_snapshot_index


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_snapshot(
    tmp_path: Path,
    snapshot_id: str,
    *,
    decision: str = "hold_review",
    total_cases: int = 1,
    passes: int = 1,
    failures: int = 0,
    blocked_promotions: int = 0,
    artifact_insufficient_count: int = 0,
    human_review_required_count: int = 1,
    malformed: bool = False,
) -> Path:
    snapshot_dir = tmp_path / snapshot_id
    (snapshot_dir / "runs" / "env05-20260424T203548Z").mkdir(parents=True, exist_ok=True)
    if malformed:
        (snapshot_dir / "README.md").write_text("# malformed\n")
        return snapshot_dir
    (snapshot_dir / "README.md").write_text(f"# {snapshot_id}\n")
    corpus_dir = snapshot_dir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        corpus_dir / "corpus_summary.json",
        {
            "aggregate": {
                "total_cases_evaluated": total_cases,
                "passes": passes,
                "failures": failures,
                "blocked_promotions": blocked_promotions,
                "artifact_insufficient_count": artifact_insufficient_count,
                "human_review_required_count": human_review_required_count,
                "coverage_by_family": {"permission_boundary": total_cases},
                "coverage_by_claim_surface": {"example claim": total_cases},
                "defect_counts_by_class": {},
            },
            "evaluated_cases": [
                {
                    "case_id": "env05_permission_boundary_blocked_chain",
                    "run_id": f"{snapshot_id}-run",
                }
            ],
            "evidence_boundaries": {
                "directly_proven": ["Example directly proven statement."],
                "still_unknown": ["Example unknown statement."],
            },
        },
    )
    _write_json(
        corpus_dir / "promotion_decision.json",
        {
            "decision": decision,
            "blocked_promotions": blocked_promotions,
            "artifact_insufficient_count": artifact_insufficient_count,
            "human_review_required_count": human_review_required_count,
        },
    )
    (corpus_dir / "corpus_report.md").write_text("# corpus report\n")
    return snapshot_dir


def test_index_renders_one_valid_snapshot(tmp_path: Path) -> None:
    snapshots_dir = tmp_path / "snapshots"
    _make_snapshot(snapshots_dir, "phase0-20260424")
    out_path = snapshots_dir / "INDEX.md"
    report = update_snapshot_index(snapshots_dir, out_path)
    assert out_path.exists()
    assert "## phase0-20260424" in report
    assert "Corpus decision: `hold_review`" in report
    assert "`env05_permission_boundary_blocked_chain` / `phase0-20260424-run`" in report


def test_index_renders_multiple_snapshots(tmp_path: Path) -> None:
    snapshots_dir = tmp_path / "snapshots"
    _make_snapshot(snapshots_dir, "phase0-a", decision="hold_review")
    _make_snapshot(snapshots_dir, "phase0-b", decision="promote", human_review_required_count=0)
    report = update_snapshot_index(snapshots_dir, snapshots_dir / "INDEX.md")
    assert "## phase0-a" in report
    assert "## phase0-b" in report


def test_malformed_snapshot_is_reported(tmp_path: Path) -> None:
    snapshots_dir = tmp_path / "snapshots"
    _make_snapshot(snapshots_dir, "phase0-bad", malformed=True)
    report = update_snapshot_index(snapshots_dir, snapshots_dir / "INDEX.md")
    assert "## phase0-bad" in report
    assert "Status: `malformed`" in report


def test_no_composite_score_appears(tmp_path: Path) -> None:
    snapshots_dir = tmp_path / "snapshots"
    _make_snapshot(snapshots_dir, "phase0-20260424")
    report = update_snapshot_index(snapshots_dir, snapshots_dir / "INDEX.md")
    assert "- Composite score:" not in report
    assert "`composite_score`" not in report
    assert "composite_score:" not in report
