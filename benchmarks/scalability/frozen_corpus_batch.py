from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json

SCHEMA_VERSION = "0.1"
REPORT_TYPE = "frozen_corpus_batch_report"
BOUNDARY = (
    "Offline frozen-corpus batch reporting only; this does not prove real-world scalability, "
    "production readiness, live AWS behavior, broad IAMScope correctness, or arbitrary enterprise graph correctness."
)
UNAVAILABLE_METRICS = [
    {
        "metric": "wall_clock_runtime_ms",
        "reason": "not_collected: frozen semantic snapshots do not include scalability runtime instrumentation",
    },
    {
        "metric": "peak_memory_bytes",
        "reason": "not_collected: frozen semantic snapshots do not include memory instrumentation",
    },
    {
        "metric": "candidate_paths_considered",
        "reason": "not_collected: frozen semantic snapshots do not include scalability candidate-path counters",
    },
    {
        "metric": "paths_validated",
        "reason": "not_collected: frozen semantic snapshots do not expose scalability path-validation counters",
    },
    {
        "metric": "paths_rejected",
        "reason": "not_collected: frozen semantic snapshots do not expose scalability path-rejection counters",
    },
    {
        "metric": "constraint_evaluations",
        "reason": "not_collected: frozen semantic snapshots do not include scalability constraint-evaluation counters",
    },
    {
        "metric": "artifact_load_time_ms",
        "reason": "not_collected: frozen semantic snapshots do not include scalability artifact-load timings",
    },
    {
        "metric": "report_generation_time_ms",
        "reason": "not_collected: frozen semantic snapshots do not include prior scalability report timings",
    },
]


def build_report(snapshot: str | Path) -> dict[str, Any]:
    snapshot_path = Path(snapshot)
    if not snapshot_path.exists():
        raise ValueError(f"snapshot path does not exist: {snapshot_path}")
    if not snapshot_path.is_dir():
        raise ValueError(f"snapshot path is not a directory: {snapshot_path}")

    corpus_summary_path = snapshot_path / "corpus" / "corpus_summary.json"
    if not corpus_summary_path.exists():
        raise ValueError(f"snapshot is missing corpus summary: {corpus_summary_path}")

    corpus_summary = load_json(corpus_summary_path)
    aggregate = corpus_summary.get("aggregate", {})
    evaluated_cases = corpus_summary.get("evaluated_cases", [])
    if not isinstance(evaluated_cases, list):
        raise ValueError(f"snapshot corpus summary has malformed evaluated_cases: {corpus_summary_path}")

    case_by_id = {
        str(item.get("case_id")): item
        for item in evaluated_cases
        if isinstance(item, dict) and item.get("case_id") is not None
    }
    cases = [_summarize_run(run_dir, case_by_id=case_by_id) for run_dir in _run_dirs(snapshot_path)]
    cases.sort(key=lambda item: (str(item["case_id"]), str(item["run_id"])))

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "snapshot_path": str(snapshot_path),
        "offline_only": True,
        "live_aws_used": False,
        "case_count": len(cases),
        "batch_summary": _batch_summary(aggregate, cases),
        "cases": cases,
        "unavailable_metrics": UNAVAILABLE_METRICS,
        "caveats": [
            "offline_only: reads already-frozen safe benchmark snapshot artifacts",
            "no_live_aws: does not collect from AWS or require cloud credentials",
            "no_raw_artifacts: does not copy scenario.json, findings.json, binding_metadata.json, or run.log",
            "no composite scoring: counts and per-case rows remain separate",
            "does_not_prove_real_world_scalability_or_correctness",
            "does_not_replace_live_semantic_benchmark_interpretation",
        ],
        "evidence_boundary": BOUNDARY,
    }


def write_report(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope Frozen Corpus Batch Report",
        "",
        "Offline only: this report reads already-frozen benchmark snapshot artifacts.",
        "",
        "No live AWS is used. No cloud credentials, Terraform, or collection steps are required.",
        "",
        "No composite score is emitted. Counts and per-case rows remain separate.",
        "",
        "This report does not prove real-world scalability or correctness and does not replace live semantic benchmark interpretation.",
        "",
        "## Snapshot",
        "",
        f"- Snapshot path: `{report['snapshot_path']}`.",
        f"- Offline only: `{str(report['offline_only']).lower()}`.",
        f"- Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        "",
        "## Batch Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in report["batch_summary"].items():
        lines.append(f"| {key} | {value} |")

    lines.extend(
        [
            "",
            "## Per-Case Summary",
            "",
            "| Case ID | Run ID | Family | Score Passed | Artifact Sufficient | Promotion Blocked | Human Review | Assertions | Defects |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for case in report["cases"]:
        lines.append(
            "| {case_id} | {run_id} | {family} | {score_passed} | {artifact_sufficient} | "
            "{promotion_blocked} | {human_review_required} | {assertion_count} | {defect_count} |".format(
                case_id=case["case_id"],
                run_id=case["run_id"],
                family=case["family"],
                score_passed=_markdown_bool(case["score_passed"]),
                artifact_sufficient=_markdown_bool(case["artifact_sufficient"]),
                promotion_blocked=_markdown_bool(case["promotion_blocked"]),
                human_review_required=_markdown_bool(case["human_review_required"]),
                assertion_count=case["assertion_count"],
                defect_count=case["defect_count"],
            )
        )

    lines.extend(
        [
            "",
            "## Unavailable Metrics",
            "",
            "| Metric | Reason |",
            "| --- | --- |",
        ]
    )
    for item in report["unavailable_metrics"]:
        lines.append(f"| {item['metric']} | {item['reason']} |")

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- Offline only: reads already-frozen safe benchmark snapshot artifacts.",
            "- No live AWS: does not collect from AWS or require cloud credentials.",
            "- No raw artifacts: does not copy scenario.json, findings.json, binding_metadata.json, or run.log.",
            "- No composite score: this is not a pass/fail grade, benchmark ranking, or production-readiness signal.",
            "- Does not prove real-world scalability or correctness.",
            "- Does not replace live semantic benchmark interpretation.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: str | Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def _run_dirs(snapshot_path: Path) -> list[Path]:
    runs_dir = snapshot_path / "runs"
    if not runs_dir.exists() or not runs_dir.is_dir():
        raise ValueError(f"snapshot is missing runs directory: {runs_dir}")
    return sorted(path for path in runs_dir.iterdir() if path.is_dir())


def _summarize_run(run_dir: Path, *, case_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    manifest = _load_required_json(run_dir / "run_manifest.json")
    scorer = _load_required_json(run_dir / "scorer_result.json")
    gate = _load_required_json(run_dir / "gate_result.json")
    case_id = str(manifest.get("case_id") or scorer.get("case_id") or run_dir.name)
    corpus_case = case_by_id.get(case_id, {})
    assertion_results = scorer.get("assertion_results", [])
    defects = gate.get("defects", scorer.get("defects", []))
    artifact_status = manifest.get("artifact_status", {})
    return {
        "case_id": case_id,
        "run_id": str(manifest.get("run_id") or scorer.get("run_id") or run_dir.name),
        "family": str(corpus_case.get("family", "unavailable_with_reason:not_present_in_corpus_summary")),
        "benchmark_date": _string_or_unavailable(manifest.get("benchmark_date")),
        "environment": _string_or_unavailable(manifest.get("environment")),
        "authority": _string_or_unavailable(manifest.get("authority")),
        "confidence": _string_or_unavailable(manifest.get("confidence")),
        "scenario_validation": _string_or_unavailable(artifact_status.get("scenario_validation")),
        "score_passed": bool(scorer.get("passed", corpus_case.get("score_passed", False))),
        "artifact_sufficient": bool(gate.get("artifact_sufficient", corpus_case.get("artifact_sufficient", False))),
        "promotion_blocked": bool(gate.get("promotion_blocked", corpus_case.get("promotion_blocked", False))),
        "human_review_required": bool(
            gate.get("human_review_required", corpus_case.get("human_review_required", False))
        ),
        "assertion_count": len(assertion_results) if isinstance(assertion_results, list) else 0,
        "assertion_passed_count": _passed_assertions(assertion_results),
        "defect_count": len(defects) if isinstance(defects, list) else 0,
        "defect_classes": corpus_case.get("defect_classes", []),
        "safe_snapshot_artifacts": {
            "run_manifest_json": (run_dir / "run_manifest.json").exists(),
            "scorer_result_json": (run_dir / "scorer_result.json").exists(),
            "gate_result_json": (run_dir / "gate_result.json").exists(),
            "report_md": (run_dir / "report.md").exists(),
        },
    }


def _batch_summary(aggregate: dict[str, Any], cases: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "cases": len(cases),
        "total_cases_evaluated": _int_or_default(aggregate.get("total_cases_evaluated"), len(cases)),
        "passes": _int_or_default(aggregate.get("passes"), sum(1 for case in cases if case["score_passed"])),
        "failures": _int_or_default(aggregate.get("failures"), sum(1 for case in cases if not case["score_passed"])),
        "artifact_insufficient_count": _int_or_default(
            aggregate.get("artifact_insufficient_count"),
            sum(1 for case in cases if not case["artifact_sufficient"]),
        ),
        "blocked_promotions": _int_or_default(
            aggregate.get("blocked_promotions"),
            sum(1 for case in cases if case["promotion_blocked"]),
        ),
        "human_review_required_count": _int_or_default(
            aggregate.get("human_review_required_count"),
            sum(1 for case in cases if case["human_review_required"]),
        ),
    }


def _load_required_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"required frozen snapshot artifact is missing: {path}")
    return load_json(path)


def _passed_assertions(assertion_results: Any) -> int:
    if not isinstance(assertion_results, list):
        return 0
    return sum(1 for item in assertion_results if isinstance(item, dict) and item.get("passed") is True)


def _int_or_default(value: Any, default: int) -> int:
    return value if isinstance(value, int) else default


def _string_or_unavailable(value: Any) -> str:
    return str(value) if value is not None else "unavailable_with_reason:not_present_in_frozen_artifact"


def _markdown_bool(value: bool) -> str:
    return "true" if value else "false"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render an offline frozen-corpus batch report.")
    parser.add_argument("--snapshot", required=True, type=Path, help="Path to a frozen benchmark snapshot directory.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON summary.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown summary.")
    args = parser.parse_args(argv)

    try:
        report = build_report(args.snapshot)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_report(report, args.json_out)
        print(f"frozen_corpus_batch_report_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"frozen_corpus_batch_report_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
