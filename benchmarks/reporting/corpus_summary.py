from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json


REQUIRED_RUN_FILES = {
    "run_manifest.json",
    "scorer_result.json",
    "gate_result.json",
    "report.md",
}


def _discover_run_dirs(runs_dir: Path | None, run_dirs: list[Path]) -> list[Path]:
    discovered: list[Path] = []
    if runs_dir is not None:
        for child in sorted(runs_dir.iterdir()):
            if child.is_dir() and REQUIRED_RUN_FILES.issubset({path.name for path in child.iterdir()}):
                discovered.append(child)
    discovered.extend(run_dirs)
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in discovered:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    if not unique:
        raise ValueError("no evaluated benchmark run directories found")
    return unique


def _require_run_files(run_dir: Path) -> None:
    missing = [name for name in sorted(REQUIRED_RUN_FILES) if not (run_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"missing required evaluated run files in {run_dir}: {', '.join(missing)}")


def _load_case_manifest(repo_root: Path, case_id: str) -> dict[str, Any]:
    case_path = repo_root / "benchmarks" / "cases" / f"{case_id}.json"
    if not case_path.exists():
        raise FileNotFoundError(f"missing case manifest for evaluated run: {case_path}")
    return load_json(case_path)


def summarize_corpus(*, runs_dir: Path | None, run_dirs: list[Path], out_dir: Path, repo_root: Path) -> dict[str, Any]:
    selected_run_dirs = _discover_run_dirs(runs_dir, run_dirs)
    out_dir.mkdir(parents=True, exist_ok=True)

    case_summaries: list[dict[str, Any]] = []
    directly_proven: list[str] = []
    strongly_supported: list[str] = []
    only_implied: list[str] = []
    still_unknown: list[str] = []
    defect_counter: Counter[str] = Counter()
    family_counter: Counter[str] = Counter()
    claim_surface_counter: Counter[str] = Counter()

    passes = 0
    failures = 0
    evaluated_case_ids: set[str] = set()
    blocked_promotions = 0
    artifact_insufficient_count = 0
    human_review_required_count = 0

    for run_dir in selected_run_dirs:
        _require_run_files(run_dir)
        run_manifest = load_json(run_dir / "run_manifest.json")
        scorer_result = load_json(run_dir / "scorer_result.json")
        gate_result = load_json(run_dir / "gate_result.json")
        case_manifest = _load_case_manifest(repo_root, str(run_manifest["case_id"]))

        score_passed = bool(scorer_result.get("passed"))
        evaluated_case_ids.add(str(run_manifest["case_id"]))
        promotion_blocked = bool(gate_result.get("promotion_blocked"))
        artifact_sufficient = bool(gate_result.get("artifact_sufficient"))
        human_review_required = bool(gate_result.get("human_review_required"))
        defect_classes = sorted({str(defect.get("defect_class")) for defect in gate_result.get("defects", [])})

        if score_passed:
            passes += 1
        else:
            failures += 1
        if promotion_blocked:
            blocked_promotions += 1
        if not artifact_sufficient:
            artifact_insufficient_count += 1
        if human_review_required:
            human_review_required_count += 1
        defect_counter.update(defect_classes)

        family = str(case_manifest.get("family", "unknown"))
        family_counter[family] += 1
        for claim in case_manifest.get("claim_surface", []):
            if isinstance(claim, str):
                claim_surface_counter[claim] += 1

        if score_passed and artifact_sufficient:
            directly_proven.extend(item for item in case_manifest.get("honesty_ground_truth", {}).get("directly_proven_if_pass", []) if isinstance(item, str))
            strongly_supported.extend(item for item in case_manifest.get("honesty_ground_truth", {}).get("strongly_supported_if_pass", []) if isinstance(item, str))
        only_implied.extend(item for item in case_manifest.get("honesty_ground_truth", {}).get("only_implied_even_if_pass", []) if isinstance(item, str))
        still_unknown.extend(item for item in case_manifest.get("unknowns_remaining", []) if isinstance(item, str))

        case_summaries.append(
            {
                "case_id": run_manifest["case_id"],
                "run_id": run_manifest["run_id"],
                "family": family,
                "score_passed": score_passed,
                "promotion_blocked": promotion_blocked,
                "artifact_sufficient": artifact_sufficient,
                "defect_classes": defect_classes,
                "human_review_required": human_review_required,
                "report_path": str((run_dir / "report.md")),
            }
        )

    if blocked_promotions > 0 or artifact_insufficient_count > 0:
        decision = "block"
        reasons = []
        if blocked_promotions > 0:
            reasons.append("one_or_more_case_gates_block_promotion")
        if artifact_insufficient_count > 0:
            reasons.append("one_or_more_cases_are_artifact_insufficient")
    elif human_review_required_count > 0:
        decision = "hold_review"
        reasons = ["human_review_required_for_one_or_more_cases"]
    else:
        decision = "promote"
        reasons = []

    mutation_signals: list[str] = []
    if {"env05_permission_boundary_blocked_chain", "env09_boundary_removed_validated_admin"}.issubset(evaluated_case_ids):
        mutation_signals.append(
            "Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability."
        )

    corpus_summary = {
        "evaluated_cases": case_summaries,
        "aggregate": {
            "total_cases_evaluated": len(case_summaries),
            "passes": passes,
            "failures": failures,
            "blocked_promotions": blocked_promotions,
            "artifact_insufficient_count": artifact_insufficient_count,
            "defect_counts_by_class": dict(sorted(defect_counter.items())),
            "human_review_required_count": human_review_required_count,
            "coverage_by_family": dict(sorted(family_counter.items())),
            "coverage_by_claim_surface": dict(sorted(claim_surface_counter.items())),
        },
        "mutation_signals": mutation_signals,
        "evidence_boundaries": {
            "directly_proven": sorted(dict.fromkeys(directly_proven)),
            "strongly_supported": sorted(dict.fromkeys(strongly_supported)),
            "only_implied": sorted(dict.fromkeys(only_implied)),
            "still_unknown": sorted(dict.fromkeys(still_unknown)),
        },
    }
    promotion_decision = {
        "decision": decision,
        "reasons": reasons,
        "blocked_promotions": blocked_promotions,
        "artifact_insufficient_count": artifact_insufficient_count,
        "human_review_required_count": human_review_required_count,
    }

    lines: list[str] = []
    lines.append("# Phase 0 Benchmark Corpus Summary")
    lines.append("")
    lines.append("This summary applies only to the evaluated corpus cases listed below. It does not claim broad IAMScope correctness.")
    lines.append("")
    lines.append(f"- Total cases evaluated: `{len(case_summaries)}`")
    lines.append(f"- Passes: `{passes}`")
    lines.append(f"- Failures: `{failures}`")
    lines.append(f"- Blocked promotions: `{blocked_promotions}`")
    lines.append(f"- Artifact insufficient count: `{artifact_insufficient_count}`")
    lines.append(f"- Human review required count: `{human_review_required_count}`")
    lines.append(f"- Promotion decision: `{decision}`")
    lines.append("")
    lines.append("## Directly Proven")
    for item in corpus_summary["evidence_boundaries"]["directly_proven"] or ["None across the evaluated corpus."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Strongly Supported")
    for item in corpus_summary["evidence_boundaries"]["strongly_supported"] or ["None across the evaluated corpus."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Only Implied")
    for item in corpus_summary["evidence_boundaries"]["only_implied"] or ["None."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Still Unknown")
    for item in corpus_summary["evidence_boundaries"]["still_unknown"] or ["None."]:
        lines.append(f"- {item}")
    lines.append("")
    if mutation_signals:
        lines.append("## Mutation Signals")
        for item in mutation_signals:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("## Cases")
    for case in case_summaries:
        defects = ", ".join(case["defect_classes"]) if case["defect_classes"] else "none"
        lines.append(
            f"- `{case['case_id']}` / `{case['run_id']}`: score_passed=`{str(case['score_passed']).lower()}`, promotion_blocked=`{str(case['promotion_blocked']).lower()}`, artifact_sufficient=`{str(case['artifact_sufficient']).lower()}`, human_review_required=`{str(case['human_review_required']).lower()}`, defect_classes={defects}"
        )
    lines.append("")
    lines.append("## Aggregate Defects")
    if defect_counter:
        for defect_class, count in sorted(defect_counter.items()):
            lines.append(f"- `{defect_class}`: `{count}`")
    else:
        lines.append("- None")

    dump_json(out_dir / "corpus_summary.json", corpus_summary)
    dump_json(out_dir / "promotion_decision.json", promotion_decision)
    (out_dir / "corpus_report.md").write_text("\n".join(lines) + "\n")

    return {
        "corpus_summary_path": out_dir / "corpus_summary.json",
        "promotion_decision_path": out_dir / "promotion_decision.json",
        "corpus_report_path": out_dir / "corpus_report.md",
        "corpus_summary": corpus_summary,
        "promotion_decision": promotion_decision,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a corpus of completed Phase 0 benchmark evaluations")
    parser.add_argument("--runs-dir")
    parser.add_argument("--run-dir", action="append", default=[])
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repo-root", default=str(Path.cwd()))
    args = parser.parse_args()
    if not args.runs_dir and not args.run_dir:
        raise SystemExit("either --runs-dir or --run-dir is required")
    result = summarize_corpus(
        runs_dir=Path(args.runs_dir) if args.runs_dir else None,
        run_dirs=[Path(item) for item in args.run_dir],
        out_dir=Path(args.out_dir),
        repo_root=Path(args.repo_root),
    )
    print(f"corpus_summary={result['corpus_summary_path']}")
    print(f"promotion_decision={result['promotion_decision_path']}")
    print(f"corpus_report={result['corpus_report_path']}")
    if result["promotion_decision"]["decision"] == "block":
        raise SystemExit(1)


if __name__ == "__main__":
    main()