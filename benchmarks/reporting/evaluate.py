from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json
from benchmarks.reporting.render import build_report
from benchmarks.scoring.gates import collect_artifact_defects, evaluate_gates
from benchmarks.scoring.ingest import ingest_archive
from benchmarks.scoring.scorer import score_case
from benchmarks.scoring.validator import validate_case_manifest, validate_gate_manifest, validate_run_manifest


def evaluate_archive(case_id: str, archive_dir: Path, out_dir: Path, repo_root: Path) -> dict[str, Any]:
    case_path = repo_root / "benchmarks" / "cases" / f"{case_id}.json"
    gates_path = repo_root / "benchmarks" / "scoring" / "promotion_gates_phase0.json"
    if not case_path.exists():
        raise FileNotFoundError(f"missing Phase 0 case manifest: {case_path}")
    if not gates_path.exists():
        raise FileNotFoundError(f"missing Phase 0 gate manifest: {gates_path}")

    out_dir.mkdir(parents=True, exist_ok=True)
    run_manifest_path = out_dir / "run_manifest.json"
    scorer_result_path = out_dir / "scorer_result.json"
    gate_result_path = out_dir / "gate_result.json"
    report_path = out_dir / "report.md"

    run_manifest = ingest_archive(case_id, archive_dir, run_manifest_path, repo_root)
    case_manifest = load_json(case_path)
    gate_manifest = load_json(gates_path)
    errors = [
        *validate_case_manifest(case_manifest),
        *validate_run_manifest(run_manifest),
        *validate_gate_manifest(gate_manifest),
    ]
    if errors:
        raise ValueError("; ".join(errors))

    artifact_defects = collect_artifact_defects(case_manifest, run_manifest, repo_root)
    if artifact_defects:
        score_result = {
            "case_id": case_manifest["case_id"],
            "run_id": run_manifest["run_id"],
            "passed": False,
            "assertion_results": [],
            "defects": [],
        }
    else:
        score_result = score_case(case_manifest, run_manifest, repo_root)
    dump_json(scorer_result_path, score_result)

    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, gate_manifest, repo_root)
    dump_json(gate_result_path, gate_result)

    report = build_report(case_manifest, run_manifest, score_result, gate_result)
    report_path.write_text(report)

    success = bool(score_result.get("passed")) and not bool(gate_result.get("promotion_blocked"))
    return {
        "run_manifest_path": run_manifest_path,
        "scorer_result_path": scorer_result_path,
        "gate_result_path": gate_result_path,
        "report_path": report_path,
        "score_result": score_result,
        "gate_result": gate_result,
        "success": success,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a completed Phase 0 benchmark archive")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--archive-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repo-root", default=str(Path.cwd()))
    args = parser.parse_args()

    result = evaluate_archive(
        case_id=args.case_id,
        archive_dir=Path(args.archive_dir),
        out_dir=Path(args.out_dir),
        repo_root=Path(args.repo_root),
    )
    print(f"run_manifest={result['run_manifest_path']}")
    print(f"scorer_result={result['scorer_result_path']}")
    print(f"gate_result={result['gate_result_path']}")
    print(f"report={result['report_path']}")
    if not result["success"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
