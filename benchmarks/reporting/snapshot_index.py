from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from benchmarks.common import load_json


REQUIRED_CORPUS_FILES = {
    "corpus_summary.json",
    "promotion_decision.json",
    "corpus_report.md",
}


def _snapshot_dirs(snapshots_dir: Path) -> list[Path]:
    if not snapshots_dir.exists():
        return []
    return sorted(path for path in snapshots_dir.iterdir() if path.is_dir())


def _load_snapshot(snapshot_dir: Path) -> dict[str, Any]:
    readme_path = snapshot_dir / "README.md"
    corpus_dir = snapshot_dir / "corpus"
    missing: list[str] = []
    if not readme_path.exists():
        missing.append("README.md")
    for filename in sorted(REQUIRED_CORPUS_FILES):
        if not (corpus_dir / filename).exists():
            missing.append(f"corpus/{filename}")
    if missing:
        return {
            "snapshot_id": snapshot_dir.name,
            "status": "malformed",
            "reason": f"missing required files: {', '.join(missing)}",
            "readme_path": str(readme_path),
            "corpus_report_path": str(corpus_dir / "corpus_report.md"),
        }

    summary = load_json(corpus_dir / "corpus_summary.json")
    decision = load_json(corpus_dir / "promotion_decision.json")
    aggregate = summary.get("aggregate", {})
    evaluated_cases = summary.get("evaluated_cases", [])
    evidence = summary.get("evidence_boundaries", {})
    cases = [
        {
            "case_id": item.get("case_id"),
            "run_id": item.get("run_id"),
        }
        for item in evaluated_cases
        if isinstance(item, dict)
    ]
    return {
        "snapshot_id": snapshot_dir.name,
        "status": "ok",
        "decision": decision.get("decision", "unknown"),
        "total_cases_evaluated": int(aggregate.get("total_cases_evaluated", 0)),
        "passes": int(aggregate.get("passes", 0)),
        "failures": int(aggregate.get("failures", 0)),
        "blocked_promotions": int(aggregate.get("blocked_promotions", 0)),
        "artifact_insufficient_count": int(aggregate.get("artifact_insufficient_count", 0)),
        "human_review_required_count": int(aggregate.get("human_review_required_count", 0)),
        "included_cases": cases,
        "directly_proven": [item for item in evidence.get("directly_proven", []) if isinstance(item, str)],
        "still_unknown": [item for item in evidence.get("still_unknown", []) if isinstance(item, str)],
        "mutation_signals": [item for item in summary.get("mutation_signals", []) if isinstance(item, str)],
        "readme_path": str(readme_path),
        "corpus_report_path": str(corpus_dir / "corpus_report.md"),
    }


def build_index(snapshot_records: list[dict[str, Any]], snapshots_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Benchmark Snapshot Index")
    lines.append("")
    lines.append(f"Generated from `{snapshots_dir}`.")
    lines.append("This index summarizes only the frozen benchmark snapshots present here. It does not claim broad IAMScope correctness.")
    lines.append("")
    if not snapshot_records:
        lines.append("No frozen benchmark snapshots found.")
        lines.append("")
        return "\n".join(lines)

    for record in snapshot_records:
        lines.append(f"## {record['snapshot_id']}")
        if record.get("status") == "malformed":
            lines.append("")
            lines.append("- Status: `malformed`")
            lines.append(f"- Reason: {record['reason']}")
            lines.append(f"- README: `{record['readme_path']}`")
            lines.append(f"- Corpus report: `{record['corpus_report_path']}`")
            lines.append("")
            continue
        lines.append("")
        lines.append(f"- Corpus decision: `{record['decision']}`")
        lines.append(f"- Total cases evaluated: `{record['total_cases_evaluated']}`")
        lines.append(f"- Passes: `{record['passes']}`")
        lines.append(f"- Failures: `{record['failures']}`")
        lines.append(f"- Blocked promotions: `{record['blocked_promotions']}`")
        lines.append(f"- Artifact insufficient count: `{record['artifact_insufficient_count']}`")
        lines.append(f"- Human review required count: `{record['human_review_required_count']}`")
        lines.append(f"- README: `{record['readme_path']}`")
        lines.append(f"- Corpus report: `{record['corpus_report_path']}`")
        lines.append("")
        lines.append("### Included Cases / Runs")
        for case in record.get("included_cases", []) or [{"case_id": "None", "run_id": "None"}]:
            lines.append(f"- `{case['case_id']}` / `{case['run_id']}`")
        if record.get("mutation_signals"):
            lines.append("")
            lines.append("### Mutation Signals")
            for item in record.get("mutation_signals", []):
                lines.append(f"- {item}")
        lines.append("")
        lines.append("### Directly Proven")
        for item in record.get("directly_proven", []) or ["None."]:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Still Unknown")
        for item in record.get("still_unknown", []) or ["None."]:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def update_snapshot_index(snapshots_dir: Path, out_path: Path) -> str:
    records = [_load_snapshot(snapshot_dir) for snapshot_dir in _snapshot_dirs(snapshots_dir)]
    report = build_index(records, snapshots_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Phase 0 frozen benchmark snapshot index")
    parser.add_argument("--snapshots-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    report = update_snapshot_index(Path(args.snapshots_dir), Path(args.out))
    print(report, end="")


if __name__ == "__main__":
    main()