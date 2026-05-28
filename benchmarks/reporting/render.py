from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from benchmarks.common import load_json
from benchmarks.scoring.gates import collect_artifact_defects, evaluate_gates
from benchmarks.scoring.scorer import score_case
from benchmarks.scoring.validator import validate_case_manifest, validate_gate_manifest, validate_run_manifest


def build_report(
    case_manifest: dict[str, Any],
    run_manifest: dict[str, Any],
    score_result: dict[str, Any],
    gate_result: dict[str, Any],
) -> str:
    if score_result.get("passed") and gate_result.get("artifact_sufficient"):
        directly_proven = case_manifest.get("honesty_ground_truth", {}).get("directly_proven_if_pass", [])
        strongly_supported = case_manifest.get("honesty_ground_truth", {}).get("strongly_supported_if_pass", [])
    else:
        directly_proven = []
        strongly_supported = []
    only_implied = case_manifest.get("honesty_ground_truth", {}).get("only_implied_even_if_pass", [])
    still_unknown = case_manifest.get("unknowns_remaining", [])
    defects = gate_result.get("defects", [])
    gate_results = gate_result.get("gate_results", [])

    lines: list[str] = []
    lines.append(f"# Benchmark Dry Run: {case_manifest['case_id']}")
    lines.append("")
    lines.append(f"- Run ID: `{run_manifest['run_id']}`")
    lines.append(f"- Artifact sufficient: `{'yes' if gate_result['artifact_sufficient'] else 'no'}`")
    lines.append(f"- Human review required: `{'yes' if gate_result['human_review_required'] else 'no'}`")
    lines.append("")
    lines.append("## Directly Proven")
    for item in directly_proven or ["None in this dry run."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Strongly Supported")
    for item in strongly_supported or ["None in this dry run."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Only Implied")
    for item in only_implied or ["None."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Still Unknown")
    for item in still_unknown or ["None."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Defects")
    if defects:
        for defect in defects:
            lines.append(f"- `{defect['defect_class']}` - {defect['message']}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Gate Results")
    for gate in gate_results:
        trigger_text = ", ".join(gate.get("triggered_by", [])) or "none"
        lines.append(f"- `{gate['gate_id']}`: `{gate['status']}` (triggered_by={trigger_text})")
    lines.append("")
    lines.append("## Artifact Sufficiency")
    lines.append(
        f"- Required scenario validation: `{case_manifest['scoring_expectations']['required_scenario_validation']}`"
    )
    lines.append(
        f"- Observed scenario validation: `{run_manifest['artifact_status'].get('scenario_validation', 'unknown')}`"
    )
    return "\n".join(lines) + "\n"


def render(
    case_path: Path, run_path: Path, gates_path: Path, output_path: Path | None = None, repo_root: Path | None = None
) -> str:
    root = repo_root or Path.cwd()
    case_manifest = load_json(case_path)
    run_manifest = load_json(run_path)
    gate_manifest = load_json(gates_path)
    errors = [
        *validate_case_manifest(case_manifest),
        *validate_run_manifest(run_manifest),
        *validate_gate_manifest(gate_manifest),
    ]
    if errors:
        raise ValueError("; ".join(errors))
    artifact_defects = collect_artifact_defects(case_manifest, run_manifest, root)
    if artifact_defects:
        score_result = {
            "case_id": case_manifest["case_id"],
            "run_id": run_manifest["run_id"],
            "passed": False,
            "assertion_results": [],
            "defects": [],
        }
    else:
        score_result = score_case(case_manifest, run_manifest, root)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, gate_manifest, root)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)
    if output_path is not None:
        output_path.write_text(report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a Phase 0 IAMScope benchmark dry-run report")
    parser.add_argument("--case", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--gates", required=True)
    parser.add_argument("--output")
    parser.add_argument("--repo-root", default=str(Path.cwd()))
    args = parser.parse_args()
    output_path = Path(args.output) if args.output else None
    report = render(Path(args.case), Path(args.run), Path(args.gates), output_path, Path(args.repo_root))
    print(report, end="")


if __name__ == "__main__":
    main()
