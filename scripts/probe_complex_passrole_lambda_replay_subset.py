#!/usr/bin/env python3
"""Probe a narrow PassRole-to-Lambda replay-ready subset fixture.

This script is intentionally local-only. It does not collect AWS data, does
not call Terraform or AWS APIs, and does not mutate the committed fixture.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo" / "complex_replay_subset_passrole_lambda"
DEFAULT_OUT = Path("/tmp/iamscope-complex-passrole-lambda-replay-subset")
SUMMARY_NAME = "replay-subset-summary.md"
MANIFEST_NAME = "replay-subset-manifest.json"
GENERATED_FINDINGS_NAME = "generated-findings.json"

NON_CLAIMS = [
    "no full complex benchmark replay-equivalence",
    "no broad IAMScope correctness",
    "no broad PassRole correctness",
    "no generic Deny correctness",
    "no exploitability proof",
    "no downstream authorization proof",
    "no Lambda invocation behavior",
    "no production readiness",
    "no correctness for real AWS environments",
    (
        "no correctness for other principals, roles, accounts, regions, "
        "conditions, permission boundaries, SCPs, resource policies, or findings"
    ),
    "no composite benchmark score",
    "no pass/fail benchmark label",
]


def _resolve_out(out: str | Path) -> Path:
    path = Path(out).expanduser().resolve()
    repo_root = REPO_ROOT.resolve()
    if path == repo_root or repo_root in path.parents:
        raise ValueError(f"refusing to write probe outputs inside repository tree: {path}")
    return path


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _input_contract_gaps(fixture_dir: Path = FIXTURE_DIR) -> dict[str, list[str]]:
    gaps: dict[str, list[str]] = {"scenario_json": [], "binding_metadata_json": []}
    scenario = _load_json(fixture_dir / "scenario.json")
    binding_metadata = _load_json(fixture_dir / "binding_metadata.json")

    if not scenario.get("metadata", {}).get("canonical_hash"):
        gaps["scenario_json"].append("scenario.json lacks metadata.canonical_hash")
    if not isinstance(scenario.get("constraints"), list):
        gaps["scenario_json"].append("scenario.json constraints is not an array")
    if not isinstance(scenario.get("edge_constraints"), list):
        gaps["scenario_json"].append("scenario.json edge_constraints is not an array")
    for index, edge in enumerate(scenario.get("edges", [])):
        if not isinstance(edge.get("src"), dict) or not isinstance(edge.get("dst"), dict):
            gaps["scenario_json"].append(f"edge {index} does not use NodeRef src/dst objects")
            break
        if not isinstance(edge.get("features"), dict):
            gaps["scenario_json"].append(f"edge {index} lacks features object")
            break

    if not isinstance(binding_metadata, list):
        gaps["binding_metadata_json"].append("binding_metadata.json is not a sidecar list")
    else:
        for index, entry in enumerate(binding_metadata):
            if not isinstance(entry, dict):
                gaps["binding_metadata_json"].append(f"binding metadata entry {index} is not an object")
                break
            missing = {"edge_id", "constraint_id", "binding_metadata"} - set(entry)
            if missing:
                gaps["binding_metadata_json"].append(
                    f"binding metadata entry {index} missing {', '.join(sorted(missing))}"
                )
                break

    return {name: entries for name, entries in gaps.items() if entries}


def _row_from_finding(finding: Any) -> dict[str, str]:
    return {
        "finding_id": str(finding.finding_id),
        "finding_key": str(finding.finding_key),
        "pattern_id": str(finding.pattern_id),
        "verdict": str(finding.verdict.value),
        "severity": str(finding.severity),
        "source": str(finding.source.provider_id),
        "target": str(finding.target.provider_id),
    }


def _expected_match_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("finding_key", "")),
        str(row.get("pattern_id", "")),
        str(row.get("verdict", "")),
        str(row.get("source", "")),
        str(row.get("target", "")),
    )


def _generated_match_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("finding_key", "")),
        str(row.get("pattern_id", "")),
        str(row.get("verdict", "")),
        str(row.get("source", "")),
        str(row.get("target", "")),
    )


def _attempt_replay(fixture_dir: Path, out_dir: Path) -> tuple[dict[str, Any], list[str]]:
    from iamscope.reasoner import PassRoleLambdaReasoner
    from iamscope.reasoner.replay import run_reasoners_on_frozen_artifacts

    result = run_reasoners_on_frozen_artifacts(
        scenario_path=fixture_dir / "scenario.json",
        binding_metadata_path=fixture_dir / "binding_metadata.json",
        probe_overlay_path=None,
        reasoner_instances=(PassRoleLambdaReasoner(),),
        reasoning_timestamp="2026-06-03T00:00:00Z",
    )
    generated_path = out_dir / GENERATED_FINDINGS_NAME
    generated_path.write_bytes(result.findings_bytes)
    generated_rows = [_row_from_finding(finding) for finding in result.findings]
    return (
        {
            "generated_rows": generated_rows,
            "generated_findings_path": GENERATED_FINDINGS_NAME,
            "reasoners_attempted": list(result.reasoners_run),
            "reasoners_skipped": dict(result.reasoners_skipped),
            "scenario_hash": result.scenario_hash,
            "findings_hash": result.findings_hash,
        },
        [GENERATED_FINDINGS_NAME],
    )


def build_probe_result(*, fixture_dir: Path = FIXTURE_DIR, out_dir: Path | None = None) -> tuple[dict[str, Any], str]:
    expected = _load_json(fixture_dir / "expected_rows.json")
    contract_gaps = _input_contract_gaps(fixture_dir)
    input_contract_status = "replay_ready" if not contract_gaps else "not_replay_ready"

    generated_rows: list[dict[str, Any]] = []
    output_files = [SUMMARY_NAME, MANIFEST_NAME]
    safe_replay_attempted = False
    reasoners_attempted: list[str] = []
    reasoners_skipped: dict[str, str] = {}
    replay_error = ""
    generated_findings_path = None

    if input_contract_status == "replay_ready" and out_dir is not None:
        safe_replay_attempted = True
        try:
            replay_data, generated_outputs = _attempt_replay(fixture_dir, out_dir)
            generated_rows = list(replay_data["generated_rows"])
            reasoners_attempted = list(replay_data["reasoners_attempted"])
            reasoners_skipped = dict(replay_data["reasoners_skipped"])
            generated_findings_path = replay_data["generated_findings_path"]
            output_files.extend(generated_outputs)
        except Exception as exc:  # noqa: BLE001
            replay_error = f"{type(exc).__name__}: {exc}"

    expected_rows = list(expected.get("expected_rows", []))
    expected_keys = {_expected_match_key(row): row for row in expected_rows}
    generated_keys = {_generated_match_key(row): row for row in generated_rows}
    matched_rows = [
        {"row_id": expected_keys[key].get("row_id", ""), **generated_keys[key]}
        for key in sorted(expected_keys.keys() & generated_keys.keys())
    ]
    missing_rows = [
        expected_keys[key]
        for key in sorted(expected_keys.keys() - generated_keys.keys())
    ]
    extra_rows = [
        generated_keys[key]
        for key in sorted(generated_keys.keys() - expected_keys.keys())
    ]

    if input_contract_status != "replay_ready" or replay_error:
        replay_subset_status = "not_proven"
    elif not missing_rows and not extra_rows and matched_rows:
        replay_subset_status = "replayed_selected_passrole_lambda_subset"
    else:
        replay_subset_status = "not_proven"

    manifest: dict[str, Any] = {
        "schema_version": "complex_passrole_lambda_replay_subset_probe.v1",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "fixture_id": expected.get("fixture_id", "complex_replay_subset_passrole_lambda_001"),
        "fixture_path": str(fixture_dir.relative_to(REPO_ROOT)),
        "local_only": True,
        "live_aws_used": False,
        "aws_calls_made": 0,
        "replay_subset_status": replay_subset_status,
        "input_contract_status": input_contract_status,
        "input_contract_gaps": contract_gaps,
        "safe_replay_attempted": safe_replay_attempted,
        "reasoners_attempted": reasoners_attempted,
        "reasoners_skipped": reasoners_skipped,
        "replay_error": replay_error,
        "expected_rows": expected_rows,
        "generated_rows": generated_rows,
        "matched_rows": matched_rows,
        "missing_rows": missing_rows,
        "extra_rows": extra_rows,
        "static_only_rows": list(expected.get("static_only_rows", [])),
        "unsupported_rows": list(expected.get("unsupported_rows", [])),
        "generated_findings_output": generated_findings_path,
        "non_claims": NON_CLAIMS,
        "output_files_generated": output_files,
    }
    return manifest, _render_summary(manifest)


def _render_summary(manifest: dict[str, Any]) -> str:
    lines = [
        "# Complex PassRole-to-Lambda Replay Subset Probe",
        "",
        "This is a narrow PassRole-to-Lambda replay subset.",
        "This does not prove replay-equivalence for the full complex synthetic benchmark.",
        "This does not prove broad IAMScope correctness.",
        "Missing-precondition/static-only rows are not treated as generated findings.",
        "No composite benchmark score or pass/fail benchmark label is produced.",
        "",
        "## Result",
        "",
        f"- Replay subset status: `{manifest['replay_subset_status']}`",
        f"- Input contract status: `{manifest['input_contract_status']}`",
        f"- Safe replay attempted: `{str(manifest['safe_replay_attempted']).lower()}`",
        f"- Live AWS used: `{str(manifest['live_aws_used']).lower()}`",
        f"- AWS calls made: `{manifest['aws_calls_made']}`",
        "",
        "## Row Summary",
        "",
        f"- Expected generated rows: `{len(manifest['expected_rows'])}`",
        f"- Generated rows: `{len(manifest['generated_rows'])}`",
        f"- Matched rows: `{len(manifest['matched_rows'])}`",
        f"- Missing rows: `{len(manifest['missing_rows'])}`",
        f"- Extra rows: `{len(manifest['extra_rows'])}`",
        f"- Static-only rows: `{len(manifest['static_only_rows'])}`",
        f"- Unsupported rows: `{len(manifest['unsupported_rows'])}`",
        "",
        "## Non-Claims",
        "",
    ]
    lines.extend(f"- {claim}" for claim in manifest["non_claims"])
    lines.append("")
    return "\n".join(lines)


def run_probe(out: str | Path = DEFAULT_OUT) -> dict[str, Any]:
    out_dir = _resolve_out(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest, summary = build_probe_result(out_dir=out_dir)
    (out_dir / SUMMARY_NAME).write_text(summary, encoding="utf-8")
    (out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output directory outside the repository tree")
    args = parser.parse_args(argv)

    try:
        manifest = run_probe(args.out)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("IAMScope complex PassRole-to-Lambda replay subset probe (local only)")
    print(f"Output: {_resolve_out(args.out)}")
    print(f"Replay subset status: {manifest['replay_subset_status']}")
    print(f"Input contract status: {manifest['input_contract_status']}")
    print(f"Safe replay attempted: {str(manifest['safe_replay_attempted']).lower()}")
    print(f"Matched rows: {len(manifest['matched_rows'])}")
    print(f"Missing rows: {len(manifest['missing_rows'])}")
    print(f"Static-only rows: {len(manifest['static_only_rows'])}")
    print("Live AWS used: false")
    print("AWS calls made: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
