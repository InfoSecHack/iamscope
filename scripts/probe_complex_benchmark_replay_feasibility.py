#!/usr/bin/env python3
"""Probe replay feasibility for the complex synthetic benchmark fixture."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo" / "complex_shared_uncertainty_iam_benchmark"
DEFAULT_OUT = Path("/tmp/iamscope-complex-replay-feasibility")

REQUIRED_PATTERN_ORDER = [
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
]

SUPPORTED_CLAIMS = [
    "The probe reports replay feasibility for the local frozen complex synthetic benchmark fixture.",
    "The probe identifies replay input-contract gaps without changing reasoners or fixture semantics.",
    "The probe keeps unsupported and static-only rows labeled as such.",
]

NON_CLAIMS = [
    "no broad IAMScope correctness",
    "no broad PassRole correctness",
    "no generic Deny correctness",
    "no resource-policy Deny support",
    "no SCP Deny support beyond selected synthetic fixture behavior",
    "no exploitability proof",
    "no downstream authorization proof",
    "no Lambda invocation behavior",
    "no production readiness",
    "no correctness for real AWS environments",
    "no correctness for other principals, roles, accounts, regions, conditions, permission boundaries, SCPs, resource policies, or findings",
    "no composite benchmark score",
    "no pass/fail benchmark label",
]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_out(output_dir: Path) -> Path:
    output_abs = output_dir.expanduser().resolve()
    repo_abs = REPO_ROOT.resolve()
    if _is_relative_to(output_abs, repo_abs):
        raise ValueError(f"refusing to write replay feasibility outputs inside repository tree: {output_abs}")
    return output_abs


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _load_fixture(fixture_dir: Path) -> dict[str, dict[str, Any]]:
    required = [
        "scenario.json",
        "binding_metadata.json",
        "findings.json",
        "naive_candidates.json",
        "expected_uncertainty_groups.json",
    ]
    return {name: _load_json(fixture_dir / name) for name in required}


def _scenario_contract_status(scenario: dict[str, Any]) -> tuple[str, list[str]]:
    gaps: list[str] = []
    if "metadata" not in scenario:
        gaps.append("scenario.json lacks emitted IAMScope metadata with canonical_hash")
    if "constraints" not in scenario:
        gaps.append("scenario.json lacks emitted constraints array")
    for index, edge in enumerate(scenario.get("edges", [])):
        if not isinstance(edge, dict):
            gaps.append(f"scenario edge {index} is not an object")
            continue
        if not isinstance(edge.get("src"), dict) or not isinstance(edge.get("dst"), dict):
            gaps.append(f"scenario edge {edge.get('edge_id', index)} uses descriptive src/dst ids instead of NodeRef objects")
            break
        if "features" not in edge:
            gaps.append(f"scenario edge {edge.get('edge_id', index)} lacks emitted features object")
            break
    return ("replay_ready" if not gaps else "not_replay_ready", gaps)


def _binding_contract_status(binding_metadata: dict[str, Any]) -> tuple[str, list[str]]:
    gaps: list[str] = []
    if not isinstance(binding_metadata, list):
        gaps.append("binding_metadata.json is descriptive object metadata, not an edge-constraint binding sidecar list")
        return "not_replay_ready", gaps
    for index, entry in enumerate(binding_metadata):
        if not isinstance(entry, dict):
            gaps.append(f"binding metadata entry {index} is not an object")
            continue
        for key in ["edge_id", "constraint_id", "binding_metadata"]:
            if key not in entry:
                gaps.append(f"binding metadata entry {index} lacks {key}")
    return ("replay_ready" if not gaps else "not_replay_ready", gaps)


def _pattern_feasibility() -> list[dict[str, str]]:
    return [
        {
            "pattern_category": "passrole_lambda",
            "replayable_now": "partial",
            "status": "blocked_by_input_contract",
            "reason": "PassRoleLambdaReasoner exists, but the fixture scenario is not currently in emitted replay-ready FactGraph shape.",
            "recommended_next_action": "Add a local conversion/readiness probe for replay-compatible PassRole-to-Lambda rows.",
        },
        {
            "pattern_category": "passrole_ecs",
            "replayable_now": "partial",
            "status": "blocked_by_input_contract",
            "reason": "PassRoleEcsReasoner exists, but the fixture lacks replay-ready edge features and sidecar bindings.",
            "recommended_next_action": "Probe ECS rows separately once input-contract compatibility is available.",
        },
        {
            "pattern_category": "assume_role_chain",
            "replayable_now": "partial",
            "status": "blocked_by_input_contract",
            "reason": "AssumeRoleChainReasoner is covered by existing replay tests, but this fixture is descriptive rather than emitted scenario format.",
            "recommended_next_action": "Try existing replay on a replay-ready converted subset, without changing the frozen oracle.",
        },
        {
            "pattern_category": "cross_account_trust",
            "replayable_now": "partial",
            "status": "blocked_by_input_contract_and_synthetic_cross_account_shape",
            "reason": "CrossAccountTrustReasoner exists, but synthetic same-account placeholders may not encode cross-account classification.",
            "recommended_next_action": "Report whether sanitized synthetic cross-account attributes can be replayed without real account IDs.",
        },
        {
            "pattern_category": "permission_boundary_blocked_path",
            "replayable_now": "partial",
            "status": "requires_replay_compatible_constraints",
            "reason": "Boundary blockers require emitted Constraint and EdgeConstraint objects; current fixture has descriptive blocker rows.",
            "recommended_next_action": "Keep rows static until replay-compatible boundary constraints are present.",
        },
        {
            "pattern_category": "scp_blocked_path",
            "replayable_now": "partial",
            "status": "requires_replay_compatible_constraints",
            "reason": "SCP blockers require concrete constraints and binding metadata; fixture support is selected synthetic behavior only.",
            "recommended_next_action": "Keep SCP rows scoped and static until sidecar constraints are proven replayable.",
        },
        {
            "pattern_category": "identity_deny_suppressed_path",
            "replayable_now": "partial",
            "status": "requires_selected_fixture_constraint_binding",
            "reason": "Identity-Deny suppression must remain selected-fixture behavior and needs precise constraint binding before replay.",
            "recommended_next_action": "Probe selected identity-Deny rows only; do not broaden to generic Deny correctness.",
        },
        {
            "pattern_category": "missing_iam_passrole_precondition",
            "replayable_now": "no",
            "status": "static_only_expected_absence",
            "reason": "Missing iam:PassRole preconditions usually produce no selected finding; absence is not a generated finding.",
            "recommended_next_action": "Compare as expected absence or non-finding reason, not replayed finding output.",
        },
        {
            "pattern_category": "missing_target_trust_precondition",
            "replayable_now": "no",
            "status": "static_only_expected_absence",
            "reason": "Missing target trust preconditions usually produce no selected finding; frozen precondition-only rows are report rows.",
            "recommended_next_action": "Keep as static-only unless a report-only precondition explanation layer is added.",
        },
        {
            "pattern_category": "shared_uncertainty_grouping",
            "replayable_now": "no",
            "status": "report_only_static_grouping",
            "reason": "Shared uncertainty classes are report-only fixture metadata, not existing reasoner output.",
            "recommended_next_action": "Compare grouping separately from generated finding replay.",
        },
    ]


def _static_only_rows(findings: dict[str, Any], naive: dict[str, Any]) -> list[dict[str, str]]:
    static_rows: list[dict[str, str]] = []
    for finding in findings["findings"]:
        if finding["verdict"] == "precondition_only" or finding.get("uncertainty_class"):
            static_rows.append(
                {
                    "row_id": str(finding["finding_id"]),
                    "kind": "finding",
                    "status": "static_only",
                    "reason": "precondition-only or shared uncertainty row is not currently proven replayable",
                }
            )
    for candidate in naive["candidate_paths"]:
        mapping = candidate.get("maps_to", {})
        if mapping.get("non_finding_reason"):
            static_rows.append(
                {
                    "row_id": str(candidate["candidate_id"]),
                    "kind": "naive_candidate_non_finding",
                    "status": "static_only",
                    "reason": str(mapping["non_finding_reason"]),
                }
            )
    return static_rows


def build_probe_result(fixture_dir: Path = DEFAULT_FIXTURE_DIR) -> dict[str, Any]:
    fixture = _load_fixture(fixture_dir)
    scenario = fixture["scenario.json"]
    binding = fixture["binding_metadata.json"]
    findings = fixture["findings.json"]
    naive = fixture["naive_candidates.json"]
    uncertainty = fixture["expected_uncertainty_groups.json"]

    scenario_status, scenario_gaps = _scenario_contract_status(scenario)
    binding_status, binding_gaps = _binding_contract_status(binding)
    input_contract_status = "replay_ready" if scenario_status == binding_status == "replay_ready" else "not_replay_ready"
    safe_replay_attempted = input_contract_status == "replay_ready"

    verdict_breakdown = dict(Counter(finding["verdict"] for finding in findings["findings"]))
    group_counts = {group["uncertainty_class"]: group["count"] for group in uncertainty["groups"]}

    return {
        "schema_version": "complex_benchmark_replay_feasibility_probe.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fixture_id": findings["fixture_id"],
        "fixture_path": str(fixture_dir),
        "fixture_generation_mode": findings["generation_mode"],
        "fixture_source_tool": findings["source_tool"],
        "generated_or_replayed_by_iamscope": findings["generated_or_replayed_by_iamscope"],
        "reasoners_run_in_fixture": findings["reasoners_run"],
        "replay_equivalence_status": "not_proven",
        "input_contract_status": input_contract_status,
        "input_contract_gaps": {
            "scenario_json": scenario_gaps,
            "binding_metadata_json": binding_gaps,
        },
        "safe_replay_attempted": safe_replay_attempted,
        "reasoners_attempted": [] if not safe_replay_attempted else ["not_implemented_in_probe"],
        "reasoners_skipped": {
            "all": "input_contract_status_not_replay_ready" if not safe_replay_attempted else "probe_does_not_claim_equivalence"
        },
        "oracle_counts": {
            "naive_candidate_count": len(naive["candidate_paths"]),
            "finding_count": len(findings["findings"]),
            "verdict_breakdown": verdict_breakdown,
            "uncertainty_group_counts": group_counts,
        },
        "pattern_feasibility": _pattern_feasibility(),
        "static_only_rows": _static_only_rows(findings, naive),
        "unsupported_rows": [
            {
                "category": "shared_uncertainty_grouping",
                "reason": "report-only grouping is not existing reasoner output",
            },
            {
                "category": "precondition_only_rows",
                "reason": "reasoner precondition failure is expected absence, not a generated finding",
            },
        ],
        "supported_claims": SUPPORTED_CLAIMS,
        "non_claims": NON_CLAIMS,
        "local_only": True,
        "live_aws_used": False,
        "aws_calls_made": 0,
        "output_files_generated": ["replay-feasibility-summary.md", "replay-feasibility-manifest.json"],
    }


def _render_summary(manifest: dict[str, Any], out_dir: Path) -> str:
    pattern_lines = "\n".join(
        f"- `{row['pattern_category']}`: {row['replayable_now']} ({row['status']})"
        for row in manifest["pattern_feasibility"]
    )
    gaps = [
        *manifest["input_contract_gaps"]["scenario_json"],
        *manifest["input_contract_gaps"]["binding_metadata_json"],
    ]
    gap_lines = "\n".join(f"- {gap}" for gap in gaps) if gaps else "- none"
    return f"""# Complex Benchmark Replay Feasibility Probe

Replay-equivalence is not yet proven.

The complex synthetic benchmark remains a frozen synthetic oracle.

The current fixture is not generated/replayed IAMScope output.

Unsupported or static-only rows remain labeled as such.

No composite benchmark score or pass/fail benchmark label is produced.

## Output

Output directory: `{out_dir}`

## Fixture

- fixture id: `{manifest['fixture_id']}`
- fixture generation mode: `{manifest['fixture_generation_mode']}`
- generated/replayed by IAMScope: {str(manifest['generated_or_replayed_by_iamscope']).lower()}
- reasoners run in fixture: {manifest['reasoners_run_in_fixture']}
- replay equivalence status: `{manifest['replay_equivalence_status']}`
- input contract status: `{manifest['input_contract_status']}`
- safe replay attempted: {str(manifest['safe_replay_attempted']).lower()}

## Input Contract Gaps

{gap_lines}

## Pattern Feasibility

{pattern_lines}

## Safety

- local-only: true
- live AWS used: false
- AWS calls made: 0
- no AWS credentials required
- no Terraform, AWS CLI, STS, Lambda API, or `iam:PassRole` calls
"""


def run_probe(output_dir: Path, *, fixture_dir: Path = DEFAULT_FIXTURE_DIR) -> dict[str, Any]:
    out_abs = _resolve_out(output_dir)
    out_abs.mkdir(parents=True, exist_ok=True)
    manifest = build_probe_result(fixture_dir)
    summary = _render_summary(manifest, out_abs)
    (out_abs / "replay-feasibility-summary.md").write_text(summary, encoding="utf-8")
    (out_abs / "replay-feasibility-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT), help=f"Output directory, default: {DEFAULT_OUT}")
    parser.add_argument("--fixture-dir", default=str(DEFAULT_FIXTURE_DIR), help="Complex fixture directory")
    args = parser.parse_args(argv)
    try:
        manifest = run_probe(Path(args.out), fixture_dir=Path(args.fixture_dir))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("IAMScope complex benchmark replay feasibility probe (local only)")
    print(f"Output: {Path(args.out).expanduser().resolve()}")
    print(f"Replay-equivalence status: {manifest['replay_equivalence_status']}")
    print(f"Input contract status: {manifest['input_contract_status']}")
    print(f"Safe replay attempted: {str(manifest['safe_replay_attempted']).lower()}")
    print("Live AWS used: false")
    print("AWS calls made: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
