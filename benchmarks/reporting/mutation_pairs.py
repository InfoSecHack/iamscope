from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json


@dataclass(frozen=True)
class MutationPair:
    pair_id: str
    control_family: str
    control_present_case_id: str
    control_removed_or_mutated_case_id: str
    expected_control_present_verdict: str
    expected_mutation_verdict: str
    evidence_boundary: str


KNOWN_MUTATION_PAIRS: tuple[MutationPair, ...] = (
    MutationPair(
        pair_id="env03_env16_identity_deny_removed",
        control_family="identity_deny",
        control_present_case_id="env03_identity_deny_group_escalation",
        control_removed_or_mutated_case_id="env16_identity_deny_removed_validated_group_escalation",
        expected_control_present_verdict="blocked iam_group_membership_escalation",
        expected_mutation_verdict="validated iam_group_membership_escalation",
        evidence_boundary="Only compares the Env03/Env16 identity-Deny group-escalation path; it does not prove broad identity-Deny correctness.",
    ),
    MutationPair(
        pair_id="env05_env09_permission_boundary_removed",
        control_family="permission_boundary",
        control_present_case_id="env05_permission_boundary_blocked_chain",
        control_removed_or_mutated_case_id="env09_boundary_removed_validated_admin",
        expected_control_present_verdict="blocked admin_reachability and blocked assume_role_chain",
        expected_mutation_verdict="validated admin_reachability",
        evidence_boundary="Only compares the Env05/Env09 permission-boundary assume-role/admin path; it does not prove broad boundary handling.",
    ),
    MutationPair(
        pair_id="env08_env10_trust_condition_removed",
        control_family="trust_condition",
        control_present_case_id="env08_trust_condition_blocked_admin",
        control_removed_or_mutated_case_id="env10_trust_condition_removed_validated_admin",
        expected_control_present_verdict="non-validated admin_reachability",
        expected_mutation_verdict="validated admin_reachability",
        evidence_boundary="Only compares the Env08/Env10 trust-condition path; it does not prove every trust-condition shape.",
    ),
    MutationPair(
        pair_id="env14_env15_permission_condition_removed",
        control_family="permission_condition",
        control_present_case_id="env14_permission_condition_blocked_admin",
        control_removed_or_mutated_case_id="env15_permission_condition_removed_validated_admin",
        expected_control_present_verdict="non-validated admin_reachability",
        expected_mutation_verdict="validated admin_reachability",
        evidence_boundary="Only compares the Env14/Env15 permission-side MFA-condition path; it does not prove every permission-condition shape.",
    ),
    MutationPair(
        pair_id="env13_env17_scp_removed",
        control_family="scp",
        control_present_case_id="env13_complete_scp_blocked_assumerole",
        control_removed_or_mutated_case_id="env17_scp_removed_validated_admin",
        expected_control_present_verdict="blocked admin_reachability",
        expected_mutation_verdict="validated admin_reachability",
        evidence_boundary="Only compares the Env13/Env17 complete-SCP target path; it does not prove every SCP attachment or condition form.",
    ),
    MutationPair(
        pair_id="env18_env19_lambda_passedtoservice_scoped_away",
        control_family="lambda_passrole_passedtoservice",
        control_present_case_id="env18_lambda_passrole_validated",
        control_removed_or_mutated_case_id="env19_passedtoservice_scoped_away_nonvalidated",
        expected_control_present_verdict="validated passrole_lambda",
        expected_mutation_verdict="precondition_only passrole_lambda",
        evidence_boundary="Only compares the Env18/Env19 Lambda PassRole path; it does not prove every iam:PassedToService operator or Lambda PassRole shape.",
    ),
    MutationPair(
        pair_id="env20_env21_ecs_passedtoservice_scoped_away",
        control_family="ecs_passrole_passedtoservice",
        control_present_case_id="env20_ecs_passrole_validated",
        control_removed_or_mutated_case_id="env21_ecs_passedtoservice_scoped_away_nonvalidated",
        expected_control_present_verdict="validated passrole_ecs",
        expected_mutation_verdict="precondition_only passrole_ecs",
        evidence_boundary="Only compares the Env20/Env21 ECS PassRole path; it does not prove every iam:PassedToService operator or ECS PassRole shape.",
    ),
    MutationPair(
        pair_id="env22_env23_cross_account_trust_scoped_away",
        control_family="cross_account_trust",
        control_present_case_id="env22_cross_account_validated_admin",
        control_removed_or_mutated_case_id="env23_cross_account_trust_scoped_away_nonvalidated",
        expected_control_present_verdict="validated admin_reachability and validated cross_account_trust",
        expected_mutation_verdict="non-validated admin_reachability and non-validated cross_account_trust",
        evidence_boundary="Only compares the Env22/Env23 cross-account AssumeRole path; it does not prove every cross-account trust principal shape.",
    ),
    MutationPair(
        pair_id="env24_env25_s3_resource_policy_allow_scoped_away",
        control_family="s3_resource_policy_allow",
        control_present_case_id="env24_s3_resource_policy_allow",
        control_removed_or_mutated_case_id="env25_s3_resource_policy_allow_scoped_away_nonvalidated",
        expected_control_present_verdict="scenario-edge resource-policy Allow edge present for reader",
        expected_mutation_verdict="reader resource-policy Allow edge absent; decoy resource-policy Allow edge present",
        evidence_boundary=(
            "Only compares the Env24/Env25 S3 resource-policy Allow scenario-edge path; it does not prove "
            "finding-level resource-policy reachability or generic resource-policy Deny support."
        ),
    ),
    MutationPair(
        pair_id="env26_env27_multihop_trust_scoped_away",
        control_family="same_account_multihop_trust",
        control_present_case_id="env26_multihop_chain_validated_admin",
        control_removed_or_mutated_case_id="env27_multihop_trust_scoped_away_nonvalidated",
        expected_control_present_verdict="validated assume_role_chain and validated admin_reachability",
        expected_mutation_verdict="non-validated assume_role_chain and non-validated admin_reachability",
        evidence_boundary=(
            "Only compares the Env26/Env27 controlled same-account multihop AssumeRole path; it does not prove "
            "arbitrary enterprise graph correctness or broader multihop-chain behavior."
        ),
    ),
)


def _snapshot_id(snapshot_dir: Path) -> str:
    return snapshot_dir.name


def _load_runs_by_case(snapshot_dir: Path) -> dict[str, Path]:
    runs_dir = snapshot_dir / "runs"
    runs: dict[str, Path] = {}
    if not runs_dir.exists():
        return runs
    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        manifest = load_json(manifest_path)
        case_id = str(manifest.get("case_id", ""))
        if case_id:
            runs[case_id] = run_dir
    return runs


def _assertion_summary(scorer_result: dict[str, Any]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for assertion in scorer_result.get("assertion_results", []):
        if not isinstance(assertion, dict):
            continue
        summary.append(
            {
                "assertion_id": assertion.get("assertion_id"),
                "type": assertion.get("type"),
                "passed": bool(assertion.get("passed")),
                "op": assertion.get("op"),
                "expected_value": assertion.get("expected_value"),
                "actual_value": assertion.get("actual_value"),
            }
        )
    return summary


def _observed_case_summary(case_id: str, run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {
            "case_id": case_id,
            "status": "missing",
        }

    manifest = load_json(run_dir / "run_manifest.json")
    scorer = load_json(run_dir / "scorer_result.json")
    gate = load_json(run_dir / "gate_result.json")
    assertion_results = _assertion_summary(scorer)
    return {
        "case_id": case_id,
        "status": "present",
        "run_id": manifest.get("run_id"),
        "score_passed": bool(scorer.get("passed")),
        "artifact_sufficient": bool(gate.get("artifact_sufficient")),
        "promotion_blocked": bool(gate.get("promotion_blocked")),
        "defect_classes": sorted({str(defect.get("defect_class")) for defect in gate.get("defects", []) if isinstance(defect, dict)}),
        "assertions_passed": all(item["passed"] for item in assertion_results),
        "assertion_results": assertion_results,
    }


def _case_passed(summary: dict[str, Any]) -> bool:
    return (
        summary.get("status") == "present"
        and bool(summary.get("score_passed"))
        and bool(summary.get("artifact_sufficient"))
        and not bool(summary.get("promotion_blocked"))
        and bool(summary.get("assertions_passed"))
    )


def build_pair_report(snapshot_dir: Path) -> dict[str, Any]:
    runs_by_case = _load_runs_by_case(snapshot_dir)
    pairs: list[dict[str, Any]] = []
    complete_count = 0
    pair_delta_pass_count = 0

    for pair in KNOWN_MUTATION_PAIRS:
        control_present_summary = _observed_case_summary(pair.control_present_case_id, runs_by_case.get(pair.control_present_case_id))
        mutation_summary = _observed_case_summary(
            pair.control_removed_or_mutated_case_id,
            runs_by_case.get(pair.control_removed_or_mutated_case_id),
        )
        missing_cases = [
            case_id
            for case_id, summary in (
                (pair.control_present_case_id, control_present_summary),
                (pair.control_removed_or_mutated_case_id, mutation_summary),
            )
            if summary.get("status") != "present"
        ]
        pair_complete = not missing_cases
        pair_delta_passed = pair_complete and _case_passed(control_present_summary) and _case_passed(mutation_summary)
        if pair_complete:
            complete_count += 1
        if pair_delta_passed:
            pair_delta_pass_count += 1
        pairs.append(
            {
                "pair_id": pair.pair_id,
                "control_family": pair.control_family,
                "control_present_case_id": pair.control_present_case_id,
                "control_removed_or_mutated_case_id": pair.control_removed_or_mutated_case_id,
                "expected_control_present_verdict": pair.expected_control_present_verdict,
                "expected_mutation_verdict": pair.expected_mutation_verdict,
                "observed_control_present_summary": control_present_summary,
                "observed_mutation_summary": mutation_summary,
                "pair_complete": pair_complete,
                "missing_cases": missing_cases,
                "pair_delta_passed": pair_delta_passed,
                "evidence_boundary": pair.evidence_boundary,
            }
        )

    return {
        "report_type": "benchmark_mutation_pair_report",
        "schema_version": "0.1",
        "snapshot_id": _snapshot_id(snapshot_dir),
        "snapshot_path": str(snapshot_dir),
        "pair_count": len(pairs),
        "complete_pair_count": complete_count,
        "pair_delta_pass_count": pair_delta_pass_count,
        "report_boundary": (
            "This report summarizes expected vs observed deltas for known benchmark mutation pairs only. "
            "It does not emit a composite score and does not claim broad IAMScope correctness or production readiness."
        ),
        "pairs": pairs,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Benchmark Mutation Pair Report: {report['snapshot_id']}",
        "",
        report["report_boundary"],
        "",
        f"- Snapshot: `{report['snapshot_path']}`",
        f"- Known pairs: `{report['pair_count']}`",
        f"- Complete pairs: `{report['complete_pair_count']}`",
        f"- Pair deltas passed: `{report['pair_delta_pass_count']}`",
        "",
        "No composite score is emitted.",
        "",
        "## Pairs",
    ]
    for pair in report["pairs"]:
        control = pair["observed_control_present_summary"]
        mutation = pair["observed_mutation_summary"]
        lines.extend(
            [
                "",
                f"### {pair['pair_id']}",
                "",
                f"- Control family: `{pair['control_family']}`",
                f"- Control-present case: `{pair['control_present_case_id']}`",
                f"- Removed/mutated case: `{pair['control_removed_or_mutated_case_id']}`",
                f"- Expected control-present verdict: `{pair['expected_control_present_verdict']}`",
                f"- Expected mutation verdict: `{pair['expected_mutation_verdict']}`",
                f"- Pair complete: `{str(pair['pair_complete']).lower()}`",
                f"- Pair delta passed: `{str(pair['pair_delta_passed']).lower()}`",
                f"- Evidence boundary: {pair['evidence_boundary']}",
                "",
                "#### Observed Control-Present Summary",
                f"- Status: `{control.get('status')}`",
            ]
        )
        if control.get("status") == "present":
            lines.extend(
                [
                    f"- Run ID: `{control.get('run_id')}`",
                    f"- Score passed: `{str(control.get('score_passed')).lower()}`",
                    f"- Artifact sufficient: `{str(control.get('artifact_sufficient')).lower()}`",
                    f"- Promotion blocked: `{str(control.get('promotion_blocked')).lower()}`",
                    f"- Assertions passed: `{str(control.get('assertions_passed')).lower()}`",
                ]
            )
        lines.extend(
            [
                "",
                "#### Observed Mutation Summary",
                f"- Status: `{mutation.get('status')}`",
            ]
        )
        if mutation.get("status") == "present":
            lines.extend(
                [
                    f"- Run ID: `{mutation.get('run_id')}`",
                    f"- Score passed: `{str(mutation.get('score_passed')).lower()}`",
                    f"- Artifact sufficient: `{str(mutation.get('artifact_sufficient')).lower()}`",
                    f"- Promotion blocked: `{str(mutation.get('promotion_blocked')).lower()}`",
                    f"- Assertions passed: `{str(mutation.get('assertions_passed')).lower()}`",
                ]
            )
    lines.append("")
    return "\n".join(lines)


def write_pair_report(*, snapshot_dir: Path, json_out: Path, markdown_out: Path) -> dict[str, Any]:
    report = build_pair_report(snapshot_dir)
    dump_json(json_out, report)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.write_text(render_markdown(report))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a benchmark mutation-pair report from a frozen snapshot")
    parser.add_argument("--snapshot-dir", required=True)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    args = parser.parse_args()
    write_pair_report(
        snapshot_dir=Path(args.snapshot_dir),
        json_out=Path(args.json_out),
        markdown_out=Path(args.markdown_out),
    )


if __name__ == "__main__":
    main()
