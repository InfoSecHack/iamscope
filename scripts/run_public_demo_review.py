#!/usr/bin/env python3
"""Run the local-only public IAMScope demo/evidence review summary."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.probe_complex_passrole_lambda_replay_subset import run_probe as run_passrole_lambda_replay_subset_probe

DEFAULT_OUT = Path("/tmp/iamscope-public-demo-review")
COMPLEX_PASSROLE_SCOPE_CLASS = "shared_passrole_target_resource_scope_unknown"
COMPLEX_TRUST_CONDITION_CLASS = "shared_cross_account_trust_condition_unknown"
COMPLEX_BOUNDARY_CONTEXT_CLASS = "shared_boundary_or_session_policy_context_missing"

CLAIM_BOUNDARY = (
    "IAMScope currently has a local synthetic path-overcounting teaching demo and one "
    "two-sided controlled PassRole-to-Lambda validation pair. This is not broad IAMScope correctness."
)

SUPPORTED_CLAIMS = [
    "Local synthetic path-overcounting demo shows how IAMScope separates naive path-shaped candidates from validated, blocked, precondition-only, and inconclusive fixture verdicts.",
    "Allowed PassRole-to-Lambda case: selected local `validated` finding matched live AWS `lambda:CreateFunction` success.",
    "Denied missing-PassRole case: live AWS returned `access_denied`, and local IAMScope emitted no selected validated `passrole_lambda` finding for the corresponding source/target shape.",
]

NON_CLAIMS = [
    "no broad IAMScope correctness",
    "no broad PassRole correctness",
    "no generic Deny correctness",
    "no resource-policy Deny support",
    "no SCP Deny support",
    "no exploitability proof",
    "no downstream authorization proof",
    "no Lambda invocation behavior",
    "no production readiness",
    "no correctness for other principals, roles, accounts, regions, conditions, permission boundaries, SCPs, resource policies, or findings",
    "no composite benchmark score",
    "no pass/fail benchmark label",
]

EVIDENCE_LINKS = [
    "docs/REVIEWER_GUIDE.md",
    "docs/case-studies/passrole-lambda-controlled-live-validation.md",
    "docs/case-studies/path-overcounting-shared-uncertainty.md",
    "docs/specs/controlled-passrole-lambda-live-binding-001-checkpoint.md",
    "docs/specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md",
    "tests/fixtures/live_binding/passrole_lambda_selected_finding/",
    "tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/",
]


@dataclass(frozen=True)
class CheckResult:
    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    expect_empty_stdout: bool = False

    @property
    def passed(self) -> bool:
        if self.returncode != 0:
            return False
        if self.expect_empty_stdout and self.stdout.strip():
            return False
        return True


CheckRunner = Callable[[Path], list[CheckResult]]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_output_dir(output_dir: Path) -> Path:
    output_abs = output_dir.expanduser().resolve()
    repo_abs = REPO_ROOT.resolve()
    if _is_relative_to(output_abs, repo_abs):
        raise ValueError(f"refusing to write public demo review outputs inside repository tree: {output_abs}")
    return output_abs


def _run_command(name: str, command: Sequence[str], *, expect_empty_stdout: bool = False) -> CheckResult:
    completed = subprocess.run(
        list(command),
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return CheckResult(
        name=name,
        command=" ".join(command),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        expect_empty_stdout=expect_empty_stdout,
    )


def run_local_checks(output_dir: Path) -> list[CheckResult]:
    uncertainty_out = output_dir / "path-overcounting-uncertainty-groups.json"
    return [
        _run_command(
            "focused_live_binding_tests",
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/test_passrole_lambda_live_binding_fixture.py",
                "tests/test_live_passrole_lambda_validation.py",
            ],
        ),
        _run_command(
            "account_id_hygiene_scan",
            [
                "bash",
                "-lc",
                r"grep -RInE '[0-9]{12}' docs tests | grep -v '000000000000' || true",
            ],
            expect_empty_stdout=True,
        ),
        _run_command(
            "iam_arn_hygiene_scan",
            [
                "bash",
                "-lc",
                r"grep -RInE 'arn:aws:iam::[0-9]{12}' docs tests | grep -v '000000000000' || true",
            ],
            expect_empty_stdout=True,
        ),
        _run_command(
            "artifact_hygiene_scan",
            [
                "bash",
                "-lc",
                "find . -name 'result.json' -o -name 'terraform.tfstate*' -o -name '.terraform.lock.hcl' -o -name '*.tfplan' -o -name 'terraform-outputs.json'",
            ],
            expect_empty_stdout=True,
        ),
        _run_command(
            "path_overcounting_uncertainty_grouping",
            [
                sys.executable,
                "scripts/group_inconclusive_uncertainty.py",
                "--findings",
                "tests/fixtures/demo/path_overcounting_shared_uncertainty/findings.json",
                "--expected-groups",
                "tests/fixtures/demo/path_overcounting_shared_uncertainty/expected_uncertainty_groups.json",
                "--out",
                str(uncertainty_out),
            ],
        ),
    ]


def _path_overcounting_summary() -> dict[str, object]:
    fixture_dir = REPO_ROOT / "tests" / "fixtures" / "demo" / "path_overcounting_shared_uncertainty"
    naive = json.loads((fixture_dir / "naive_candidates.json").read_text(encoding="utf-8"))
    findings = json.loads((fixture_dir / "findings.json").read_text(encoding="utf-8"))
    uncertainty = json.loads((fixture_dir / "expected_uncertainty_groups.json").read_text(encoding="utf-8"))
    verdicts = {"validated": 0, "blocked": 0, "precondition_only": 0, "inconclusive": 0}
    for finding in findings["findings"]:
        verdict = finding["verdict"]
        if verdict in verdicts:
            verdicts[verdict] += 1
    group_counts = {group["uncertainty_class"]: len(group["finding_ids"]) for group in uncertainty["groups"]}
    return {
        "naive_candidate_count": len(naive["candidate_paths"]),
        "verdict_breakdown": verdicts,
        "top_uncertainty_class": "shared_passrole_target_resource_scope_unknown",
        "top_uncertainty_count": group_counts["shared_passrole_target_resource_scope_unknown"],
    }


def _complex_synthetic_benchmark_summary() -> dict[str, object]:
    fixture_dir = REPO_ROOT / "tests" / "fixtures" / "demo" / "complex_shared_uncertainty_iam_benchmark"
    naive = json.loads((fixture_dir / "naive_candidates.json").read_text(encoding="utf-8"))
    findings = json.loads((fixture_dir / "findings.json").read_text(encoding="utf-8"))
    uncertainty = json.loads((fixture_dir / "expected_uncertainty_groups.json").read_text(encoding="utf-8"))
    verdicts = {"validated": 0, "blocked": 0, "precondition_only": 0, "inconclusive": 0}
    for finding in findings["findings"]:
        verdict = finding["verdict"]
        if verdict in verdicts:
            verdicts[verdict] += 1
    group_counts = {group["uncertainty_class"]: group["count"] for group in uncertainty["groups"]}
    return {
        "fixture_id": findings["fixture_id"],
        "source_tool": findings["source_tool"],
        "generation_mode": findings["generation_mode"],
        "local_only": True,
        "live_aws_used": findings["live_aws_used"],
        "aws_calls_made": findings["aws_calls_made"],
        "generated_or_replayed_by_iamscope": findings["generated_or_replayed_by_iamscope"],
        "reasoners_run": findings["reasoners_run"],
        "naive_candidate_count": len(naive["candidate_paths"]),
        "finding_count": len(findings["findings"]),
        "verdict_breakdown": verdicts,
        "uncertainty_group_counts": group_counts,
        "report_only": True,
        "not_composite_score": True,
        "not_pass_fail_benchmark_label": True,
    }


def _passrole_lambda_replay_subset_summary(output_dir: Path) -> dict[str, object]:
    subset_out = output_dir / "passrole-lambda-replay-subset"
    subset_manifest = run_passrole_lambda_replay_subset_probe(subset_out)
    return {
        "replay_subset_status": subset_manifest["replay_subset_status"],
        "input_contract_status": subset_manifest["input_contract_status"],
        "safe_replay_attempted": subset_manifest["safe_replay_attempted"],
        "reasoners_attempted": subset_manifest["reasoners_attempted"],
        "matched_row_count": len(subset_manifest["matched_rows"]),
        "missing_row_count": len(subset_manifest["missing_rows"]),
        "extra_row_count": len(subset_manifest["extra_rows"]),
        "static_only_row_count": len(subset_manifest["static_only_rows"]),
        "generated_findings_output": (
            "passrole-lambda-replay-subset/" + str(subset_manifest["generated_findings_output"])
        ),
        "local_only": subset_manifest["local_only"],
        "live_aws_used": subset_manifest["live_aws_used"],
        "aws_calls_made": subset_manifest["aws_calls_made"],
        "non_claims": subset_manifest["non_claims"],
    }


def _passrole_summary() -> dict[str, object]:
    selected = json.loads(
        (
            REPO_ROOT
            / "tests"
            / "fixtures"
            / "live_binding"
            / "passrole_lambda_selected_finding"
            / "expected_finding.json"
        ).read_text(encoding="utf-8")
    )
    denied = json.loads(
        (
            REPO_ROOT
            / "tests"
            / "fixtures"
            / "live_binding"
            / "passrole_lambda_denied_missing_passrole"
            / "expected_no_selected_finding.json"
        ).read_text(encoding="utf-8")
    )
    return {
        "allowed": {
            "finding_id": selected["selected_finding"]["finding_id"],
            "expected_verdict": selected["selected_finding"]["expected_verdict"],
            "binding_status": selected["binding_status"],
            "summary": "selected local `validated` finding matched live AWS `lambda:CreateFunction` success",
        },
        "denied": {
            "expected_verdict": denied["local_expectation"]["expected_verdict"],
            "binding_status": denied["binding_status"],
            "missing_required_evidence": denied["local_expectation"]["missing_required_evidence"],
            "summary": "live AWS returned `access_denied`, and local IAMScope emitted no selected validated `passrole_lambda` finding",
        },
    }


def _render_summary(
    *,
    output_dir: Path,
    checks: list[CheckResult],
    path_summary: dict[str, object],
    complex_summary: dict[str, object],
    replay_subset_summary: dict[str, object],
    passrole_summary: dict[str, object],
) -> str:
    check_lines = "\n".join(
        f"- {check.name}: {'passed' if check.passed else 'failed'} (`{check.command}`)" for check in checks
    )
    supported = "\n".join(f"- {claim}" for claim in SUPPORTED_CLAIMS)
    non_claims = "\n".join(f"- {claim}" for claim in NON_CLAIMS)
    links = "\n".join(f"- `{link}`" for link in EVIDENCE_LINKS)
    verdicts = path_summary["verdict_breakdown"]
    assert isinstance(verdicts, dict)
    complex_verdicts = complex_summary["verdict_breakdown"]
    complex_groups = complex_summary["uncertainty_group_counts"]
    assert isinstance(complex_verdicts, dict)
    assert isinstance(complex_groups, dict)
    reasoners_attempted = replay_subset_summary["reasoners_attempted"]
    assert isinstance(reasoners_attempted, list)
    allowed = passrole_summary["allowed"]
    denied = passrole_summary["denied"]
    assert isinstance(allowed, dict)
    assert isinstance(denied, dict)
    return f"""# IAMScope Public Demo Review Summary

## Public claim boundary

{CLAIM_BOUNDARY}

Output directory: `{output_dir}`

## Local synthetic path-overcounting demo

- Naive path-shaped candidates: {path_summary["naive_candidate_count"]}
- `validated`: {verdicts["validated"]}
- `blocked`: {verdicts["blocked"]}
- `precondition_only`: {verdicts["precondition_only"]}
- `inconclusive`: {verdicts["inconclusive"]}
- Top uncertainty class: `{path_summary["top_uncertainty_class"]}` with {path_summary["top_uncertainty_count"]} inconclusive paths

## Complex synthetic benchmark

- Fixture id: `{complex_summary["fixture_id"]}`
- Local-only frozen synthetic oracle: true
- Source tool: `{complex_summary["source_tool"]}`
- Generation mode: `{complex_summary["generation_mode"]}`
- Naive path-shaped candidates: {complex_summary["naive_candidate_count"]}
- Findings: {complex_summary["finding_count"]}
- `validated`: {complex_verdicts["validated"]}
- `blocked`: {complex_verdicts["blocked"]}
- `precondition_only`: {complex_verdicts["precondition_only"]}
- `inconclusive`: {complex_verdicts["inconclusive"]}
- `{COMPLEX_PASSROLE_SCOPE_CLASS}`: {complex_groups[COMPLEX_PASSROLE_SCOPE_CLASS]}
- `{COMPLEX_TRUST_CONDITION_CLASS}`: {complex_groups[COMPLEX_TRUST_CONDITION_CLASS]}
- `{COMPLEX_BOUNDARY_CONTEXT_CLASS}`: {complex_groups[COMPLEX_BOUNDARY_CONTEXT_CLASS]}
- Generated/replayed by IAMScope: {str(complex_summary["generated_or_replayed_by_iamscope"]).lower()}
- Reasoners run: {complex_summary["reasoners_run"]}
- Report-only: true
- This is not generated/replayed by IAMScope.
- This is not a composite score or pass/fail benchmark label.

## Narrow PassRole-to-Lambda replay subset

- replay subset status: `{replay_subset_summary["replay_subset_status"]}`
- input contract status: `{replay_subset_summary["input_contract_status"]}`
- safe replay attempted: `{str(replay_subset_summary["safe_replay_attempted"]).lower()}`
- reasoners attempted: `{", ".join(str(reasoner) for reasoner in reasoners_attempted)}`
- matched rows: {replay_subset_summary["matched_row_count"]}
- missing rows: {replay_subset_summary["missing_row_count"]}
- extra rows: {replay_subset_summary["extra_row_count"]}
- static-only rows: {replay_subset_summary["static_only_row_count"]}
- live AWS used: `{str(replay_subset_summary["live_aws_used"]).lower()}`
- AWS calls made: `{replay_subset_summary["aws_calls_made"]}`
- This does not prove replay-equivalence for the full complex synthetic benchmark.

## PassRole-to-Lambda allowed-side summary

- {allowed["summary"]}.
- Binding status: `{allowed["binding_status"]}`.
- Finding ID: `{allowed["finding_id"]}`.

## PassRole-to-Lambda denied-side summary

- {denied["summary"]}.
- Binding status: `{denied["binding_status"]}`.
- Missing required evidence: `{denied["missing_required_evidence"]}`.

## Focused tests and hygiene scans

{check_lines}

## Supported claims

{supported}

## Non-claims

{non_claims}

## Evidence links

{links}

## Safety

- local-only: true
- live AWS used: false
- AWS calls made: 0
- no AWS credentials required
- no Terraform apply/destroy
- no STS, Lambda, AWS CLI, or `iam:PassRole` calls
"""


def _manifest(
    *,
    output_dir: Path,
    checks: list[CheckResult],
    generated_files: list[str],
    path_summary: dict[str, object],
    complex_summary: dict[str, object],
    replay_subset_summary: dict[str, object],
    passrole_summary: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "public_demo_review_manifest.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repository_root": str(REPO_ROOT),
        "output_directory": str(output_dir),
        "local_only": True,
        "live_aws_used": False,
        "aws_calls_made": 0,
        "commands_checks_run": [
            {
                "name": check.name,
                "command": check.command,
                "returncode": check.returncode,
                "passed": check.passed,
                "expect_empty_stdout": check.expect_empty_stdout,
            }
            for check in checks
        ],
        "output_files_generated": generated_files,
        "path_overcounting_demo": path_summary,
        "complex_synthetic_benchmark": complex_summary,
        "passrole_lambda_replay_subset": replay_subset_summary,
        "passrole_lambda_controlled_pair": passrole_summary,
        "supported_claims": SUPPORTED_CLAIMS,
        "non_claims": NON_CLAIMS,
    }


def run_public_demo_review(output_dir: Path, *, check_runner: CheckRunner = run_local_checks) -> dict[str, object]:
    out_abs = _resolve_output_dir(output_dir)
    out_abs.mkdir(parents=True, exist_ok=True)

    checks = check_runner(out_abs)
    failed = [check for check in checks if not check.passed]
    path_summary = _path_overcounting_summary()
    complex_summary = _complex_synthetic_benchmark_summary()
    replay_subset_summary = _passrole_lambda_replay_subset_summary(out_abs)
    passrole_summary = _passrole_summary()
    generated_files = ["summary.md", "manifest.json"]
    if (out_abs / "path-overcounting-uncertainty-groups.json").exists():
        generated_files.append("path-overcounting-uncertainty-groups.json")
    subset_generated_files = [
        "passrole-lambda-replay-subset/replay-subset-summary.md",
        "passrole-lambda-replay-subset/replay-subset-manifest.json",
        "passrole-lambda-replay-subset/generated-findings.json",
    ]
    generated_files.extend(
        path for path in subset_generated_files if (out_abs / path).exists()
    )

    summary = _render_summary(
        output_dir=out_abs,
        checks=checks,
        path_summary=path_summary,
        complex_summary=complex_summary,
        replay_subset_summary=replay_subset_summary,
        passrole_summary=passrole_summary,
    )
    manifest = _manifest(
        output_dir=out_abs,
        checks=checks,
        generated_files=generated_files,
        path_summary=path_summary,
        complex_summary=complex_summary,
        replay_subset_summary=replay_subset_summary,
        passrole_summary=passrole_summary,
    )

    (out_abs / "summary.md").write_text(summary, encoding="utf-8")
    (out_abs / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failed:
        failure_names = ", ".join(check.name for check in failed)
        raise RuntimeError(f"public demo review checks failed: {failure_names}")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT), help=f"Output directory, default: {DEFAULT_OUT}")
    args = parser.parse_args(argv)

    try:
        manifest = run_public_demo_review(Path(args.out))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("IAMScope public demo review (local only)")
    print(f"Output: {manifest['output_directory']}")
    print()
    print(CLAIM_BOUNDARY)
    print()
    print("Focused tests and hygiene scans: passed")
    print("Live AWS used: false")
    print("AWS calls made: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
