from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json
from benchmarks.runtime.controlled_sts_validation_report import (
    PREDICTED_ACTION,
    PROBE_TYPE,
    REPORT_TYPE,
    SCHEMA_VERSION,
    validate_report,
)

SUPPORTED_CASES = {"denied", "assumed"}
REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_NON_CLAIMS = [
    "no production readiness",
    "no broad IAMScope correctness",
    "no arbitrary enterprise graph correctness",
    "no broad runtime exploitability",
    "no downstream authorization proof",
    "no generic resource-policy Deny support",
    "no finding-level reachability proof",
]


def build_report(case: str) -> dict[str, Any]:
    if case == "denied":
        return _build_case_report(
            case=case,
            source_principal_arn="arn:aws:iam::516525145310:user/iamscope-admin",
            target_role_arn="arn:aws:iam::516525145310:role/arf-rt-DevRole",
            expected_outcome="denied",
            observed_outcome="denied",
            credentials_obtained=False,
            safe_error_category="access_denied",
            source_document="BENCHMARK_RUNTIME_STS_SINGLE_CASE_PROOF_PROTOCOL.md",
            proof_summary_document="BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md",
            evidence_boundary=(
                "one source principal could not assume one target role under the "
                "documented test condition"
            ),
        )
    if case == "assumed":
        return _build_case_report(
            case=case,
            source_principal_arn="arn:aws:iam::516525145310:user/iamscope-positive-source",
            target_role_arn="arn:aws:iam::516525145310:role/iamscope-positive-target-role",
            expected_outcome="assumed",
            observed_outcome="assumed",
            credentials_obtained=True,
            safe_error_category="none",
            source_document="BENCHMARK_RUNTIME_STS_POSITIVE_PROOF_PROTOCOL.md",
            proof_summary_document="BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md",
            evidence_boundary=(
                "one isolated test source principal could assume one isolated test "
                "target role under documented test conditions"
            ),
        )
    raise ValueError(f"unsupported controlled STS validation report case: {case!r}")


def write_report(
    *,
    case: str,
    json_out: str | Path,
    allow_repo_output: bool = False,
    repo_root: str | Path = REPO_ROOT,
) -> dict[str, Any]:
    output_path = Path(json_out)
    if not output_path:
        raise ValueError("--json-out is required")
    _reject_repo_local_output(output_path, allow_repo_output=allow_repo_output, repo_root=Path(repo_root))

    report = build_report(case)
    validation_summary = validate_report(report)
    dump_json(output_path, report)
    return {
        "report_type": "controlled_sts_validation_report_generation",
        "generated": True,
        "case": case,
        "json_out": str(output_path),
        "validated_before_write": True,
        "validation_id": validation_summary["validation_id"],
        "outcome_classification": validation_summary["outcome_classification"],
        "observed_outcome": validation_summary["observed_outcome"],
        "credentials_obtained": validation_summary["credentials_obtained"],
        "caveats": [
            "sanitized_summary_source_only: generator uses committed sanitized proof facts only",
            "no_aws_calls: generator does not call AWS or STS AssumeRole",
            "no_raw_artifact_ingestion: generator does not read raw /tmp proof outputs or raw AWS logs",
            "not_committed_by_default: generated reports are caller-provided outputs",
        ],
    }


def _build_case_report(
    *,
    case: str,
    source_principal_arn: str,
    target_role_arn: str,
    expected_outcome: str,
    observed_outcome: str,
    credentials_obtained: bool,
    safe_error_category: str,
    source_document: str,
    proof_summary_document: str,
    evidence_boundary: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "validation_id": f"controlled-sts-{case}-proof-summary-001",
        "created_at": "2026-05-16T00:00:00Z",
        "environment_label": f"controlled-sts-{case}-proof-summary",
        "input_bundle_reference": proof_summary_document,
        "finding_reference": {
            "path_id": f"runtime-sts-{case}-single-case-proof",
            "source_principal_arn": source_principal_arn,
            "target_role_arn": target_role_arn,
            "expected_account_id": "516525145310",
            "reasoner_or_finding_type": "sts_assume_role_path",
            "prediction_source": "already-committed sanitized STS proof summary",
            "source_document": source_document,
            "source_bundle": proof_summary_document,
        },
        "predicted_behavior": {
            "predicted_action": PREDICTED_ACTION,
            "predicted_outcome": expected_outcome,
            "prediction_basis": (
                "sanitized committed proof summary records the expected STS "
                f"outcome as {expected_outcome}"
            ),
            "prediction_caveats": [
                "selected STS path only",
                "controlled test condition only",
                "report generated from sanitized committed summary, not raw proof output",
            ],
        },
        "runtime_probe": {
            "probe_id": f"runtime-sts-{case}-single-case-proof",
            "probe_type": PROBE_TYPE,
            "mode": "sanitized_summary_import",
            "operator_confirmation_used": True,
            "live_aws_used": True,
            "aws_calls_made": True,
            "sts_assume_role_called": True,
            "downstream_actions_performed": False,
            "credentials_obtained": credentials_obtained,
            "output_paths": {
                "source_summary_document": proof_summary_document,
                "raw_tmp_outputs_read": False,
                "generated_report_path": "caller-provided",
            },
            "safe_error_category": safe_error_category,
        },
        "observed_behavior": {
            "observed_outcome": observed_outcome,
            "observed_account_id": "516525145310",
            "result_classification": observed_outcome,
            "sanitized_reasons": [
                f"sanitized committed proof summary recorded observed outcome {observed_outcome}",
                "no downstream AWS actions were performed",
                "raw credential material and raw /tmp proof outputs were not committed",
            ],
            "no_raw_credentials": True,
            "no_raw_aws_errors": True,
        },
        "outcome_classification": "corroborated",
        "evidence_summary": {
            "sanitized_inputs": "one source principal and one target role from committed proof-summary docs",
            "runtime_observation": (
                f"sanitized summary records one STS AssumeRole attempt classified as {observed_outcome}"
            ),
            "manual_context_review": evidence_boundary,
        },
        "caveats": [
            "one selected STS path only",
            "one controlled test condition only",
            "no downstream AWS actions",
            "generated from committed sanitized summary only",
            "raw /tmp proof outputs were not read",
        ],
        "non_claims": REQUIRED_NON_CLAIMS,
        "artifact_safety_status": {
            "raw_artifacts_committed": False,
            "credentials_committed": False,
            "tmp_outputs_committed": False,
            "downstream_actions": False,
            "sanitized_summary_only": True,
            "reviewer_checked": True,
            "raw_aws_logs_committed": False,
            "terraform_artifacts_committed": False,
            "credential_shaped_fields_present": False,
        },
    }


def _reject_repo_local_output(output_path: Path, *, allow_repo_output: bool, repo_root: Path) -> None:
    if allow_repo_output:
        return
    resolved_output = output_path.expanduser().resolve()
    resolved_repo = repo_root.expanduser().resolve()
    if _is_relative_to(resolved_output, resolved_repo):
        raise ValueError(
            "refusing to write controlled STS validation report inside the repository "
            "without --allow-repo-output"
        )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate one controlled STS validation report from sanitized committed proof summaries."
    )
    parser.add_argument("--case", required=True, choices=sorted(SUPPORTED_CASES), help="Sanitized proof case to export.")
    parser.add_argument("--json-out", required=True, type=Path, help="Caller-provided JSON report output path.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow writing inside the repository. Disabled by default to avoid committing generated reports.",
    )
    args = parser.parse_args(argv)

    try:
        summary = write_report(case=args.case, json_out=args.json_out, allow_repo_output=args.allow_repo_output)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
