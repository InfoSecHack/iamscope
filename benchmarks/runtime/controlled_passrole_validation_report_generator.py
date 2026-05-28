from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json
from benchmarks.runtime.controlled_passrole_validation_report import (
    PREDICTED_ACTION,
    REPORT_TYPE,
    SCHEMA_VERSION,
    validate_report,
)

SUPPORTED_CASES = {
    "corroborated_allowed_static",
    "corroborated_denied_static",
    "inconclusive_static",
}
REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PRINCIPAL = "lambda.amazonaws.com"
SOURCE_PRINCIPAL_ARN = "arn:aws:iam::123456789012:user/iamscope-test/passrole-source"
TARGET_ROLE_ARN = "arn:aws:iam::123456789012:role/iamscope-test/passrole-service-role"
EXPECTED_ACCOUNT_ID = "123456789012"
SOURCE_DOCUMENT = "docs/specs/controlled-passrole-validation-report-generator-design.md"
INPUT_BUNDLE_REFERENCE = "sanitized://controlled-passrole/static-summary-cases"
REQUIRED_NON_CLAIMS = [
    "no production readiness",
    "no broad IAMScope correctness",
    "no arbitrary enterprise graph correctness",
    "no broad runtime exploitability",
    "no downstream service execution proof",
    "no downstream authorization proof",
    "no resource-policy Deny support unless explicitly in scope",
    "no finding-level reachability unless explicitly in scope",
]


def build_report(case: str) -> dict[str, Any]:
    if case == "corroborated_allowed_static":
        return _build_case_report(
            case=case,
            predicted_outcome="allowed",
            observed_outcome="allowed",
            outcome_classification="corroborated",
            service_principal_match="matched",
            source_permission_evidence=(
                "Sanitized static summary indicates the selected source principal has iam:PassRole "
                "permission scoped to the selected target role."
            ),
            target_trust_evidence=(
                "Sanitized static summary indicates the selected target role trusts the selected service principal."
            ),
            condition_context="No unresolved condition context was required for this sanitized static allowed case.",
            sanitized_reasons=[
                "source_permission_matches_selected_target_role",
                "target_trust_matches_selected_service_principal",
                "static_sanitized_evidence_supports_allowed_outcome",
            ],
            evidence_summary=(
                "Built-in sanitized static evidence represents one selected PassRole prediction as allowed."
            ),
        )
    if case == "corroborated_denied_static":
        return _build_case_report(
            case=case,
            predicted_outcome="denied",
            observed_outcome="denied",
            outcome_classification="corroborated",
            service_principal_match="mismatched",
            source_permission_evidence=(
                "Sanitized static summary indicates the selected source principal lacks an applicable "
                "iam:PassRole allowance for the selected target role."
            ),
            target_trust_evidence=(
                "Sanitized static summary is insufficient to establish a matching service trust for the selected path."
            ),
            condition_context="No live context was evaluated for this sanitized static denied case.",
            sanitized_reasons=[
                "source_permission_does_not_match_selected_target_role",
                "static_sanitized_evidence_supports_denied_outcome",
            ],
            evidence_summary=(
                "Built-in sanitized static evidence represents one selected PassRole prediction as denied."
            ),
        )
    if case == "inconclusive_static":
        return _build_case_report(
            case=case,
            predicted_outcome="inconclusive",
            observed_outcome="inconclusive",
            outcome_classification="inconclusive",
            service_principal_match="unknown",
            source_permission_evidence=(
                "Sanitized static summary does not contain enough source-side permission evidence to decide the path."
            ),
            target_trust_evidence=(
                "Sanitized static summary does not contain enough target trust evidence to decide the path."
            ),
            condition_context="Sanitized static summary leaves condition context unresolved for the selected path.",
            sanitized_reasons=[
                "source_permission_evidence_incomplete",
                "target_trust_evidence_incomplete",
                "condition_context_unresolved",
            ],
            evidence_summary=(
                "Built-in sanitized static evidence leaves one selected PassRole prediction inconclusive."
            ),
        )
    raise ValueError(f"unsupported controlled PassRole validation report case: {case!r}")


def write_report(
    *,
    case: str,
    json_out: str | Path,
    allow_repo_output: bool = False,
    repo_root: str | Path = REPO_ROOT,
) -> dict[str, Any]:
    output_path = Path(json_out)
    _reject_repo_local_output(output_path, allow_repo_output=allow_repo_output, repo_root=Path(repo_root))

    report = build_report(case)
    validation_summary = validate_report(report)
    dump_json(output_path, report)
    return {
        "report_type": "controlled_passrole_validation_report_generation",
        "generated": True,
        "case": case,
        "json_out": str(output_path),
        "validated_before_write": True,
        "validation_id": validation_summary["validation_id"],
        "outcome_classification": validation_summary["outcome_classification"],
        "observed_outcome": validation_summary["observed_outcome"],
        "method_type": validation_summary["method_type"],
        "iam_passrole_called": validation_summary["iam_passrole_called"],
        "service_launch_attempted": validation_summary["service_launch_attempted"],
        "downstream_actions_performed": validation_summary["downstream_actions_performed"],
        "caveats": [
            "sanitized_summary_source_only: generator uses built-in sanitized summary facts only",
            "no_aws_calls: generator does not call AWS, iam:PassRole, or STS AssumeRole",
            "no_service_launch: generator does not launch services or create resources",
            "not_committed_by_default: generated reports are caller-provided outputs",
        ],
    }


def _build_case_report(
    *,
    case: str,
    predicted_outcome: str,
    observed_outcome: str,
    outcome_classification: str,
    service_principal_match: str,
    source_permission_evidence: str,
    target_trust_evidence: str,
    condition_context: str,
    sanitized_reasons: list[str],
    evidence_summary: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "validation_id": f"controlled-passrole-{case}-summary-001",
        "created_at": "2026-05-19T00:00:00Z",
        "environment_label": f"controlled-passrole-{case}",
        "input_bundle_reference": INPUT_BUNDLE_REFERENCE,
        "finding_reference": {
            "finding_id": None,
            "path_id": None,
            "validation_layer_id": f"validation-layer-passrole-{case}-001",
            "source_principal_arn": SOURCE_PRINCIPAL_ARN,
            "target_role_arn": TARGET_ROLE_ARN,
            "service_principal": SERVICE_PRINCIPAL,
            "expected_account_id": EXPECTED_ACCOUNT_ID,
            "reasoner_or_finding_type": "passrole_service_path",
            "prediction_source": "built-in sanitized PassRole static summary facts",
            "source_document": SOURCE_DOCUMENT,
            "source_bundle": INPUT_BUNDLE_REFERENCE,
        },
        "predicted_behavior": {
            "predicted_action": PREDICTED_ACTION,
            "predicted_service_principal": SERVICE_PRINCIPAL,
            "predicted_target_role_arn": TARGET_ROLE_ARN,
            "predicted_outcome": predicted_outcome,
            "prediction_basis": (
                "Built-in sanitized static summary facts describe the selected source principal, "
                "target role, service principal, and expected PassRole outcome."
            ),
            "prediction_caveats": [
                "one selected PassRole finding/path only",
                "sanitized static summary only",
                "no live AWS calls",
                "no service launch",
            ],
        },
        "evidence_method": {
            "method_type": "static_policy_trust_corroboration",
            "live_aws_used": False,
            "aws_calls_made": False,
            "iam_passrole_called": False,
            "service_launch_attempted": False,
            "downstream_actions_performed": False,
            "output_paths": [],
            "safe_error_category": "none",
        },
        "observed_evidence": {
            "source_permission_evidence": source_permission_evidence,
            "target_trust_evidence": target_trust_evidence,
            "service_principal_match": service_principal_match,
            "condition_context": condition_context,
            "observed_outcome": observed_outcome,
            "sanitized_reasons": sanitized_reasons,
            "no_raw_credentials": True,
            "no_raw_aws_errors": True,
        },
        "outcome_classification": outcome_classification,
        "evidence_summary": evidence_summary,
        "caveats": [
            "generated from built-in sanitized summary facts only",
            "one selected PassRole finding/path only",
            "no live PassRole validation",
            "no service launch",
            "no downstream AWS actions",
            "generated report is not committed by default",
        ],
        "non_claims": REQUIRED_NON_CLAIMS,
        "artifact_safety_status": {
            "raw_artifacts_committed": False,
            "credentials_committed": False,
            "tmp_outputs_committed": False,
            "downstream_actions": False,
            "service_launch_attempted": False,
            "sanitized_summary_only": True,
            "reviewer_checked": True,
        },
    }


def _reject_repo_local_output(output_path: Path, *, allow_repo_output: bool, repo_root: Path) -> None:
    if allow_repo_output:
        return
    resolved_output = output_path.expanduser().resolve()
    resolved_repo = repo_root.expanduser().resolve()
    if _is_relative_to(resolved_output, resolved_repo):
        raise ValueError(
            "refusing to write controlled PassRole validation report inside the repository "
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
        description="Generate one controlled PassRole validation report from built-in sanitized summary facts."
    )
    parser.add_argument("--case", required=True, choices=sorted(SUPPORTED_CASES), help="Sanitized summary case to export.")
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
