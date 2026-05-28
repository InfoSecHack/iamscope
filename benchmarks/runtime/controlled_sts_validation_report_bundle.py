from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json
from benchmarks.runtime.controlled_sts_validation_report import validate_report_from_path
from benchmarks.runtime.controlled_sts_validation_report_generator import (
    REPO_ROOT,
    write_report,
)

BUNDLE_TYPE = "controlled_sts_validation_report_bundle"
DENIED_REPORT_FILENAME = "controlled-sts-denied-validation-report.json"
ASSUMED_REPORT_FILENAME = "controlled-sts-assumed-validation-report.json"
BUNDLE_INDEX_FILENAME = "bundle_index.md"
ARTIFACT_SAFETY_MANIFEST_FILENAME = "artifact_safety_manifest.json"
VALIDATOR_SUMMARY_FILENAME = "validator_summary.json"
BUNDLE_FILENAMES = {
    DENIED_REPORT_FILENAME,
    ASSUMED_REPORT_FILENAME,
    BUNDLE_INDEX_FILENAME,
    ARTIFACT_SAFETY_MANIFEST_FILENAME,
    VALIDATOR_SUMMARY_FILENAME,
}


def generate_bundle(
    *,
    out_dir: str | Path,
    allow_repo_output: bool = False,
    repo_root: str | Path = REPO_ROOT,
) -> dict[str, Any]:
    bundle_dir = Path(out_dir)
    _reject_repo_local_output(bundle_dir, allow_repo_output=allow_repo_output, repo_root=Path(repo_root))
    bundle_dir.mkdir(parents=True, exist_ok=True)

    denied_report_path = bundle_dir / DENIED_REPORT_FILENAME
    assumed_report_path = bundle_dir / ASSUMED_REPORT_FILENAME

    denied_generation = write_report(case="denied", json_out=denied_report_path, allow_repo_output=True)
    assumed_generation = write_report(case="assumed", json_out=assumed_report_path, allow_repo_output=True)

    denied_validation = validate_report_from_path(denied_report_path)
    assumed_validation = validate_report_from_path(assumed_report_path)
    validator_summary = _validator_summary(
        denied_validation=denied_validation,
        assumed_validation=assumed_validation,
    )
    manifest = _artifact_safety_manifest()
    index = _bundle_index()

    dump_json(bundle_dir / VALIDATOR_SUMMARY_FILENAME, validator_summary)
    dump_json(bundle_dir / ARTIFACT_SAFETY_MANIFEST_FILENAME, manifest)
    (bundle_dir / BUNDLE_INDEX_FILENAME).write_text(index, encoding="utf-8")

    return {
        "bundle_type": BUNDLE_TYPE,
        "generated": True,
        "out_dir": str(bundle_dir),
        "files": sorted(BUNDLE_FILENAMES),
        "reports_validated": True,
        "denied_report": str(denied_report_path),
        "assumed_report": str(assumed_report_path),
        "denied_generation": denied_generation,
        "assumed_generation": assumed_generation,
        "caveats": [
            "sanitized_summaries_only: bundle uses existing sanitized report generator outputs",
            "no_aws_calls: bundle generator does not call AWS or STS AssumeRole",
            "no_raw_artifact_ingestion: bundle generator does not read raw proof outputs or raw AWS logs",
            "not_committed_by_default: bundle output is caller-provided and outside repo by default",
        ],
    }


def _validator_summary(*, denied_validation: dict[str, Any], assumed_validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary_type": "controlled_sts_validation_report_bundle_validator_summary",
        "reports_validated": True,
        "validator": "benchmarks/runtime/controlled_sts_validation_report.py",
        "reports": {
            "denied": denied_validation,
            "assumed": assumed_validation,
        },
        "caveats": [
            "shape_and_safety_validation_only",
            "no AWS calls or STS AssumeRole calls",
            "no controlled validation execution",
            "no composite score",
        ],
    }


def _artifact_safety_manifest() -> dict[str, Any]:
    return {
        "bundle_type": BUNDLE_TYPE,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "raw_artifacts_included": False,
        "credentials_included": False,
        "tmp_proof_outputs_included": False,
        "raw_aws_logs_included": False,
        "terraform_state_included": False,
        "composite_score_included": False,
        "pass_fail_labels_included": False,
        "downstream_actions_claimed": False,
        "sanitized_summaries_only": True,
        "reports_validated": True,
        "caveats": [
            "generated from sanitized committed proof summaries via existing report generator",
            "generated reports are not committed by default",
            "bundle does not contain raw credentials, raw logs, or raw /tmp proof outputs",
            "bundle does not claim production readiness, broad correctness, or broad exploitability",
        ],
    }


def _bundle_index() -> str:
    return """# Controlled STS Validation Report Bundle

## Generated Bundle Contents

- `controlled-sts-denied-validation-report.json`
- `controlled-sts-assumed-validation-report.json`
- `validator_summary.json`
- `artifact_safety_manifest.json`
- `bundle_index.md`

## Denied Report Summary

- Source principal: `arn:aws:iam::516525145310:user/iamscope-admin`
- Target role: `arn:aws:iam::516525145310:role/arf-rt-DevRole`
- Predicted outcome: `denied`
- Observed outcome: `denied`
- Outcome classification: `corroborated`
- `credentials_obtained=false`
- `downstream_actions_performed=false`

## Assumed Report Summary

- Source principal: `arn:aws:iam::516525145310:user/iamscope-positive-source`
- Target role: `arn:aws:iam::516525145310:role/iamscope-positive-target-role`
- Predicted outcome: `assumed`
- Observed outcome: `assumed`
- Outcome classification: `corroborated`
- `credentials_obtained=true` as a boolean only
- `downstream_actions_performed=false`

## Evidence Boundary

This bundle shows only that the sanitized denied and assumed STS proof summaries
can be represented as controlled STS validation reports and that those reports
pass schema and safety validation. It is not new runtime evidence.

## Non-Claims

- No production-readiness claim.
- No broad runtime exploitability claim.
- No broad IAMScope correctness claim.
- No downstream authorization proof.
- No resource-policy Deny support.
- No finding-level reachability proof.
- No real-world scalability claim.
- No composite score.
- No pass/fail benchmark label.

## Artifact Safety Statement

This bundle is generated from sanitized committed summaries only. It does not
include raw `/tmp` proof outputs, raw AWS logs, credentials, Terraform state,
collect directories, raw scenario files, raw findings files, raw binding
metadata, or run logs.
"""


def _reject_repo_local_output(output_path: Path, *, allow_repo_output: bool, repo_root: Path) -> None:
    if allow_repo_output:
        return
    resolved_output = output_path.expanduser().resolve()
    resolved_repo = repo_root.expanduser().resolve()
    if _is_relative_to(resolved_output, resolved_repo):
        raise ValueError(
            "refusing to write controlled STS validation report bundle inside the repository "
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
        description="Generate a safe controlled STS validation report bundle without calling AWS."
    )
    parser.add_argument("--out-dir", required=True, type=Path, help="Caller-provided bundle output directory.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow writing inside the repository. Disabled by default to avoid committing generated bundles.",
    )
    args = parser.parse_args(argv)

    try:
        summary = generate_bundle(out_dir=args.out_dir, allow_repo_output=args.allow_repo_output)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
