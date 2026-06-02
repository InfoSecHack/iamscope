#!/usr/bin/env python3
"""Group inconclusive IAMScope findings by uncertainty class for reporting only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_OVERRIDE_ENV = "IAMSCOPE_ALLOW_REPO_OUTPUT_FOR_TESTS"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reviewer_actions(expected_groups: Path | None) -> dict[str, str]:
    if expected_groups is None:
        return {}
    payload = _load_json(expected_groups)
    actions: dict[str, str] = {}
    for group in payload.get("groups", []):
        if not isinstance(group, dict):
            continue
        uncertainty_class = group.get("uncertainty_class")
        reviewer_action = group.get("reviewer_action")
        if isinstance(uncertainty_class, str) and isinstance(reviewer_action, str):
            actions[uncertainty_class] = reviewer_action
    return actions


def group_inconclusive_uncertainty(
    findings_payload: dict[str, Any],
    *,
    reviewer_actions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return report-only grouping for inconclusive findings.

    This function does not mutate findings, change verdicts, infer exploitability,
    or make replay-equivalence claims.
    """

    actions = reviewer_actions or {}
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for finding in findings_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        if finding.get("verdict") != "inconclusive":
            continue
        uncertainty_class = finding.get("uncertainty_class")
        finding_id = finding.get("finding_id")
        if not isinstance(uncertainty_class, str) or not uncertainty_class:
            uncertainty_class = "uncertainty_class_missing"
        if not isinstance(finding_id, str) or not finding_id:
            continue
        grouped.setdefault(uncertainty_class, []).append(finding_id)

    group_details: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for uncertainty_class, finding_ids in grouped.items():
        detail: dict[str, Any] = {
            "uncertainty_class": uncertainty_class,
            "count": len(finding_ids),
            "finding_ids": finding_ids,
        }
        if uncertainty_class in actions:
            detail["reviewer_action"] = actions[uncertainty_class]
        group_details.append(detail)
        counts[uncertainty_class] = len(finding_ids)

    top_class = None
    top_count = 0
    if group_details:
        top = max(group_details, key=lambda item: item["count"])
        top_class = top["uncertainty_class"]
        top_count = top["count"]

    return {
        "fixture_id": findings_payload.get("fixture_id"),
        "report_only": True,
        "groups": counts,
        "group_details": group_details,
        "top_uncertainty_class": top_class,
        "top_uncertainty_count": top_count,
        "non_claims": {
            "does_not_mutate_findings": True,
            "does_not_change_verdicts": True,
            "does_not_infer_exploitability": True,
            "does_not_claim_replay_equivalence": True,
            "requires_aws_credentials": False,
        },
    }


def _write_output(output_path: Path, text: str) -> None:
    output_abs = output_path.resolve()
    repo_abs = REPO_ROOT.resolve()
    if _is_relative_to(output_abs, repo_abs) and os.environ.get(TEST_OVERRIDE_ENV) != "1":
        raise ValueError(
            f"refusing to write uncertainty grouping output inside repository tree: {output_abs}"
        )
    output_abs.parent.mkdir(parents=True, exist_ok=True)
    output_abs.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="Path to findings.json")
    parser.add_argument(
        "--expected-groups",
        default=None,
        help="Optional expected groups JSON used only to enrich reviewer_action fields",
    )
    parser.add_argument("--out", default=None, help="Optional output JSON path; stdout if omitted")
    args = parser.parse_args(argv)

    findings_path = Path(args.findings)
    expected_path = Path(args.expected_groups) if args.expected_groups else None
    try:
        payload = group_inconclusive_uncertainty(
            _load_json(findings_path),
            reviewer_actions=_reviewer_actions(expected_path),
        )
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.out:
            _write_output(Path(args.out), text)
        else:
            print(text, end="")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
