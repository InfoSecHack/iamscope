#!/usr/bin/env python3
"""Create sanitized reviewer classification artifacts for real-pilot findings."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_OVERRIDE_ENV = "IAMSCOPE_ALLOW_REPO_OUTPUT_FOR_TESTS"

CLASSIFICATIONS = {
    "valid_path",
    "expected_benign",
    "blocked_or_controlled",
    "inconclusive_needs_context",
    "environmental_extra",
    "tool_bug",
    "needs_more_evidence",
}
CONFIDENCE_VALUES = {"low", "medium", "high"}
ARN_RE = re.compile(r"arn:aws:(iam|sts)::[0-9]{12}:([A-Za-z0-9+=,.@_:/-]+)")
ACCOUNT_ID_RE = re.compile(r"\b[0-9]{12}\b")


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _ensure_output_dir(path: Path) -> Path:
    output = path.resolve()
    repo = REPO_ROOT.resolve()
    if _is_relative_to(output, repo) and os.environ.get(TEST_OVERRIDE_ENV) != "1":
        raise ValueError(f"refusing to write real-pilot review artifacts inside repository tree: {output}")
    output.mkdir(parents=True, exist_ok=True)
    return output


def _tail_name(value: str) -> str:
    resource = value.split(":", 5)[-1]
    if resource.startswith("assumed-role/"):
        parts = resource.split("/")
        return parts[1] if len(parts) > 1 and parts[1] else "assumed-role"
    if "/" in resource:
        return resource.rstrip("/").split("/")[-1] or resource.split("/", 1)[0]
    return resource or "resource"


def sanitize_text(value: Any) -> str:
    text = str(value)

    def replace_arn(match: re.Match[str]) -> str:
        service = match.group(1)
        tail = _tail_name(match.group(0))
        return f"<redacted-{service}-arn:{tail}>"

    text = ARN_RE.sub(replace_arn, text)
    return ACCOUNT_ID_RE.sub("<redacted-aws-account-id>", text)


def sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {sanitize_text(key): sanitize_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def _iter_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        strings: list[str] = []
        for key, item in value.items():
            strings.append(str(key))
            strings.extend(_iter_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_iter_strings(item))
        return strings
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool):
        return [str(value).lower()]
    if value is None:
        return []
    return [str(value)]


def _find_values_by_key(value: Any, wanted: set[str]) -> dict[str, list[Any]]:
    found: dict[str, list[Any]] = {key: [] for key in wanted}
    if isinstance(value, dict):
        for key, item in value.items():
            if key in wanted:
                found[key].append(item)
            nested = _find_values_by_key(item, wanted)
            for nested_key, nested_values in nested.items():
                found[nested_key].extend(nested_values)
    elif isinstance(value, list):
        for item in value:
            nested = _find_values_by_key(item, wanted)
            for nested_key, nested_values in nested.items():
                found[nested_key].extend(nested_values)
    return found


def _boolish(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "unknown"
    return sanitize_text(value)


def _required_check_states(finding: dict[str, Any]) -> dict[str, str]:
    checks: dict[str, str] = {}
    required_checks = finding.get("required_checks")
    if isinstance(required_checks, list):
        for check in required_checks:
            if not isinstance(check, dict):
                continue
            name = check.get("name")
            state = check.get("state")
            if isinstance(name, str):
                checks[name] = sanitize_text(state if state is not None else "unknown")
    states = finding.get("required_check_states")
    if isinstance(states, dict):
        for name, state in states.items():
            checks[str(name)] = sanitize_text(state)
    return dict(sorted(checks.items()))


def _source_or_target_name(finding: dict[str, Any], side: str) -> str:
    direct_keys = {
        "source": ["source_name", "source_principal", "source_principal_arn", "source_arn"],
        "target": ["target_name", "target", "target_role_arn", "target_arn"],
    }[side]
    for key in direct_keys:
        value = finding.get(key)
        if isinstance(value, str) and value:
            return sanitize_text(_tail_name(value) if value.startswith("arn:aws:") else value)
    nested = finding.get(side)
    if isinstance(nested, dict):
        provider_id = nested.get("provider_id") or nested.get("arn") or nested.get("name")
        if isinstance(provider_id, str) and provider_id:
            return sanitize_text(_tail_name(provider_id) if provider_id.startswith("arn:aws:") else provider_id)
    return "unknown"


def _finding_id(finding: dict[str, Any]) -> str:
    finding_id = finding.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding missing non-empty finding_id")
    return finding_id


def _finding_prefix(finding_id: str) -> str:
    prefix = finding_id[:12]
    if ACCOUNT_ID_RE.fullmatch(prefix):
        prefix = finding_id[:10]
    return prefix


def _evidence_summary(finding: dict[str, Any]) -> list[str]:
    pattern = finding.get("pattern_id")
    values = _find_values_by_key(
        finding,
        {
            "trust_scope",
            "naked_trust",
            "wildcard_principal",
            "has_external_id",
            "has_conditions",
            "reachable_admins_count",
        },
    )
    strings = " ".join(_iter_strings(finding)).lower()
    checks = _required_check_states(finding)
    parts: list[str] = []

    if pattern == "cross_account_trust":
        for key in ("trust_scope", "naked_trust", "wildcard_principal", "has_external_id", "has_conditions"):
            if values[key]:
                parts.append(f"{key}: {_boolish(values[key][0])}")
        if "externalid" in strings and not values["has_external_id"]:
            parts.append("has_external_id: yes")
        if "wildcard" in strings and not values["wildcard_principal"]:
            parts.append("wildcard_principal: mentioned")
        if "account-root" in strings or "account root" in strings:
            parts.append("account_root_trust: mentioned")

    if pattern == "admin_reachability":
        assume_role_state = next(
            (state for name, state in checks.items() if "assume" in name.lower() and "role" in name.lower()),
            None,
        )
        if assume_role_state:
            parts.append(f"source_has_assume_role: {assume_role_state}")
        if values["reachable_admins_count"]:
            parts.append(f"reachable_admins_count: {sanitize_text(values['reachable_admins_count'][0])}")
        clean_witness_state = checks.get("at_least_one_reachable_chain_uses_clean_witnesses")
        if clean_witness_state:
            parts.append(f"clean_witness_check: {clean_witness_state}")
        if "administratoraccess" in strings:
            parts.append("admin_witness_policy: AdministratorAccess")

    if checks:
        summary = ", ".join(f"{name}={state}" for name, state in list(checks.items())[:6])
        parts.append(f"check_states: {summary}")

    if not parts:
        edge_refs = finding.get("evidence", {}).get("edge_refs") if isinstance(finding.get("evidence"), dict) else None
        if isinstance(edge_refs, list):
            parts.append(f"evidence_edges: {len(edge_refs)}")
    return [sanitize_text(part) for part in parts[:8]]


def _extract_findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        findings = payload["findings"]
    elif isinstance(payload, list):
        findings = payload
    else:
        raise ValueError("findings JSON must be a list or an object with a findings list")
    if not all(isinstance(finding, dict) for finding in findings):
        raise ValueError("all findings must be JSON objects")
    return list(findings)


def _scenario_counts(scenario: Any) -> dict[str, int]:
    if not isinstance(scenario, dict):
        return {"nodes": 0, "edges": 0, "constraints": 0, "edge_constraints": 0}
    return {
        "nodes": len(scenario.get("nodes", []) or []),
        "edges": len(scenario.get("edges", []) or []),
        "constraints": len(scenario.get("constraints", []) or []),
        "edge_constraints": len(scenario.get("edge_constraints", []) or []),
    }


def _load_labels(path: Path | None, findings_by_id: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("labels"), list):
        raise ValueError("labels JSON must be an object with a labels list")

    matched: dict[str, dict[str, Any]] = {}
    for label in payload["labels"]:
        if not isinstance(label, dict):
            raise ValueError("each label must be an object")
        prefix = label.get("finding_id_prefix")
        if not isinstance(prefix, str) or not prefix:
            raise ValueError("each label requires a non-empty finding_id_prefix")
        classification = label.get("classification")
        if classification not in CLASSIFICATIONS:
            raise ValueError(f"invalid classification for {prefix}: {classification}")
        confidence = label.get("reviewer_confidence")
        if confidence is not None and confidence not in CONFIDENCE_VALUES:
            raise ValueError(f"invalid reviewer_confidence for {prefix}: {confidence}")
        owner_confirmed = label.get("owner_confirmed")
        if owner_confirmed is not None and not isinstance(owner_confirmed, bool):
            raise ValueError(f"owner_confirmed must be boolean for {prefix}")

        matches = [finding_id for finding_id in findings_by_id if finding_id.startswith(prefix)]
        if len(matches) != 1:
            raise ValueError(f"finding_id_prefix {prefix!r} matched {len(matches)} findings")
        finding_id = matches[0]
        if finding_id in matched:
            raise ValueError(f"duplicate label for finding_id_prefix {prefix!r}")
        matched[finding_id] = sanitize_json(label)
    return matched


def build_review_artifacts(
    *,
    scenario_payload: Any,
    findings_payload: Any,
    labels_payload_path: Path | None = None,
) -> dict[str, Any]:
    findings = _extract_findings(findings_payload)
    findings_by_id = {_finding_id(finding): finding for finding in findings}
    if len(findings_by_id) != len(findings):
        raise ValueError("duplicate finding_id values are not allowed")
    labels_by_id = _load_labels(labels_payload_path, findings_by_id)

    inventory: list[dict[str, Any]] = []
    template: list[dict[str, Any]] = []
    for finding_id in sorted(findings_by_id):
        finding = findings_by_id[finding_id]
        label = labels_by_id.get(finding_id)
        classification = label.get("classification") if label else "unlabeled"
        label_status = "labeled" if label else "unlabeled"
        entry: dict[str, Any] = {
            "finding_id_prefix": _finding_prefix(finding_id),
            "pattern_id": sanitize_text(finding.get("pattern_id", "unknown")),
            "verdict": sanitize_text(finding.get("verdict", "unknown")),
            "severity": sanitize_text(finding.get("severity", "unknown")),
            "source_name": _source_or_target_name(finding, "source"),
            "target_name": _source_or_target_name(finding, "target"),
            "title": sanitize_text(finding.get("title", "")),
            "evidence_summary": _evidence_summary(finding),
            "reviewer_classification": classification,
            "label_status": label_status,
        }
        if label:
            for key in (
                "reviewer_confidence",
                "owner_confirmed",
                "notes",
                "recommended_followup",
                "sanitized_evidence_refs",
            ):
                if key in label:
                    entry[key] = label[key]
        inventory.append(entry)
        template.append(
            {
                "finding_id_prefix": entry["finding_id_prefix"],
                "pattern_id": entry["pattern_id"],
                "verdict": entry["verdict"],
                "severity": entry["severity"],
                "source_name": entry["source_name"],
                "target_name": entry["target_name"],
                "classification": "",
                "reviewer_confidence": "",
                "owner_confirmed": False,
                "notes": "",
                "recommended_followup": "",
                "sanitized_evidence_refs": [],
            }
        )

    unlabeled = [entry for entry in inventory if entry["label_status"] == "unlabeled"]
    summary = {
        "scenario_counts": _scenario_counts(scenario_payload),
        "finding_count": len(inventory),
        "counts": {
            "by_pattern_id": dict(sorted(Counter(entry["pattern_id"] for entry in inventory).items())),
            "by_iamscope_verdict": dict(sorted(Counter(entry["verdict"] for entry in inventory).items())),
            "by_reviewer_classification": dict(
                sorted(Counter(entry["reviewer_classification"] for entry in inventory).items())
            ),
            "by_severity": dict(sorted(Counter(entry["severity"] for entry in inventory).items())),
            "by_label_status": dict(sorted(Counter(entry["label_status"] for entry in inventory).items())),
        },
        "non_claims": {
            "no_quantitative_performance_metric": True,
            "no_composite_benchmark_label": True,
            "reviewer_judgment_required": True,
        },
    }
    return {
        "inventory": inventory,
        "unlabeled": unlabeled,
        "template": {
            "pilot_id": "real-pilot-dev-001",
            "label_schema_version": 1,
            "labels": template,
        },
        "summary": summary,
    }


def _markdown_table(inventory: list[dict[str, Any]]) -> str:
    rows = [
        "# Real Pilot Finding Review Table",
        "",
        "| Finding | Pattern | IAMScope verdict | Severity | Reviewer classification | Source | Target | Evidence summary |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in inventory:
        evidence = "; ".join(entry["evidence_summary"]) if entry["evidence_summary"] else "none"
        cells = [
            entry["finding_id_prefix"],
            entry["pattern_id"],
            entry["verdict"],
            entry["severity"],
            entry["reviewer_classification"],
            entry["source_name"],
            entry["target_name"],
            evidence,
        ]
        rows.append("| " + " | ".join(sanitize_text(cell).replace("|", "\\|") for cell in cells) + " |")
    rows.append("")
    return "\n".join(rows)


def write_review_artifacts(output_dir: Path, artifacts: dict[str, Any]) -> None:
    output = _ensure_output_dir(output_dir)
    (output / "review-table.md").write_text(_markdown_table(artifacts["inventory"]), encoding="utf-8")
    _write_json(output / "review-summary.json", artifacts["summary"])
    _write_json(output / "unlabeled-findings.json", {"findings": artifacts["unlabeled"]})
    _write_json(output / "reviewer-label-template.json", artifacts["template"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, help="Path to scenario.json")
    parser.add_argument("--findings", required=True, help="Path to findings.json")
    parser.add_argument("--labels", default=None, help="Optional reviewer-labels.json")
    parser.add_argument("--out", required=True, help="Output directory outside the repository")
    args = parser.parse_args(argv)

    try:
        artifacts = build_review_artifacts(
            scenario_payload=_load_json(Path(args.scenario)),
            findings_payload=_load_json(Path(args.findings)),
            labels_payload_path=Path(args.labels) if args.labels else None,
        )
        write_review_artifacts(Path(args.out), artifacts)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
