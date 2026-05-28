"""Inspect stale principal unique-ID drift evidence in scenario/findings artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamscope.constants import CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT


def summarize_stale_drift_from_paths(
    *,
    scenario_path: str | Path,
    edge_id: str | None = None,
    findings_path: str | Path | None = None,
    finding_key: str | None = None,
) -> dict[str, Any]:
    """Load artifacts and summarize stale-drift evidence for an edge/finding."""
    scenario = json.loads(Path(scenario_path).read_text(encoding="utf-8"))
    findings = json.loads(Path(findings_path).read_text(encoding="utf-8")) if findings_path is not None else None
    return summarize_stale_drift(scenario, edge_id=edge_id, findings=findings, finding_key=finding_key)


def summarize_stale_drift(
    scenario: dict[str, Any],
    *,
    edge_id: str | None = None,
    findings: dict[str, Any] | None = None,
    finding_key: str | None = None,
) -> dict[str, Any]:
    """Return machine-readable stale-drift evidence for one edge or finding."""
    target_edge_ids: set[str] = set()
    target_constraint_ids: set[str] = set()
    if edge_id:
        target_edge_ids.add(edge_id)
    if finding_key and findings:
        finding = _finding_by_key(findings, finding_key)
        if finding is not None:
            evidence = finding.get("evidence", {}) or {}
            target_edge_ids.update(str(e) for e in evidence.get("edge_refs", []) or [])
            target_constraint_ids.update(str(c) for c in evidence.get("constraint_refs", []) or [])

    constraints = {
        c.get("constraint_id"): c
        for c in scenario.get("constraints", [])
        if c.get("constraint_type") == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT
    }
    rows: list[dict[str, Any]] = []
    for binding in scenario.get("edge_constraints", []) or []:
        cid = binding.get("constraint_id")
        eid = binding.get("edge_id")
        if cid not in constraints:
            continue
        if target_edge_ids and eid not in target_edge_ids:
            continue
        if target_constraint_ids and cid not in target_constraint_ids and not target_edge_ids:
            continue
        constraint = constraints[cid]
        rows.append(
            {
                "edge_id": eid,
                "constraint_id": cid,
                "principal_id": constraint.get("properties", {}).get("principal_id"),
                "principal_id_kind": constraint.get("properties", {}).get("principal_id_kind"),
                "evidence_level": constraint.get("properties", {}).get("evidence_level"),
                "drift_state": constraint.get("properties", {}).get("drift_state"),
                "reason": constraint.get("properties", {}).get("reason"),
                "target": constraint.get("properties", {}).get("target"),
            }
        )
    rows.sort(key=lambda r: (str(r.get("edge_id")), str(r.get("constraint_id"))))
    return {
        "edge_id": edge_id,
        "finding_key": finding_key,
        "stale_drift_count": len(rows),
        "evidence": rows,
    }


def render_stale_drift_summary(summary: dict[str, Any]) -> str:
    """Render compact human-readable stale-drift evidence."""
    lines = ["Stale Principal Drift Evidence"]
    if summary.get("edge_id"):
        lines.append(f"edge_id: {summary['edge_id']}")
    if summary.get("finding_key"):
        lines.append(f"finding_key: {summary['finding_key']}")
    rows = summary.get("evidence", []) or []
    if not rows:
        lines.append("no stale principal drift evidence found")
        return "\n".join(lines)
    for row in rows:
        lines.append(
            "- edge={edge_id} principal_id={principal_id} kind={principal_id_kind} "
            "state={drift_state} evidence={evidence_level}".format(**row)
        )
        if row.get("target"):
            lines.append(f"  target={row['target']}")
    return "\n".join(lines)


def _finding_by_key(findings: dict[str, Any], finding_key: str) -> dict[str, Any] | None:
    for finding in findings.get("findings", []) or []:
        if isinstance(finding, dict) and finding.get("finding_key") == finding_key:
            return finding
    return None
