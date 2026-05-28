"""Findings diff engine keyed by stable semantic finding_key.

This module compares two findings.json files without relying on list order or
mutable evidence-derived finding_id. It is intentionally output-layer only: it
never re-runs reasoners and never changes scenario semantics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_CHANGE_ADDED = "added_semantic_finding"
_CHANGE_REMOVED = "removed_semantic_finding"
_CHANGE_VERDICT = "verdict_changed"
_CHANGE_EVIDENCE = "evidence_changed"
_CHANGE_TRACE = "reasoning_trace_changed"
_CHANGE_PROBE = "probe_evidence_added"


@dataclass(frozen=True)
class FindingChange:
    """One semantic finding diff keyed by finding_key."""

    finding_key: str
    change_types: tuple[str, ...]
    baseline_finding_id: str | None
    candidate_finding_id: str | None
    baseline_verdict: str | None
    candidate_verdict: str | None
    probe_evidence_added: bool
    pattern_id: str = ""
    source: str = ""
    target: str = ""
    title: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_finding_id": self.baseline_finding_id,
            "baseline_verdict": self.baseline_verdict,
            "candidate_finding_id": self.candidate_finding_id,
            "candidate_verdict": self.candidate_verdict,
            "change_types": list(self.change_types),
            "finding_key": self.finding_key,
            "pattern_id": self.pattern_id,
            "probe_evidence_added": self.probe_evidence_added,
            "source": self.source,
            "target": self.target,
            "title": self.title,
        }


@dataclass(frozen=True)
class FindingsDiffResult:
    """Structured diff between two findings.json documents."""

    baseline_total: int
    candidate_total: int
    baseline_hash: str
    candidate_hash: str
    changes: tuple[FindingChange, ...] = field(default_factory=tuple)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "added_semantic_findings": sum(1 for c in self.changes if _CHANGE_ADDED in c.change_types),
            "baseline_total_findings": self.baseline_total,
            "candidate_total_findings": self.candidate_total,
            "changed_semantic_findings": len(self.changes),
            "evidence_changes": sum(1 for c in self.changes if _CHANGE_EVIDENCE in c.change_types),
            "probe_evidence_additions": sum(1 for c in self.changes if c.probe_evidence_added),
            "reasoning_trace_changes": sum(1 for c in self.changes if _CHANGE_TRACE in c.change_types),
            "removed_semantic_findings": sum(1 for c in self.changes if _CHANGE_REMOVED in c.change_types),
            "verdict_changes": sum(1 for c in self.changes if _CHANGE_VERDICT in c.change_types),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_hash": self.baseline_hash,
            "candidate_hash": self.candidate_hash,
            "changes": [c.to_dict() for c in self.changes],
            "summary": self.summary,
        }


def diff_findings_from_files(
    baseline_path: str | Path,
    candidate_path: str | Path,
) -> FindingsDiffResult:
    """Load two findings.json files and compute a semantic diff."""
    with Path(baseline_path).open(encoding="utf-8") as f:
        baseline = json.load(f)
    with Path(candidate_path).open(encoding="utf-8") as f:
        candidate = json.load(f)
    return diff_findings(baseline, candidate)


def diff_findings(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> FindingsDiffResult:
    """Compare two findings documents by stable finding_key."""
    baseline_findings = _findings_by_key(baseline.get("findings", []), "baseline")
    candidate_findings = _findings_by_key(candidate.get("findings", []), "candidate")

    changes: list[FindingChange] = []
    for key in sorted(set(baseline_findings) | set(candidate_findings)):
        before = baseline_findings.get(key)
        after = candidate_findings.get(key)
        if before is None and after is not None:
            changes.append(_change_for_added(key, after))
            continue
        if before is not None and after is None:
            changes.append(_change_for_removed(key, before))
            continue
        if before is None or after is None:
            continue
        change = _change_for_common(key, before, after)
        if change is not None:
            changes.append(change)

    return FindingsDiffResult(
        baseline_total=len(baseline_findings),
        candidate_total=len(candidate_findings),
        baseline_hash=_metadata_hash(baseline),
        candidate_hash=_metadata_hash(candidate),
        changes=tuple(changes),
    )


def format_findings_diff(result: FindingsDiffResult) -> str:
    """Render a compact human-readable findings diff report."""
    lines: list[str] = []
    summary = result.summary
    lines.append("# IAMScope Findings Diff")
    lines.append("")
    lines.append(f"Baseline findings: {summary['baseline_total_findings']}")
    lines.append(f"Candidate findings: {summary['candidate_total_findings']}")
    lines.append(f"Changed semantic findings: {summary['changed_semantic_findings']}")
    lines.append(f"Verdict changes: {summary['verdict_changes']}")
    lines.append(f"Probe evidence additions: {summary['probe_evidence_additions']}")
    lines.append("")

    if not result.changes:
        lines.append("No semantic finding changes detected.")
        return "\n".join(lines)

    lines.append("## Changed Findings")
    lines.append("")
    for change in result.changes:
        lines.append(f"- `{change.finding_key}`")
        lines.append(f"  - change_types: {', '.join(change.change_types)}")
        lines.append(f"  - verdict: {change.baseline_verdict or '-'} -> {change.candidate_verdict or '-'}")
        lines.append(f"  - finding_id: {_short(change.baseline_finding_id)} -> {_short(change.candidate_finding_id)}")
        lines.append(f"  - probe_evidence_added: {str(change.probe_evidence_added).lower()}")
        if change.pattern_id:
            lines.append(f"  - pattern: `{change.pattern_id}`")
        if change.source or change.target:
            lines.append(f"  - relation: `{change.source}` -> `{change.target}`")
        if change.title:
            lines.append(f"  - title: {change.title}")
    return "\n".join(lines)


def _findings_by_key(
    findings: Any,
    label: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(findings, list):
        raise ValueError(f"{label} findings.json has non-list findings field")
    indexed: dict[str, dict[str, Any]] = {}
    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError(f"{label} findings[{i}] is not an object")
        key = finding.get("finding_key")
        if not isinstance(key, str) or not key:
            raise ValueError(
                f"{label} findings[{i}] is missing finding_key. "
                "Run with a findings.json emitted by a finding_key-aware IAMScope."
            )
        if key in indexed:
            raise ValueError(f"{label} findings.json contains duplicate finding_key {key}")
        indexed[key] = finding
    return indexed


def _change_for_added(key: str, finding: dict[str, Any]) -> FindingChange:
    return FindingChange(
        finding_key=key,
        change_types=(_CHANGE_ADDED,),
        baseline_finding_id=None,
        candidate_finding_id=_finding_id(finding),
        baseline_verdict=None,
        candidate_verdict=_verdict(finding),
        probe_evidence_added=_has_probe_evidence(finding),
        **_finding_context(finding),
    )


def _change_for_removed(key: str, finding: dict[str, Any]) -> FindingChange:
    return FindingChange(
        finding_key=key,
        change_types=(_CHANGE_REMOVED,),
        baseline_finding_id=_finding_id(finding),
        candidate_finding_id=None,
        baseline_verdict=_verdict(finding),
        candidate_verdict=None,
        probe_evidence_added=False,
        **_finding_context(finding),
    )


def _change_for_common(
    key: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> FindingChange | None:
    change_types: list[str] = []
    if _verdict(before) != _verdict(after):
        change_types.append(_CHANGE_VERDICT)
    if _evidence_core(before) != _evidence_core(after):
        change_types.append(_CHANGE_EVIDENCE)
    if _reasoning_trace(before) != _reasoning_trace(after):
        change_types.append(_CHANGE_TRACE)
    probe_added = not _has_probe_evidence(before) and _has_probe_evidence(after)
    if probe_added:
        change_types.append(_CHANGE_PROBE)
    if not change_types:
        return None

    context = _finding_context(after)
    return FindingChange(
        finding_key=key,
        change_types=tuple(change_types),
        baseline_finding_id=_finding_id(before),
        candidate_finding_id=_finding_id(after),
        baseline_verdict=_verdict(before),
        candidate_verdict=_verdict(after),
        probe_evidence_added=probe_added,
        **context,
    )


def _finding_context(finding: dict[str, Any]) -> dict[str, str]:
    source = finding.get("source", {})
    target = finding.get("target", {})
    return {
        "pattern_id": str(finding.get("pattern_id", "")),
        "source": str(source.get("provider_id", "")) if isinstance(source, dict) else "",
        "target": str(target.get("provider_id", "")) if isinstance(target, dict) else "",
        "title": str(finding.get("title", "")),
    }


def _evidence_core(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    return {k: v for k, v in evidence.items() if k != "reasoning_trace"}


def _reasoning_trace(finding: dict[str, Any]) -> Any:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        return []
    return evidence.get("reasoning_trace", [])


def _has_probe_evidence(finding: dict[str, Any]) -> bool:
    if any(
        isinstance(check, dict) and check.get("name") == "probe_overlay_runtime_truth"
        for check in finding.get("required_checks", []) or []
    ):
        return True
    if any(
        isinstance(blocker, dict) and blocker.get("kind") == "probe_overlay"
        for blocker in finding.get("blockers_observed", []) or []
    ):
        return True
    return any(
        isinstance(entry, dict) and entry.get("action") == "apply_probe_overlay" for entry in _reasoning_trace(finding)
    )


def _metadata_hash(document: dict[str, Any]) -> str:
    metadata = document.get("metadata", {})
    return str(metadata.get("canonical_hash", "")) if isinstance(metadata, dict) else ""


def _finding_id(finding: dict[str, Any]) -> str | None:
    value = finding.get("finding_id")
    return value if isinstance(value, str) else None


def _verdict(finding: dict[str, Any]) -> str | None:
    value = finding.get("verdict")
    return value if isinstance(value, str) else None


def _short(value: str | None) -> str:
    if not value:
        return "-"
    return f"{value[:12]}..."
