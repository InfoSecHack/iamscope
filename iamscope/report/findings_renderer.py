"""Findings-first rendering for the pentest report (priority 2).

Takes a parsed `findings.json` dict and renders a markdown section
suitable for a pentest deliverable. This is the **top-level** section
of the report — clients see findings first, graph statistics second.

Ordering within a pattern group:
    1. VALIDATED   — confirmed exploits, full detail. The headline results.
    2. INCONCLUSIVE — refuses-to-lie verdict, full detail.
                     Surfaced prominently so it's not missed.
    3. PRECONDITION_ONLY — "almost-exploit" case, collapsed one-liner.
    4. BLOCKED     — defensive evidence, collapsed one-liner.

Within each verdict bucket: sort by severity desc (critical > high >
medium > info), then by finding_id for stability.

The rendering is pure markdown with no emoji — professional tone for
client-facing deliverables. Bold labels and blockquotes provide visual
emphasis without relying on unicode decoration.

The `scenario_data` argument is optional. When present, evidence refs
can be resolved back to friendly names via node/edge lookup. When
absent, refs are rendered as raw IDs — still useful for drill-down but
less human-readable.
"""

from __future__ import annotations

from typing import Any

# Severity rank for sorting within verdict buckets.
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Verdict order determines top-to-bottom placement within a pattern group.
# Tuple index = sort key.
_VERDICT_ORDER = {
    "validated": 0,
    "inconclusive": 1,
    "precondition_only": 2,
    "blocked": 3,
}

# Verdicts rendered with full detail (checks table, evidence, trace).
_FULL_DETAIL_VERDICTS = frozenset({"validated", "inconclusive"})

# Verdicts rendered as one-line collapsed summary.
_COLLAPSED_VERDICTS = frozenset({"precondition_only", "blocked"})


def render_findings_section(
    findings_data: dict[str, Any],
    scenario_data: dict[str, Any] | None = None,
) -> str:
    """Render the full findings section as markdown.

    Top-level entry point. Returns a markdown string beginning with
    the executive summary and followed by per-pattern subsections.
    """
    lines: list[str] = []
    lines.append("# Findings")
    lines.append("")

    lines.append(_render_executive_summary(findings_data))

    findings = findings_data.get("findings", [])
    if not findings:
        lines.append("")
        lines.append("## No findings emitted")
        lines.append("")
        lines.append(
            "No reasoner produced a finding against this fact graph. "
            "This is information, not silence: it means every registered "
            "reasoner ran to completion and found nothing matching its "
            "pattern. Check the executive summary above to confirm which "
            "reasoners ran and which (if any) were skipped."
        )
        lines.append("")
        return "\n".join(lines)

    # Group findings by pattern_id.
    by_pattern: dict[str, list[dict[str, Any]]] = {}
    pattern_titles: dict[str, str] = {}
    for f in findings:
        pid = f.get("pattern_id", "unknown")
        by_pattern.setdefault(pid, []).append(f)
        if pid not in pattern_titles:
            pattern_titles[pid] = f.get("pattern_title", pid)

    # Render patterns in stable order.
    for pid in sorted(by_pattern.keys()):
        lines.append("")
        lines.append(
            _render_pattern_group(
                pattern_id=pid,
                pattern_title=pattern_titles[pid],
                findings=by_pattern[pid],
                scenario_data=scenario_data,
            )
        )

    return "\n".join(lines)


def _render_executive_summary(findings_data: dict[str, Any]) -> str:
    """Top-of-section summary: counts by verdict + reasoner status."""
    metadata = findings_data.get("metadata", {})
    total = metadata.get("findings_count", 0)
    breakdown = metadata.get("verdict_breakdown", {})
    reasoners_run = metadata.get("reasoners_run", [])
    reasoners_skipped = metadata.get("reasoners_skipped", {})
    scenario_hash = findings_data.get("scenario_hash", "")

    lines: list[str] = []
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"**Total findings:** {total}")
    lines.append("")

    if total > 0:
        lines.append("**Verdict breakdown:**")
        lines.append("")
        lines.append("| Verdict | Count | Meaning |")
        lines.append("|---|---|---|")
        lines.append(
            f"| **validated** | {breakdown.get('validated', 0)} | "
            "Chain proven exploitable end-to-end. Every check passed. |"
        )
        lines.append(
            f"| **inconclusive** | {breakdown.get('inconclusive', 0)} | "
            "At least one check returned UNKNOWN. Requires reviewer judgment. |"
        )
        lines.append(
            f"| **precondition_only** | {breakdown.get('precondition_only', 0)} | "
            "Pattern core exists but a gate isn't crossed. Not actively blocked. |"
        )
        lines.append(
            f"| **blocked** | {breakdown.get('blocked', 0)} | "
            "Proven NOT exploitable due to an active SCP or boundary blocker. |"
        )
        lines.append("")

    if reasoners_run:
        run_str = ", ".join(f"`{r}`" for r in sorted(reasoners_run))
        lines.append(f"**Reasoners run:** {run_str}")
        lines.append("")

    if reasoners_skipped:
        lines.append("**Reasoners SKIPPED (gaps in coverage):**")
        lines.append("")
        for name, reason in sorted(reasoners_skipped.items()):
            lines.append(f"- `{name}`: {reason}")
        lines.append("")
        lines.append(
            "> Skipped reasoners represent gaps in this report's coverage. "
            "Review the skip reasons above before treating this report as "
            "a complete assessment."
        )
        lines.append("")

    if scenario_hash:
        lines.append(f"**Scenario hash:** `{scenario_hash}`")
        lines.append("")
        lines.append(
            "Every evidence reference below resolves against this fact "
            "graph. The scenario hash is byte-stable across runs — if it "
            "changes, the underlying facts changed."
        )

    return "\n".join(lines)


def _render_pattern_group(
    *,
    pattern_id: str,
    pattern_title: str,
    findings: list[dict[str, Any]],
    scenario_data: dict[str, Any] | None,
) -> str:
    """Render all findings for one pattern_id."""
    lines: list[str] = []
    lines.append(f"## {pattern_title}")
    lines.append("")
    lines.append(f"*Pattern ID: `{pattern_id}`*")
    lines.append("")

    # Sort: verdict order, then severity desc, then finding_id.
    def sort_key(f: dict[str, Any]) -> tuple[int, int, str]:
        v = f.get("verdict", "")
        s = f.get("severity", "")
        fid = f.get("finding_id", "")
        return (
            _VERDICT_ORDER.get(v, 99),
            -_SEVERITY_RANK.get(s, 0),  # negate for desc
            fid,
        )

    findings_sorted = sorted(findings, key=sort_key)

    # Split into full-detail vs collapsed groups for rendering.
    full_detail = [f for f in findings_sorted if f.get("verdict") in _FULL_DETAIL_VERDICTS]
    collapsed = [f for f in findings_sorted if f.get("verdict") in _COLLAPSED_VERDICTS]

    for i, f in enumerate(full_detail, start=1):
        lines.append(_render_finding_detail(f, i, scenario_data))
        lines.append("")

    if collapsed:
        lines.append("### Collapsed findings")
        lines.append("")
        lines.append(
            "The following findings are either actively blocked by "
            "governance controls (SCPs, boundaries) or blocked by a "
            "missing precondition. They are included for completeness "
            "but are not immediately actionable as exploits."
        )
        lines.append("")
        for f in collapsed:
            lines.append(_render_finding_collapsed(f))
        lines.append("")

    return "\n".join(lines)


def _render_finding_detail(
    finding: dict[str, Any],
    index: int,
    scenario_data: dict[str, Any] | None,
) -> str:
    """Full-detail render for a validated or inconclusive finding."""
    verdict = finding.get("verdict", "unknown").upper()
    severity = finding.get("severity", "unknown").upper()
    title = finding.get("title", "(untitled)")
    finding_id = finding.get("finding_id", "")
    source = finding.get("source", {})
    target = finding.get("target", {})
    required_checks = finding.get("required_checks", [])
    blockers = finding.get("blockers_observed", [])
    assumptions = finding.get("assumptions", [])
    evidence = finding.get("evidence", {})
    exit_reason = finding.get("reasoner_exit_reason", "")

    lines: list[str] = []
    lines.append(f"### Finding {index}: {verdict} / {severity}")
    lines.append("")
    lines.append(f"**{title}**")
    lines.append("")
    lines.append(f"- **Source:** `{source.get('provider_id', '(unknown)')}`")
    lines.append(f"- **Target:** `{target.get('provider_id', '(unknown)')}`")
    lines.append(f"- **Finding ID:** `{finding_id}`")
    if exit_reason:
        lines.append(f"- **Reasoner exit reason:** {exit_reason}")
    lines.append("")

    # Required checks table.
    if required_checks:
        lines.append("**Required checks:**")
        lines.append("")
        lines.append("| # | Check | State | Reason |")
        lines.append("|---|---|---|---|")
        for i, chk in enumerate(required_checks, start=1):
            state = chk.get("state", "").upper()
            name = chk.get("name", "")
            reason = chk.get("reason", "")
            # Truncate long reasons for table readability.
            if len(reason) > 80:
                reason = reason[:77] + "..."
            lines.append(f"| {i} | `{name}` | **{state}** | {reason} |")
        lines.append("")

        # Highlight UNKNOWN checks explicitly — these are the refuses-to-lie signal.
        unknown_checks = [c for c in required_checks if c.get("state", "").lower() == "unknown"]
        if unknown_checks:
            lines.append(
                "> **Why this is inconclusive:** the following check(s) "
                "returned UNKNOWN, which forces the verdict per "
                "invariant #1 (IAMScope refuses to guess):"
            )
            lines.append(">")
            for c in unknown_checks:
                lines.append(f"> - **{c.get('name', '')}**: {c.get('reason', '')}")
            lines.append("")

    # Blockers.
    if blockers:
        lines.append("**Blockers observed:**")
        lines.append("")
        for b in blockers:
            kind = b.get("kind", "")
            reason = b.get("reason", "")
            cid = b.get("constraint_id")
            eid = b.get("edge_id")
            ref = ""
            if cid:
                ref = f" (constraint `{cid}`)"
            elif eid:
                ref = f" (edge `{eid}`)"
            lines.append(f"- **{kind}**{ref}: {reason}")
        lines.append("")

    # Assumptions.
    if assumptions:
        lines.append("**Assumptions:**")
        lines.append("")
        for a in assumptions:
            kind = a.get("kind", "")
            detail = a.get("detail", "")
            lines.append(f"- **{kind}**: {detail}")
        lines.append("")

    # Evidence summary — counts, not full listing.
    lines.append("**Evidence:**")
    lines.append("")
    lines.append(f"- {len(evidence.get('statement_digests', []))} statement digests")
    lines.append(f"- {len(evidence.get('edge_refs', []))} edge references")
    if evidence.get("constraint_refs"):
        lines.append(f"- {len(evidence.get('constraint_refs', []))} constraint references")
    if evidence.get("edge_constraint_refs"):
        lines.append(f"- {len(evidence.get('edge_constraint_refs', []))} edge-constraint bindings examined")
    lines.append(f"- {len(evidence.get('node_refs', []))} node references")
    lines.append(f"- {len(evidence.get('reasoning_trace', []))}-step reasoning trace")
    lines.append("")
    lines.append("*Drill into `findings.json` for full evidence refs and the complete reasoning trace.*")

    return "\n".join(lines)


def _render_finding_collapsed(finding: dict[str, Any]) -> str:
    """One-line render for a blocked or precondition_only finding."""
    verdict = finding.get("verdict", "unknown").upper().replace("_", "-")
    severity = finding.get("severity", "unknown")
    source_id = finding.get("source", {}).get("provider_id", "(unknown)")
    target_id = finding.get("target", {}).get("provider_id", "(unknown)")

    # Build the "why" fragment from the first blocker or the exit reason.
    blockers = finding.get("blockers_observed", [])
    if blockers:
        b = blockers[0]
        why = f"{b.get('kind', '')}: {b.get('reason', '')}"
    else:
        why = finding.get("reasoner_exit_reason", "")

    # Shorten ARNs for readability in the compact form.
    source_short = _shorten_arn(source_id)
    target_short = _shorten_arn(target_id)

    return f"- **{verdict}** ({severity}): `{source_short}` → `{target_short}` — {why}"


def _shorten_arn(arn: str, max_len: int = 50) -> str:
    """Shorten an ARN for inline display."""
    if len(arn) <= max_len:
        return arn
    # Keep the tail (the resource name is the interesting part).
    return "..." + arn[-(max_len - 3) :]
