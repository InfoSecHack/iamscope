"""Finding introspection — the `iamscope why <finding>` explainer.

This module renders a human-readable, terminal-friendly explanation of
why a specific finding was emitted with the verdict it got. It walks
the finding's check results, evidence bundle, blockers, and optional
reasoning trace to show the exact reasoning path from raw fact graph
to final verdict.

The core design principle: **the refuses-to-lie invariant should be
visible in the output**. When a finding is INCONCLUSIVE because a
check returned UNKNOWN, the `why` output calls that out explicitly,
naming the specific ambiguity (wildcard resource, condition block,
hyperedge) that prevented the reasoner from guessing. This is the
differentiator between IAMScope and commodity security tools that
either flood you with false positives or silently omit findings when
they can't be sure.

Output format (color-coded when stdout is a TTY):

    Finding <id> [VERDICT/severity]
    <title>

    Source: <principal_arn>
    Target: <resource_arn>

    Verdict reasoning: <reasoner_exit_reason>

    Checks:
      [✓] check_name — reason
      [?] check_name — UNKNOWN because <ambiguity_kind>
      [✗] check_name — reason

    Blockers (if any):
      <kind> <constraint_id> on edge <edge_id>: <reason>

    Reasoning trace (with --verbose):
      Step 1: action → result (reason)
      ...

Color semantics:
    green  — PASS, validated
    red    — FAIL, blocked
    yellow — UNKNOWN, inconclusive (the "refuses to lie" color)
    blue   — precondition_only (preconditions not met, chain blocked)
    dim    — neutral metadata

Filtering:
    A caller can locate a finding via (a) a prefix of the finding_id,
    (b) a combination of pattern_id + source substring + target
    substring, or (c) some combination of the two. If multiple findings
    match, `locate_finding` returns them all and the caller displays a
    disambiguation list rather than picking arbitrarily.
"""

from __future__ import annotations

import sys
from typing import Any


# ANSI color escape codes. No-op strings when color is disabled.
class _Colors:
    """Terminal color codes. Instance methods no-op when disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


def should_use_color(explicit_no_color: bool) -> bool:
    """Decide whether to use ANSI colors in the output."""
    if explicit_no_color:
        return False
    # Auto-detect: only color when stdout is a TTY
    return sys.stdout.isatty()


def locate_finding(
    findings: list[dict[str, Any]],
    *,
    finding_id: str | None = None,
    pattern_id: str | None = None,
    source_arn: str | None = None,
    target_arn: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Filter findings by the provided criteria.

    Returns (matches, error). The `error` is a short human-readable
    string describing the problem (zero matches, unresolvable prefix,
    etc.) or None if matches is non-empty. The caller is responsible
    for disambiguating when len(matches) > 1.

    Filter semantics:
    - `finding_id`: prefix match against finding_id (so 'abc123' matches
      both 'abc123def' and 'abc1234')
    - `pattern_id`: exact match
    - `source_arn`: substring match against source.provider_id
    - `target_arn`: substring match against target.provider_id

    Multiple filters are combined with AND.
    """
    if finding_id is None and pattern_id is None and source_arn is None and target_arn is None:
        return ([], "no filter provided — pass --finding-id or --pattern")

    matches: list[dict[str, Any]] = []
    for f in findings:
        if finding_id is not None:
            fid = f.get("finding_id", "")
            if not fid.startswith(finding_id):
                continue
        if pattern_id is not None and f.get("pattern_id", "") != pattern_id:
            continue
        if source_arn is not None:
            src = f.get("source", {}).get("provider_id", "")
            if source_arn not in src:
                continue
        if target_arn is not None:
            tgt = f.get("target", {}).get("provider_id", "")
            if target_arn not in tgt:
                continue
        matches.append(f)

    if not matches:
        return ([], "no findings match the provided filters")
    return (matches, None)


def _verdict_color(c: _Colors, verdict: str) -> str:
    """Apply the verdict-specific color to a verdict label."""
    verdict_upper = verdict.upper().replace("_", "-")
    v = verdict.lower()
    if v == "validated":
        return c.green(verdict_upper)
    if v == "blocked":
        return c.red(verdict_upper)
    if v == "inconclusive":
        return c.yellow(verdict_upper)
    if v == "precondition_only":
        return c.blue(verdict_upper)
    return verdict_upper


def _severity_color(c: _Colors, severity: str) -> str:
    """Apply color to a severity label based on impact."""
    s = severity.lower()
    if s == "critical":
        return c.red(c.bold(severity.upper()))
    if s == "high":
        return c.red(severity.upper())
    if s == "medium":
        return c.yellow(severity.upper())
    if s == "low":
        return c.blue(severity.upper())
    return c.dim(severity.upper())


def _check_state_marker(c: _Colors, state: str) -> str:
    """Return the symbol + color for a check state."""
    s = state.lower()
    if s == "pass":
        return c.green("[✓]")
    if s == "fail":
        return c.red("[✗]")
    if s == "unknown":
        return c.yellow("[?]")
    return c.dim(f"[{state}]")


def _ambiguity_hint(check: dict[str, Any]) -> str:
    """Extract a hint about why a check returned UNKNOWN.

    Looks at the reason string for common ambiguity keywords and
    returns a descriptive phrase. If none match, returns the raw
    reason unchanged.
    """
    reason = check.get("reason", "").lower()
    if "wildcard" in reason or "hyperedge" in reason:
        return "wildcard-resource or hyperedge-expansion ambiguity"
    if "condition" in reason:
        return "runtime-dependent Condition block in source policy"
    if "partial" in reason:
        return "constraint parse incomplete — governance confidence partial"
    if "needs_review" in reason:
        return "constraint flagged needs_review"
    if "not in fact graph" in reason:
        return "referenced entity missing from fact graph"
    if "malformed" in reason:
        return "malformed policy JSON"
    if "deny" in reason:
        return "Deny statement present (conservative UNKNOWN)"
    return str(check.get("reason", "(no reason recorded)"))


def explain_finding(
    finding: dict[str, Any],
    *,
    verbose: bool = False,
    use_color: bool = True,
) -> str:
    """Render a human-readable explanation for a single finding.

    Returns a multi-line string. Caller is responsible for printing it.
    Newlines are embedded; no trailing newline.
    """
    c = _Colors(use_color)
    lines: list[str] = []

    # Header
    finding_id = finding.get("finding_id", "(no id)")
    pattern_id = finding.get("pattern_id", "(no pattern)")
    verdict = finding.get("verdict", "unknown")
    severity = finding.get("severity", "unknown")
    title = finding.get("title", "(no title)")

    lines.append(
        f"{c.bold('Finding')} {c.dim(finding_id[:12] + '…')} "
        f"[{_verdict_color(c, verdict)}/{_severity_color(c, severity)}]"
    )
    lines.append(f"{c.dim('Pattern:')} {pattern_id}")
    lines.append(f"{c.dim('Title:  ')} {title}")
    lines.append("")

    # Source / target
    source = finding.get("source", {})
    target = finding.get("target", {})
    lines.append(f"{c.dim('Source:')} {source.get('provider_id', '(unknown)')}")
    lines.append(f"{c.dim('Target:')} {target.get('provider_id', '(unknown)')}")
    lines.append("")

    # Verdict reasoning
    exit_reason = finding.get("reasoner_exit_reason", "")
    if exit_reason:
        lines.append(f"{c.bold('Verdict reasoning:')} {exit_reason}")
        lines.append("")

    # Per-check breakdown
    checks = finding.get("required_checks", [])
    if checks:
        lines.append(c.bold("Checks:"))
        for chk in checks:
            name = chk.get("name", "(unnamed)")
            state = chk.get("state", "unknown")
            reason = chk.get("reason", "")
            marker = _check_state_marker(c, state)
            if state.lower() == "unknown":
                hint = _ambiguity_hint(chk)
                lines.append(f"  {marker} {name} — {c.yellow('UNKNOWN')} ({c.dim(hint)})")
            else:
                lines.append(f"  {marker} {name} — {reason}")
        lines.append("")

    # Refuses-to-lie callout for inconclusive findings
    if verdict.lower() == "inconclusive":
        unknown_checks = [c_.get("name", "") for c_ in checks if c_.get("state", "").lower() == "unknown"]
        if unknown_checks:
            lines.append(c.yellow(c.bold("⚠  Why this is inconclusive (refuses-to-lie):")))
            lines.append("   The reasoner returned UNKNOWN on check(s): " + c.yellow(", ".join(unknown_checks)))
            lines.append(
                "   "
                + c.dim(
                    "IAMScope refuses to guess PASS or FAIL when a check is ambiguous. This finding needs human review."
                )
            )
            lines.append("")

    # Blockers
    blockers = finding.get("blockers_observed", [])
    if blockers:
        lines.append(c.bold("Blockers observed:"))
        for b in blockers:
            kind = b.get("kind", "(unknown)")
            constraint_id = b.get("constraint_id", "")
            edge_id = b.get("edge_id", "")
            reason = b.get("reason", "")
            lines.append(
                f"  {c.red('●')} {kind} {c.dim(constraint_id)} "
                f"on edge {c.dim(edge_id[:12] + '…' if edge_id else '')}: "
                f"{reason}"
            )
        lines.append("")

    # Evidence summary
    evidence = finding.get("evidence", {})
    stmt_count = len(evidence.get("statement_digests", []))
    edge_count = len(evidence.get("edge_refs", []))
    constraint_count = len(evidence.get("constraint_refs", []))
    node_count = len(evidence.get("node_refs", []))
    lines.append(c.bold("Evidence bundle:"))
    lines.append(
        f"  {c.dim('•')} {stmt_count} statement digest(s), "
        f"{edge_count} edge ref(s), "
        f"{constraint_count} constraint ref(s), "
        f"{node_count} node ref(s)"
    )
    lines.append("")

    # Reasoning trace (verbose only)
    if verbose:
        trace = evidence.get("reasoning_trace", [])
        if trace:
            lines.append(c.bold("Reasoning trace:"))
            for entry in trace:
                step = entry.get("step", "?")
                action = entry.get("action", "")
                result = entry.get("result", "")
                reason = entry.get("reason", "")
                if result == "PASS":
                    result_fmt = c.green(result)
                elif result == "FAIL":
                    result_fmt = c.red(result)
                elif result == "UNKNOWN":
                    result_fmt = c.yellow(result)
                else:
                    result_fmt = result
                lines.append(f"  {c.dim(f'Step {step}:')} {action} → {result_fmt}")
                if reason:
                    lines.append(f"    {c.dim(reason)}")
            lines.append("")

    # Footer
    scenario_hash = finding.get("scenario_hash", "")
    if scenario_hash:
        lines.append(c.dim(f"scenario_hash: {scenario_hash[:16]}…"))

    return "\n".join(lines)


def format_disambiguation_list(
    matches: list[dict[str, Any]],
    use_color: bool = True,
) -> str:
    """Format a list of matching findings for disambiguation.

    When `locate_finding` returns multiple matches, the CLI shows this
    list so the user can re-run with a more specific filter.
    """
    c = _Colors(use_color)
    lines = [
        f"{c.yellow(f'{len(matches)} findings match')} — refine filters to select one:",
        "",
    ]
    for f in matches:
        fid = f.get("finding_id", "(no id)")
        pattern = f.get("pattern_id", "")
        verdict = f.get("verdict", "")
        severity = f.get("severity", "")
        src = f.get("source", {}).get("provider_id", "")
        tgt = f.get("target", {}).get("provider_id", "")
        lines.append(
            f"  {c.dim(fid[:16] + '…')} [{_verdict_color(c, verdict)}/{_severity_color(c, severity)}] {pattern}"
        )
        lines.append(f"    {c.dim('source:')} {src}")
        lines.append(f"    {c.dim('target:')} {tgt}")
        lines.append("")
    lines.append(c.dim("Re-run with --finding-id <prefix>, or add --source / --target substring filters"))
    return "\n".join(lines)
