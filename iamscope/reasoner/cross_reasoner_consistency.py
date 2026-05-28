"""Cross-reasoner consistency post-processor — AR-1 fix.

Orchestration-level reconciliation between admin_reachability and
assume_role_chain findings for the same (source, target) endpoint
pair. Without this step, the two reasoners can emit contradictory
verdicts for the same path: assume_role_chain correctly marks a
chain BLOCKED (SCP, boundary, trust-missing, etc.) while
admin_reachability's BFS ignores governance constraints and emits
VALIDATED for the same reachability.

Contract:
  A VALIDATED admin_reachability finding is demoted to INCONCLUSIVE
  iff there exists a BLOCKED assume_role_chain finding with the same
  (source.provider_id, target.provider_id) AND at least one edge_id
  appears in both findings' evidence.edge_refs.

Path-level (not endpoint-pair) matching matters: admin_reachability
may reach the same target via an alternate path that the blocked
assume_role_chain finding does not cover. Endpoint-pair-only matching
would over-demote those cases.

Shape of the demoted finding:
  - verdict: Verdict.INCONCLUSIVE
  - blockers_observed: a single Blocker with
      kind="cross_reasoner_blocked",
      edge_id=<the overlapping edge chosen deterministically>,
      reason=<references the blocked ARC finding by short id>
  - All other fields preserved (severity, checks, evidence, title).
    INCONCLUSIVE is permissive at the Finding dataclass level, so the
    existing PASS checks remain valid.

finding_id stability: because the demotion only changes `verdict` and
`blockers_observed` — neither of which contributes to the finding_id
formula (pattern_id, pattern_version, source.provider_id,
target.provider_id, evidence.bundle_digest) — the demoted finding
keeps the same finding_id as the pre-demotion admin_reachability
finding. That's intentional: the demoted finding is the same logical
finding with a reconciled verdict, not a new observation.
"""

from __future__ import annotations

import dataclasses

from iamscope.reasoner.verdict import Blocker, Finding, Verdict

_ADMIN_REACHABILITY = "admin_reachability"
_ASSUME_ROLE_CHAIN = "assume_role_chain"
_BLOCKER_KIND = "cross_reasoner_blocked"


def apply_cross_reasoner_demotions(findings: list[Finding]) -> list[Finding]:
    """Demote admin_reachability findings to INCONCLUSIVE when an
    overlapping assume_role_chain finding is BLOCKED.

    Uses edge_refs overlap matching (not endpoint-pair alone) to avoid
    over-demoting when admin_reachability reached the target via an
    alternate path that the blocked assume_role_chain finding does
    not represent.
    """
    # Index BLOCKED assume_role_chain findings by endpoint pair.
    # assume_role_chain dedupes to 1 finding per (source, target) at
    # enumeration time, so at most one entry per key. If duplicates
    # ever appear, first-wins is fine — any BLOCKED finding for the
    # endpoint pair is a valid anchor for demotion.
    blocked_arc: dict[tuple[str, str], Finding] = {}
    for f in findings:
        if f.pattern_id != _ASSUME_ROLE_CHAIN:
            continue
        if f.verdict is not Verdict.BLOCKED:
            continue
        key = (f.source.provider_id, f.target.provider_id)
        blocked_arc.setdefault(key, f)

    if not blocked_arc:
        return list(findings)

    out: list[Finding] = []
    for f in findings:
        if f.pattern_id != _ADMIN_REACHABILITY or f.verdict is not Verdict.VALIDATED:
            out.append(f)
            continue
        key = (f.source.provider_id, f.target.provider_id)
        blocked = blocked_arc.get(key)
        if blocked is None:
            out.append(f)
            continue
        overlap = set(f.evidence.edge_refs) & set(blocked.evidence.edge_refs)
        if not overlap:
            out.append(f)
            continue
        out.append(_demote(f, blocked, overlap))
    return out


def _demote(finding: Finding, blocked: Finding, overlap: set[str]) -> Finding:
    """Replace an admin_reachability VALIDATED finding with its
    INCONCLUSIVE counterpart carrying a cross_reasoner_blocked
    blocker.

    The chosen overlap edge is the first edge in the admin_reachability
    finding's edge_refs tuple that appears in the overlap set. Tuple
    iteration order is deterministic, set iteration order is not —
    iterating the tuple ensures stable output across runs.
    """
    chosen_edge = next(e for e in finding.evidence.edge_refs if e in overlap)
    demoted_blocker = Blocker(
        kind=_BLOCKER_KIND,
        constraint_id=None,
        edge_id=chosen_edge,
        reason=(
            f"demoted by cross_reasoner consistency check: "
            f"assume_role_chain finding {blocked.finding_id[:16]}... "
            f"marks hop {chosen_edge} as blocked"
        ),
    )
    return dataclasses.replace(
        finding,
        verdict=Verdict.INCONCLUSIVE,
        blockers_observed=(demoted_blocker,),
    )
