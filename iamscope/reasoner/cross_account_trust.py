"""Cross-account trust reasoner — S10.

Wraps the existing `naked_trust` classifier output to emit `Finding`
objects against cross-account trust edges that lack strong constraints.
This is the first reasoner in the rebuild — it proves the S09
scaffolding (FactGraph + Reasoner Protocol + EvidenceBundle + Registry)
end-to-end on logic that's already been validated by the fact-layer
classifier.

Per plan §4A, the reasoner runs 6 checks against each trust edge with a
`naked_trust` classification:

1. `edge_is_cross_account` — early exit if False, no finding
2. `naked_trust_is_risky` — early exit if INTRA_ACCOUNT or CONDITIONED
3. `source_principal_resolvable` — data integrity (see spec resolution below)
4. `no_scp_blocks_sts_assumerole` — walk SCP bindings
5. `trust_conditions_confirm_classification` — self-consistency safety net
6. `target_role_exists_in_graph` — data integrity

Verdict mapping (top-down, first match wins):

- Check 1 or 2 FAIL → no finding (early exit)
- Check 4 FAIL → BLOCKED, severity info
- Check 5 or 6 FAIL → INCONCLUSIVE, severity high
- Any check UNKNOWN → INCONCLUSIVE, severity high
- All PASS → VALIDATED with severity from naked_trust class:
  - CRITICAL_NAKED → critical
  - BROAD_NAKED → high
  - NARROW_NAKED → medium
  - Same-org cross-account → severity downgraded by one level

This reasoner NEVER emits PRECONDITION_ONLY. The permission IS the
cross-account trust; there is no separate "working path" to check.

**Spec ambiguity resolution for check 3.** Plan §4A.2 names check 3
`source_resolves_to_external_org` with "PASS: False (truly external) /
FAIL: True (cross-account within same org — downgrades severity but
still finding) / UNKNOWN: source node not resolvable." But §3.4
requires "VALIDATED → all checks PASS," so emitting check 3 with
FAIL state in the same-org case would prevent the documented
"validated, downgraded severity" outcome. This reasoner resolves the
ambiguity by:

1. Renaming check 3 to `source_principal_resolvable` (data integrity).
   PASS = source NodeRef points to a node in the graph. FAIL = not
   resolvable.
2. Tracking same-org status as a separate side-channel (an internal
   `_org_membership` enum) that drives a severity modifier without
   becoming a Check state. The org membership decision is captured in
   the reasoning trace and in a dedicated trace entry for audit.

This respects both §4A.2 (the information is captured and influences
severity exactly as specified) and §3.4 (VALIDATED's all-checks-PASS
invariant is preserved).
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from iamscope.constants import (
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NAKED_NARROW,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from iamscope.models import Edge, NodeRef
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.probe_overlay import (
    assess_probe_overlay_for_edges,
    probe_overlay_trace_entries,
)
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


# The three sts:* trust action types this reasoner cares about.
_TRUST_ACTIONS: tuple[str, ...] = (
    "sts:AssumeRole",
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRoleWithSAML",
)

# The risky naked_trust classification values that produce findings.
_RISKY_CLASSIFICATIONS: frozenset[str] = frozenset(
    {
        NAKED_CRITICAL,
        NAKED_BROAD,
        NAKED_NARROW,
    }
)

# Severity ordering for the same-org downgrade (highest to lowest).
# Each level is one step lower than the previous; downgrading from the
# lowest level (info) is a no-op (info stays info).
_SEVERITY_LADDER: tuple[str, ...] = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)


class _OrgMembership(Enum):
    """Side-channel for check 3's org-membership status.

    Drives a severity modifier without becoming a Check state. See the
    module docstring for the spec-ambiguity resolution rationale.
    """

    EXTERNAL = "external"  # source node org_member=False (truly external)
    SAME_ORG = "same_org"  # source node org_member=True (downgrade severity)
    UNKNOWN = "unknown"  # could not determine (escalates verdict to inconclusive)


def _extract_account_id_from_arn(provider_id: str) -> str | None:
    """Extract the account id from an ARN-like provider id."""
    parts = provider_id.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


def _resolve_source_org_membership(
    facts: FactGraph,
    source_node: Any,
) -> tuple[_OrgMembership, str]:
    """Resolve source org membership, falling back to account-root metadata.

    Concrete IAMUser/IAMRole nodes do not always carry `org_member`; collected
    account-root synthetic nodes do. Use that root metadata only when the
    concrete node has no explicit value.
    """
    org_member_value = source_node.properties.get("org_member")
    if org_member_value is False:
        return (
            _OrgMembership.EXTERNAL,
            "source node properties.org_member resolved to external",
        )
    if org_member_value is True:
        return (
            _OrgMembership.SAME_ORG,
            "source node properties.org_member resolved to same_org",
        )

    account_id = source_node.properties.get("account_id")
    if not account_id:
        account_id = _extract_account_id_from_arn(source_node.provider_id)
    if not account_id:
        return (
            _OrgMembership.UNKNOWN,
            "source node org_member and account_id unavailable",
        )

    account_root_arn = f"arn:aws:iam::{account_id}:root"
    account_root = facts.node_by_provider_id(account_root_arn)
    if account_root is None:
        return (
            _OrgMembership.UNKNOWN,
            f"source account root {account_root_arn} not in fact graph",
        )

    root_org_member_value = account_root.properties.get("org_member")
    if root_org_member_value is False:
        return (
            _OrgMembership.EXTERNAL,
            f"source account root {account_root_arn} properties.org_member resolved to external",
        )
    if root_org_member_value is True:
        return (
            _OrgMembership.SAME_ORG,
            f"source account root {account_root_arn} properties.org_member resolved to same_org",
        )

    return (
        _OrgMembership.UNKNOWN,
        f"source account root {account_root_arn} org_member unavailable",
    )


def _downgrade_severity(severity: str) -> str:
    """Drop one level on the severity ladder. info stays info."""
    try:
        idx = _SEVERITY_LADDER.index(severity)
    except ValueError:
        # Unknown severity — return unchanged. The Finding constructor
        # will reject it via SEVERITY_VALUES anyway.
        return severity
    if idx == len(_SEVERITY_LADDER) - 1:
        return severity
    return _SEVERITY_LADDER[idx + 1]


class CrossAccountTrustReasoner:
    """Reasoner for cross-account trust without strong constraints (§4A).

    Identity attributes per Reasoner Protocol:
    """

    pattern_id: str = "cross_account_trust"
    pattern_version: str = "1.0.0"
    pattern_title: str = "Cross-account trust without strong constraints"
    severity_default: str = SEVERITY_HIGH

    # ---------------------------------------------------------------
    # Reasoner Protocol methods
    # ---------------------------------------------------------------

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Run only when there's at least one classified trust edge.

        Returns (False, reason) when:
        - No sts:* trust edges exist in the graph at all.
        - Trust edges exist but none carry a `naked_trust` feature
          (the fact-layer classifier didn't run).

        Per plan §4A.1: "Runs on any scenario with at least one trust
        edge carrying a naked_trust feature. Does not require post-fix
        collector."
        """
        trust_edges = self._iter_trust_edges(facts)
        if not trust_edges:
            return (False, "no trust edges in scenario")
        if not any(e.features.get("naked_trust") for e in trust_edges):
            return (
                False,
                "trust edges lack naked_trust classification (fact layer did not run classify_naked_trust)",
            )
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Iterate trust edges and emit one finding per risky cross-account edge.

        Trust edges are iterated in deterministic edge_id order
        (FactGraph's edges_by_action helper sorts by edge_id, per plan
        §4A.6 failure mode 5). Each edge is evaluated independently —
        no cross-edge deduplication is performed because each trust
        statement represents a distinct grant.
        """
        findings: list[Finding] = []
        for edge in self._iter_trust_edges(facts):
            finding = self._evaluate_edge(facts, edge)
            if finding is not None:
                findings.append(finding)
        return findings

    # ---------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------

    def _iter_trust_edges(self, facts: FactGraph) -> tuple[Edge, ...]:
        """Return all sts:* trust edges in deterministic edge_id order.

        Combines results from `edges_by_action` for the three trust
        action types. Per plan §4A.6 failure mode 5, FactGraph's index
        already sorts by edge_id, but we re-sort the combined tuple to
        guarantee a stable interleaving order across the three action
        types.
        """
        combined: list[Edge] = []
        for action in _TRUST_ACTIONS:
            combined.extend(facts.edges_by_action(action))
        return tuple(sorted(combined, key=lambda e: e.edge_id))

    def _evaluate_edge(
        self,
        facts: FactGraph,
        edge: Edge,
    ) -> Finding | None:
        """Run the 6-check pipeline against a single trust edge.

        Returns None for early-exit cases (intra-account, conditioned,
        not classified as risky). Otherwise builds a Finding with the
        appropriate verdict and severity per the §4A.3 mapping.
        """
        features: dict[str, Any] = edge.features or {}

        # Check 1: edge_is_cross_account. Early exit on FAIL.
        if not features.get("cross_account", False):
            return None

        # Check 2: naked_trust_is_risky. Early exit on FAIL.
        naked_trust_value = features.get("naked_trust")
        if naked_trust_value in (NAKED_INTRA_ACCOUNT, NAKED_CONDITIONED):
            return None
        if naked_trust_value not in _RISKY_CLASSIFICATIONS:
            # Unrecognized or missing classification → emit a finding
            # with check 2 in UNKNOWN state (the only path that would
            # have rejected this case is preconditions, which already
            # confirmed at least one edge had a naked_trust feature).
            naked_trust_value = None  # signal to check 2 below

        # Build the check evaluation results. We carry tuples of
        # (Check, optional_blocker, optional_evidence_refs_set) so the
        # final assembly step has all the data it needs.
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        node_refs: set[str] = set()
        trace: list[TraceEntry] = []

        # Pull statement digests from the edge's allow_controls (DIG-1
        # post-S05). If empty, the evidence bundle has no digests and
        # the finding will be inconclusive — see plan §4A.4.
        for ref in features.get("allow_controls", []) or []:
            if isinstance(ref, dict):
                digest = ref.get("digest", "")
                if digest:
                    statement_digests.add(digest)
                    policy_arn = ref.get("policy_arn") or ""
                    statement_sources[digest] = (
                        policy_arn,
                        int(ref.get("statement_index", 0)),
                        ref.get("summary", ""),
                    )

        # Always include the edge_id in evidence.
        edge_id = edge.edge_id

        # ---- Check 1: edge_is_cross_account (we already returned None
        # above if FAIL, so it's PASS by definition here).
        check_results.append(
            Check(
                name="edge_is_cross_account",
                description="Trust edge crosses an account boundary",
                state=CheckState.PASS,
                evidence_refs=(edge_id,),
                reason="features.cross_account is True",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_edge_is_cross_account",
                inputs=(edge_id,),
                result="PASS",
                reason="features.cross_account is True",
            )
        )

        # ---- Check 2: naked_trust_is_risky.
        if naked_trust_value is None:
            check_2_state = CheckState.UNKNOWN
            check_2_reason = "naked_trust classification absent — fact layer did not classify this edge"
        else:
            check_2_state = CheckState.PASS
            check_2_reason = f"naked_trust={naked_trust_value} ∈ risky set"
        check_results.append(
            Check(
                name="naked_trust_is_risky",
                description="naked_trust classification is in the risky set",
                state=check_2_state,
                evidence_refs=(edge_id,),
                reason=check_2_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_naked_trust_is_risky",
                inputs=(str(naked_trust_value),),
                result=check_2_state.value.upper(),
                reason=check_2_reason,
            )
        )

        # ---- Check 3: source_principal_resolvable. Renamed from spec
        # to resolve §4A.2 / §3.4 ambiguity (see module docstring).
        # The same-org status is tracked as a side-channel below.
        source_node = facts.node_by_provider_id(edge.src.provider_id)
        if source_node is None:
            check_3_state = CheckState.FAIL
            check_3_reason = f"source principal {edge.src.provider_id} not resolvable in fact graph"
            org_membership = _OrgMembership.UNKNOWN
            org_membership_reason = "source principal not resolvable"
        else:
            check_3_state = CheckState.PASS
            check_3_reason = f"source principal {edge.src.provider_id} resolved to node {source_node.node_type}"
            node_refs.add(source_node.node_id)
            org_membership, org_membership_reason = _resolve_source_org_membership(facts, source_node)
        check_results.append(
            Check(
                name="source_principal_resolvable",
                description="Source principal node exists in the fact graph",
                state=check_3_state,
                evidence_refs=(edge_id,),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_source_principal_resolvable",
                inputs=(edge.src.provider_id,),
                result=check_3_state.value.upper(),
                reason=check_3_reason,
            )
        )
        # Side-channel trace entry for the org membership decision.
        # NOT a Check — drives severity modifier only.
        trace.append(
            TraceEntry(
                step=4,
                action="evaluate_source_org_membership",
                inputs=(edge.src.provider_id,),
                result=org_membership.value.upper(),
                reason=org_membership_reason,
            )
        )

        # ---- Check 4: no_scp_blocks_sts_assumerole.
        # Walk all SCP bindings on this edge. In V1, all bindings on
        # trust edges are SCPs (permission boundaries don't bind to
        # trust edges), so we don't filter by constraint_type — every
        # binding is in scope for this check.
        check_4_state = CheckState.PASS
        check_4_reason = "no SCP bindings observed on this edge"
        bindings = facts.bindings_for_edge(edge_id)
        if bindings:
            edge_constraint_refs.update(f"{b.edge_id}|{b.constraint_id}" for b in bindings)
            constraint_refs.update(b.constraint_id for b in bindings)
            blocking_complete: list = []
            ambiguous: list = []
            for binding in bindings:
                if binding.likely_blocking and binding.governance_confidence == "complete":
                    blocking_complete.append(binding)
                elif binding.governance_confidence in ("partial", "needs_review"):
                    ambiguous.append(binding)
            if blocking_complete:
                check_4_state = CheckState.FAIL
                check_4_reason = (
                    f"{len(blocking_complete)} SCP binding(s) likely_blocking with governance_confidence=complete"
                )
                for b in blocking_complete:
                    blockers.append(
                        Blocker(
                            kind="scp",
                            constraint_id=b.constraint_id,
                            edge_id=edge_id,
                            reason=b.binding_reason or "SCP denies sts:AssumeRole",
                        )
                    )
            elif ambiguous:
                check_4_state = CheckState.UNKNOWN
                check_4_reason = (
                    f"{len(ambiguous)} SCP binding(s) with "
                    f"governance_confidence ∈ partial/needs_review — "
                    f"cannot confirm whether the action is blocked"
                )
            else:
                check_4_reason = f"{len(bindings)} SCP binding(s) all non-blocking with governance_confidence=complete"
        check_results.append(
            Check(
                name="no_scp_blocks_sts_assumerole",
                description="No SCP blocks the trust action with full confidence",
                state=check_4_state,
                evidence_refs=tuple(sorted(constraint_refs)) if constraint_refs else (edge_id,),
                reason=check_4_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_no_scp_blocks_sts_assumerole",
                inputs=tuple(sorted(constraint_refs)) if constraint_refs else (edge_id,),
                result=check_4_state.value.upper(),
                reason=check_4_reason,
            )
        )

        # ---- Check 5: trust_conditions_confirm_classification.
        # Self-consistency safety net — catches bugs in the naked_trust
        # classifier where the classification disagrees with the
        # condition features on the same edge.
        check_5_state, check_5_reason = self._verify_classification_consistency(naked_trust_value, features)
        check_results.append(
            Check(
                name="trust_conditions_confirm_classification",
                description="naked_trust value agrees with condition features",
                state=check_5_state,
                evidence_refs=(edge_id,),
                reason=check_5_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=6,
                action="check_trust_conditions_confirm_classification",
                inputs=(str(naked_trust_value),),
                result=check_5_state.value.upper(),
                reason=check_5_reason,
            )
        )

        # ---- Check 6: target_role_exists_in_graph.
        target_node = facts.node_by_provider_id(edge.dst.provider_id)
        if target_node is None:
            check_6_state = CheckState.FAIL
            check_6_reason = f"target role {edge.dst.provider_id} not in fact graph"
        else:
            check_6_state = CheckState.PASS
            check_6_reason = f"target role {edge.dst.provider_id} resolved to node {target_node.node_type}"
            node_refs.add(target_node.node_id)
        check_results.append(
            Check(
                name="target_role_exists_in_graph",
                description="Target role node exists in the fact graph",
                state=check_6_state,
                evidence_refs=(edge_id,),
                reason=check_6_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=7,
                action="check_target_role_exists_in_graph",
                inputs=(edge.dst.provider_id,),
                result=check_6_state.value.upper(),
                reason=check_6_reason,
            )
        )

        # ---- Verdict mapping per §4A.3 (top-down, first match wins).
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results=check_results,
            naked_trust_value=naked_trust_value,
            org_membership=org_membership,
        )

        # ---- Optional live-probe overlay adjustment. No overlay means no
        # check, no trace entry, and byte-identical behavior to the base path.
        probe_assessment = assess_probe_overlay_for_edges(
            facts,
            (edge_id,),
            check_name="probe_overlay_runtime_truth",
            check_description=("Live probe overlay agrees with the declared cross-account trust edge"),
        )
        if probe_assessment.has_records:
            if probe_assessment.check is not None:
                check_results.append(probe_assessment.check)
            if probe_assessment.blocker is not None:
                blockers.append(probe_assessment.blocker)
            constraint_refs.update(probe_assessment.contributing_control_refs)
            trace.extend(
                probe_overlay_trace_entries(
                    probe_assessment,
                    start_step=len(trace) + 1,
                )
            )
            if probe_assessment.verdict_override is not None:
                verdict = probe_assessment.verdict_override
                severity = probe_assessment.severity_override or severity
                exit_reason = probe_assessment.exit_reason or exit_reason

        # ---- Final trace entry: verdict emission.
        trace.append(
            TraceEntry(
                step=len(trace) + 1,
                action="emit_verdict",
                inputs=(verdict.value, severity),
                result=verdict.value.upper(),
                reason=exit_reason,
            )
        )

        # ---- Build the EvidenceBundle.
        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=statement_sources,
            edge_refs=(edge_id,),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(sorted(node_refs)),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        # ---- Build the Finding.
        title = self._compose_title(
            naked_trust_value=naked_trust_value,
            verdict=verdict,
            org_membership=org_membership,
        )
        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=NodeRef(
                provider=edge.src.provider,
                node_type=edge.src.node_type,
                provider_id=edge.src.provider_id,
                region=edge.src.region,
            ),
            target=NodeRef(
                provider=edge.dst.provider,
                node_type=edge.dst.node_type,
                provider_id=edge.dst.provider_id,
                region=edge.dst.region,
            ),
            verdict=verdict,
            severity=severity,
            title=title,
            required_checks=tuple(check_results),
            blockers_observed=tuple(blockers),
            assumptions=(),
            evidence=evidence,
            scenario_hash=facts.scenario_hash,
            reasoner_exit_reason=exit_reason,
        )

    def _verify_classification_consistency(
        self,
        naked_trust_value: str | None,
        features: dict[str, Any],
    ) -> tuple[CheckState, str]:
        """Self-consistency check between naked_trust value and condition features.

        - CRITICAL_NAKED implies no conditions of any kind.
        - BROAD_NAKED implies no strong conditions (no MFA, no OrgID).
        - NARROW_NAKED implies at least one condition exists, but no
          strong condition (no MFA, no OrgID).

        Returns (CheckState.PASS, reason) on agreement, (CheckState.FAIL,
        reason) on disagreement (which is a fact-layer bug indicator),
        or (CheckState.UNKNOWN, reason) if we can't classify.
        """
        if naked_trust_value is None:
            return (
                CheckState.UNKNOWN,
                "naked_trust value missing — cannot cross-check",
            )

        has_external_id = features.get("has_external_id", False)
        has_mfa = features.get("has_mfa_condition", False)
        has_org_id = features.get("has_org_id_condition", False)
        has_any_condition = (
            has_external_id
            or has_mfa
            or has_org_id
            or features.get("has_source_account_condition", False)
            or features.get("has_source_ip_condition", False)
            or features.get("has_source_vpc_condition", False)
        )
        has_strong_condition = has_mfa or has_org_id

        if naked_trust_value == NAKED_CRITICAL:
            if has_any_condition:
                return (
                    CheckState.FAIL,
                    "CRITICAL_NAKED classification disagrees with edge having conditions — fact-layer bug indicator",
                )
            return (
                CheckState.PASS,
                "CRITICAL_NAKED with no conditions — consistent",
            )

        if naked_trust_value == NAKED_BROAD:
            if has_strong_condition:
                return (
                    CheckState.FAIL,
                    "BROAD_NAKED classification disagrees with edge "
                    "having strong condition (MFA or OrgID) — "
                    "fact-layer bug indicator",
                )
            return (
                CheckState.PASS,
                "BROAD_NAKED with no strong conditions — consistent",
            )

        if naked_trust_value == NAKED_NARROW:
            if has_strong_condition:
                return (
                    CheckState.FAIL,
                    "NARROW_NAKED classification disagrees with edge "
                    "having strong condition (MFA or OrgID) — "
                    "fact-layer bug indicator",
                )
            return (
                CheckState.PASS,
                "NARROW_NAKED with weak/no conditions — consistent",
            )

        # Should be unreachable because we already early-exited on
        # INTRA_ACCOUNT and CONDITIONED before reaching this check.
        return (
            CheckState.UNKNOWN,
            f"unexpected naked_trust value {naked_trust_value!r}",
        )

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
        naked_trust_value: str | None,
        org_membership: _OrgMembership,
    ) -> tuple[Verdict, str, str]:
        """Apply the §4A.3 verdict mapping table.

        Returns (verdict, severity, exit_reason). The exit_reason is a
        short string describing why the reasoner picked this verdict —
        captured in `Finding.reasoner_exit_reason`.
        """
        # Find checks by name for the verdict mapping rules.
        check_by_name = {c.name: c for c in check_results}
        check_4 = check_by_name.get("no_scp_blocks_sts_assumerole")
        check_5 = check_by_name.get("trust_conditions_confirm_classification")
        check_6 = check_by_name.get("target_role_exists_in_graph")

        # Rule 1: Check 4 FAIL → BLOCKED, info severity.
        if check_4 is not None and check_4.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "SCP binding blocks sts:AssumeRole with complete governance confidence",
            )

        # Rule 2: Check 6 FAIL → INCONCLUSIVE, high severity.
        if check_6 is not None and check_6.state is CheckState.FAIL:
            return (
                Verdict.INCONCLUSIVE,
                SEVERITY_HIGH,
                "target role not in fact graph — data integrity alarm",
            )

        # Rule 3: Check 5 FAIL → INCONCLUSIVE, high severity.
        if check_5 is not None and check_5.state is CheckState.FAIL:
            return (
                Verdict.INCONCLUSIVE,
                SEVERITY_HIGH,
                "naked_trust classification disagrees with condition features",
            )

        # Rule 4: Any check UNKNOWN → INCONCLUSIVE, high severity.
        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                SEVERITY_HIGH,
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}",
            )
        # Rule 4b: org_membership UNKNOWN escalates verdict (side-channel).
        if org_membership is _OrgMembership.UNKNOWN:
            return (
                Verdict.INCONCLUSIVE,
                SEVERITY_HIGH,
                "source node org_membership unknown",
            )

        # Rule 5: All PASS → VALIDATED with severity from naked_trust class.
        # Same-org modifier downgrades by one level.
        base_severity = self._severity_for_classification(naked_trust_value)
        if org_membership is _OrgMembership.SAME_ORG:
            severity = _downgrade_severity(base_severity)
            exit_reason = (
                f"all checks PASS; classification {naked_trust_value}; "
                f"same-org cross-account → severity downgraded "
                f"{base_severity}→{severity}"
            )
        else:
            severity = base_severity
            exit_reason = f"all checks PASS; classification {naked_trust_value}; truly external source"
        return (Verdict.VALIDATED, severity, exit_reason)

    def _severity_for_classification(
        self,
        naked_trust_value: str | None,
    ) -> str:
        """Map a risky naked_trust classification to a severity."""
        if naked_trust_value == NAKED_CRITICAL:
            return SEVERITY_CRITICAL
        if naked_trust_value == NAKED_BROAD:
            return SEVERITY_HIGH
        if naked_trust_value == NAKED_NARROW:
            return SEVERITY_MEDIUM
        return SEVERITY_HIGH  # defensive default

    def _compose_title(
        self,
        naked_trust_value: str | None,
        verdict: Verdict,
        org_membership: _OrgMembership,
    ) -> str:
        """Build a human-readable one-line title for the finding."""
        org_qualifier = (
            "same-org cross-account" if org_membership is _OrgMembership.SAME_ORG else "external cross-account"
        )
        if verdict is Verdict.VALIDATED:
            return f"Validated {naked_trust_value} {org_qualifier} trust grant"
        if verdict is Verdict.BLOCKED:
            return f"Blocked {org_qualifier} trust grant ({naked_trust_value})"
        return f"Inconclusive {org_qualifier} trust evaluation ({naked_trust_value})"
