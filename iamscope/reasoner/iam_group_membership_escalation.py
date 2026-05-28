"""IAM group membership escalation reasoner.

Pattern: a principal with `iam:AddUserToGroup` permission targeting
a group that has admin-equivalent permissions can add themselves (if
they are a user) or any user they control to that group and inherit
the group's permissions. If the group is admin-equivalent, this is
direct privilege escalation to admin.

Source scoping (v1): only IAMUser sources. Roles are excluded because
a role session can't meaningfully benefit from adding a user to a
group — the attacker would need to control the user's credentials
separately, which is a different attack primitive (credential theft
via secrets_blast_radius) rather than this pattern. A v2 could extend
the source set to IAMRole nodes where there's a back-path via
sts:AssumeRole from a user.

Target scoping: only admin-equivalent IAMGroup nodes. If the target
group isn't admin-equivalent, adding users to it isn't privilege
escalation — it's just routine user management. No finding emitted.

Fact layer dependency: this reasoner requires group-sourced permission
edges (added in v0.2.25 via `_process_group` enhancement in
`iamscope/collector/account.py`). Before that enhancement, IAMGroup
nodes had no outgoing permission edges and the shared
`admin_detection.find_admin_witness_edge` helper would incorrectly
return None for every group.

Verdict mapping:
    Check 3 FAIL (SCP blocks)          → blocked / info
    Check 4 FAIL (boundary blocks)     → blocked / info
    Check 5 FAIL (target not admin)    → no finding (filtered)
    Check 2 UNKNOWN (wildcard witness) → inconclusive / high
    Any check UNKNOWN                  → inconclusive / high
    All checks PASS                    → validated / critical

Severity rationale: becoming admin via group membership is always a
critical-severity finding because the attacker fully compromises the
account. There's no "partial admin" — group membership confers the
full group permission set. An inconclusive variant (wildcard resource,
partial SCP confidence) is `high` severity because the wildcard case
is common and floods pentest reports if classified as critical.
"""

from __future__ import annotations

import logging

from iamscope.constants import (
    NODE_TYPE_IAM_GROUP,
    NODE_TYPE_IAM_USER,
)
from iamscope.models import Edge, Node
from iamscope.reasoner.admin_detection import find_admin_witness_edge
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph, _is_unknown_witness
from iamscope.reasoner.identity_deny import check_identity_deny_blockers
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


_ADD_USER_TO_GROUP_ACTION: str = "iam:AddUserToGroup"
_ADD_USER_TO_GROUP_EDGE_TYPE: str = f"{_ADD_USER_TO_GROUP_ACTION}_permission"


class IAMGroupMembershipEscalationReasoner:
    """Detect users who can escalate to admin via iam:AddUserToGroup."""

    pattern_id: str = "iam_group_membership_escalation"
    pattern_version: str = "1.0.0"
    pattern_title: str = "IAM Group Membership Escalation"
    severity_default: str = "critical"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Run only if there are users AND groups in the graph."""
        has_user = any(n.node_type == NODE_TYPE_IAM_USER for n in facts.nodes)
        if not has_user:
            return (False, "no IAMUser nodes in graph")
        has_group = any(n.node_type == NODE_TYPE_IAM_GROUP for n in facts.nodes)
        if not has_group:
            return (False, "no IAMGroup nodes in graph")
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Enumerate (user, admin-group) pairs and emit findings."""
        findings: list[Finding] = []
        all_groups: list[Node] = [n for n in facts.nodes if n.node_type == NODE_TYPE_IAM_GROUP]

        # Enumerate users with AddUserToGroup permission in any form
        for node in facts.nodes:
            if node.node_type != NODE_TYPE_IAM_USER:
                continue
            witnesses: list[Edge] = [
                e for e in facts.edges_from(node.provider_id) if e.edge_type == _ADD_USER_TO_GROUP_EDGE_TYPE
            ]
            if not witnesses:
                continue

            # Compute (target_group, representative_witness_edge, is_clean)
            # candidates for this user. Deduplicate by group provider_id
            # so we emit at most one finding per (user, group) pair.
            targets: dict[str, tuple[Node, Edge, bool]] = {}
            for edge in witnesses:
                dst_provider_id = edge.dst.provider_id
                is_unknown = _is_unknown_witness(edge)
                if is_unknown:
                    # Hyperedge, wildcard resource, or conditioned edge:
                    # the witness cannot resolve to a specific group.
                    # Iterate ALL groups as potential targets and mark
                    # the check as UNKNOWN.
                    for g in all_groups:
                        if g.provider_id not in targets:
                            targets[g.provider_id] = (g, edge, False)
                else:
                    # Clean witness edge → specific dst. O(1) lookup
                    # via the FactGraph provider_id index, then verify
                    # the node is actually a group (not e.g. a role
                    # with a colliding ARN substring).
                    candidate = facts.node_by_provider_id(dst_provider_id)
                    if candidate is not None and candidate.node_type == NODE_TYPE_IAM_GROUP:
                        targets[dst_provider_id] = (candidate, edge, True)

            # Evaluate each (user, group) target
            for group_provider_id in sorted(targets.keys()):
                group, witness_edge, is_clean = targets[group_provider_id]
                finding = self._build_finding(
                    facts=facts,
                    user=node,
                    group=group,
                    witness_edge=witness_edge,
                    is_clean_witness=is_clean,
                )
                if finding is not None:
                    findings.append(finding)

        # Deterministic sort
        findings.sort(
            key=lambda f: (f.source.provider_id, f.target.provider_id),
        )
        return findings

    # ---------------------------------------------------------------
    # Finding construction
    # ---------------------------------------------------------------

    def _build_finding(
        self,
        *,
        facts: FactGraph,
        user: Node,
        group: Node,
        witness_edge: Edge,
        is_clean_witness: bool,
    ) -> Finding | None:
        """Evaluate the 5 checks and assemble the Finding."""
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        edge_refs: list[str] = [witness_edge.edge_id]
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        node_refs_set: set[str] = {user.node_id, group.node_id}
        trace: list[TraceEntry] = []

        self._absorb_digests(witness_edge, statement_digests, statement_sources)

        # ---- Check 1: source_has_add_user_to_group_permission
        # Always PASS by enumeration — the candidate wouldn't be here
        # otherwise. The check is included for the audit trail so a
        # reviewer running `iamscope why` sees the full check list.
        check_results.append(
            Check(
                name="source_has_add_user_to_group_permission",
                description=("User has a permission edge for iam:AddUserToGroup (enumeration invariant)"),
                state=CheckState.PASS,
                evidence_refs=(witness_edge.edge_id,),
                reason="permission edge witnessed",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_source_has_add_user_to_group_permission",
                inputs=(user.provider_id,),
                result="PASS",
                reason="permission edge witnessed",
            )
        )

        # ---- Check 2: witness_edge_is_clean
        # PASS if the witness resolves to a specific group; UNKNOWN if
        # the edge is a hyperedge, wildcard resource, or conditioned.
        check_2_state = CheckState.PASS if is_clean_witness else CheckState.UNKNOWN
        check_2_reason = (
            "witness edge resolves to specific target group"
            if is_clean_witness
            else "witness edge is wildcard-expansion hyperedge or "
            "wildcard-resource (target group iterated from all groups)"
        )
        check_results.append(
            Check(
                name="witness_edge_is_clean",
                description=(
                    "Permission edge for iam:AddUserToGroup resolves to a "
                    "specific target group (clean witness proves the edge's "
                    "target)"
                ),
                state=check_2_state,
                evidence_refs=(witness_edge.edge_id,),
                reason=check_2_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_witness_edge_is_clean",
                inputs=(witness_edge.edge_id,),
                result=check_2_state.value.upper(),
                reason=check_2_reason,
            )
        )

        # ---- Check 3: no_scp_blocks_add_user_to_group
        # Each check gets its own constraint_refs accumulator so the
        # evidence_refs attributed to check 3 are ONLY the SCPs it
        # evaluated, not a contaminated mix of SCPs and boundaries.
        # The per-check sets are unioned into the bundle's top-level
        # constraint_refs at the end so the bundle's full constraint
        # reference set is preserved.
        check_3_constraint_refs: set[str] = set()
        check_3_state, check_3_reason, check_3_blockers = self._check_scp_blockers(
            facts,
            witness_edge,
            check_3_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_3_blockers)
        check_results.append(
            Check(
                name="no_scp_blocks_add_user_to_group",
                description=("No SCP blocks iam:AddUserToGroup on this edge with complete governance confidence"),
                state=check_3_state,
                evidence_refs=(
                    tuple(sorted(check_3_constraint_refs)) if check_3_constraint_refs else (witness_edge.edge_id,)
                ),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_no_scp_blocks_add_user_to_group",
                inputs=(witness_edge.edge_id,),
                result=check_3_state.value.upper(),
                reason=check_3_reason,
            )
        )
        constraint_refs.update(check_3_constraint_refs)

        # ---- Check 4: no_boundary_blocks_add_user_to_group
        check_4_constraint_refs: set[str] = set()
        check_4_state, check_4_reason, check_4_blockers = self._check_boundary_blockers(
            facts,
            witness_edge,
            check_4_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_4_blockers)
        check_results.append(
            Check(
                name="no_boundary_blocks_add_user_to_group",
                description=("No permission boundary blocks iam:AddUserToGroup on this edge"),
                state=check_4_state,
                evidence_refs=(
                    tuple(sorted(check_4_constraint_refs)) if check_4_constraint_refs else (witness_edge.edge_id,)
                ),
                reason=check_4_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_no_boundary_blocks_add_user_to_group",
                inputs=(witness_edge.edge_id,),
                result=check_4_state.value.upper(),
                reason=check_4_reason,
            )
        )
        constraint_refs.update(check_4_constraint_refs)

        # ---- Check 5: no_identity_deny_blocks_add_user_to_group
        check_5_constraint_refs: set[str] = set()
        check_5_state, check_5_reason, check_5_blockers = check_identity_deny_blockers(
            facts,
            witness_edge,
            check_5_constraint_refs,
            edge_constraint_refs,
            action_label="iam:AddUserToGroup",
        )
        blockers.extend(check_5_blockers)
        check_results.append(
            Check(
                name="no_identity_deny_blocks_add_user_to_group",
                description=("No identity-policy Deny blocks iam:AddUserToGroup on this edge"),
                state=check_5_state,
                evidence_refs=(
                    tuple(sorted(check_5_constraint_refs)) if check_5_constraint_refs else (witness_edge.edge_id,)
                ),
                reason=check_5_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_no_identity_deny_blocks_add_user_to_group",
                inputs=(witness_edge.edge_id,),
                result=check_5_state.value.upper(),
                reason=check_5_reason,
            )
        )
        constraint_refs.update(check_5_constraint_refs)

        # ---- Check 6: target_group_is_admin_equivalent
        # Uses the shared two-tier admin detection from
        # `admin_detection.py`. Tier 1: explicit *_permission or
        # iam:*_permission edges from the group. Tier 2: wildcard
        # expansion hyperedges spanning ≥3 service prefixes (rare for
        # groups in practice but supported for completeness).
        admin_witness = find_admin_witness_edge(facts, group)
        if admin_witness is None:
            # Target group is not admin-equivalent → not an escalation
            # pattern, drop the finding.
            return None
        edge_refs.append(admin_witness.edge_id)
        self._absorb_digests(
            admin_witness,
            statement_digests,
            statement_sources,
        )
        check_5_state = CheckState.PASS
        check_5_reason = f"target group has admin-equivalent permissions (witness edge {admin_witness.edge_id[:12]}…)"
        check_results.append(
            Check(
                name="target_group_is_admin_equivalent",
                description=(
                    "Target group has permissions equivalent to administrator "
                    "access via the shared two-tier admin detection "
                    "(explicit iam:* or wildcard expansion across ≥3 prefixes)"
                ),
                state=check_5_state,
                evidence_refs=(admin_witness.edge_id,),
                reason=check_5_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=6,
                action="check_target_group_is_admin_equivalent",
                inputs=(group.provider_id,),
                result="PASS",
                reason=check_5_reason,
            )
        )

        # ---- Verdict + severity
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results,
        )
        if verdict is None:
            return None

        title = self._compose_title(user, group, verdict)

        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=dict(statement_sources),
            edge_refs=tuple(edge_refs),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(sorted(node_refs_set)),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=user.to_ref(),
            target=group.to_ref(),
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

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    def _check_scp_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check for SCP blockers on the AddUserToGroup edge."""
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no SCP bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "SCP":
                continue
            edge_constraint_refs.add(
                f"{binding.edge_id}:{binding.constraint_id}",
            )
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="scp",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=(binding.binding_reason or "SCP denies iam:AddUserToGroup"),
                    )
                )
                state = CheckState.FAIL
                reason = f"SCP {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"SCP {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _check_boundary_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check for permission boundary blockers on the AddUserToGroup edge."""
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no permission boundary bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "PERMISSION_BOUNDARY":
                continue
            edge_constraint_refs.add(
                f"{binding.edge_id}:{binding.constraint_id}",
            )
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="permission_boundary",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=(binding.binding_reason or "boundary blocks iam:AddUserToGroup"),
                    )
                )
                state = CheckState.FAIL
                reason = f"boundary {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"boundary {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
    ) -> tuple[Verdict | None, str, str]:
        """Apply verdict mapping rules.

        Returns (verdict, severity, exit_reason). If check 5 (admin
        equivalence) was not PASS, returns (None, ...) because we only
        emit findings for actual privilege escalation paths.
        """
        check_by_name = {c.name: c for c in check_results}
        check_3 = check_by_name["no_scp_blocks_add_user_to_group"]
        check_4 = check_by_name["no_boundary_blocks_add_user_to_group"]
        check_5 = check_by_name["no_identity_deny_blocks_add_user_to_group"]
        check_6 = check_by_name["target_group_is_admin_equivalent"]

        # Safety: target admin equivalence must be PASS (we only call _compute_verdict
        # when it is), but bail defensively if it's not.
        if check_6.state is not CheckState.PASS:
            return (None, "", "target group is not admin-equivalent")

        # Rule 1: SCP blocks with complete confidence → blocked
        if check_3.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "SCP blocks iam:AddUserToGroup",
            )

        # Rule 2: Boundary blocks with complete confidence → blocked
        if check_4.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "permission boundary blocks iam:AddUserToGroup",
            )

        # Rule 2.5: Identity policy Deny blocks with complete confidence -> blocked
        if check_5.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "identity policy Deny blocks iam:AddUserToGroup",
            )

        # Rule 3: Any check UNKNOWN -> inconclusive / high
        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                "high",
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}",
            )

        # Rule 4: All PASS → validated / critical
        # Becoming admin via group membership is always critical.
        return (
            Verdict.VALIDATED,
            "critical",
            "all checks PASS; user can add themselves to admin-equivalent group and inherit its permissions",
        )

    def _compose_title(
        self,
        user: Node,
        group: Node,
        verdict: Verdict,
    ) -> str:
        verdict_label = {
            Verdict.VALIDATED: "Validated",
            Verdict.BLOCKED: "Blocked",
            Verdict.INCONCLUSIVE: "Inconclusive",
            Verdict.PRECONDITION_ONLY: "Precondition-only",
        }.get(verdict, "Unknown")
        return (
            f"{verdict_label} group membership escalation: "
            f"{user.provider_id} can call iam:AddUserToGroup on "
            f"admin-equivalent group {group.provider_id}"
        )

    def _absorb_digests(
        self,
        edge: Edge,
        digests: set[str],
        sources: dict[str, tuple[str, int, str]],
    ) -> None:
        for ref in (edge.features or {}).get("allow_controls", []) or []:
            if isinstance(ref, dict):
                digest = ref.get("digest", "")
                if digest:
                    digests.add(digest)
                    sources[digest] = (
                        ref.get("policy_arn", ""),
                        int(ref.get("statement_index", 0)),
                        ref.get("summary", ""),
                    )
