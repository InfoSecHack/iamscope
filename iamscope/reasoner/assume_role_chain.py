"""Multi-hop AssumeRole privilege escalation reasoner.

Detects chains of `sts:AssumeRole` calls where a starting principal can
transitively reach an admin-equivalent role via 2+ hops, where each hop
satisfies BOTH a permission edge (`sts:AssumeRole_permission`) AND a
trust edge on the next role (`sts:AssumeRole_trust`).

Pattern shape::

    Alice ──sts:AssumeRole──> DevOpsRole ──sts:AssumeRole──> AdminRole
           (permission edge)                (permission edge)
           +                                +
           Alice ∈ DevOpsRole.trust         DevOpsRole ∈ AdminRole.trust
           (trust edge)                     (trust edge)

This kind of chain hides in plain sight in big orgs because each
individual hop looks innocuous when reviewed in isolation. The
single-pair reasoners (`cross_account_trust`, `passrole_lambda`,
`passrole_ecs`) cannot catch it by design.

Walking strategy: BFS from each candidate starting principal, depth-
limited to 4 hops, with cycle detection via visited-set. At each visited
role, check admin-equivalence — if true and depth >= 2, emit a finding.

The Finding shape:
    source = starting principal (first hop's source)
    target = endpoint role (last hop's destination, admin-equivalent)
    chain_length = number of hops (== finding's primary severity input)
    evidence.node_refs = ordered sequence [source, hop1, hop2, ..., target]
    evidence.edge_refs = all permission + trust edges along the chain

Verdict mapping:
    All checks PASS                                → validated
    Check 4 FAIL (SCP blocks any hop)              → blocked / info
    Check 5 FAIL (boundary blocks any hop)         → blocked / info
    Any check UNKNOWN                              → inconclusive / high
    Check 1 (length < 2) or check 2 (not admin)    → no finding (early exit)

Severity (validated only):
    Admin endpoint + chain length 2-3 → high
    Admin endpoint + chain length 4+  → critical (deeper = harder to spot)
    Non-admin endpoint                → medium
"""

from __future__ import annotations

import logging
from collections import deque

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
)
from iamscope.models import Edge, Node
from iamscope.reasoner.combinators import and_tristate_many
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.identity_deny import check_identity_deny_blockers
from iamscope.reasoner.probe_overlay import (
    assess_probe_overlay_for_edges,
    probe_overlay_trace_entries,
)
from iamscope.reasoner.stale_principal_drift import (
    check_stale_principal_drift_blockers,
    has_stale_principal_drift_binding,
)
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


_ASSUMEROLE_ACTION: str = "sts:AssumeRole"
_MAX_DEPTH: int = 4  # max number of hops in a chain
_MIN_CHAIN_LENGTH: int = 2  # single-hop is covered by cross_account_trust


# A "hop" in the chain: from one principal to the next role, with the
# permission edge and trust edge that authorize the hop.
class _Hop:
    """A single step in an AssumeRole chain.

    Stored as a lightweight tuple-like class rather than a dataclass to
    avoid the import cost — this class is instantiated O(N²) times in
    BFS frontiers.
    """

    __slots__ = ("source_arn", "target_arn", "permission_edge", "trust_edge")

    def __init__(
        self,
        source_arn: str,
        target_arn: str,
        permission_edge: Edge,
        trust_edge: Edge,
    ) -> None:
        self.source_arn = source_arn
        self.target_arn = target_arn
        self.permission_edge = permission_edge
        self.trust_edge = trust_edge


class AssumeRoleChainReasoner:
    """Multi-hop sts:AssumeRole privilege escalation chain detector."""

    pattern_id: str = "assume_role_chain"
    pattern_version: str = "1.0.0"
    pattern_title: str = "Multi-Hop AssumeRole Privilege Escalation"
    severity_default: str = "high"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Run only if there are IAM roles in the graph."""
        has_role = any(n.node_type == NODE_TYPE_IAM_ROLE for n in facts.nodes)
        if not has_role:
            return (False, "no IAM roles in graph")
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Enumerate chains and emit findings.

        Strategy: BFS from each candidate starting principal. At each
        visited role, check admin-equivalence. If admin and chain
        length >= 2, evaluate the chain and emit a finding (verdict
        depends on per-hop checks).

        Findings are deduplicated by (source_arn, target_arn, chain
        hop sequence) so the same chain isn't emitted multiple times
        if BFS reaches the same endpoint via different intermediate
        paths.
        """
        findings: list[Finding] = []

        # Find every IAMUser or IAMRole that has any sts:AssumeRole
        # outgoing permission. These are the candidate starting principals.
        starting_principals: list[Node] = []
        for node in facts.nodes:
            if node.node_type not in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE):
                continue
            state = facts.has_action(node.provider_id, _ASSUMEROLE_ACTION)
            if state is not CheckState.FAIL:
                starting_principals.append(node)

        if not starting_principals:
            return []

        # Track emitted (source_arn, target_arn) pairs to dedupe findings
        # for the same source/target chain via different intermediate
        # paths. We deliberately keep ONE finding per (source, target)
        # pair — the shortest chain, since BFS finds it first.
        seen_endpoints: set[tuple[str, str]] = set()

        for source in starting_principals:
            # BFS from this source. Frontier is a deque of (current_role_arn,
            # chain_so_far). chain_so_far is a tuple of _Hop instances.
            # visited prevents cycles.
            frontier: deque[tuple[str, tuple[_Hop, ...]]] = deque()
            visited: set[str] = {source.provider_id}
            frontier.append((source.provider_id, ()))

            while frontier:
                current_arn, chain = frontier.popleft()

                # Check admin-equivalence at the current node (if it's a
                # role and not the source itself). Only emit a finding if
                # chain length is >= MIN_CHAIN_LENGTH (single-hop is
                # covered by cross_account_trust).
                current_node = self._find_node(facts, current_arn)
                if (
                    current_node is not None
                    and current_node.node_type == NODE_TYPE_IAM_ROLE
                    and len(chain) >= _MIN_CHAIN_LENGTH
                    and self._is_admin_equivalent(facts, current_node)
                ):
                    endpoint_key = (source.provider_id, current_arn)
                    if endpoint_key not in seen_endpoints:
                        seen_endpoints.add(endpoint_key)
                        finding = self._build_finding(
                            facts=facts,
                            source=source,
                            target=current_node,
                            chain=chain,
                        )
                        if finding is not None:
                            findings.append(finding)

                # Stop BFS if we hit max depth — no point exploring
                # deeper chains.
                if len(chain) >= _MAX_DEPTH:
                    continue

                # Walk all sts:AssumeRole permission edges from
                # current_arn to find candidate next hops.
                for perm_edge in self._assumerole_permission_edges_from(
                    facts,
                    current_arn,
                ):
                    next_arn = perm_edge.dst.provider_id
                    if next_arn in visited:
                        continue  # cycle prevention

                    # Verify the trust edge on the next role admits
                    # current_arn. If no admitting trust edge, skip
                    # this hop entirely.
                    trust_edge = self._find_admitting_trust_edge(
                        facts,
                        current_arn=current_arn,
                        next_arn=next_arn,
                    )
                    if trust_edge is None:
                        continue

                    new_visited_marker = next_arn  # added to visited below
                    new_chain = chain + (
                        _Hop(
                            source_arn=current_arn,
                            target_arn=next_arn,
                            permission_edge=perm_edge,
                            trust_edge=trust_edge,
                        ),
                    )
                    visited.add(new_visited_marker)
                    frontier.append((next_arn, new_chain))

        # Stable sort: by source_arn, then by target_arn, then by chain
        # length (shorter first). Ensures deterministic finding order
        # across runs regardless of dict iteration order in BFS.
        findings.sort(
            key=lambda f: (f.source.provider_id, f.target.provider_id),
        )
        return findings

    # ---------------------------------------------------------------
    # BFS helpers (delegated to shared modules in 3c-refactor)
    # ---------------------------------------------------------------

    def _find_node(self, facts: FactGraph, provider_id: str) -> Node | None:
        from iamscope.reasoner.chain_walking import find_node

        return find_node(facts, provider_id)

    def _assumerole_permission_edges_from(
        self,
        facts: FactGraph,
        src_provider_id: str,
    ) -> tuple[Edge, ...]:
        from iamscope.reasoner.chain_walking import (
            assumerole_permission_edges_from,
        )

        return assumerole_permission_edges_from(facts, src_provider_id)

    def _find_admitting_trust_edge(
        self,
        facts: FactGraph,
        *,
        current_arn: str,
        next_arn: str,
    ) -> Edge | None:
        from iamscope.reasoner.chain_walking import find_admitting_trust_edge

        return find_admitting_trust_edge(
            facts,
            current_arn=current_arn,
            next_arn=next_arn,
        )

    def _is_admin_equivalent(
        self,
        facts: FactGraph,
        target_role: Node,
    ) -> bool:
        from iamscope.reasoner.admin_detection import is_admin_equivalent

        return is_admin_equivalent(facts, target_role)

    def _find_admin_witness_edge(
        self,
        facts: FactGraph,
        target_role: Node,
    ) -> Edge | None:
        from iamscope.reasoner.admin_detection import find_admin_witness_edge

        return find_admin_witness_edge(facts, target_role)

    # ---------------------------------------------------------------
    # Finding construction
    # ---------------------------------------------------------------

    def _build_finding(
        self,
        *,
        facts: FactGraph,
        source: Node,
        target: Node,
        chain: tuple[_Hop, ...],
    ) -> Finding | None:
        """Evaluate the chain's checks and assemble the Finding."""
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        edge_refs: list[str] = []
        node_refs: list[str] = [source.node_id]
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        trace: list[TraceEntry] = []

        # Pull statement digests from every hop's permission and trust
        # edges. node_refs accumulates the chain in order: source →
        # hop1 → hop2 → ... → target.
        for hop in chain:
            edge_refs.append(hop.permission_edge.edge_id)
            edge_refs.append(hop.trust_edge.edge_id)
            self._absorb_digests(
                hop.permission_edge,
                statement_digests,
                statement_sources,
            )
            self._absorb_digests(
                hop.trust_edge,
                statement_digests,
                statement_sources,
            )
            target_node = self._find_node(facts, hop.target_arn)
            if target_node is not None:
                node_refs.append(target_node.node_id)

        chain_length = len(chain)

        # Find the admin witness edge (if any) and add to edge_refs so
        # check 2 can cite a concrete witness instead of a node_id
        # (which would fail evidence cross-reference validation).
        admin_witness = self._find_admin_witness_edge(facts, target)
        if admin_witness is not None and admin_witness.edge_id not in edge_refs:
            edge_refs.append(admin_witness.edge_id)
            self._absorb_digests(admin_witness, statement_digests, statement_sources)

        # ---- Check 1: chain_length >= 2
        check_1_state = CheckState.PASS if chain_length >= _MIN_CHAIN_LENGTH else CheckState.FAIL
        check_results.append(
            Check(
                name="chain_length_at_least_two",
                description=(
                    f"Chain length must be >= {_MIN_CHAIN_LENGTH} hops "
                    f"(single-hop chains are covered by cross_account_trust)"
                ),
                state=check_1_state,
                evidence_refs=tuple(edge_refs),
                reason=f"chain length is {chain_length} hops",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_chain_length_at_least_two",
                inputs=(str(chain_length),),
                result=check_1_state.value.upper(),
                reason=f"chain length is {chain_length} hops",
            )
        )
        if check_1_state is CheckState.FAIL:
            return None  # defensive — caller already filters

        # ---- Check 2: endpoint is admin-equivalent
        is_admin = admin_witness is not None
        check_2_state = CheckState.PASS if is_admin else CheckState.FAIL
        check_results.append(
            Check(
                name="endpoint_is_admin_equivalent",
                description="Chain endpoint role has admin-equivalent permissions (* or iam:*)",
                state=check_2_state,
                evidence_refs=((admin_witness.edge_id,) if admin_witness is not None else tuple(edge_refs)),
                reason=(
                    "endpoint role has * or iam:* permission edge"
                    if is_admin
                    else "endpoint role does not have admin-equivalent permissions"
                ),
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_endpoint_is_admin_equivalent",
                inputs=(target.provider_id,),
                result=check_2_state.value.upper(),
                reason=("endpoint has * or iam:*" if is_admin else "endpoint not admin-equivalent"),
            )
        )
        if check_2_state is CheckState.FAIL:
            return None  # defensive — caller already filters

        # ---- Check 3: all hops have valid trust + permission edges
        # By construction (BFS only adds hops with both edges), this is
        # always PASS unless we somehow built a degenerate chain. Kept
        # as an explicit check so the verdict mapping is consistent
        # with other reasoners.
        check_3_state = CheckState.PASS
        check_results.append(
            Check(
                name="all_hops_have_valid_trust_and_permission_edges",
                description=(
                    "Every hop in the chain has BOTH a valid sts:AssumeRole "
                    "permission edge AND an admitting trust edge on the next role"
                ),
                state=check_3_state,
                evidence_refs=tuple(edge_refs),
                reason=f"all {chain_length} hops verified",
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_all_hops_have_valid_trust_and_permission_edges",
                inputs=(str(chain_length),),
                result=check_3_state.value.upper(),
                reason=f"{chain_length}/{chain_length} hops have both edges",
            )
        )

        # ---- Check 4: no SCP blocks any hop's sts:AssumeRole
        # NOTE (audit): this function shares a single `constraint_refs`
        # accumulator across check 4 (SCPs) and check 5 (boundaries)
        # below. That looks superficially like the BUG-003 pattern
        # fixed by v0.2.29 in iam_group_membership_escalation,
        # s3_bucket_takeover, and secrets_blast_radius, but it's
        # actually correct here for two reasons:
        #
        # 1. Check 4's `evidence_refs` is materialized from
        #    `constraint_refs` BEFORE check 5 runs (line immediately
        #    below this loop), so check 4's evidence captures only
        #    the SCP constraint IDs that have been accumulated so far.
        # 2. Check 5's `evidence_refs` is `tuple(edge_refs)`, not
        #    `tuple(sorted(constraint_refs))`, so the post-check-4
        #    constraint_refs contents are irrelevant to check 5's
        #    evidence.
        #
        # This is ordering-dependent, though. If a future refactor
        # inserts another check between 4 and 5, or reorders them,
        # or changes check 5 to reference constraint_refs for its
        # own evidence, the shared accumulator silently leaks. In
        # that case, switch to the per-check-local accumulator
        # pattern used in the v0.2.29 BUG-003 fix (grep for
        # `check_3_constraint_refs` in s3_bucket_takeover.py for
        # the template).
        check_4_states: list[CheckState] = []
        check_4_reasons: list[str] = []
        check_4_input_edges: list[str] = []
        for i, hop in enumerate(chain, start=1):
            state, reason, hop_blockers = self._check_scp_blockers_on_edge(
                facts,
                hop.permission_edge,
                constraint_refs,
                edge_constraint_refs,
                hop_index=i,
            )
            check_4_input_edges.append(hop.permission_edge.edge_id)
            blockers.extend(hop_blockers)
            if self._has_scp_binding(facts, hop.trust_edge):
                trust_state, trust_reason, trust_blockers = self._check_scp_blockers_on_edge(
                    facts,
                    hop.trust_edge,
                    constraint_refs,
                    edge_constraint_refs,
                    hop_index=i,
                )
                check_4_states.append(and_tristate_many((state, trust_state)))
                check_4_reasons.append(f"hop {i}: permission: {reason}; trust: {trust_reason}")
                check_4_input_edges.append(hop.trust_edge.edge_id)
                blockers.extend(trust_blockers)
            else:
                check_4_states.append(state)
                check_4_reasons.append(f"hop {i}: {reason}")
        check_4_state = and_tristate_many(tuple(check_4_states))
        check_results.append(
            Check(
                name="no_scp_blocks_any_hop",
                description=("No SCP blocks sts:AssumeRole on any hop in the chain with complete confidence"),
                state=check_4_state,
                evidence_refs=(tuple(sorted(constraint_refs)) if constraint_refs else tuple(edge_refs)),
                reason="; ".join(check_4_reasons),
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_no_scp_blocks_any_hop",
                inputs=tuple(check_4_input_edges),
                result=check_4_state.value.upper(),
                reason="; ".join(check_4_reasons),
            )
        )

        # ---- Check 5: no boundary blocks any hop's sts:AssumeRole
        check_5_states: list[CheckState] = []
        check_5_reasons: list[str] = []
        for i, hop in enumerate(chain, start=1):
            state, reason, hop_blockers = self._check_boundary_blockers_on_edge(
                facts,
                hop.permission_edge,
                constraint_refs,
                edge_constraint_refs,
                hop_index=i,
            )
            check_5_states.append(state)
            check_5_reasons.append(f"hop {i}: {reason}")
            blockers.extend(hop_blockers)
        if admin_witness is not None and self._has_boundary_binding(facts, admin_witness):
            state, reason, admin_blockers = self._check_boundary_blockers_on_edge(
                facts,
                admin_witness,
                constraint_refs,
                edge_constraint_refs,
                hop_index=chain_length + 1,
            )
            check_5_states.append(state)
            check_5_reasons.append(f"admin witness: {reason}")
            blockers.extend(admin_blockers)
        check_5_state = and_tristate_many(tuple(check_5_states))
        check_results.append(
            Check(
                name="no_boundary_blocks_any_hop",
                description=("No permission boundary blocks sts:AssumeRole on any hop in the chain"),
                state=check_5_state,
                evidence_refs=tuple(edge_refs),
                reason="; ".join(check_5_reasons),
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_no_boundary_blocks_any_hop",
                inputs=tuple(hop.permission_edge.edge_id for hop in chain),
                result=check_5_state.value.upper(),
                reason="; ".join(check_5_reasons),
            )
        )

        # ---- Check 6: no identity-policy Deny blocks any hop's sts:AssumeRole
        check_6_constraint_refs: set[str] = set()
        check_6_states: list[CheckState] = []
        check_6_reasons: list[str] = []
        for i, hop in enumerate(chain, start=1):
            state, reason, hop_blockers = check_identity_deny_blockers(
                facts,
                hop.permission_edge,
                check_6_constraint_refs,
                edge_constraint_refs,
                action_label="sts:AssumeRole",
            )
            check_6_states.append(state)
            check_6_reasons.append(f"hop {i}: {reason}")
            blockers.extend(hop_blockers)
        check_6_state = and_tristate_many(tuple(check_6_states))
        check_results.append(
            Check(
                name="no_identity_deny_blocks_any_hop",
                description=("No identity-policy Deny blocks sts:AssumeRole on any hop in the chain"),
                state=check_6_state,
                evidence_refs=(tuple(sorted(check_6_constraint_refs)) if check_6_constraint_refs else tuple(edge_refs)),
                reason="; ".join(check_6_reasons),
            )
        )
        trace.append(
            TraceEntry(
                step=6,
                action="check_no_identity_deny_blocks_any_hop",
                inputs=tuple(hop.permission_edge.edge_id for hop in chain),
                result=check_6_state.value.upper(),
                reason="; ".join(check_6_reasons),
            )
        )
        constraint_refs.update(check_6_constraint_refs)

        stale_drift_check_added = False

        # ---- Check 7: no stale principal drift blocks any hop trust edge.
        # Omit this check when no stale-drift evidence is bound so legacy
        # chain findings remain stable until the detector has signal.
        if any(has_stale_principal_drift_binding(facts, hop.trust_edge) for hop in chain):
            stale_drift_check_added = True
            check_7_constraint_refs: set[str] = set()
            check_7_states: list[CheckState] = []
            check_7_reasons: list[str] = []
            for i, hop in enumerate(chain, start=1):
                state, reason, hop_blockers = check_stale_principal_drift_blockers(
                    facts,
                    hop.trust_edge,
                    check_7_constraint_refs,
                    edge_constraint_refs,
                    action_label="sts:AssumeRole trust",
                )
                check_7_states.append(state)
                check_7_reasons.append(f"hop {i}: {reason}")
                blockers.extend(hop_blockers)
            check_7_state = and_tristate_many(tuple(check_7_states))
            check_results.append(
                Check(
                    name="no_stale_principal_drift_blocks_any_hop",
                    description=("No trust edge in the chain references a stale IAM unique principal ID"),
                    state=check_7_state,
                    evidence_refs=(
                        tuple(sorted(check_7_constraint_refs)) if check_7_constraint_refs else tuple(edge_refs)
                    ),
                    reason="; ".join(check_7_reasons),
                )
            )
            trace.append(
                TraceEntry(
                    step=7,
                    action="check_no_stale_principal_drift_blocks_any_hop",
                    inputs=tuple(hop.trust_edge.edge_id for hop in chain),
                    result=check_7_state.value.upper(),
                    reason="; ".join(check_7_reasons),
                )
            )
            constraint_refs.update(check_7_constraint_refs)
        hop_ambiguity_trace_step = 8 if stale_drift_check_added else 7
        # ---- Check 8: no hop traverses a hyperedge or wildcard ambiguity
        check_8_states: list[CheckState] = []
        for _i, hop in enumerate(chain, start=1):
            state = self._classify_hop_witness(hop.permission_edge, hop.trust_edge)
            check_8_states.append(state)
        check_8_state = and_tristate_many(tuple(check_8_states))
        check_results.append(
            Check(
                name="no_hop_traverses_hyperedge",
                description=("No hop's permission edge is a wildcard hyperedge or wildcard-resource grant"),
                state=check_8_state,
                evidence_refs=tuple(edge_refs),
                reason=(
                    f"all {chain_length} hops have clean witness edges"
                    if check_8_state is CheckState.PASS
                    else "at least one hop traverses an ambiguous edge"
                ),
            )
        )
        clean_hop_count = sum(1 for s in check_8_states if s is CheckState.PASS)
        trace.append(
            TraceEntry(
                step=hop_ambiguity_trace_step,
                action="check_no_hop_traverses_hyperedge",
                inputs=tuple(hop.permission_edge.edge_id for hop in chain),
                result=check_8_state.value.upper(),
                reason=f"clean witnesses on {clean_hop_count}/{chain_length} hops",
            )
        )

        # ---- Compute verdict + severity
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results,
            chain_length=chain_length,
            is_admin=is_admin,
        )
        if verdict is None:
            return None

        # ---- Optional live-probe overlay adjustment. The overlay is sidecar
        # state only; without it, this block is inert and the base finding is
        # byte-identical to prior behavior.
        chain_edge_ids = tuple(
            edge_id for hop in chain for edge_id in (hop.permission_edge.edge_id, hop.trust_edge.edge_id)
        )
        relation_edge_ids = (
            facts.assume_role_relation_edge_ids_for_edges(chain_edge_ids)
            if hasattr(facts, "assume_role_relation_edge_ids_for_edges")
            else chain_edge_ids
        )
        probe_assessment = assess_probe_overlay_for_edges(
            facts,
            relation_edge_ids,
            check_name="probe_overlay_runtime_truth",
            check_description=("Live probe overlay agrees with the declared AssumeRole chain"),
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

        # ---- Assemble title
        title = self._compose_title(source, target, chain_length, verdict)

        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=dict(statement_sources),
            edge_refs=tuple(edge_refs),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(node_refs),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=source.to_ref(),
            target=target.to_ref(),
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
    # Per-hop SCP / boundary helpers
    # ---------------------------------------------------------------

    def _has_scp_binding(self, facts: FactGraph, edge: Edge) -> bool:
        """Return True when an edge has any SCP binding."""
        for binding in facts.bindings_for_edge(edge.edge_id):
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None:
                continue
            if constraint.constraint_type == CONSTRAINT_TYPE_SCP:
                return True
        return False

    def _check_scp_blockers_on_edge(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
        *,
        hop_index: int,
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check whether any SCP binding on this edge blocks sts:AssumeRole.

        Returns (state, reason, blockers).

        State semantics:
            PASS    no blocker observed
            FAIL    SCP with governance_confidence=complete + likely_blocking=True
            UNKNOWN SCP with governance_confidence=partial / needs_review

        Mirrors the per-witness SCP check in passrole_lambda — same
        logic, applied to one hop at a time. Caller combines per-hop
        states via and_tristate_many.
        """
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no SCP bindings observed on this hop"

        bindings = facts.bindings_for_edge(edge.edge_id)
        for binding in bindings:
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None:
                continue
            # Only count SCP-type constraints in this check
            if constraint.constraint_type != CONSTRAINT_TYPE_SCP:
                continue
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if binding.likely_blocking and confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="scp",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=binding.binding_reason or "SCP denies sts:AssumeRole",
                    )
                )
                state = CheckState.FAIL
                reason = f"SCP {binding.constraint_id} blocks (complete)"
                break  # short-circuit on FAIL
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"SCP {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _has_boundary_binding(self, facts: FactGraph, edge: Edge) -> bool:
        """Return True when an edge has any permission-boundary binding."""
        for binding in facts.bindings_for_edge(edge.edge_id):
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None:
                continue
            if constraint.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY:
                return True
        return False

    def _check_boundary_blockers_on_edge(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
        *,
        hop_index: int,
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check whether any permission boundary on this edge blocks the hop.

        Same logic as _check_scp_blockers_on_edge but filters for
        boundary-type constraints. Per BND-1 (S04), boundary bindings
        with `likely_blocking=True` and `governance_confidence=complete`
        mean the boundary's intersection with the role's effective
        permissions excludes sts:AssumeRole.
        """
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no permission boundary bindings on this hop"

        bindings = facts.bindings_for_edge(edge.edge_id)
        for binding in bindings:
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None:
                continue
            if constraint.constraint_type != CONSTRAINT_TYPE_PERMISSION_BOUNDARY:
                continue
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if binding.likely_blocking and confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="permission_boundary",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=binding.binding_reason or "boundary blocks sts:AssumeRole",
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

    def _classify_hop_witness(self, permission_edge: Edge, trust_edge: Edge) -> CheckState:
        """Classify whether a hop's permission and trust witnesses are clean.

        PASS: both edges are clean witnesses.
        UNKNOWN: either edge is ambiguous because it is a hyperedge,
            wildcard-resource grant, or conditioned edge.
        FAIL: never (we can't prove negative ambiguity, so absence of
              clean state defaults to UNKNOWN)
        """
        from iamscope.reasoner.fact_graph import _is_unknown_witness

        if _is_unknown_witness(permission_edge) or _is_unknown_witness(trust_edge):
            return CheckState.UNKNOWN
        return CheckState.PASS

    # ---------------------------------------------------------------
    # Verdict mapping
    # ---------------------------------------------------------------

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
        *,
        chain_length: int,
        is_admin: bool,
    ) -> tuple[Verdict | None, str, str]:
        """Apply the verdict mapping rules in order.

        Returns (verdict, severity, exit_reason). Returns (None, ..., ...)
        only as a defensive case — early-exit FAIL on checks 1/2 is
        handled before this method is called.
        """
        check_by_name = {c.name: c for c in check_results}
        check_4 = check_by_name["no_scp_blocks_any_hop"]
        check_5 = check_by_name["no_boundary_blocks_any_hop"]
        check_6 = check_by_name["no_identity_deny_blocks_any_hop"]
        check_7 = check_by_name.get("no_stale_principal_drift_blocks_any_hop")

        # Rule 1: SCP blocks any hop with complete confidence → blocked
        if check_4.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                f"SCP blocks at least one hop in the {chain_length}-hop chain",
            )

        # Rule 2: Boundary blocks any hop with complete confidence → blocked
        if check_5.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                f"permission boundary blocks at least one hop in the {chain_length}-hop chain",
            )

        # Rule 3: Identity policy Deny blocks any hop with complete confidence -> blocked
        if check_6.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                f"identity policy Deny blocks at least one hop in the {chain_length}-hop chain",
            )

        if check_7 is not None and check_7.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                f"stale principal unique-ID drift blocks at least one hop in the {chain_length}-hop chain",
            )
        # Rule 4: Any check UNKNOWN -> inconclusive / high
        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                "high",
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}",
            )

        # Rule 5: All checks PASS -> validated. Severity from chain length
        # and admin equivalence.
        if is_admin and chain_length >= 4:
            severity = "critical"  # deeper chains harder to spot
        elif is_admin:
            severity = "high"
        else:
            severity = "medium"  # defensive — caller filters non-admin
        return (
            Verdict.VALIDATED,
            severity,
            f"all checks PASS; {chain_length}-hop chain to admin-equivalent endpoint",
        )

    # ---------------------------------------------------------------
    # Title composition
    # ---------------------------------------------------------------

    def _compose_title(
        self,
        source: Node,
        target: Node,
        chain_length: int,
        verdict: Verdict,
    ) -> str:
        """Build a human-readable title for the finding."""
        verdict_label = {
            Verdict.VALIDATED: "Validated",
            Verdict.BLOCKED: "Blocked",
            Verdict.INCONCLUSIVE: "Inconclusive",
            Verdict.PRECONDITION_ONLY: "Precondition-only",
        }.get(verdict, "Unknown")
        return f"{verdict_label} {chain_length}-hop AssumeRole chain from {source.provider_id} to {target.provider_id}"

    # ---------------------------------------------------------------
    # Digest absorption
    # ---------------------------------------------------------------

    def _absorb_digests(
        self,
        edge: Edge,
        digests: set[str],
        sources: dict[str, tuple[str, int, str]],
    ) -> None:
        """Pull DIG-1 statement digests from an edge's allow_controls."""
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
