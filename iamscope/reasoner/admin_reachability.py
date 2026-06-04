"""Admin reachability reasoner â€” per-principal blast-forward analysis.

For each starting principal, compute the SET of admin-equivalent roles
reachable via any chain of `sts:AssumeRole` hops. Emit one finding per
starting principal that reaches at least one admin role, listing ALL
reachable admin endpoints in the evidence.

This is the "blast forward" complement to `assume_role_chain`'s
"chain to specific target" view::

    assume_role_chain     â†’ N findings per principal (one per chain)
    admin_reachability    â†’ 1 finding per principal (set of all reachable admins)

The two reasoners are complementary, not redundant. AssumeRoleChain
answers "what's the chain from Alice to AdminRole?" with full per-hop
SCP/boundary analysis. AdminReachability answers "is Alice effectively
an admin?" with a single yes-or-no plus the set of admin endpoints.

Pentest framing: a reviewer reading the AdminReachability findings
gets an immediate answer to "who in this org is effectively admin?"
without having to mentally aggregate dozens of per-chain findings.
The single-finding-per-principal shape is the right abstraction for
that question.

Verdict shape:
    validated     at least one reachable admin chain has clean witnesses
    inconclusive  admin reachability exists only through a hyperedge
                  or wildcard ambiguity

No blocked verdict â€” SCP analysis is per-chain, and this reasoner is
per-principal. SCP/boundary blocking is the territory of
`assume_role_chain`. AdminReachability is purely about "can this
principal reach admin via any path."

Severity:
    1 reachable admin   â†’ high
    2+ reachable admins â†’ critical (multiple paths to admin is
                          unambiguously bad â€” single SCP can't break
                          the chain because there's no single chain)
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
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


_ASSUMEROLE_ACTION: str = "sts:AssumeRole"
_MAX_DEPTH: int = 4


class AdminReachabilityReasoner:
    """Per-principal blast-forward reachability to admin-equivalent roles."""

    pattern_id: str = "admin_reachability"
    pattern_version: str = "1.0.0"
    pattern_title: str = "Admin Reachability via AssumeRole Chains"
    severity_default: str = "high"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        has_role = any(n.node_type == NODE_TYPE_IAM_ROLE for n in facts.nodes)
        if not has_role:
            return (False, "no IAM roles in graph")
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """For each candidate starting principal, BFS-reach all admins.

        Emits one Finding per principal that reaches at least one
        admin-equivalent role. The finding's target is the first
        reachable admin in lexicographic order (deterministic). The
        full set of reachable admins lives in evidence.node_refs.
        """
        findings: list[Finding] = []

        # Find every IAMUser/IAMRole that has any sts:AssumeRole permission.
        starting_principals: list[Node] = []
        for node in facts.nodes:
            if node.node_type not in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE):
                continue
            state = facts.has_action(node.provider_id, _ASSUMEROLE_ACTION)
            if state is not CheckState.FAIL:
                starting_principals.append(node)

        if not starting_principals:
            return []

        for source in starting_principals:
            finding = self._compute_reachability(facts, source)
            if finding is not None:
                findings.append(finding)

        # Stable sort by source provider_id for deterministic output order.
        findings.sort(key=lambda f: f.source.provider_id)
        return findings

    # ---------------------------------------------------------------
    # BFS reachability walker
    # ---------------------------------------------------------------

    def _compute_reachability(
        self,
        facts: FactGraph,
        source: Node,
    ) -> Finding | None:
        """BFS from source, collecting all reachable admin-equivalent roles.

        Returns a Finding if at least one admin is reached, else None.
        Tracks all visited roles and per-hop edges. Clean versus
        ambiguous reachability is tracked per BFS path so an unrelated
        wildcard branch cannot poison a separate clean admin proof.
        """
        reachable_admins: set[str] = set()  # admin role ARNs
        clean_reachable_admins: set[str] = set()  # reached via non-ambiguous path
        ambiguous_reachable_admins: set[str] = set()  # reached via ambiguous path
        admin_witness_edges: list[Edge] = []  # admin equivalence proof edges
        clean_admin_witness_edges: list[Edge] = []  # admin witnesses for clean proofs
        visited: set[tuple[str, bool]] = {(source.provider_id, True)}
        all_walk_edges: list[Edge] = []  # every permission + trust edge traversed
        clean_proof_walk_edges: list[Edge] = []  # edges from clean admin-reaching path(s)
        all_visited_roles: list[Node] = []  # in BFS order
        any_hyperedge_traversed = False
        walk_hit_depth_limit = False

        # Frontier: (current_arn, depth, path_is_clean, path_edges)
        frontier: deque[tuple[str, int, bool, tuple[Edge, ...]]] = deque()
        frontier.append((source.provider_id, 0, True, ()))

        while frontier:
            current_arn, depth, path_is_clean, path_edges = frontier.popleft()

            # If current is a role and depth >= 1, check admin equivalence.
            if depth >= 1:
                current_node = self._find_node(facts, current_arn)
                if current_node is not None and current_node.node_type == NODE_TYPE_IAM_ROLE:
                    if current_node not in all_visited_roles:
                        all_visited_roles.append(current_node)
                    admin_witness = self._find_admin_witness_edge(
                        facts,
                        current_node,
                    )
                    if admin_witness is not None:
                        reachable_admins.add(current_arn)
                        self._append_unique_edge(admin_witness_edges, admin_witness)
                        if path_is_clean:
                            clean_reachable_admins.add(current_arn)
                            self._append_unique_edge(clean_admin_witness_edges, admin_witness)
                            self._append_unique_edges(clean_proof_walk_edges, path_edges)
                        else:
                            ambiguous_reachable_admins.add(current_arn)

            # Stop walking deeper if depth limit hit.
            if depth >= _MAX_DEPTH:
                walk_hit_depth_limit = True
                continue

            # Walk all sts:AssumeRole permission edges from current.
            for perm_edge in self._assumerole_permission_edges_from(
                facts,
                current_arn,
            ):
                next_arn = perm_edge.dst.provider_id

                trust_edge = self._find_admitting_trust_edge(
                    facts,
                    current_arn=current_arn,
                    next_arn=next_arn,
                )
                if trust_edge is None:
                    continue

                # Track ambiguity: if either edge is a hyperedge witness,
                # the walk has touched ambiguous ground.
                hop_is_clean = True
                if self._is_ambiguous_edge(perm_edge):
                    any_hyperedge_traversed = True
                    hop_is_clean = False
                if self._is_ambiguous_edge(trust_edge):
                    any_hyperedge_traversed = True
                    hop_is_clean = False

                next_path_is_clean = path_is_clean and hop_is_clean
                visited_key = (next_arn, next_path_is_clean)
                if visited_key in visited:
                    continue

                self._append_unique_edge(all_walk_edges, perm_edge)
                self._append_unique_edge(all_walk_edges, trust_edge)
                visited.add(visited_key)
                frontier.append((next_arn, depth + 1, next_path_is_clean, path_edges + (perm_edge, trust_edge)))

        # No reachable admins â†’ no finding
        if not reachable_admins:
            return None

        return self._build_finding(
            facts=facts,
            source=source,
            reachable_admins=sorted(reachable_admins),
            clean_reachable_admins=sorted(clean_reachable_admins),
            ambiguous_reachable_admins=sorted(ambiguous_reachable_admins),
            admin_witness_edges=admin_witness_edges,
            clean_admin_witness_edges=clean_admin_witness_edges,
            all_walk_edges=all_walk_edges,
            clean_proof_walk_edges=clean_proof_walk_edges,
            all_visited_roles=all_visited_roles,
            any_hyperedge_traversed=any_hyperedge_traversed,
            walk_hit_depth_limit=walk_hit_depth_limit,
        )

    # ---------------------------------------------------------------
    # Helpers (delegated to shared modules in 3c-refactor)
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

    def _find_admin_witness_edge(
        self,
        facts: FactGraph,
        target_role: Node,
    ) -> Edge | None:
        from iamscope.reasoner.admin_detection import find_admin_witness_edge

        return find_admin_witness_edge(facts, target_role)

    def _is_ambiguous_edge(self, edge: Edge) -> bool:
        """Does this edge have a hyperedge dst or wildcard resource flag?"""
        from iamscope.reasoner.fact_graph import _is_unknown_witness

        return _is_unknown_witness(edge)

    def _append_unique_edge(self, edges: list[Edge], edge: Edge) -> None:
        """Append edge once, preserving first-seen deterministic order."""
        if edge.edge_id not in {existing.edge_id for existing in edges}:
            edges.append(edge)

    def _append_unique_edges(self, edges: list[Edge], new_edges: tuple[Edge, ...]) -> None:
        """Append each edge once, preserving first-seen deterministic order."""
        for edge in new_edges:
            self._append_unique_edge(edges, edge)

    def _check_boundary_blockers_on_walk(
        self,
        facts: FactGraph,
        walk_edges: list[Edge],
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check permission-boundary bindings on traversed permission edges."""
        boundary_bindings = []
        for edge in walk_edges:
            if not edge.edge_type.endswith("_permission"):
                continue
            for binding in facts.bindings_for_edge(edge.edge_id):
                constraint = facts.constraint_by_id(binding.constraint_id)
                if constraint is None:
                    continue
                if constraint.constraint_type != CONSTRAINT_TYPE_PERMISSION_BOUNDARY:
                    continue
                boundary_bindings.append((edge, binding))

        if not boundary_bindings:
            return (CheckState.PASS, "no permission boundary bindings on reachable walk", [])

        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = f"{len(boundary_bindings)} permission boundary binding(s) are non-blocking"
        for edge, binding in boundary_bindings:
            constraint_refs.add(binding.constraint_id)
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            confidence = binding.governance_confidence
            if binding.likely_blocking and confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="permission_boundary",
                        constraint_id=binding.constraint_id,
                        edge_id=edge.edge_id,
                        reason=binding.binding_reason or "permission boundary blocks reachable admin walk",
                    )
                )
                state = CheckState.FAIL
                reason = f"boundary {binding.constraint_id} blocks reachable admin walk (complete)"
                break
            if confidence in ("partial", "needs_review") and state is CheckState.PASS:
                state = CheckState.UNKNOWN
                reason = f"boundary {binding.constraint_id} ambiguous ({confidence})"

        return state, reason, blockers

    def _check_scp_blockers_on_walk(
        self,
        facts: FactGraph,
        walk_edges: list[Edge],
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check SCP bindings on traversed trust edges.

        Complete likely-blocking SCPs block the walk. Partial or
        needs-review SCP bindings make admin reachability inconclusive:
        IAMScope has evidence of governance control, but not enough proof
        to validate reachability through the path.
        """
        scp_bindings = []
        for edge in walk_edges:
            if not edge.edge_type.endswith("_trust"):
                continue
            for binding in facts.bindings_for_edge(edge.edge_id):
                constraint = facts.constraint_by_id(binding.constraint_id)
                if constraint is None:
                    continue
                if constraint.constraint_type != CONSTRAINT_TYPE_SCP:
                    continue
                scp_bindings.append((edge, binding))

        if not scp_bindings:
            return (CheckState.PASS, "no SCP bindings observed on reachable walk", [])

        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = f"{len(scp_bindings)} SCP binding(s) are non-blocking"
        for edge, binding in scp_bindings:
            constraint_refs.add(binding.constraint_id)
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            confidence = binding.governance_confidence
            if binding.likely_blocking and confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="scp",
                        constraint_id=binding.constraint_id,
                        edge_id=edge.edge_id,
                        reason=binding.binding_reason or "SCP blocks reachable admin walk",
                    )
                )
                state = CheckState.FAIL
                reason = f"SCP {binding.constraint_id} blocks reachable admin walk (complete)"
                break
            if confidence in ("partial", "needs_review") and state is CheckState.PASS:
                state = CheckState.UNKNOWN
                reason = f"SCP {binding.constraint_id} ambiguous ({confidence})"

        return state, reason, blockers

    # ---------------------------------------------------------------
    # Finding construction
    # ---------------------------------------------------------------

    def _build_finding(
        self,
        *,
        facts: FactGraph,
        source: Node,
        reachable_admins: list[str],
        clean_reachable_admins: list[str],
        ambiguous_reachable_admins: list[str],
        admin_witness_edges: list[Edge],
        clean_admin_witness_edges: list[Edge],
        all_walk_edges: list[Edge],
        clean_proof_walk_edges: list[Edge],
        all_visited_roles: list[Node],
        any_hyperedge_traversed: bool,
        walk_hit_depth_limit: bool,
    ) -> Finding:
        """Assemble the per-principal Finding from BFS results."""
        check_results: list[Check] = []
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        edge_refs: list[str] = []
        node_refs: list[str] = [source.node_id]
        trace: list[TraceEntry] = []
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        blockers: list[Blocker] = []

        # Pull statement digests from every walked edge + admin witnesses.
        for edge in all_walk_edges:
            if edge.edge_id not in edge_refs:
                edge_refs.append(edge.edge_id)
            self._absorb_digests(edge, statement_digests, statement_sources)

        for w in admin_witness_edges:
            if w.edge_id not in edge_refs:
                edge_refs.append(w.edge_id)
            self._absorb_digests(w, statement_digests, statement_sources)

        # node_refs: source first, then every visited role in BFS order.
        for n in all_visited_roles:
            if n.node_id not in node_refs:
                node_refs.append(n.node_id)

        admin_count = len(reachable_admins)

        # ---- Check 1: source has sts:AssumeRole permissions
        check_1_state = (
            CheckState.PASS
            if any(
                e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == source.provider_id
                for e in all_walk_edges
            )
            else CheckState.FAIL
        )
        # If walk produced any edges from source, source has the permission.
        # If walk produced zero edges from source but reachable_admins is
        # non-empty (impossible by construction), defensive PASS.
        if check_1_state is CheckState.FAIL and admin_count > 0:
            check_1_state = CheckState.PASS  # defensive
        assumerole_count = sum(
            1
            for e in all_walk_edges
            if e.src.provider_id == source.provider_id and e.edge_type == "sts:AssumeRole_permission"
        )
        # Note: in the current BFS contract, `edge_refs` is guaranteed
        # non-empty whenever we reach this code path â€” `_build_finding`
        # is only called after BFS found â‰¥1 reachable admin, which
        # requires at least one traversed edge, which populates
        # `all_walk_edges` â†’ `edge_refs`. The empty-tuple form below is
        # therefore dead code today, but it's the correct defensive
        # shape if the BFS contract ever changes. A prior revision used
        # `(source.provider_id,)` as the fallback, which was a Rule 4
        # violation (node identifiers are not valid evidence_refs) and
        # would have crashed `Finding._validate_evidence_cross_references`
        # if the branch were ever reached.
        check_results.append(
            Check(
                name="source_has_assumerole_permissions",
                description="Source principal has at least one sts:AssumeRole permission edge",
                state=check_1_state,
                evidence_refs=tuple(edge_refs),
                reason=f"source has {assumerole_count} sts:AssumeRole permission edges",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_source_has_assumerole_permissions",
                inputs=(source.provider_id,),
                result=check_1_state.value.upper(),
                reason="source has assumerole edges in walk",
            )
        )

        # ---- Check 2: reaches at least one admin-equivalent role
        check_2_state = CheckState.PASS if admin_count >= 1 else CheckState.FAIL
        check_results.append(
            Check(
                name="reaches_at_least_one_admin",
                description="BFS walk reaches at least one admin-equivalent role within depth limit",
                state=check_2_state,
                evidence_refs=tuple(w.edge_id for w in admin_witness_edges) or tuple(edge_refs),
                reason=(
                    f"reachable admins: {admin_count} ({', '.join(reachable_admins)})"
                    if admin_count > 0
                    else "no admin-equivalent roles reachable"
                ),
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_reaches_at_least_one_admin",
                inputs=tuple(reachable_admins),
                result=check_2_state.value.upper(),
                reason=f"{admin_count} admin endpoints reachable",
            )
        )

        # ---- Check 3: at least one reachable chain uses clean witnesses
        # Ambiguous alternate branches are still retained in evidence, but
        # do not downgrade a separate clean proof path to an admin endpoint.
        has_clean_admin_path = bool(clean_reachable_admins)
        check_3_state = CheckState.PASS if has_clean_admin_path else CheckState.UNKNOWN
        if has_clean_admin_path and any_hyperedge_traversed:
            check_3_reason = (
                "at least one clean reachable admin path exists; ambiguous alternate walk evidence also observed"
            )
        elif has_clean_admin_path:
            check_3_reason = "all BFS paths use clean witness edges"
        else:
            check_3_reason = "BFS walk traversed at least one wildcard/hyperedge edge"
        check_results.append(
            Check(
                name="at_least_one_reachable_chain_uses_clean_witnesses",
                description=(
                    "At least one BFS path from source to a reachable admin "
                    "traverses only non-wildcard, non-hyperedge edges"
                ),
                state=check_3_state,
                evidence_refs=tuple(edge_refs),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_at_least_one_reachable_chain_uses_clean_witnesses",
                inputs=(
                    (
                        str(any_hyperedge_traversed),
                        str(len(clean_reachable_admins)),
                        str(len(ambiguous_reachable_admins)),
                    )
                    if has_clean_admin_path and any_hyperedge_traversed
                    else (str(any_hyperedge_traversed),)
                ),
                result=check_3_state.value.upper(),
                reason=(
                    "clean path with ambiguous alternate walk"
                    if has_clean_admin_path and any_hyperedge_traversed
                    else ("clean walk" if has_clean_admin_path else "ambiguity in walk")
                ),
            )
        )

        # ---- Check 4: walk terminated within depth limit
        # If the walk hit the depth limit, there may be additional
        # admin endpoints we didn't explore. The check is UNKNOWN in
        # that case (we can't prove the reported set is complete).
        check_4_state = CheckState.UNKNOWN if walk_hit_depth_limit else CheckState.PASS
        check_results.append(
            Check(
                name="walk_terminated_within_depth_limit",
                description=(
                    f"BFS walk terminated naturally within {_MAX_DEPTH} hops (reported admin set is complete)"
                ),
                state=check_4_state,
                evidence_refs=tuple(edge_refs),
                reason=(
                    f"walk hit depth limit ({_MAX_DEPTH} hops); reported admin set may be incomplete"
                    if walk_hit_depth_limit
                    else f"walk terminated naturally within {_MAX_DEPTH} hops"
                ),
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_walk_terminated_within_depth_limit",
                inputs=(str(_MAX_DEPTH),),
                result=check_4_state.value.upper(),
                reason="hit limit" if walk_hit_depth_limit else "terminated naturally",
            )
        )

        # ---- Check 5: no permission boundary blocks reachable walk
        scp_constraint_refs: set[str] = set()
        scp_edge_constraint_refs: set[str] = set()
        blocker_walk_edges = clean_proof_walk_edges if clean_reachable_admins else all_walk_edges
        blocker_admin_witness_edges = clean_admin_witness_edges if clean_reachable_admins else admin_witness_edges
        check_5_state, check_5_reason, check_5_blockers = self._check_scp_blockers_on_walk(
            facts,
            blocker_walk_edges,
            scp_constraint_refs,
            scp_edge_constraint_refs,
        )
        if scp_constraint_refs:
            constraint_refs.update(scp_constraint_refs)
            edge_constraint_refs.update(scp_edge_constraint_refs)
            blockers.extend(check_5_blockers)
            check_results.append(
                Check(
                    name="no_scp_blocks_reachable_walk",
                    description="SCPs do not block traversed AssumeRole trust edges",
                    state=check_5_state,
                    evidence_refs=tuple(sorted(scp_constraint_refs)),
                    reason=check_5_reason,
                )
            )
            trace.append(
                TraceEntry(
                    step=len(trace) + 1,
                    action="check_no_scp_blocks_reachable_walk",
                    inputs=tuple(e.edge_id for e in all_walk_edges if e.edge_type.endswith("_trust")),
                    result=check_5_state.value.upper(),
                    reason=check_5_reason,
                )
            )

        # ---- Check 6: no permission boundary blocks reachable walk
        boundary_constraint_refs: set[str] = set()
        boundary_edge_constraint_refs: set[str] = set()
        check_6_state, check_6_reason, check_6_blockers = self._check_boundary_blockers_on_walk(
            facts,
            blocker_walk_edges + blocker_admin_witness_edges,
            boundary_constraint_refs,
            boundary_edge_constraint_refs,
        )
        if boundary_constraint_refs:
            constraint_refs.update(boundary_constraint_refs)
            edge_constraint_refs.update(boundary_edge_constraint_refs)
            blockers.extend(check_6_blockers)
            check_results.append(
                Check(
                    name="no_permission_boundary_blocks_reachable_walk",
                    description=(
                        "Permission boundaries do not block traversed AssumeRole or admin witness permission edges"
                    ),
                    state=check_6_state,
                    evidence_refs=tuple(sorted(boundary_constraint_refs)),
                    reason=check_6_reason,
                )
            )
            trace.append(
                TraceEntry(
                    step=len(trace) + 1,
                    action="check_no_permission_boundary_blocks_reachable_walk",
                    inputs=tuple(e.edge_id for e in all_walk_edges if e.edge_type.endswith("_permission")),
                    result=check_6_state.value.upper(),
                    reason=check_6_reason,
                )
            )

        # ---- Verdict + severity
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results,
            admin_count=admin_count,
        )
        if verdict is None:
            return None  # type: ignore[return-value]

        # Target: first reachable admin in lexicographic order. The full
        # set lives in node_refs (visited roles include all admins reached).
        primary_admin_arn = reachable_admins[0]
        primary_admin_node = self._find_node(facts, primary_admin_arn)
        if primary_admin_node is None:
            return None  # type: ignore[return-value]

        title = self._compose_title(source, reachable_admins, verdict)

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
            target=primary_admin_node.to_ref(),
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

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
        *,
        admin_count: int,
    ) -> tuple[Verdict | None, str, str]:
        """Apply verdict mapping rules.

        - Check 1 or 2 FAIL â†’ no finding (caller filters)
        - Any UNKNOWN â†’ inconclusive
        - All PASS â†’ validated
        - Severity scales with admin count: 1 admin â†’ high; 2+ â†’ critical
        """
        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        fail_checks = [c.name for c in check_results if c.state is CheckState.FAIL]

        if "no_scp_blocks_reachable_walk" in fail_checks:
            return (
                Verdict.BLOCKED,
                "info",
                "SCP blocks at least one reachable admin path",
            )

        if "no_permission_boundary_blocks_reachable_walk" in fail_checks:
            return (
                Verdict.BLOCKED,
                "info",
                "permission boundary blocks at least one reachable admin path",
            )

        if fail_checks:
            return (None, "info", f"check(s) FAIL: {', '.join(fail_checks)}")

        severity = "critical" if admin_count >= 2 else "high"

        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                severity,
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}; reaches {admin_count} admin(s)",
            )

        return (
            Verdict.VALIDATED,
            severity,
            f"all checks PASS; reaches {admin_count} admin-equivalent role(s)",
        )

    def _compose_title(
        self,
        source: Node,
        reachable_admins: list[str],
        verdict: Verdict,
    ) -> str:
        verdict_label = {
            Verdict.VALIDATED: "Validated",
            Verdict.INCONCLUSIVE: "Inconclusive",
            Verdict.BLOCKED: "Blocked",
        }.get(verdict, "Unknown")
        admin_count = len(reachable_admins)
        plural = "s" if admin_count > 1 else ""
        return f"{verdict_label} admin reachability: {source.provider_id} can reach {admin_count} admin role{plural}"

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
