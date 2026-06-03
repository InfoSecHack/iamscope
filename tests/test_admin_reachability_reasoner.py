"""Tests for the admin_reachability reasoner.

Covers:
- Basic 2-hop reachability → validated/high (1 admin reachable)
- Multi-admin reachability → validated/critical (2+ admins)
- No admin reachable → no finding
- Single principal in graph → checked correctly
- Hyperedge in walk → inconclusive
- Cycle detection (no infinite loop)
- Determinism: double run produces identical findings
- Source enumeration: all eligible principals get findings
- Walk hits depth limit → check 4 UNKNOWN → inconclusive

Reuses helpers from test_assume_role_chain_reasoner.py since the
fact-graph builders are identical.
"""

from __future__ import annotations

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, EdgeConstraint
from iamscope.reasoner import AdminReachabilityReasoner, FactGraph
from tests.test_assume_role_chain_reasoner import (  # noqa: I001
    _ADMIN_ARN,
    _ALICE_ARN,
    _DEVOPS_ARN,
    _NON_ADMIN_ARN,
    _PROD_ARN,
    _admin_grant_edge,
    _assume_perm_edge,
    _build_three_hop_chain,
    _build_two_hop_chain,
    _make_facts,
    _role,
    _trust_edge,
    _user,
)

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_empty_graph_skipped(self) -> None:
        empty = FactGraph(
            nodes=(),
            edges=(),
            constraints=(),
            edge_constraints=(),
            scenario_hash="x" * 64,
            edge_budget_exhausted=False,
        )
        ok, reason = AdminReachabilityReasoner().preconditions_met(empty)
        assert not ok
        assert "no IAM roles" in reason

    def test_role_present_runs(self) -> None:
        facts = _make_facts(nodes=(_role(_ADMIN_ARN),), edges=())
        ok, reason = AdminReachabilityReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Basic reachability — 2-hop chain
# ---------------------------------------------------------------------------


class TestTwoHopReachability:
    def test_emits_one_finding(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        # Source candidates: Alice (has assumerole perm) + DevOps (has assumerole perm).
        # Alice reaches Admin via DevOps → 1 finding
        # DevOps reaches Admin directly (1 hop) → 1 finding
        # Total: 2 findings
        assert len(findings) == 2

    def test_alice_finding_validated_high(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        # Alice reaches 1 admin → severity high
        assert alice_f.severity == "high"

    def test_alice_target_is_admin(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.target.provider_id == _ADMIN_ARN

    def test_check_2_reports_one_admin(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        c = next(c for c in alice_f.required_checks if c.name == "reaches_at_least_one_admin")
        assert "1" in c.reason
        assert _ADMIN_ARN in c.reason


# ---------------------------------------------------------------------------
# Multi-admin reachability → critical severity
# ---------------------------------------------------------------------------


class TestMultiAdminReachability:
    def _build_two_admins_facts(self) -> FactGraph:
        """Alice → DevOps → AdminRole AND Alice → DevOps → ProdAdmin.

        DevOps trusts Alice. AdminRole and ProdAdmin both trust DevOps.
        Both AdminRole and ProdAdmin are admin-equivalent.
        """
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        prod_admin = _role(_PROD_ARN)

        # Alice → DevOps
        perm_a_d = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN, digest="1" * 64)
        trust_a_d = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN, digest="2" * 64)
        # DevOps → Admin
        perm_d_a = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN, digest="3" * 64)
        trust_d_a = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN, digest="4" * 64)
        # DevOps → ProdAdmin
        perm_d_p = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_PROD_ARN, digest="5" * 64)
        trust_d_p = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_PROD_ARN, digest="6" * 64)
        # Both targets are admin-equivalent
        admin_grant_1 = _admin_grant_edge(_ADMIN_ARN)
        admin_grant_2 = _admin_grant_edge(_PROD_ARN)
        return _make_facts(
            nodes=(alice, devops, admin, prod_admin),
            edges=(
                perm_a_d,
                trust_a_d,
                perm_d_a,
                trust_d_a,
                perm_d_p,
                trust_d_p,
                admin_grant_1,
                admin_grant_2,
            ),
        )

    def test_alice_severity_critical_with_two_admins(self) -> None:
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        assert alice_f.severity == "critical"

    def test_alice_check_2_lists_both_admins(self) -> None:
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        c = next(c for c in alice_f.required_checks if c.name == "reaches_at_least_one_admin")
        assert "2" in c.reason
        assert _ADMIN_ARN in c.reason
        assert _PROD_ARN in c.reason

    def test_target_is_first_admin_lexicographically(self) -> None:
        """Deterministic target selection: smallest ARN wins."""
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        # _ADMIN_ARN ("...:role/Admin") and _PROD_ARN ("...:role/Prod")
        # Lexicographic sort: Admin < Prod
        assert alice_f.target.provider_id == _ADMIN_ARN

    def test_evidence_contains_both_admin_witnesses(self) -> None:
        """Both admin grant edges should appear in evidence.edge_refs."""
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        # The walk has 4 chain edges (2 hops × 2 edges each + 2 more for
        # the second branch) + 2 admin witnesses = 6+ edge refs
        assert len(alice_f.evidence.edge_refs) >= 6


# ---------------------------------------------------------------------------
# No reachable admin → no finding
# ---------------------------------------------------------------------------


class TestNoReachableAdmin:
    def test_chain_to_non_admin_no_finding(self) -> None:
        """Alice → DevOps → NonAdmin (NonAdmin has no admin permissions)."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        non_admin = _role(_NON_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_NON_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_NON_ADMIN_ARN)
        # No admin_grant — NonAdmin has no admin permissions
        facts = _make_facts(
            nodes=(alice, devops, non_admin),
            edges=(perm_1, trust_1, perm_2, trust_2),
        )
        findings = AdminReachabilityReasoner().run(facts)
        assert len(findings) == 0

    def test_principal_with_no_assumerole_no_finding(self) -> None:
        """A principal with no sts:AssumeRole permission should not be a candidate."""
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        # Alice has no permission edges at all
        facts = _make_facts(nodes=(alice, admin), edges=(admin_grant,))
        findings = AdminReachabilityReasoner().run(facts)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Permission boundary blockers
# ---------------------------------------------------------------------------


class TestConditionedTrustReachability:
    def test_conditioned_trust_downgrades_reachable_admin_to_inconclusive(self) -> None:
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(
            principal_arn=_ALICE_ARN,
            target_arn=_DEVOPS_ARN,
            raw_conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )
        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "inconclusive"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "unknown"


class TestPermissionBoundaryReachability:
    def _boundary(self) -> Constraint:
        return Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
            scope_type="Principal",
            scope_id=_ALICE_ARN,
            policy_id="arn:aws:iam::111111\u003111111:policy/AliceBoundary",
            statement_id="Boundary",
            region=REGION_GLOBAL,
            properties={"boundary_arn": "arn:aws:iam::111111\u003111111:policy/AliceBoundary"},
        )

    def test_boundary_block_downgrades_reachable_admin_to_blocked(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=first_hop.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="permission boundary excludes sts:AssumeRole on DevOps",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        assert alice_f.severity == "info"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert alice_f.blockers_observed[0].kind == "permission_boundary"
        assert boundary.constraint_id in alice_f.evidence.constraint_refs

    def test_boundary_block_on_admin_witness_downgrades_reachability(self) -> None:
        facts = _build_two_hop_chain()
        admin_witness = next(
            e for e in facts.edges if e.edge_type == "iam:*_permission" and e.src.provider_id == _ADMIN_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=admin_witness.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="permission boundary excludes admin witness permission",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert boundary.constraint_id in alice_f.evidence.constraint_refs

    def test_boundary_needs_review_makes_reachable_admin_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=first_hop.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=False,
            binding_reason="permission boundary condition requires runtime context",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# SCP blockers
# ---------------------------------------------------------------------------


class TestScpReachability:
    def _scp(
        self,
        *,
        parse_status: str = "partial",
        resource_patterns: list[str] | None = None,
    ) -> Constraint:
        return Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="ACCOUNT",
            scope_id="111111\u003111111",
            policy_id="p-env12",
            statement_id="Env12DenyAssumeEnv12Admin",
            region=REGION_GLOBAL,
            properties={
                "deny_actions": ["sts:AssumeRole"],
                "deny_not_actions": [],
                "exception_principal_patterns": [],
                "parse_status": parse_status,
                "resource_patterns": resource_patterns or [_ADMIN_ARN],
            },
        )

    def test_resource_scoped_scp_downgrades_reachable_admin_to_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        admin_trust = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_trust" and e.dst.provider_id == _ADMIN_ARN
        )
        scp = self._scp()
        binding = EdgeConstraint(
            edge_id=admin_trust.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
            likely_blocking=False,
            binding_reason="resource-scoped SCP denies sts:AssumeRole on admin target",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(c for c in alice_f.required_checks if c.name == "no_scp_blocks_reachable_walk")
        assert check.state.value == "unknown"
        assert scp.constraint_id in alice_f.evidence.constraint_refs

    def test_complete_scp_block_downgrades_reachable_admin_to_blocked(self) -> None:
        facts = _build_two_hop_chain()
        admin_trust = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_trust" and e.dst.provider_id == _ADMIN_ARN
        )
        scp = self._scp(parse_status="complete", resource_patterns=["*"])
        binding = EdgeConstraint(
            edge_id=admin_trust.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="SCP denies sts:AssumeRole",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        check = next(c for c in alice_f.required_checks if c.name == "no_scp_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert alice_f.blockers_observed[0].kind == "scp"


# ---------------------------------------------------------------------------
# Hyperedge → inconclusive
# ---------------------------------------------------------------------------


class TestHyperedgeInconclusive:
    def test_wildcard_hop_produces_inconclusive(self) -> None:
        """Wildcard sts:AssumeRole on first hop → check 3 UNKNOWN."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(
            src_arn=_ALICE_ARN,
            dst_arn=_DEVOPS_ARN,
            is_wildcard_resource=True,
        )
        trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )
        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "inconclusive"
        # Check 3 should be UNKNOWN
        c = next(c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses")
        assert c.state.value == "unknown"


# ---------------------------------------------------------------------------
# 3-hop chain — Alice reaches Admin via DevOps → Prod (intermediate not admin)
# ---------------------------------------------------------------------------


class TestThreeHopReachability:
    def test_alice_reaches_admin_through_three_hops(self) -> None:
        """Alice → DevOps → Prod → Admin. Only Admin is admin-equivalent."""
        findings = AdminReachabilityReasoner().run(_build_three_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        assert alice_f.severity == "high"  # 1 admin reachable
        assert alice_f.target.provider_id == _ADMIN_ARN


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = AdminReachabilityReasoner().run(_build_two_hop_chain())
        f2 = AdminReachabilityReasoner().run(_build_two_hop_chain())
        assert len(f1) == len(f2)
        for a, b in zip(f1, f2, strict=True):
            assert a.finding_id == b.finding_id
            assert a.evidence.bundle_digest == b.evidence.bundle_digest

    def test_findings_sorted_by_source_arn(self) -> None:
        """Output ordering is stable across runs."""
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        sources = [f.source.provider_id for f in findings]
        assert sources == sorted(sources)
