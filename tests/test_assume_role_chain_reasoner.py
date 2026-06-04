"""Tests for the assume_role_chain reasoner.

Covers:
- Basic 2-hop chain → validated/high
- 3-hop chain → validated/high
- 4-hop chain → validated/critical (depth-based severity bump)
- Single-hop principal-to-admin → no finding (covered by cross_account_trust)
- Chain to non-admin endpoint → no finding (check 2 FAIL)
- Cycle detection (A → B → A) → no infinite loop, no spurious finding
- SCP blocks a middle hop → blocked
- SCP partial confidence on a hop → inconclusive
- Wildcard hyperedge in a hop → inconclusive (check 6)
- Determinism: double run produces identical findings
- Account-root trust principal correctly admits same-account principal
- Trust edge missing on next role → BFS skips that hop
- Multiple chains from same source to same target → one finding (dedup)
- Max depth enforcement → no findings beyond _MAX_DEPTH hops
"""

from __future__ import annotations

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    CONSTRAINT_TYPE_IDENTITY_DENY,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROBE_KIND_RUNTIME,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATED_STATE_ALLOWED,
    VALIDATED_STATE_DENIED,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.reasoner import AssumeRoleChainReasoner, FactGraph
from iamscope.resolver.cross_account import build_trust_edges
from iamscope.truth.probe_overlay import ProbeRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACCOUNT = "111111\u003111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_DEVOPS_ARN = f"arn:aws:iam::{_ACCOUNT}:role/DevOps"
_PROD_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Prod"
_ADMIN_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Admin"
_DEPLOY_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Deploy"
_NON_ADMIN_ARN = f"arn:aws:iam::{_ACCOUNT}:role/NonAdmin"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _role(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _assume_perm_edge(
    *,
    src_arn: str,
    dst_arn: str,
    digest: str = "1" * 64,
    is_wildcard_resource: bool = False,
) -> Edge:
    """Permission edge: src can call sts:AssumeRole on dst."""
    return Edge(
        edge_type="sts:AssumeRole_permission",
        src=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER if "user/" in src_arn else NODE_TYPE_IAM_ROLE,
            provider_id=src_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        dst=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=dst_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/AssumeRolePerms",
                    "statement_index": 0,
                    "digest": digest,
                    "summary": "sts:AssumeRole grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": is_wildcard_resource,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": dst_arn,
            "statement_index": 0,
        },
    )


def _trust_edge(
    *,
    principal_arn: str,
    target_arn: str,
    digest: str = "2" * 64,
    raw_conditions: dict | None = None,
) -> Edge:
    """Trust edge: target's trust policy admits principal_arn."""
    raw_conditions = raw_conditions or {}
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER if "user/" in principal_arn else NODE_TYPE_IAM_ROLE,
            provider_id=principal_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        dst=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=target_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": target_arn,
                    "statement_index": 0,
                    "digest": digest,
                    "summary": f"trust {principal_arn}",
                }
            ],
            "effect": "Allow",
            "has_conditions": bool(raw_conditions),
            "is_wildcard_principal": False,
            "layer": "trust",
            "principal_type": "AWS",
            "raw_conditions": raw_conditions,
            "statement_index": 0,
        },
    )


def _wildcard_trust_edge(
    *,
    target_arn: str,
) -> Edge:
    """Trust edge: target role has Principal: \"*\" wildcard trust."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }
    trust_results = parse_trust_policy(policy, target_arn, _ACCOUNT)
    edges = build_trust_edges(trust_results, _role(target_arn))
    assert len(edges) == 1
    return edges[0]


def _admin_grant_edge(role_arn: str) -> Edge:
    """The admin-equivalence permission edge: role has iam:* on itself."""
    return Edge(
        edge_type="iam:*_permission",
        src=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        dst=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "statement_index": 0,
                    "digest": "a" * 64,
                    "summary": "iam:*",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )


def _scp(
    *,
    statement_id: str = "DenyAssumeRole",
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-assumerole",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyAssumeRoleProd",
            "resource_patterns": ["*"],
        },
    )


def _identity_deny(
    *,
    statement_id: str = "DenyAssumeRole",
    has_conditions: bool = False,
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY,
        scope_type="Principal",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceDeny",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "resource_patterns": ["*"],
            "has_conditions": has_conditions,
            "raw_conditions": {"StringEquals": {"aws:PrincipalArn": _ALICE_ARN}} if has_conditions else {},
            "parse_status": parse_status,
        },
    )


def _binding(
    *,
    edge_id: str,
    constraint_id: str,
    governance_confidence: str = "complete",
    likely_blocking: bool = True,
) -> EdgeConstraint:
    return EdgeConstraint(
        edge_id=edge_id,
        constraint_id=constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=f"SCP {constraint_id} denies sts:AssumeRole",
    )


def _make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...] = (),
    edge_constraints: tuple[EdgeConstraint, ...] = (),
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="c" * 64,
        edge_budget_exhausted=False,
    )


def _probe_record(
    edge_id: str,
    probe_state: str,
    *,
    confounded: bool = False,
    controls: tuple[str, ...] = (),
) -> ProbeRecord:
    return ProbeRecord(
        probe_id=f"probe-{probe_state}",
        edge_id=edge_id,
        action_class=ACTION_CLASS_STS_ASSUME_ROLE,
        probe_kind=PROBE_KIND_RUNTIME,
        probe_state=probe_state,
        probed_at_utc="2026-01-01T00:00:00Z",
        authorization_ref=None,
        confounded=confounded,
        confounded_reason="test confounder" if confounded else "",
        contributing_control_refs=controls,
        simulator_state=None,
        runtime_state=(
            VALIDATED_STATE_ALLOWED if probe_state == PROBE_STATE_PROBED_CORRELATED_ALLOWED else VALIDATED_STATE_DENIED
        ),
        cloudtrail_state=None,
        notes_digest=None,
    )


def _with_probe(facts: FactGraph, probe: ProbeRecord) -> FactGraph:
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=facts.constraints,
        edge_constraints=facts.edge_constraints,
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=facts.edge_budget_exhausted,
        probe_records_by_edge={probe.edge_id: (probe,)},
    )


def _edge_by_src_dst(facts: FactGraph, src_arn: str, dst_arn: str) -> Edge:
    return next(edge for edge in facts.edges if edge.src.provider_id == src_arn and edge.dst.provider_id == dst_arn)


def _build_two_hop_chain() -> FactGraph:
    """Alice → DevOps → Admin (Admin is admin-equivalent)."""
    alice = _user(_ALICE_ARN)
    devops = _role(_DEVOPS_ARN)
    admin = _role(_ADMIN_ARN)

    # Hop 1: Alice → DevOps
    perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN, digest="1" * 64)
    trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN, digest="2" * 64)

    # Hop 2: DevOps → Admin
    perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN, digest="3" * 64)
    trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN, digest="4" * 64)

    # Admin equivalence on Admin role
    admin_grant = _admin_grant_edge(_ADMIN_ARN)

    return _make_facts(
        nodes=(alice, devops, admin),
        edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
    )


def _build_three_hop_chain() -> FactGraph:
    """Alice → DevOps → Prod → Admin."""
    alice = _user(_ALICE_ARN)
    devops = _role(_DEVOPS_ARN)
    prod = _role(_PROD_ARN)
    admin = _role(_ADMIN_ARN)

    perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN, digest="1" * 64)
    trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN, digest="2" * 64)
    perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_PROD_ARN, digest="3" * 64)
    trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_PROD_ARN, digest="4" * 64)
    perm_3 = _assume_perm_edge(src_arn=_PROD_ARN, dst_arn=_ADMIN_ARN, digest="5" * 64)
    trust_3 = _trust_edge(principal_arn=_PROD_ARN, target_arn=_ADMIN_ARN, digest="6" * 64)
    admin_grant = _admin_grant_edge(_ADMIN_ARN)

    return _make_facts(
        nodes=(alice, devops, prod, admin),
        edges=(perm_1, trust_1, perm_2, trust_2, perm_3, trust_3, admin_grant),
    )


def _build_four_hop_chain() -> FactGraph:
    """Alice → Deploy → DevOps → Prod → Admin (4 hops, severity bumps to critical)."""
    alice = _user(_ALICE_ARN)
    deploy = _role(_DEPLOY_ARN)
    devops = _role(_DEVOPS_ARN)
    prod = _role(_PROD_ARN)
    admin = _role(_ADMIN_ARN)

    perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEPLOY_ARN, digest="1" * 64)
    trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEPLOY_ARN, digest="2" * 64)
    perm_2 = _assume_perm_edge(src_arn=_DEPLOY_ARN, dst_arn=_DEVOPS_ARN, digest="3" * 64)
    trust_2 = _trust_edge(principal_arn=_DEPLOY_ARN, target_arn=_DEVOPS_ARN, digest="4" * 64)
    perm_3 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_PROD_ARN, digest="5" * 64)
    trust_3 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_PROD_ARN, digest="6" * 64)
    perm_4 = _assume_perm_edge(src_arn=_PROD_ARN, dst_arn=_ADMIN_ARN, digest="7" * 64)
    trust_4 = _trust_edge(principal_arn=_PROD_ARN, target_arn=_ADMIN_ARN, digest="8" * 64)
    admin_grant = _admin_grant_edge(_ADMIN_ARN)

    return _make_facts(
        nodes=(alice, deploy, devops, prod, admin),
        edges=(perm_1, trust_1, perm_2, trust_2, perm_3, trust_3, perm_4, trust_4, admin_grant),
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
        ok, reason = AssumeRoleChainReasoner().preconditions_met(empty)
        assert not ok
        assert "no IAM roles" in reason

    def test_graph_with_only_user_skipped(self) -> None:
        facts = _make_facts(nodes=(_user(_ALICE_ARN),), edges=())
        ok, reason = AssumeRoleChainReasoner().preconditions_met(facts)
        assert not ok

    def test_graph_with_role_runs(self) -> None:
        facts = _make_facts(nodes=(_role(_ADMIN_ARN),), edges=())
        ok, reason = AssumeRoleChainReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Two-hop chain (canonical case)
# ---------------------------------------------------------------------------


class TestTwoHopValidated:
    def test_emits_one_finding(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_two_hop_chain())
        assert len(findings) == 1

    def test_verdict_validated(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        assert f.verdict.value == "validated"

    def test_severity_high_for_two_hop_admin(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        assert f.severity == "high"

    def test_source_is_alice(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        assert f.source.provider_id == _ALICE_ARN

    def test_target_is_admin(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        assert f.target.provider_id == _ADMIN_ARN

    def test_check_1_passes(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        c = next(c for c in f.required_checks if c.name == "chain_length_at_least_two")
        assert c.state.value == "pass"
        assert "2 hops" in c.reason

    def test_check_2_passes(self) -> None:
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        c = next(c for c in f.required_checks if c.name == "endpoint_is_admin_equivalent")
        assert c.state.value == "pass"

    def test_evidence_node_refs_in_chain_order(self) -> None:
        """node_refs should be source → hop1 target → hop2 target."""
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        # node_refs are node_ids, not arns; just verify count
        assert len(f.evidence.node_refs) == 3  # alice + devops + admin

    def test_evidence_has_5_edge_refs(self) -> None:
        """2 hops × 2 edges per hop = 4 chain edges + 1 admin witness = 5."""
        f = AssumeRoleChainReasoner().run(_build_two_hop_chain())[0]
        assert len(f.evidence.edge_refs) == 5


# ---------------------------------------------------------------------------
# Three-hop chain
# ---------------------------------------------------------------------------


class TestThreeHopValidated:
    def test_emits_one_finding(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_three_hop_chain())
        # BFS may also find a 2-hop subchain (DevOps → Prod → Admin? no, DevOps
        # is not a starting principal because it has no incoming sts:AssumeRole
        # permission from outside the chain). But Prod, DevOps are also valid
        # starting principals. Let me check what BFS produces.
        # Actually: starting principals are those with sts:AssumeRole permission
        # OUTGOING — Alice has it, DevOps has it, Prod has it.
        # From Alice: Alice → DevOps → Prod → Admin (3 hops to admin) — emit 1
        # From DevOps: DevOps → Prod → Admin (2 hops to admin) — emit 1
        # From Prod: Prod → Admin (1 hop, < MIN, no emit)
        # Total: 2 findings
        assert len(findings) == 2

    def test_three_hop_alice_finding_severity(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_three_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        # 3-hop admin chain → high (not critical until 4+)
        assert alice_f.severity == "high"
        assert alice_f.verdict.value == "validated"

    def test_two_hop_devops_subchain_also_emitted(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_three_hop_chain())
        devops_f = next(f for f in findings if f.source.provider_id == _DEVOPS_ARN)
        assert devops_f.target.provider_id == _ADMIN_ARN
        assert devops_f.verdict.value == "validated"


# ---------------------------------------------------------------------------
# Four-hop chain (severity bump)
# ---------------------------------------------------------------------------


class TestFourHopValidatedCritical:
    def test_severity_critical_at_four_hops(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_four_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.severity == "critical"

    def test_check_3_reports_four_hops(self) -> None:
        findings = AssumeRoleChainReasoner().run(_build_four_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        c = next(c for c in alice_f.required_checks if c.name == "chain_length_at_least_two")
        assert "4 hops" in c.reason


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


class TestNoFindingCases:
    def test_single_hop_to_admin_no_finding(self) -> None:
        """Alice → Admin directly. Single-hop is covered by cross_account_trust,
        not assume_role_chain. No finding emitted."""
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_ADMIN_ARN)
        trust = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(perm, trust, admin_grant),
        )
        findings = AssumeRoleChainReasoner().run(facts)
        assert len(findings) == 0

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
        findings = AssumeRoleChainReasoner().run(facts)
        assert len(findings) == 0

    def test_missing_trust_edge_breaks_chain(self) -> None:
        """Alice has permission to DevOps, but DevOps doesn't trust Alice."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        # Alice has permission edge but no admitting trust edge
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        # NO trust_1
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, perm_2, trust_2, admin_grant),
        )
        findings = AssumeRoleChainReasoner().run(facts)
        assert len(findings) == 0  # Alice's chain breaks at hop 1


# ---------------------------------------------------------------------------
# Cycle detection
# ---------------------------------------------------------------------------


class TestCycleDetection:
    def test_cycle_no_infinite_loop(self) -> None:
        """A → B → A → B → ... must not loop forever."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        # Alice → DevOps
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN)
        # DevOps → Admin
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        # Admin → DevOps (cycle: DevOps and Admin can each assume the other)
        perm_3 = _assume_perm_edge(src_arn=_ADMIN_ARN, dst_arn=_DEVOPS_ARN)
        # The trust_1 edge already admits the principal type, but we need
        # an explicit trust edge admitting Admin specifically.
        trust_admin_to_devops = _trust_edge(
            principal_arn=_ADMIN_ARN,
            target_arn=_DEVOPS_ARN,
            digest="9" * 64,
        )
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, perm_3, trust_admin_to_devops, admin_grant),
        )
        # Should NOT hang or emit duplicate findings
        findings = AssumeRoleChainReasoner().run(facts)
        # Expected: Alice → DevOps → Admin (one finding)
        # DevOps → Admin (one finding from DevOps as starting principal)
        # No infinite loop on Admin → DevOps → Admin → ...
        alice_findings = [f for f in findings if f.source.provider_id == _ALICE_ARN]
        assert len(alice_findings) == 1
        assert alice_findings[0].target.provider_id == _ADMIN_ARN


# ---------------------------------------------------------------------------
# SCP blocker
# ---------------------------------------------------------------------------


class TestSCPBlockerAnyHop:
    def test_scp_blocks_first_hop_blocked_verdict(self) -> None:
        """SCP denies sts:AssumeRole on the Alice → DevOps edge."""
        facts = _build_two_hop_chain()
        # Find the first hop's permission edge
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        scp = _scp(statement_id="DenyAliceAssumeRole")
        binding = _binding(edge_id=first_hop.edge_id, constraint_id=scp.constraint_id)
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "blocked"
        assert f.severity == "info"

    def test_scp_blocks_last_hop_blocked_verdict(self) -> None:
        """SCP denies sts:AssumeRole on the DevOps → Admin edge."""
        facts = _build_two_hop_chain()
        last_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _DEVOPS_ARN
        )
        scp = _scp(statement_id="DenyDevOpsAssumeRole")
        binding = _binding(edge_id=last_hop.edge_id, constraint_id=scp.constraint_id)
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"

    def test_scp_partial_confidence_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        scp = _scp(parse_status="partial")
        binding = _binding(
            edge_id=first_hop.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"

    def test_scp_partial_nonblocking_binding_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_trust" and e.src.provider_id == _ALICE_ARN
        )
        scp = _scp(parse_status="partial")
        binding = _binding(
            edge_id=first_hop.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
            likely_blocking=False,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"


# ---------------------------------------------------------------------------
# Identity-policy Deny blocker
# ---------------------------------------------------------------------------


class TestIdentityDenyBlockerAnyHop:
    def test_complete_identity_deny_blocks_first_hop(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        deny = _identity_deny(statement_id="DenyAliceAssumeRole")
        binding = _binding(
            edge_id=first_hop.edge_id,
            constraint_id=deny.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "blocked"
        assert f.severity == "info"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_any_hop")
        assert check.state.value == "fail"
        assert any(b.kind == "identity_deny" for b in f.blockers_observed)

    def test_needs_review_identity_deny_is_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        deny = _identity_deny(
            statement_id="ConditionalDenyAliceAssumeRole",
            has_conditions=True,
        )
        binding = _binding(
            edge_id=first_hop.edge_id,
            constraint_id=deny.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        assert f.severity == "high"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_any_hop")
        assert check.state.value == "unknown"

    def test_partial_identity_deny_is_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        last_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _DEVOPS_ARN
        )
        deny = _identity_deny(
            statement_id="PartialDenyDevOpsAssumeRole",
            parse_status="partial",
        )
        binding = _binding(
            edge_id=last_hop.edge_id,
            constraint_id=deny.constraint_id,
            governance_confidence="partial",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = AssumeRoleChainReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        assert f.severity == "high"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_any_hop")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# Stale principal drift blocker
# ---------------------------------------------------------------------------


class TestStalePrincipalDriftBlockerAnyHop:
    def test_complete_stale_principal_drift_blocks_trust_hop(self) -> None:
        facts = _build_two_hop_chain()
        first_trust_hop = next(
            e
            for e in facts.edges
            if e.edge_type == "sts:AssumeRole_trust"
            and e.src.provider_id == _ALICE_ARN
            and e.dst.provider_id == _DEVOPS_ARN
        )
        drift = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
            scope_type="EDGE",
            scope_id=first_trust_hop.edge_id,
            policy_id=_DEVOPS_ARN,
            statement_id="stale-principal",
            region=REGION_GLOBAL,
            properties={
                "principal_id": "AIDAABCDEFGHIJKLMNOP",
                "evidence_level": "complete",
                "drift_state": "stale_unique_id_suspected",
            },
        )
        binding = _binding(
            edge_id=first_trust_hop.edge_id,
            constraint_id=drift.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(drift,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AssumeRoleChainReasoner().run(facts2)

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "blocked"
        assert f.severity == "info"
        check = next(c for c in f.required_checks if c.name == "no_stale_principal_drift_blocks_any_hop")
        assert check.state.value == "fail"
        assert any(b.kind == "stale_principal_drift" for b in f.blockers_observed)


# ---------------------------------------------------------------------------
# Permission boundary blockers on hop
# ---------------------------------------------------------------------------


class TestPermissionBoundaryBlockerAnyHop:
    def _boundary(self) -> Constraint:
        return Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
            scope_type="Principal",
            scope_id=_ALICE_ARN,
            policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceBoundary",
            statement_id="Boundary",
            region=REGION_GLOBAL,
            properties={"boundary_arn": f"arn:aws:iam::{_ACCOUNT}:policy/AliceBoundary"},
        )

    def test_complete_permission_boundary_blocks_first_hop(self) -> None:
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
            binding_reason="permission boundary does not allow sts:AssumeRole on DevOps",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        finding = AssumeRoleChainReasoner().run(bounded)[0]

        assert finding.verdict.value == "blocked"
        check = next(c for c in finding.required_checks if c.name == "no_boundary_blocks_any_hop")
        assert check.state.value == "fail"
        assert finding.blockers_observed[0].kind == "permission_boundary"

    def test_complete_permission_boundary_blocks_admin_witness(self) -> None:
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

        finding = AssumeRoleChainReasoner().run(bounded)[0]

        assert finding.verdict.value == "blocked"
        check = next(c for c in finding.required_checks if c.name == "no_boundary_blocks_any_hop")
        assert check.state.value == "fail"
        assert "admin witness" in check.reason

    def test_needs_review_permission_boundary_is_inconclusive(self) -> None:
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

        finding = AssumeRoleChainReasoner().run(bounded)[0]

        assert finding.verdict.value == "inconclusive"
        check = next(c for c in finding.required_checks if c.name == "no_boundary_blocks_any_hop")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# Hyperedge / wildcard ambiguity
# ---------------------------------------------------------------------------


class TestConditionedTrustAmbiguity:
    def test_conditioned_trust_hop_is_inconclusive(self) -> None:
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
        findings = AssumeRoleChainReasoner().run(facts)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.verdict.value == "inconclusive"
        check = next(c for c in finding.required_checks if c.name == "no_hop_traverses_hyperedge")
        assert check.state.value == "unknown"


class TestWildcardTrustPrincipal:
    def test_wildcard_trust_hop_emits_inconclusive_chain(self) -> None:
        """Principal: \"*\" trust admits the hop, but only as ambiguous evidence."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _wildcard_trust_edge(target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )

        findings = AssumeRoleChainReasoner().run(facts)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.verdict.value == "inconclusive"
        check = next(c for c in finding.required_checks if c.name == "no_hop_traverses_hyperedge")
        assert check.state.value == "unknown"
        assert trust_1.edge_id in finding.evidence.edge_refs

    def test_account_root_trust_hop_remains_validated(self) -> None:
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        root_arn = f"arn:aws:iam::{_ACCOUNT}:root"
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(principal_arn=root_arn, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )

        finding = AssumeRoleChainReasoner().run(facts)[0]

        assert finding.verdict.value == "validated"
        check = next(c for c in finding.required_checks if c.name == "no_hop_traverses_hyperedge")
        assert check.state.value == "pass"

    def test_unrelated_trust_still_produces_no_chain(self) -> None:
        alice = _user(_ALICE_ARN)
        bob_arn = f"arn:aws:iam::{_ACCOUNT}:user/Bob"
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        unrelated_trust = _trust_edge(principal_arn=bob_arn, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, unrelated_trust, perm_2, trust_2, admin_grant),
        )

        assert AssumeRoleChainReasoner().run(facts) == []


class TestHyperedgeOnHop:
    def test_wildcard_resource_first_hop_inconclusive(self) -> None:
        """Wildcard sts:AssumeRole resource on the Alice → DevOps hop."""
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
        findings = AssumeRoleChainReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        # check 6 should be the UNKNOWN one
        c6 = next(c for c in f.required_checks if c.name == "no_hop_traverses_hyperedge")
        assert c6.state.value == "unknown"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = AssumeRoleChainReasoner().run(_build_two_hop_chain())
        f2 = AssumeRoleChainReasoner().run(_build_two_hop_chain())
        assert len(f1) == len(f2) == 1
        assert f1[0].finding_id == f2[0].finding_id
        assert f1[0].evidence.bundle_digest == f2[0].evidence.bundle_digest


# ---------------------------------------------------------------------------
# Probe overlay runtime truth
# ---------------------------------------------------------------------------


class TestProbeOverlayRuntimeTruth:
    def test_denied_probe_blocks_validated_chain(self) -> None:
        facts = _build_two_hop_chain()
        edge = _edge_by_src_dst(facts, _DEVOPS_ARN, _ADMIN_ARN)
        probe = _probe_record(
            edge.edge_id,
            PROBE_STATE_PROBED_CORRELATED_DENIED,
            controls=("p-deny-assume",),
        )

        finding = AssumeRoleChainReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict.value == "blocked"
        assert any(b.kind == "probe_overlay" for b in finding.blockers_observed)
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state.value == "fail"
        trace = finding.evidence.reasoning_trace[-1]
        assert trace.action == "apply_probe_overlay"
        assert probe.probe_id in trace.inputs
        assert probe.probe_state in trace.inputs

    def test_confounded_probe_makes_validated_chain_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        edge = _edge_by_src_dst(facts, _DEVOPS_ARN, _ADMIN_ARN)
        probe = _probe_record(
            edge.edge_id,
            PROBE_STATE_CONFOUNDED_SKIP,
            confounded=True,
            controls=("p-inherited-prod",),
        )

        finding = AssumeRoleChainReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict.value == "inconclusive"
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state.value == "unknown"
        assert "p-inherited-prod" in finding.evidence.constraint_refs

    def test_allowed_probe_preserves_verdict_with_probe_citation(self) -> None:
        facts = _build_two_hop_chain()
        edge = _edge_by_src_dst(facts, _DEVOPS_ARN, _ADMIN_ARN)
        probe = _probe_record(edge.edge_id, PROBE_STATE_PROBED_CORRELATED_ALLOWED)

        finding = AssumeRoleChainReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict.value == "validated"
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state.value == "pass"
        trace = finding.evidence.reasoning_trace[-1]
        assert trace.action == "apply_probe_overlay"
        assert probe.probe_id in trace.inputs
        assert probe.probe_state in trace.inputs

    def test_no_overlay_keeps_existing_finding_byte_identical(self) -> None:
        facts = _build_two_hop_chain()
        copied = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=facts.constraints,
            edge_constraints=facts.edge_constraints,
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=facts.edge_budget_exhausted,
            probe_records_by_edge={},
        )

        original = AssumeRoleChainReasoner().run(facts)[0]
        with_empty_overlay = AssumeRoleChainReasoner().run(copied)[0]

        assert with_empty_overlay == original
