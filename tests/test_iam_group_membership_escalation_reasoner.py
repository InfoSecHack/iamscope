"""Tests for the iam_group_membership_escalation reasoner.

Covers:
- Preconditions: empty graph, no users, no groups, users+groups
- Validated: user can add to admin group → validated/critical
- Non-admin target filtered: no finding when target group isn't admin
- Wildcard resource inconclusive: witness edge has is_wildcard_resource
- Hyperedge witness: UNKNOWN witness, iterates all groups
- SCP blocks complete confidence → blocked/info
- SCP partial confidence → inconclusive/high
- Permission boundary blocks → blocked/info
- Multiple users + one admin group → one finding per user
- Multiple groups, only some admin → findings only for admin ones
- Determinism: double run produces identical findings
- Source filter: role sources not enumerated (v1 only enumerates users)
"""

from __future__ import annotations

from iamscope.constants import (
    CONSTRAINT_TYPE_IDENTITY_DENY,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_GROUP,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner import FactGraph, IAMGroupMembershipEscalationReasoner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACCOUNT = "111111111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_BOB_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Bob"
_ADMIN_GROUP_ARN = f"arn:aws:iam::{_ACCOUNT}:group/Admins"
_READONLY_GROUP_ARN = f"arn:aws:iam::{_ACCOUNT}:group/ReadOnly"
_HYPEREDGE_ARN = "__hyperedge__:wildcard_permission:" + _ACCOUNT

# ---------------------------------------------------------------------------
# Fixture builders
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


def _group(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_GROUP,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _add_user_to_group_edge(
    *,
    src: Node,
    group_arn: str,
    digest: str = "1" * 64,
    is_wildcard_resource: bool = False,
    dst_is_hyperedge: bool = False,
) -> Edge:
    """User has iam:AddUserToGroup permission targeting a group."""
    if dst_is_hyperedge:
        dst_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_HYPEREDGE,
            provider_id=_HYPEREDGE_ARN,
            properties={},
        )
    else:
        dst_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_GROUP,
            provider_id=group_arn,
            properties={"account_id": _ACCOUNT},
        )
    return Edge(
        edge_type="iam:AddUserToGroup_permission",
        src=src.to_ref(),
        dst=dst_node.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/GroupMgmt",
                    "statement_index": 0,
                    "digest": digest,
                    "summary": "iam:AddUserToGroup grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": is_wildcard_resource,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": ("*" if is_wildcard_resource else group_arn),
            "statement_index": 0,
        },
    )


def _admin_grant_edge_for_group(group_arn: str) -> Edge:
    """iam:*_permission self-edge on a group proving it's admin-equivalent."""
    group_ref = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_GROUP,
        provider_id=group_arn,
        properties={"account_id": _ACCOUNT},
    ).to_ref()
    return Edge(
        edge_type="iam:*_permission",
        src=group_ref,
        dst=group_ref,
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
    statement_id: str = "DenyAddUserToGroup",
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-addusertogroup",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["iam:AddUserToGroup"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyAddUserToGroup",
            "resource_patterns": ["*"],
        },
    )


def _boundary() -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        scope_type="USER",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceBoundary",
        statement_id="BoundaryNoGroupMgmt",
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["s3:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
        },
    )


def _identity_deny(
    *,
    statement_id: str = "DenyAddUserToGroup",
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
            "deny_actions": ["iam:AddUserToGroup"],
            "resource_patterns": ["*"],
            "has_conditions": has_conditions,
            "raw_conditions": {"StringEquals": {"aws:username": "Alice"}} if has_conditions else {},
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
        binding_reason=f"constraint {constraint_id} affects AddUserToGroup",
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
        scenario_hash="s" * 64,
        edge_budget_exhausted=False,
    )


def _build_alice_to_admin_group() -> FactGraph:
    """Alice has iam:AddUserToGroup on admin group. Admin group has iam:*."""
    alice = _user(_ALICE_ARN)
    admin_group = _group(_ADMIN_GROUP_ARN)
    aug_edge = _add_user_to_group_edge(src=alice, group_arn=_ADMIN_GROUP_ARN)
    admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
    return _make_facts(
        nodes=(alice, admin_group),
        edges=(aug_edge, admin_grant),
    )


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_empty_graph_skipped(self) -> None:
        facts = FactGraph(
            nodes=(),
            edges=(),
            constraints=(),
            edge_constraints=(),
            scenario_hash="x" * 64,
            edge_budget_exhausted=False,
        )
        ok, reason = IAMGroupMembershipEscalationReasoner().preconditions_met(facts)
        assert not ok
        assert "IAMUser" in reason

    def test_users_only_skipped(self) -> None:
        facts = _make_facts(nodes=(_user(_ALICE_ARN),), edges=())
        ok, reason = IAMGroupMembershipEscalationReasoner().preconditions_met(facts)
        assert not ok
        assert "IAMGroup" in reason

    def test_groups_only_skipped(self) -> None:
        facts = _make_facts(nodes=(_group(_ADMIN_GROUP_ARN),), edges=())
        ok, reason = IAMGroupMembershipEscalationReasoner().preconditions_met(facts)
        assert not ok
        assert "IAMUser" in reason

    def test_users_and_groups_runs(self) -> None:
        facts = _make_facts(
            nodes=(_user(_ALICE_ARN), _group(_ADMIN_GROUP_ARN)),
            edges=(),
        )
        ok, _ = IAMGroupMembershipEscalationReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Validated: user → admin group
# ---------------------------------------------------------------------------


class TestValidatedFindings:
    def test_alice_to_admin_group_validated_critical(self) -> None:
        findings = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "validated"
        assert f.severity == "critical"

    def test_source_is_user(self) -> None:
        findings = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())
        assert findings[0].source.provider_id == _ALICE_ARN

    def test_target_is_group(self) -> None:
        findings = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())
        assert findings[0].target.provider_id == _ADMIN_GROUP_ARN

    def test_check_1_passes(self) -> None:
        f = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())[0]
        c = next(c for c in f.required_checks if c.name == "source_has_add_user_to_group_permission")
        assert c.state.value == "pass"

    def test_check_5_admin_equivalence_passes(self) -> None:
        f = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())[0]
        c = next(c for c in f.required_checks if c.name == "target_group_is_admin_equivalent")
        assert c.state.value == "pass"

    def test_title_mentions_escalation(self) -> None:
        f = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())[0]
        assert "escalation" in f.title.lower()
        assert "admin-equivalent" in f.title.lower()


# ---------------------------------------------------------------------------
# Non-admin target filtered
# ---------------------------------------------------------------------------


class TestNonAdminTargetFiltered:
    def test_readonly_group_no_finding(self) -> None:
        """Alice can add to a ReadOnly group → not escalation → no finding."""
        alice = _user(_ALICE_ARN)
        readonly = _group(_READONLY_GROUP_ARN)
        aug_edge = _add_user_to_group_edge(
            src=alice,
            group_arn=_READONLY_GROUP_ARN,
        )
        # No admin_grant edge on readonly group
        facts = _make_facts(nodes=(alice, readonly), edges=(aug_edge,))
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        assert len(findings) == 0

    def test_mixed_admin_and_nonadmin_only_admin_finding(self) -> None:
        """Alice can add to both admin and readonly groups → 1 finding (admin only)."""
        alice = _user(_ALICE_ARN)
        admin = _group(_ADMIN_GROUP_ARN)
        readonly = _group(_READONLY_GROUP_ARN)
        admin_aug = _add_user_to_group_edge(
            src=alice,
            group_arn=_ADMIN_GROUP_ARN,
            digest="1" * 64,
        )
        readonly_aug = _add_user_to_group_edge(
            src=alice,
            group_arn=_READONLY_GROUP_ARN,
            digest="2" * 64,
        )
        admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
        facts = _make_facts(
            nodes=(alice, admin, readonly),
            edges=(admin_aug, readonly_aug, admin_grant),
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].target.provider_id == _ADMIN_GROUP_ARN


# ---------------------------------------------------------------------------
# Inconclusive: wildcard resource + hyperedge witness
# ---------------------------------------------------------------------------


class TestWildcardInconclusive:
    def test_wildcard_resource_inconclusive_high(self) -> None:
        """Wildcard resource on the AddUserToGroup edge → inconclusive/high."""
        alice = _user(_ALICE_ARN)
        admin = _group(_ADMIN_GROUP_ARN)
        # Wildcard resource means edge dst is still the admin group but
        # the features.is_wildcard_resource flag is True → UNKNOWN
        # witness via _is_unknown_witness.
        aug_edge = _add_user_to_group_edge(
            src=alice,
            group_arn=_ADMIN_GROUP_ARN,
            is_wildcard_resource=True,
        )
        admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(aug_edge, admin_grant),
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"

    def test_hyperedge_witness_iterates_all_groups(self) -> None:
        """Hyperedge witness → iterate all groups, admin-only fires."""
        alice = _user(_ALICE_ARN)
        admin = _group(_ADMIN_GROUP_ARN)
        readonly = _group(_READONLY_GROUP_ARN)
        aug_edge = _add_user_to_group_edge(
            src=alice,
            group_arn="ignored-hyperedge-dst",
            dst_is_hyperedge=True,
        )
        admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
        facts = _make_facts(
            nodes=(alice, admin, readonly),
            edges=(aug_edge, admin_grant),
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        # Only admin group produces a finding (readonly isn't admin).
        assert len(findings) == 1
        assert findings[0].target.provider_id == _ADMIN_GROUP_ARN
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# Blockers: SCP + boundary
# ---------------------------------------------------------------------------


class TestSCPBlockers:
    def test_scp_complete_blocks(self) -> None:
        facts = _build_alice_to_admin_group()
        aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
        scp = _scp()
        binding = _binding(
            edge_id=aug_edge.edge_id,
            constraint_id=scp.constraint_id,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"
        assert findings[0].severity == "info"

    def test_scp_partial_inconclusive(self) -> None:
        facts = _build_alice_to_admin_group()
        aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
        scp = _scp(parse_status="partial")
        binding = _binding(
            edge_id=aug_edge.edge_id,
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
        findings = IAMGroupMembershipEscalationReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"


class TestBoundaryBlockers:
    def test_boundary_blocks(self) -> None:
        facts = _build_alice_to_admin_group()
        aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
        boundary = _boundary()
        binding = _binding(
            edge_id=aug_edge.edge_id,
            constraint_id=boundary.constraint_id,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"


class TestIdentityDenyBlockers:
    def test_complete_identity_deny_blocks(self) -> None:
        facts = _build_alice_to_admin_group()
        aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
        deny = _identity_deny()
        binding = _binding(
            edge_id=aug_edge.edge_id,
            constraint_id=deny.constraint_id,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "blocked"
        assert f.severity == "info"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_add_user_to_group")
        assert check.state.value == "fail"
        assert any(b.kind == "identity_deny" for b in f.blockers_observed)

    def test_partial_identity_deny_is_inconclusive(self) -> None:
        facts = _build_alice_to_admin_group()
        aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
        deny = _identity_deny(
            statement_id="PartialDenyAddUserToGroup",
            parse_status="partial",
        )
        binding = _binding(
            edge_id=aug_edge.edge_id,
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
        findings = IAMGroupMembershipEscalationReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        assert f.severity == "high"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_add_user_to_group")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# Source filter: roles not enumerated
# ---------------------------------------------------------------------------


class TestRoleSourceFiltered:
    def test_role_source_not_enumerated(self) -> None:
        """Roles with iam:AddUserToGroup → no finding (v1 users only)."""
        role = _role(f"arn:aws:iam::{_ACCOUNT}:role/SomeRole")
        admin = _group(_ADMIN_GROUP_ARN)
        aug_edge = _add_user_to_group_edge(
            src=role,
            group_arn=_ADMIN_GROUP_ARN,
        )
        admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
        facts = _make_facts(
            nodes=(role, admin),
            edges=(aug_edge, admin_grant),
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multiple users
# ---------------------------------------------------------------------------


class TestMultipleUsers:
    def test_two_users_two_findings(self) -> None:
        """Alice and Bob both have AddUserToGroup on admin → 2 findings."""
        alice = _user(_ALICE_ARN)
        bob = _user(_BOB_ARN)
        admin = _group(_ADMIN_GROUP_ARN)
        alice_edge = _add_user_to_group_edge(
            src=alice,
            group_arn=_ADMIN_GROUP_ARN,
            digest="1" * 64,
        )
        bob_edge = _add_user_to_group_edge(
            src=bob,
            group_arn=_ADMIN_GROUP_ARN,
            digest="2" * 64,
        )
        admin_grant = _admin_grant_edge_for_group(_ADMIN_GROUP_ARN)
        facts = _make_facts(
            nodes=(alice, bob, admin),
            edges=(alice_edge, bob_edge, admin_grant),
        )
        findings = IAMGroupMembershipEscalationReasoner().run(facts)
        assert len(findings) == 2
        sources = sorted(f.source.provider_id for f in findings)
        assert sources == sorted([_ALICE_ARN, _BOB_ARN])


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())
        f2 = IAMGroupMembershipEscalationReasoner().run(_build_alice_to_admin_group())
        assert len(f1) == len(f2) == 1
        assert f1[0].finding_id == f2[0].finding_id
        assert f1[0].evidence.bundle_digest == f2[0].evidence.bundle_digest
