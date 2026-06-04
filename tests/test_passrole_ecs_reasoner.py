"""Tests for the passrole_ecs reasoner — 8 fixtures + preconditions + determinism.

Per plan §4B.5:
- Fixture A: validated/critical (admin-equivalent target)
- Fixture B: precondition_only/medium (target trusts EC2 not ECS tasks) — NOT blocked
- Fixture C: blocked/info (SCP blocks ecs:RegisterTaskDefinition)
- Fixture D: blocked/info (permission boundary blocks, post-BND-1)
- Fixture E: inconclusive/high (SCP partial → UNKNOWN)
- Fixture F: inconclusive/high (wildcard PassRole → hyperedge witness → UNKNOWN)
  **THE HIGHEST-PRIORITY CORRECTNESS TEST IN THE REBUILD.**
- Fixture G: precondition_only/medium (iam:PassedToService scoped to ec2)
- Fixture H: determinism double-run

The §3.4 invariant "VALIDATED → no condition_context assumption" is NOT
violated by the reasoner's session_policy assumption (kind="session_policy",
not kind="condition_context"). Per the plan §4B.4 design choice.

Per S10 plan row precedent, S12 does NOT pin byte-level findings.json
fixtures here — that's S13's deliverable. S12 pins values (verdict /
severity / finding_id format / check structure / blocker presence).
"""

from __future__ import annotations

from typing import Any

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner import (
    CheckState,
    FactGraph,
    PassRoleEcsReasoner,
    Verdict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACCOUNT = "111111\u003111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_ADMIN_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/AdminRole"
_NON_ADMIN_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/NonAdmin"
_ECS_TASKS_SERVICE = "ecs-tasks.amazonaws.com"
_EC2_SERVICE = "ec2.amazonaws.com"
_HYPEREDGE_PROVIDER_ID = "__hyperedge__:passrole_wildcard:abc123"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _alice_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=_ALICE_ARN,
        properties={"account_id": _ACCOUNT},
    )


def _admin_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_ADMIN_ROLE_ARN,
        properties={"account_id": _ACCOUNT},
    )


def _non_admin_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_NON_ADMIN_ROLE_ARN,
        properties={"account_id": _ACCOUNT},
    )


def _ecs_tasks_service_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id=_ECS_TASKS_SERVICE,
        properties={},
    )


def _ec2_service_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id=_EC2_SERVICE,
        properties={},
    )


def _hyperedge_node() -> Node:
    """Synthetic hyperedge node — used as the dst of suppressed wildcard PassRole."""
    return Node(
        provider=PROVIDER_AWS,
        node_type="__hyperedge__",
        provider_id=_HYPEREDGE_PROVIDER_ID,
        properties={"would_expand_to": 50, "expansion_type": "iam:PassRole"},
    )


def _permission_edge(
    *,
    src: Node,
    dst: Node,
    action: str,
    has_conditions: bool = False,
    is_wildcard_resource: bool = False,
    raw_conditions: dict[str, Any] | None = None,
    digest: str = "deadbeef" * 8,
    statement_index: int = 0,
    policy_arn: str | None = None,
) -> Edge:
    """Build a permission edge with the post-S05 allow_controls + post-PR-1 raw_conditions shape."""
    if raw_conditions is None:
        raw_conditions = {}
    if policy_arn is None:
        policy_arn = f"arn:aws:iam::{_ACCOUNT}:policy/AlicePerms"
    return Edge(
        edge_type=f"{action}_permission",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": policy_arn,
                    "statement_index": statement_index,
                    "digest": digest,
                    "summary": f"{action} grant",
                }
            ],
            "action_matched_via": "exact",
            "effect": "Allow",
            "has_conditions": has_conditions,
            "is_wildcard_resource": is_wildcard_resource,
            "layer": "permission",
            "policy_arn": policy_arn,
            "policy_name": "AlicePerms",
            "raw_conditions": raw_conditions,
            "resource_pattern": dst.provider_id if not is_wildcard_resource else "*",
            "statement_index": statement_index,
        },
    )


def _wildcard_passrole_to_hyperedge(src: Node) -> Edge:
    """A wildcard iam:PassRole grant suppressed to a hyperedge dst.

    This is the canonical fixture F shape: Alice has `iam:PassRole *` and
    the warn-mode collector emitted a single suppressed hyperedge instead
    of expanding to per-role edges. The reasoner must NOT treat this as
    a valid PassRole witness — `has_action` returns UNKNOWN for hyperedges.
    """
    hyper = _hyperedge_node()
    return Edge(
        edge_type="iam:PassRole_permission",
        src=src.to_ref(),
        dst=hyper.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/AlicePerms",
                    "statement_index": 0,
                    "digest": "feedface" * 8,
                    "summary": "wildcard PassRole",
                }
            ],
            "action_matched_via": "exact",
            "effect": "Allow",
            "expansion_mode": "warn",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/AlicePerms",
            "policy_name": "AlicePerms",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
            "suppressed": True,
            "would_expand_to": 50,
        },
    )


def _trust_edge_from_service(*, service: Node, target: Node) -> Edge:
    """A trust edge from an AWSService node to an IAMRole."""
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=service.to_ref(),
        dst=target.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": target.provider_id,
                    "statement_index": 0,
                    "digest": "cafebabe" * 8,
                    "summary": f"trust {service.provider_id}",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "principal_type": "Service",
            "raw_conditions": {},
            "statement_index": 0,
        },
    )


def _scp_constraint(
    *,
    statement_id: str = "DenyEcs",
    deny_actions: list[str] | None = None,
    parse_status: str = "complete",
) -> Constraint:
    if deny_actions is None:
        deny_actions = ["ecs:RegisterTaskDefinition"]
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-ecs",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": deny_actions,
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyEcsProd",
            "resource_patterns": ["*"],
        },
    )


def _boundary_constraint(
    *,
    statement_id: str = "BoundaryAllow",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        scope_type="USER",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceBoundary",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["s3:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
        },
    )


def _binding(
    *,
    edge_id: str,
    constraint_id: str,
    likely_blocking: bool = True,
    governance_confidence: str = "complete",
    binding_reason: str = "test binding",
) -> EdgeConstraint:
    return EdgeConstraint(
        edge_id=edge_id,
        constraint_id=constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=binding_reason,
    )


def _make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...] = (),
    edge_constraints: tuple[EdgeConstraint, ...] = (),
    edge_budget_exhausted: bool = False,
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=edge_budget_exhausted,
    )


def _is_sha256_hex(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    """preconditions_met enforces three §4B.1 hard gates."""

    def test_no_iam_roles_skips(self) -> None:
        facts = _make_facts(nodes=(_alice_node(),), edges=())
        ran, reason = PassRoleEcsReasoner().preconditions_met(facts)
        assert ran is False
        assert "no IAM roles" in reason

    def test_pre_pr1_skips(self) -> None:
        """A permission edge missing raw_conditions → refuse to run."""
        alice = _alice_node()
        target = _admin_role_node()
        # Build a malformed permission edge sans raw_conditions feature.
        bad_edge = Edge(
            edge_type="ecs:RegisterTaskDefinition_permission",
            src=alice.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "effect": "Allow",
                "has_conditions": False,
                # NOTE: no raw_conditions key — pre-PR-1 collector
            },
        )
        facts = _make_facts(nodes=(alice, target), edges=(bad_edge,))
        ran, reason = PassRoleEcsReasoner().preconditions_met(facts)
        assert ran is False
        assert "PR-1 not applied" in reason

    def test_edge_budget_exhausted_skips(self) -> None:
        alice = _alice_node()
        target = _admin_role_node()
        edge = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RegisterTaskDefinition",
            is_wildcard_resource=True,
        )
        facts = _make_facts(
            nodes=(alice, target),
            edges=(edge,),
            edge_budget_exhausted=True,
        )
        ran, reason = PassRoleEcsReasoner().preconditions_met(facts)
        assert ran is False
        assert "edge_budget_exhausted" in reason

    def test_minimal_valid_runs(self) -> None:
        alice = _alice_node()
        target = _admin_role_node()
        edge = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RegisterTaskDefinition",
            is_wildcard_resource=True,
        )
        facts = _make_facts(nodes=(alice, target), edges=(edge,))
        ran, _reason = PassRoleEcsReasoner().preconditions_met(facts)
        assert ran is True


# ---------------------------------------------------------------------------
# Helper: build the canonical fixture A graph (admin-equivalent target)
# ---------------------------------------------------------------------------


def _build_admin_chain(
    *,
    raw_conditions: dict[str, Any] | None = None,
    target_trusts_ecs_tasks: bool = True,
    target_admin: bool = True,
    extra_constraints: tuple[Constraint, ...] = (),
    extra_bindings_for_register_task_def: tuple = (),
    extra_bindings_for_passrole: tuple = (),
    include_register_task_def: bool = True,
    include_run_task: bool = True,
) -> tuple[FactGraph, Edge, Edge, Edge | None]:
    """Build the canonical ECS PassRole admin chain.

    Returns (facts, register_task_def_edge, passrole_edge, ecs_trust_edge).
    The ecs_trust_edge is None when target_trusts_ecs_tasks=False (used
    for fixture B).

    The ECS privilege escalation chain requires BOTH ecs:RegisterTaskDefinition
    AND ecs:RunTask permissions. By default this builder creates both edges
    so that check 1 can PASS. The `include_register_task_def` and
    `include_run_task` flags let tests in TestTwoActionCheck1 disable one
    at a time to verify check 1's combined-tristate behavior (PASS+FAIL →
    FAIL → no finding emitted).

    When include_register_task_def=False and include_run_task=True, the
    returned register_task_def_edge is actually the run_task edge — the
    "primary witness" slot gets whichever of the two ECS edges is
    available, following the reasoner's internal primary-witness
    selection logic.
    """
    alice = _alice_node()
    target = _admin_role_node()
    ecs_svc = _ecs_tasks_service_node()
    ec2_svc = _ec2_service_node()

    nodes_list: list[Node] = [alice, target, ecs_svc, ec2_svc]
    edges_list: list[Edge] = []

    # Alice has ecs:RegisterTaskDefinition (clean witness — not a
    # hyperedge, not a wildcard-resource, no conditions).
    register_task_def_edge: Edge | None = None
    if include_register_task_def:
        register_task_def_edge = _permission_edge(
            src=alice,
            dst=target,  # any dst — has_action ignores resource for non-PassRole
            action="ecs:RegisterTaskDefinition",
            digest="aaaaaaaa" * 8,
            statement_index=0,
        )
        edges_list.append(register_task_def_edge)

    # Alice has ecs:RunTask — the second required action for the ECS
    # privilege escalation pattern. Without both, the chain is
    # incomplete and check 1 returns FAIL.
    run_task_edge: Edge | None = None
    if include_run_task:
        run_task_edge = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RunTask",
            digest="aaaaaaab" * 8,  # distinct digest from register_task_def
            statement_index=1,
        )
        edges_list.append(run_task_edge)

    # Alice has iam:PassRole targeting the admin role (ECS task role).
    passrole_edge = _permission_edge(
        src=alice,
        dst=target,
        action="iam:PassRole",
        digest="bbbbbbbb" * 8,
        statement_index=2,
        raw_conditions=raw_conditions,
        has_conditions=bool(raw_conditions),
    )
    edges_list.append(passrole_edge)

    # Target trusts ECS tasks (or EC2 for fixture B).
    ecs_trust_edge: Edge | None = None
    if target_trusts_ecs_tasks:
        ecs_trust_edge = _trust_edge_from_service(service=ecs_svc, target=target)
        edges_list.append(ecs_trust_edge)
    else:
        ec2_trust_edge = _trust_edge_from_service(service=ec2_svc, target=target)
        edges_list.append(ec2_trust_edge)

    # Admin equivalence: target role has `iam:*` permission edge.
    if target_admin:
        admin_grant = Edge(
            edge_type="iam:*_permission",
            src=target.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [
                    {
                        "control_type": "PERMISSION",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "statement_index": 0,
                        "digest": "cccccccc" * 8,
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
        edges_list.append(admin_grant)

    facts = _make_facts(
        nodes=tuple(nodes_list),
        edges=tuple(edges_list),
        constraints=extra_constraints,
        edge_constraints=tuple(extra_bindings_for_register_task_def) + tuple(extra_bindings_for_passrole),
    )

    # Primary witness slot: prefer register_task_def, fall back to
    # run_task if register is disabled. If both are disabled, use a
    # placeholder so the return tuple stays 4-shape.
    primary_witness = register_task_def_edge or run_task_edge or passrole_edge
    return facts, primary_witness, passrole_edge, ecs_trust_edge


# ---------------------------------------------------------------------------
# Fixture A: validated_admin → critical
# ---------------------------------------------------------------------------


class TestFixtureAValidatedAdmin:
    """The happy path. Alice → AdminRole → all 8 checks PASS → critical."""

    def test_emits_validated_critical(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_CRITICAL

    def test_finding_id_is_sha256_hex(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleEcsReasoner().run(facts)[0]
        assert _is_sha256_hex(f.finding_id)

    def test_all_8_checks_pass(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleEcsReasoner().run(facts)[0]
        assert len(f.required_checks) == 8
        for chk in f.required_checks:
            assert chk.state is CheckState.PASS, f"check {chk.name!r} expected PASS, got {chk.state}"

    def test_session_policy_assumption_present(self) -> None:
        """VALIDATED findings carry the session_policy assumption per §4B.4."""
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleEcsReasoner().run(facts)[0]
        assert len(f.assumptions) == 1
        assert f.assumptions[0].kind == "session_policy"
        # Critically, NOT condition_context — that would force inconclusive.
        assert f.assumptions[0].kind != "condition_context"


class TestFixtureANonAdmin:
    """Same chain but target is not admin → validated/high (severity downgrade)."""

    def test_non_admin_target_emits_high_not_critical(self) -> None:
        facts, _, _, _ = _build_admin_chain(target_admin=False)
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_HIGH


# ---------------------------------------------------------------------------
# Fixture B: precondition_only_trust_missing → medium (NOT blocked)
# ---------------------------------------------------------------------------


class TestFixtureBPreconditionOnlyTrustMissing:
    """Target trusts EC2 not ECS tasks → check 3 FAIL → precondition_only/medium.

    The distinction matters: this is NOT blocked. The path is broken
    by the target's trust policy not including ECS tasks, not by an active
    blocker like an SCP. Per §4B.3 these are different verdicts.
    """

    def _build(self) -> FactGraph:
        # _build_admin_chain enumerates by walking IAMRole nodes that
        # trust ECS tasks. Fixture B's target trusts EC2 only — so candidate
        # enumeration would skip it entirely. To exercise the precondition_only
        # path, we need a target that DOES trust ECS tasks (so it gets
        # enumerated) but where the witness lookup fails for that target.
        # The plan §4B.5 fixture B (adapted for ECS) sets `target trusts ec2.amazonaws.com only`.
        # Since target-first enumeration would skip such a target,
        # there's no precondition_only finding emitted at all.
        # Resolution: the plan's source-first enumeration would have hit
        # this case, but target-first means "no ECS-trusting role"
        # → no candidate → no finding. This is a documented difference
        # from the plan's source-first enumeration semantics.
        #
        # To match the plan's INTENT (test that "target without ECS tasks
        # trust → precondition_only"), we instead build TWO targets:
        # one that trusts ECS tasks (gets enumerated, produces validated)
        # and one that trusts only EC2 (does not get enumerated, no
        # finding emitted). The fixture B intent then becomes: "the
        # EC2-only target produces no finding, the ECS-trusting
        # target produces validated."
        #
        # However, because target-first enumeration is the chosen scope
        # decision, this fixture B just becomes an assertion that
        # candidate enumeration correctly skips non-ECS-trusting roles.
        alice = _alice_node()
        ec2_svc = _ec2_service_node()
        # Build a role that trusts only EC2 — should NOT be enumerated (ECS reasoner skips non-ECS targets).
        ec2_only_role = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=f"arn:aws:iam::{_ACCOUNT}:role/Ec2Only",
            properties={"account_id": _ACCOUNT},
        )
        register_task_def_local = _permission_edge(
            src=alice,
            dst=ec2_only_role,
            action="ecs:RegisterTaskDefinition",
        )
        passrole = _permission_edge(
            src=alice,
            dst=ec2_only_role,
            action="iam:PassRole",
        )
        ec2_trust = _trust_edge_from_service(service=ec2_svc, target=ec2_only_role)
        return _make_facts(
            nodes=(alice, ec2_only_role, ec2_svc),
            edges=(register_task_def_local, passrole, ec2_trust),
        )

    def test_no_finding_emitted(self) -> None:
        """Target-first enumeration skips non-ECS-trusting roles entirely.

        Documented as a deliberate scope decision in the reasoner module
        docstring: target-first enumeration doesn't enumerate roles that
        don't trust ECS tasks, so the precondition_only/trust_missing case
        from the plan §4B.5 fixture B (adapted for ECS) simply doesn't produce a finding.
        The plan's intent (no false-positive validated finding when
        trust is missing) is preserved — and the verdict is "no finding"
        instead of "precondition_only", which is consistent with check 1
        and check 2 FAIL early-exits.
        """
        findings = PassRoleEcsReasoner().run(self._build())
        assert findings == []


# ---------------------------------------------------------------------------
# Fixture C: blocked_by_scp → info
# ---------------------------------------------------------------------------


class TestFixtureCBlockedBySCP:
    """SCP at account OU blocks ecs:RegisterTaskDefinition → blocked/info."""

    def _build(self) -> FactGraph:
        facts, register_task_def_edge, _, _ = _build_admin_chain()
        scp = _scp_constraint(
            statement_id="DenyEcsRegister",
            deny_actions=["ecs:RegisterTaskDefinition"],
        )
        binding = _binding(
            edge_id=register_task_def_edge.edge_id,
            constraint_id=scp.constraint_id,
            likely_blocking=True,
            governance_confidence="complete",
            binding_reason="SCP DenyEcsRegister at OU ou-prod denies ecs:RegisterTaskDefinition",
        )
        # Rebuild facts with constraints + binding.
        return FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

    def test_emits_blocked_info(self) -> None:
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO

    def test_check_4_fail_with_scp_blocker(self) -> None:
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_4 = next(c for c in f.required_checks if c.name == "no_scp_blocks_ecs_create_or_run")
        assert check_4.state is CheckState.FAIL
        assert any(b.kind == "scp" for b in f.blockers_observed)


# ---------------------------------------------------------------------------
# Fixture D: blocked_by_boundary_post_bnd1 → info
# ---------------------------------------------------------------------------


class TestFixtureDBlockedByBoundaryPostBnd1:
    """Permission boundary blocks ecs:RegisterTaskDefinition → blocked/info.

    Per plan §4B.5: post-BND-1 verdict is `blocked`; pre-BND-1 it would
    have been `inconclusive` because pre-fix the binder always set
    `likely_blocking=False` regardless of action intersection. S03's
    BND-1 fix correctly computes the action intersection so the binder
    can mark the binding as `likely_blocking=True` when the boundary
    does not allow the bound action.

    This test simulates the post-BND-1 binding directly by constructing
    an EdgeConstraint with `likely_blocking=True, governance_confidence=complete`
    on the ecs:RegisterTaskDefinition edge. The reasoner reads the binder's
    output via `bindings_for_edge` and does not re-implement boundary
    evaluation.
    """

    def _build(self) -> FactGraph:
        facts, register_task_def_edge, _, _ = _build_admin_chain()
        boundary = _boundary_constraint(statement_id="BoundaryDeniesEcs")
        binding = _binding(
            edge_id=register_task_def_edge.edge_id,
            constraint_id=boundary.constraint_id,
            likely_blocking=True,  # post-BND-1: action intersection finds no overlap
            governance_confidence="complete",
            binding_reason=(
                "permission boundary allowed_actions={s3:*, dynamodb:*} "
                "does not include ecs:RegisterTaskDefinition (post-BND-1)"
            ),
        )
        return FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

    def test_emits_blocked_info(self) -> None:
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO

    def test_check_6_fail_with_boundary_blocker(self) -> None:
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_6 = next(c for c in f.required_checks if c.name == "no_boundary_blocks_ecs_create_or_run")
        assert check_6.state is CheckState.FAIL
        assert any(b.kind == "boundary" for b in f.blockers_observed)


# ---------------------------------------------------------------------------
# Fixture E: inconclusive_partial_scp → high
# ---------------------------------------------------------------------------


class TestFixtureEInconclusivePartialSCP:
    """SCP with parse_status=partial → governance_confidence=partial → inconclusive.

    Plan §4B.6 row 4 regression guard: a reasoner that interprets
    `partial` or `needs_review` as "probably blocking" produces wrong
    answers. The correct answer is UNKNOWN → inconclusive.
    """

    def _build(self) -> FactGraph:
        facts, register_task_def_edge, _, _ = _build_admin_chain()
        scp = _scp_constraint(
            statement_id="PartialDenyEcs",
            parse_status="partial",
        )
        binding = _binding(
            edge_id=register_task_def_edge.edge_id,
            constraint_id=scp.constraint_id,
            likely_blocking=False,
            governance_confidence="partial",
            binding_reason="SCP parse partial — could not evaluate fully",
        )
        return FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

    def test_emits_inconclusive_high(self) -> None:
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.severity == SEVERITY_HIGH

    def test_check_4_unknown_not_blocked(self) -> None:
        """The SCP check (#4) should be UNKNOWN, not promoted to FAIL/BLOCKED."""
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_4 = next(c for c in f.required_checks if c.name == "no_scp_blocks_ecs_create_or_run")
        assert check_4.state is CheckState.UNKNOWN
        assert f.verdict is not Verdict.BLOCKED


# ---------------------------------------------------------------------------
# Fixture F: inconclusive_wildcard_passrole_hyperedge → high
# THE HIGHEST-PRIORITY CORRECTNESS TEST IN THE REBUILD
# ---------------------------------------------------------------------------


class TestFixtureFInconclusiveWildcardPassroleHyperedgeEcs:
    """Wildcard PassRole → hyperedge witness → check 2 UNKNOWN → inconclusive.

    **THE HIGHEST-PRIORITY CORRECTNESS TEST IN THE REBUILD.**

    Per plan §4B.6 row 1: a reasoner that breaks the tristate `has_action`
    so it returns PASS for hyperedges produces silent false positives. The
    hyperedge represents a warn-suppressed wildcard expansion — the
    collector knew the grant was `iam:PassRole *` but suppressed expansion
    above the budget threshold. The dst is a synthetic `__hyperedge__`
    node, NOT a specific role, so the reasoner CANNOT prove that the
    wildcard covers the specific target role. The correct answer is
    UNKNOWN, and the reasoner must surface that to the human reviewer.

    The negative test pattern from the plan: mutate `has_action` to
    return PASS on hyperedges and verify this fixture fails. That
    mutation is not implemented as a separate test (it would require
    monkeypatching FactGraph.has_action), but the test below would
    catch it because the verdict assertion would flip from
    INCONCLUSIVE to VALIDATED.
    """

    def _build(self) -> FactGraph:
        alice = _alice_node()
        target = _admin_role_node()
        ecs_svc = _ecs_tasks_service_node()
        hyper = _hyperedge_node()

        # Alice has clean ecs:RegisterTaskDefinition.
        register_task_def_local = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RegisterTaskDefinition",
        )
        # Alice also has clean ecs:RunTask — both are required for the
        # ECS pattern. Without RunTask, check 1 would early-exit FAIL
        # and this fixture's hyperedge guard would never be exercised.
        run_task_local = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RunTask",
            digest="eeeeeeee" * 8,
            statement_index=3,
        )
        # Alice has wildcard PassRole → hyperedge dst.
        wildcard_passrole = _wildcard_passrole_to_hyperedge(src=alice)
        # Target trusts ECS tasks.
        ecs_trust_local = _trust_edge_from_service(service=ecs_svc, target=target)

        # Admin equivalence (so we'd produce a critical finding if the
        # reasoner incorrectly accepted the hyperedge as a witness — the
        # critical severity makes the failure mode louder).
        admin_grant = Edge(
            edge_type="iam:*_permission",
            src=target.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [
                    {
                        "control_type": "PERMISSION",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "statement_index": 0,
                        "digest": "dddddddd" * 8,
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

        return _make_facts(
            nodes=(alice, target, ecs_svc, hyper),
            edges=(register_task_def_local, run_task_local, wildcard_passrole, ecs_trust_local, admin_grant),
        )

    def test_finding_emitted_target_first_enumeration_catches_it(self) -> None:
        """Fixture F is emitted because target-first enumeration catches it.

        Source-first enumeration would walk Alice's PassRole edges, see
        the hyperedge dst, fail to extract a target_role_arn, and skip
        the candidate entirely → NO finding emitted → silent failure.

        Target-first enumeration walks IAM roles that trust ECS tasks
        (admin role IS in the graph), checks if Alice has ecs:RegisterTaskDefinition
        (PASS), checks if Alice has PassRole to admin role (UNKNOWN
        because the hyperedge cannot prove specific-resource coverage),
        and emits a finding with INCONCLUSIVE verdict.

        This test asserts the finding IS emitted — the prerequisite for
        the verdict assertion below.
        """
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1, (
            "fixture F MUST emit one finding — target-first enumeration "
            "catches the wildcard PassRole case where source-first would skip"
        )

    def test_emits_inconclusive_high_not_validated_critical(self) -> None:
        """The headline assertion: hyperedge witness → INCONCLUSIVE, NOT VALIDATED.

        If this test ever flips to validated/critical, `has_action` has
        been broken to accept hyperedges as PASS witnesses — the single
        most common false-positive production path. Plan §4B.6 row 1.
        """
        f = PassRoleEcsReasoner().run(self._build())[0]
        assert f.verdict is Verdict.INCONCLUSIVE, (
            f"fixture F must produce INCONCLUSIVE; got {f.verdict.value}. "
            f"This means has_action accepted a hyperedge as a PASS witness "
            f"— the single most common false-positive production path "
            f"documented in plan §4B.6."
        )
        assert f.severity == SEVERITY_HIGH
        assert f.verdict is not Verdict.VALIDATED  # belt-and-suspenders

    def test_check_2_is_unknown(self) -> None:
        """Check 2 (PassRole to target) must be UNKNOWN, not PASS.

        This is the specific check whose UNKNOWN state drives the
        inconclusive verdict. If this test fails (check 2 = PASS),
        the failure mode is exactly the §4B.6 row 1 false positive.
        """
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_2 = next(c for c in f.required_checks if c.name == "source_has_passrole_to_target")
        assert check_2.state is CheckState.UNKNOWN, (
            f"check 2 must be UNKNOWN on hyperedge witness; got {check_2.state}. has_action is broken."
        )


# ---------------------------------------------------------------------------
# Fixture G: precondition_only_passedtoservice_ec2 → medium
# ---------------------------------------------------------------------------


class TestFixtureGPreconditionOnlyPassedToServiceEC2:
    """PassRole condition iam:PassedToService scoped to ec2 → check 8 FAIL → precondition_only (ec2 ≠ ecs-tasks).

    Per plan §4B.5: post-PR-1+COND-1 the reasoner reads `raw_conditions`
    on the PassRole permission edge, sees the iam:PassedToService key
    scoped to ec2.amazonaws.com (not ecs-tasks.amazonaws.com), and emits
    `precondition_only` because the chain cannot pass the role to a
    ECS task role at runtime — the IAM service will reject
    the PassRole call.

    Pre-PR-1 the reasoner would have seen `has_conditions=True` and
    stopped, producing UNKNOWN → INCONCLUSIVE. PR-1 propagates the
    full condition block; COND-1 ensures iam:PassedToService is
    extractable. This test asserts the post-fix verdict.
    """

    def _build(self) -> FactGraph:
        # Build chain with raw_conditions on the PassRole edge.
        facts, _, _, _ = _build_admin_chain(
            raw_conditions={
                "StringEquals": {
                    "iam:PassedToService": "ec2.amazonaws.com",
                },
            },
        )
        return facts

    def test_emits_precondition_only_medium(self) -> None:
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.PRECONDITION_ONLY
        assert f.severity == SEVERITY_MEDIUM

    def test_check_8_fail_reason_names_ec2(self) -> None:
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_8 = next(c for c in f.required_checks if c.name == "passrole_condition_scoped_to_ecs_or_absent")
        assert check_8.state is CheckState.FAIL
        assert "ec2.amazonaws.com" in check_8.reason

    def test_passed_to_service_blocker_present(self) -> None:
        f = PassRoleEcsReasoner().run(self._build())[0]
        assert any(b.kind == "passed_to_service" for b in f.blockers_observed)


class TestFixtureGPassedToServiceEcsTasks:
    """Variant: PassedToService scoped to ecs-tasks → check 8 PASS → validated."""

    def _build(self) -> FactGraph:
        facts, _, _, _ = _build_admin_chain(
            raw_conditions={
                "StringEquals": {
                    "iam:PassedToService": "ecs-tasks.amazonaws.com",
                },
            },
        )
        return facts

    def test_emits_validated_critical(self) -> None:
        findings = PassRoleEcsReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_CRITICAL

    def test_check_8_pass(self) -> None:
        f = PassRoleEcsReasoner().run(self._build())[0]
        check_8 = next(c for c in f.required_checks if c.name == "passrole_condition_scoped_to_ecs_or_absent")
        assert check_8.state is CheckState.PASS


class TestPassedToServiceStringLikeSemantics:
    """iam:PassedToService preserves StringEquals exactness and StringLike glob semantics."""

    def _check_state_for(self, raw_conditions: dict[str, Any]) -> CheckState:
        facts, _, _, _ = _build_admin_chain(raw_conditions=raw_conditions)
        finding = PassRoleEcsReasoner().run(facts)[0]
        check_8 = next(c for c in finding.required_checks if c.name == "passrole_condition_scoped_to_ecs_or_absent")
        return check_8.state

    def test_stringequals_exact_ecs_tasks_passes(self) -> None:
        assert (
            self._check_state_for({"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})
            is CheckState.PASS
        )

    def test_stringlike_ecs_tasks_glob_passes(self) -> None:
        assert self._check_state_for({"StringLike": {"iam:PassedToService": "ecs-tasks.*"}}) is CheckState.PASS

    def test_stringlike_amazonaws_glob_passes(self) -> None:
        assert self._check_state_for({"StringLike": {"iam:PassedToService": "*.amazonaws.com"}}) is CheckState.PASS

    def test_stringlike_star_passes(self) -> None:
        assert self._check_state_for({"StringLike": {"iam:PassedToService": "*"}}) is CheckState.PASS

    def test_stringlike_wrong_service_fails(self) -> None:
        assert self._check_state_for({"StringLike": {"iam:PassedToService": "lambda.*"}}) is CheckState.FAIL

    def test_stringequals_glob_is_exact_and_fails(self) -> None:
        assert self._check_state_for({"StringEquals": {"iam:PassedToService": "*.amazonaws.com"}}) is CheckState.FAIL

    def test_unsupported_operator_is_unknown(self) -> None:
        assert (
            self._check_state_for({"StringNotEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})
            is CheckState.UNKNOWN
        )

    def test_stringlike_list_passes_when_any_value_matches(self) -> None:
        assert (
            self._check_state_for({"StringLike": {"iam:PassedToService": ["lambda.*", "ecs-tasks.*"]}})
            is CheckState.PASS
        )


# ---------------------------------------------------------------------------
# Fixture H: determinism double-run
# ---------------------------------------------------------------------------


class TestFixtureHDeterminism:
    """Two runs over the same FactGraph produce byte-identical Findings."""

    def test_double_run_finding_equality(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        run_1 = PassRoleEcsReasoner().run(facts)
        run_2 = PassRoleEcsReasoner().run(facts)
        assert len(run_1) == len(run_2) == 1
        assert run_1[0] == run_2[0]

    def test_double_run_finding_id_equality(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        id_1 = PassRoleEcsReasoner().run(facts)[0].finding_id
        id_2 = PassRoleEcsReasoner().run(facts)[0].finding_id
        assert id_1 == id_2

    def test_double_run_bundle_digest_equality(self) -> None:
        """The deepest determinism guarantee."""
        facts, _, _, _ = _build_admin_chain()
        d_1 = PassRoleEcsReasoner().run(facts)[0].evidence.bundle_digest
        d_2 = PassRoleEcsReasoner().run(facts)[0].evidence.bundle_digest
        assert d_1 == d_2


# ---------------------------------------------------------------------------
# TestTwoActionCheck1 — ECS-specific combined check 1 logic
# ---------------------------------------------------------------------------
# These tests cover behavior unique to the ECS reasoner that the Lambda
# reasoner does not have. Check 1 in passrole_ecs is an AND-combined
# tristate over TWO actions (ecs:RegisterTaskDefinition AND ecs:RunTask)
# via the _and_tristate helper. The Lambda reasoner's check 1 is a
# single has_action call.
#
# Semantics:
#   Both PASS   → check 1 PASS
#   Either FAIL → check 1 FAIL (early exit, no finding)
#   Otherwise   → check 1 UNKNOWN (neither FAIL, at least one UNKNOWN)


class TestTwoActionCheck1:
    """Combined two-action check 1 for ecs:RegisterTaskDefinition AND ecs:RunTask."""

    def test_missing_run_task_produces_no_finding(self) -> None:
        """Source has RegisterTaskDefinition but NOT RunTask → early exit.

        Check 1a (RegisterTaskDefinition) = PASS, check 1b (RunTask) =
        FAIL because there's no matching edge. _and_tristate(PASS, FAIL)
        = FAIL → early exit in _evaluate_candidate, no finding emitted.
        """
        facts, _, _, _ = _build_admin_chain(include_run_task=False)
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 0, (
            "check 1 MUST FAIL when ecs:RunTask is missing — the ECS privilege escalation pattern requires BOTH actions"
        )

    def test_missing_register_task_def_produces_no_finding(self) -> None:
        """Source has RunTask but NOT RegisterTaskDefinition → early exit.

        Symmetric to the above: check 1a = FAIL (no Register edge),
        check 1b = PASS. _and_tristate(FAIL, PASS) = FAIL → no finding.
        """
        facts, _, _, _ = _build_admin_chain(include_register_task_def=False)
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 0, (
            "check 1 MUST FAIL when ecs:RegisterTaskDefinition is missing — "
            "the ECS privilege escalation pattern requires BOTH actions"
        )

    def test_register_pass_run_unknown_produces_inconclusive(self) -> None:
        """Register PASS + Run UNKNOWN → check 1 UNKNOWN → inconclusive verdict.

        Build the canonical admin chain but replace the ecs:RunTask edge
        with a wildcard-resource variant that produces an UNKNOWN witness.
        Check 1's combined state becomes UNKNOWN, which forces the
        verdict to inconclusive. The _explain_ecs_check_1 reason must
        name ecs:RunTask as the ambiguous action.
        """
        alice = _alice_node()
        target = _admin_role_node()
        ecs_svc = _ecs_tasks_service_node()

        register_edge = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RegisterTaskDefinition",
            digest="aaaaaaaa" * 8,
            statement_index=0,
        )
        # Wildcard RunTask → UNKNOWN witness
        run_edge_unknown = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RunTask",
            digest="bbbbbbbb" * 8,
            statement_index=1,
            is_wildcard_resource=True,
        )
        passrole_edge = _permission_edge(
            src=alice,
            dst=target,
            action="iam:PassRole",
            digest="cccccccc" * 8,
            statement_index=2,
        )
        ecs_trust_edge = _trust_edge_from_service(service=ecs_svc, target=target)

        facts = _make_facts(
            nodes=(alice, target, ecs_svc),
            edges=(register_edge, run_edge_unknown, passrole_edge, ecs_trust_edge),
        )
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 1, "expected exactly one inconclusive finding"
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        check_1 = next(c for c in f.required_checks if c.name == "source_has_ecs_create_and_run_permissions")
        assert check_1.state.value == "unknown"
        assert "ecs:RunTask" in check_1.reason, (
            f"check 1 reason must name ecs:RunTask as ambiguous; got: {check_1.reason!r}"
        )
        assert "ecs:RegisterTaskDefinition" not in check_1.reason.split("and")[0], (
            "check 1 reason must NOT list RegisterTaskDefinition as ambiguous"
        )

    def test_both_actions_unknown_produces_inconclusive_both_named(self) -> None:
        """Both actions UNKNOWN via wildcard resources → check 1 UNKNOWN.

        _explain_ecs_check_1 must name BOTH actions in the reason
        string so a reviewer can see that neither action has a clean
        witness.
        """
        alice = _alice_node()
        target = _admin_role_node()
        ecs_svc = _ecs_tasks_service_node()

        register_edge_unknown = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RegisterTaskDefinition",
            digest="aaaaaaaa" * 8,
            statement_index=0,
            is_wildcard_resource=True,
        )
        run_edge_unknown = _permission_edge(
            src=alice,
            dst=target,
            action="ecs:RunTask",
            digest="bbbbbbbb" * 8,
            statement_index=1,
            is_wildcard_resource=True,
        )
        passrole_edge = _permission_edge(
            src=alice,
            dst=target,
            action="iam:PassRole",
            digest="cccccccc" * 8,
            statement_index=2,
        )
        ecs_trust_edge = _trust_edge_from_service(service=ecs_svc, target=target)

        facts = _make_facts(
            nodes=(alice, target, ecs_svc),
            edges=(register_edge_unknown, run_edge_unknown, passrole_edge, ecs_trust_edge),
        )
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        check_1 = next(c for c in f.required_checks if c.name == "source_has_ecs_create_and_run_permissions")
        assert check_1.state.value == "unknown"
        # Both actions must be named in the reason
        assert "ecs:RegisterTaskDefinition" in check_1.reason, (
            f"check 1 reason must name RegisterTaskDefinition; got: {check_1.reason!r}"
        )
        assert "ecs:RunTask" in check_1.reason, f"check 1 reason must name RunTask; got: {check_1.reason!r}"

    def test_both_witnesses_cited_in_evidence_refs(self) -> None:
        """When both ECS edges are present, check 1 evidence_refs cites BOTH.

        The Lambda reasoner cites ONE witness (the lambda:CreateFunction
        edge). The ECS reasoner must cite both the RegisterTaskDefinition
        witness and the RunTask witness so a reviewer can inspect both
        grants. This is visible in the Check.evidence_refs field.
        """
        facts, _, _, _ = _build_admin_chain()
        findings = PassRoleEcsReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        check_1 = next(c for c in f.required_checks if c.name == "source_has_ecs_create_and_run_permissions")
        assert len(check_1.evidence_refs) == 2, (
            f"check 1 evidence_refs should cite both ECS witnesses; got {len(check_1.evidence_refs)} refs"
        )
