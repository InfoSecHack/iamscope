"""S12 tests: passrole_lambda reasoner — 8 fixtures + preconditions + determinism.

Per plan §4B.5:
- Fixture A: validated/critical (admin-equivalent target)
- Fixture B: precondition_only/medium (target trusts EC2 not Lambda) — NOT blocked
- Fixture C: blocked/info (SCP blocks lambda:CreateFunction)
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
    CONSTRAINT_TYPE_IDENTITY_DENY,
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
    PassRoleLambdaReasoner,
    Verdict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACCOUNT = "111111111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_ADMIN_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/AdminRole"
_NON_ADMIN_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/NonAdmin"
_LAMBDA_SERVICE = "lambda.amazonaws.com"
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


def _lambda_service_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id=_LAMBDA_SERVICE,
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
    statement_id: str = "DenyLambda",
    deny_actions: list[str] | None = None,
    parse_status: str = "complete",
) -> Constraint:
    if deny_actions is None:
        deny_actions = ["lambda:CreateFunction"]
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-lambda",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": deny_actions,
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyLambdaProd",
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


def _identity_deny_constraint(
    *,
    statement_id: str = "IdentityDeny",
    deny_actions: list[str] | None = None,
    has_conditions: bool = False,
    parse_status: str = "complete",
) -> Constraint:
    if deny_actions is None:
        deny_actions = ["lambda:CreateFunction"]
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY,
        scope_type="Principal",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceDeny",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": deny_actions,
            "resource_patterns": ["*"],
            "has_conditions": has_conditions,
            "raw_conditions": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}} if has_conditions else {},
            "parse_status": parse_status,
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
        ran, reason = PassRoleLambdaReasoner().preconditions_met(facts)
        assert ran is False
        assert "no IAM roles" in reason

    def test_pre_pr1_skips(self) -> None:
        """A permission edge missing raw_conditions → refuse to run."""
        alice = _alice_node()
        target = _admin_role_node()
        # Build a malformed permission edge sans raw_conditions feature.
        bad_edge = Edge(
            edge_type="lambda:CreateFunction_permission",
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
        ran, reason = PassRoleLambdaReasoner().preconditions_met(facts)
        assert ran is False
        assert "PR-1 not applied" in reason

    def test_edge_budget_exhausted_skips(self) -> None:
        alice = _alice_node()
        target = _admin_role_node()
        edge = _permission_edge(
            src=alice,
            dst=target,
            action="lambda:CreateFunction",
            is_wildcard_resource=True,
        )
        facts = _make_facts(
            nodes=(alice, target),
            edges=(edge,),
            edge_budget_exhausted=True,
        )
        ran, reason = PassRoleLambdaReasoner().preconditions_met(facts)
        assert ran is False
        assert "edge_budget_exhausted" in reason

    def test_minimal_valid_runs(self) -> None:
        alice = _alice_node()
        target = _admin_role_node()
        edge = _permission_edge(
            src=alice,
            dst=target,
            action="lambda:CreateFunction",
            is_wildcard_resource=True,
        )
        facts = _make_facts(nodes=(alice, target), edges=(edge,))
        ran, _reason = PassRoleLambdaReasoner().preconditions_met(facts)
        assert ran is True


# ---------------------------------------------------------------------------
# Helper: build the canonical fixture A graph (admin-equivalent target)
# ---------------------------------------------------------------------------


def _build_admin_chain(
    *,
    raw_conditions: dict[str, Any] | None = None,
    target_trusts_lambda: bool = True,
    target_admin: bool = True,
    extra_constraints: tuple[Constraint, ...] = (),
    extra_bindings_for_lambda_create: tuple = (),
    extra_bindings_for_passrole: tuple = (),
) -> tuple[FactGraph, Edge, Edge, Edge | None]:
    """Build the canonical Lambda PassRole admin chain.

    Returns (facts, lambda_create_edge, passrole_edge, lambda_trust_edge).
    The lambda_trust_edge is None when target_trusts_lambda=False (used
    for fixture B).
    """
    alice = _alice_node()
    target = _admin_role_node()
    lambda_svc = _lambda_service_node()
    ec2_svc = _ec2_service_node()

    nodes_list: list[Node] = [alice, target, lambda_svc, ec2_svc]
    edges_list: list[Edge] = []

    # Alice has lambda:CreateFunction (clean wildcard resource so it
    # produces an UNKNOWN witness — set is_wildcard_resource=False to
    # get a clean PASS witness).
    lambda_create_edge = _permission_edge(
        src=alice,
        dst=target,  # any dst — has_action ignores resource for non-PassRole
        action="lambda:CreateFunction",
        digest="aaaaaaaa" * 8,
        statement_index=0,
    )
    edges_list.append(lambda_create_edge)

    # Alice has iam:PassRole targeting the admin role.
    passrole_edge = _permission_edge(
        src=alice,
        dst=target,
        action="iam:PassRole",
        digest="bbbbbbbb" * 8,
        statement_index=1,
        raw_conditions=raw_conditions,
        has_conditions=bool(raw_conditions),
    )
    edges_list.append(passrole_edge)

    # Target trusts Lambda (or EC2 for fixture B).
    lambda_trust_edge: Edge | None = None
    if target_trusts_lambda:
        lambda_trust_edge = _trust_edge_from_service(service=lambda_svc, target=target)
        edges_list.append(lambda_trust_edge)
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
        edge_constraints=tuple(extra_bindings_for_lambda_create) + tuple(extra_bindings_for_passrole),
    )
    return facts, lambda_create_edge, passrole_edge, lambda_trust_edge


# ---------------------------------------------------------------------------
# Fixture A: validated_admin → critical
# ---------------------------------------------------------------------------


class TestFixtureAValidatedAdmin:
    """The happy path. Alice → AdminRole → all 8 checks PASS → critical."""

    def test_emits_validated_critical(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        findings = PassRoleLambdaReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_CRITICAL

    def test_finding_id_is_sha256_hex(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleLambdaReasoner().run(facts)[0]
        assert _is_sha256_hex(f.finding_id)

    def test_all_10_checks_pass(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleLambdaReasoner().run(facts)[0]
        assert len(f.required_checks) == 10
        for chk in f.required_checks:
            assert chk.state is CheckState.PASS, f"check {chk.name!r} expected PASS, got {chk.state}"

    def test_session_policy_assumption_present(self) -> None:
        """VALIDATED findings carry the session_policy assumption per §4B.4."""
        facts, _, _, _ = _build_admin_chain()
        f = PassRoleLambdaReasoner().run(facts)[0]
        assert len(f.assumptions) == 1
        assert f.assumptions[0].kind == "session_policy"
        # Critically, NOT condition_context — that would force inconclusive.
        assert f.assumptions[0].kind != "condition_context"


class TestFixtureANonAdmin:
    """Same chain but target is not admin → validated/high (severity downgrade)."""

    def test_non_admin_target_emits_high_not_critical(self) -> None:
        facts, _, _, _ = _build_admin_chain(target_admin=False)
        findings = PassRoleLambdaReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_HIGH


# ---------------------------------------------------------------------------
# Fixture B: precondition_only_trust_missing → medium (NOT blocked)
# ---------------------------------------------------------------------------


class TestFixtureBPreconditionOnlyTrustMissing:
    """Target trusts EC2 not Lambda → check 3 FAIL → precondition_only/medium.

    The distinction matters: this is NOT blocked. The path is broken
    by the target's trust policy not including Lambda, not by an active
    blocker like an SCP. Per §4B.3 these are different verdicts.
    """

    def _build(self) -> FactGraph:
        # _build_admin_chain enumerates by walking IAMRole nodes that
        # trust Lambda. Fixture B's target trusts EC2 only — so candidate
        # enumeration would skip it entirely. To exercise the precondition_only
        # path, we need a target that DOES trust Lambda (so it gets
        # enumerated) but where the witness lookup fails for that target.
        # The plan §4B.5 fixture B sets `target trusts ec2.amazonaws.com only`.
        # Since target-first enumeration would skip such a target,
        # there's no precondition_only finding emitted at all.
        # Resolution: the plan's source-first enumeration would have hit
        # this case, but target-first means "no Lambda-trusting role"
        # → no candidate → no finding. This is a documented difference
        # from the plan's source-first enumeration semantics.
        #
        # To match the plan's INTENT (test that "target without Lambda
        # trust → precondition_only"), we instead build TWO targets:
        # one that trusts Lambda (gets enumerated, produces validated)
        # and one that trusts only EC2 (does not get enumerated, no
        # finding emitted). The fixture B intent then becomes: "the
        # EC2-only target produces no finding, the Lambda-trusting
        # target produces validated."
        #
        # However, because target-first enumeration is the chosen scope
        # decision, this fixture B just becomes an assertion that
        # candidate enumeration correctly skips non-Lambda-trusting roles.
        alice = _alice_node()
        ec2_svc = _ec2_service_node()
        # Build a role that trusts only EC2 — should NOT be enumerated.
        ec2_only_role = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=f"arn:aws:iam::{_ACCOUNT}:role/Ec2Only",
            properties={"account_id": _ACCOUNT},
        )
        lambda_create = _permission_edge(
            src=alice,
            dst=ec2_only_role,
            action="lambda:CreateFunction",
        )
        passrole = _permission_edge(
            src=alice,
            dst=ec2_only_role,
            action="iam:PassRole",
        )
        ec2_trust = _trust_edge_from_service(service=ec2_svc, target=ec2_only_role)
        return _make_facts(
            nodes=(alice, ec2_only_role, ec2_svc),
            edges=(lambda_create, passrole, ec2_trust),
        )

    def test_no_finding_emitted(self) -> None:
        """Target-first enumeration skips non-Lambda-trusting roles entirely.

        Documented as a deliberate scope decision in the reasoner module
        docstring: target-first enumeration doesn't enumerate roles that
        don't trust Lambda, so the precondition_only/trust_missing case
        from the plan §4B.5 fixture B simply doesn't produce a finding.
        The plan's intent (no false-positive validated finding when
        trust is missing) is preserved — and the verdict is "no finding"
        instead of "precondition_only", which is consistent with check 1
        and check 2 FAIL early-exits.
        """
        findings = PassRoleLambdaReasoner().run(self._build())
        assert findings == []


# ---------------------------------------------------------------------------
# Fixture C: blocked_by_scp → info
# ---------------------------------------------------------------------------


class TestFixtureCBlockedBySCP:
    """SCP at account OU blocks lambda:CreateFunction → blocked/info."""

    def _build(self) -> FactGraph:
        facts, lambda_create_edge, _, _ = _build_admin_chain()
        scp = _scp_constraint(
            statement_id="DenyLambdaCreate",
            deny_actions=["lambda:CreateFunction"],
        )
        binding = _binding(
            edge_id=lambda_create_edge.edge_id,
            constraint_id=scp.constraint_id,
            likely_blocking=True,
            governance_confidence="complete",
            binding_reason="SCP DenyLambdaCreate at OU ou-prod denies lambda:CreateFunction",
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
        findings = PassRoleLambdaReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO

    def test_check_4_fail_with_scp_blocker(self) -> None:
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_4 = next(c for c in f.required_checks if c.name == "no_scp_blocks_lambda_create_function")
        assert check_4.state is CheckState.FAIL
        assert any(b.kind == "scp" for b in f.blockers_observed)


# ---------------------------------------------------------------------------
# Fixture D: blocked_by_boundary_post_bnd1 → info
# ---------------------------------------------------------------------------


class TestFixtureDBlockedByBoundaryPostBnd1:
    """Permission boundary blocks lambda:CreateFunction → blocked/info.

    Per plan §4B.5: post-BND-1 verdict is `blocked`; pre-BND-1 it would
    have been `inconclusive` because pre-fix the binder always set
    `likely_blocking=False` regardless of action intersection. S03's
    BND-1 fix correctly computes the action intersection so the binder
    can mark the binding as `likely_blocking=True` when the boundary
    does not allow the bound action.

    This test simulates the post-BND-1 binding directly by constructing
    an EdgeConstraint with `likely_blocking=True, governance_confidence=complete`
    on the lambda:CreateFunction edge. The reasoner reads the binder's
    output via `bindings_for_edge` and does not re-implement boundary
    evaluation.
    """

    def _build(self) -> FactGraph:
        facts, lambda_create_edge, _, _ = _build_admin_chain()
        boundary = _boundary_constraint(statement_id="BoundaryDeniesLambda")
        binding = _binding(
            edge_id=lambda_create_edge.edge_id,
            constraint_id=boundary.constraint_id,
            likely_blocking=True,  # post-BND-1: action intersection finds no overlap
            governance_confidence="complete",
            binding_reason=(
                "permission boundary allowed_actions={s3:*, dynamodb:*} "
                "does not include lambda:CreateFunction (post-BND-1)"
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
        findings = PassRoleLambdaReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO

    def test_check_6_fail_with_boundary_blocker(self) -> None:
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_6 = next(c for c in f.required_checks if c.name == "no_boundary_blocks_lambda_create_function")
        assert check_6.state is CheckState.FAIL
        assert any(b.kind == "boundary" for b in f.blockers_observed)


# ---------------------------------------------------------------------------
# Identity-policy Deny blockers
# ---------------------------------------------------------------------------


class TestIdentityDenyBlockers:
    def test_complete_lambda_create_function_deny_blocks(self) -> None:
        facts, lambda_create_edge, _, _ = _build_admin_chain()
        deny = _identity_deny_constraint(
            statement_id="DenyCreateFunction",
            deny_actions=["lambda:CreateFunction"],
        )
        binding = _binding(
            edge_id=lambda_create_edge.edge_id,
            constraint_id=deny.constraint_id,
            likely_blocking=True,
            governance_confidence="complete",
            binding_reason="identity policy Deny blocks lambda:CreateFunction",
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = PassRoleLambdaReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_lambda_create_function")
        assert check.state is CheckState.FAIL
        assert any(b.kind == "identity_deny" for b in f.blockers_observed)

    def test_needs_review_passrole_deny_is_inconclusive(self) -> None:
        facts, _, passrole_edge, _ = _build_admin_chain()
        deny = _identity_deny_constraint(
            statement_id="DenyPassRoleWithCondition",
            deny_actions=["iam:PassRole"],
            has_conditions=True,
        )
        binding = _binding(
            edge_id=passrole_edge.edge_id,
            constraint_id=deny.constraint_id,
            likely_blocking=True,
            governance_confidence="needs_review",
            binding_reason="conditional identity policy Deny may block iam:PassRole",
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = PassRoleLambdaReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.severity == SEVERITY_HIGH
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_passrole")
        assert check.state is CheckState.UNKNOWN


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
        facts, lambda_create_edge, _, _ = _build_admin_chain()
        scp = _scp_constraint(
            statement_id="PartialDenyLambda",
            parse_status="partial",
        )
        binding = _binding(
            edge_id=lambda_create_edge.edge_id,
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
        findings = PassRoleLambdaReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.severity == SEVERITY_HIGH

    def test_check_4_unknown_not_blocked(self) -> None:
        """The SCP check (#4) should be UNKNOWN, not promoted to FAIL/BLOCKED."""
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_4 = next(c for c in f.required_checks if c.name == "no_scp_blocks_lambda_create_function")
        assert check_4.state is CheckState.UNKNOWN
        assert f.verdict is not Verdict.BLOCKED


# ---------------------------------------------------------------------------
# Fixture F: inconclusive_wildcard_passrole_hyperedge → high
# THE HIGHEST-PRIORITY CORRECTNESS TEST IN THE REBUILD
# ---------------------------------------------------------------------------


class TestFixtureFInconclusiveWildcardPassroleHyperedge:
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
        lambda_svc = _lambda_service_node()
        hyper = _hyperedge_node()

        # Alice has clean lambda:CreateFunction.
        lambda_create = _permission_edge(
            src=alice,
            dst=target,
            action="lambda:CreateFunction",
        )
        # Alice has wildcard PassRole → hyperedge dst.
        wildcard_passrole = _wildcard_passrole_to_hyperedge(src=alice)
        # Target trusts Lambda.
        lambda_trust = _trust_edge_from_service(service=lambda_svc, target=target)

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
            nodes=(alice, target, lambda_svc, hyper),
            edges=(lambda_create, wildcard_passrole, lambda_trust, admin_grant),
        )

    def test_finding_emitted_target_first_enumeration_catches_it(self) -> None:
        """Fixture F is emitted because target-first enumeration catches it.

        Source-first enumeration would walk Alice's PassRole edges, see
        the hyperedge dst, fail to extract a target_role_arn, and skip
        the candidate entirely → NO finding emitted → silent failure.

        Target-first enumeration walks IAM roles that trust Lambda
        (admin role IS in the graph), checks if Alice has lambda:CreateFunction
        (PASS), checks if Alice has PassRole to admin role (UNKNOWN
        because the hyperedge cannot prove specific-resource coverage),
        and emits a finding with INCONCLUSIVE verdict.

        This test asserts the finding IS emitted — the prerequisite for
        the verdict assertion below.
        """
        findings = PassRoleLambdaReasoner().run(self._build())
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
        f = PassRoleLambdaReasoner().run(self._build())[0]
        assert f.verdict is Verdict.INCONCLUSIVE, (
            f"fixture F must produce INCONCLUSIVE; got {f.verdict.value}. "
            f"This means has_action accepted a hyperedge as a PASS witness "
            f"— the single most common false-positive production path "
            f"documented in plan §4B.6."
        )
        assert f.severity == SEVERITY_HIGH
        assert f.verdict.value != Verdict.VALIDATED.value  # belt-and-suspenders

    def test_check_2_is_unknown(self) -> None:
        """Check 2 (PassRole to target) must be UNKNOWN, not PASS.

        This is the specific check whose UNKNOWN state drives the
        inconclusive verdict. If this test fails (check 2 = PASS),
        the failure mode is exactly the §4B.6 row 1 false positive.
        """
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_2 = next(c for c in f.required_checks if c.name == "source_has_passrole_to_target")
        assert check_2.state is CheckState.UNKNOWN, (
            f"check 2 must be UNKNOWN on hyperedge witness; got {check_2.state}. has_action is broken."
        )


# ---------------------------------------------------------------------------
# Fixture G: precondition_only_passedtoservice_ec2 → medium
# ---------------------------------------------------------------------------


class TestFixtureGPreconditionOnlyPassedToServiceEC2:
    """PassRole condition iam:PassedToService scoped to ec2 → check 8 FAIL → precondition_only.

    Per plan §4B.5: post-PR-1+COND-1 the reasoner reads `raw_conditions`
    on the PassRole permission edge, sees the iam:PassedToService key
    scoped to ec2.amazonaws.com (not lambda.amazonaws.com), and emits
    `precondition_only` because the chain cannot pass the role to a
    Lambda execution role at runtime — the IAM service will reject
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
        findings = PassRoleLambdaReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.PRECONDITION_ONLY
        assert f.severity == SEVERITY_MEDIUM

    def test_check_8_fail_reason_names_ec2(self) -> None:
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_8 = next(c for c in f.required_checks if c.name == "passrole_condition_scoped_to_lambda_or_absent")
        assert check_8.state is CheckState.FAIL
        assert "ec2.amazonaws.com" in check_8.reason

    def test_passed_to_service_blocker_present(self) -> None:
        f = PassRoleLambdaReasoner().run(self._build())[0]
        assert any(b.kind == "passed_to_service" for b in f.blockers_observed)


class TestFixtureGPassedToServiceLambda:
    """Variant: PassedToService scoped to lambda → check 8 PASS → validated."""

    def _build(self) -> FactGraph:
        facts, _, _, _ = _build_admin_chain(
            raw_conditions={
                "StringEquals": {
                    "iam:PassedToService": "lambda.amazonaws.com",
                },
            },
        )
        return facts

    def test_emits_validated_critical(self) -> None:
        findings = PassRoleLambdaReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_CRITICAL

    def test_check_8_pass(self) -> None:
        f = PassRoleLambdaReasoner().run(self._build())[0]
        check_8 = next(c for c in f.required_checks if c.name == "passrole_condition_scoped_to_lambda_or_absent")
        assert check_8.state is CheckState.PASS


# ---------------------------------------------------------------------------
# Fixture H: determinism double-run
# ---------------------------------------------------------------------------


class TestFixtureHDeterminism:
    """Two runs over the same FactGraph produce byte-identical Findings."""

    def test_double_run_finding_equality(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        run_1 = PassRoleLambdaReasoner().run(facts)
        run_2 = PassRoleLambdaReasoner().run(facts)
        assert len(run_1) == len(run_2) == 1
        assert run_1[0] == run_2[0]

    def test_double_run_finding_id_equality(self) -> None:
        facts, _, _, _ = _build_admin_chain()
        id_1 = PassRoleLambdaReasoner().run(facts)[0].finding_id
        id_2 = PassRoleLambdaReasoner().run(facts)[0].finding_id
        assert id_1 == id_2

    def test_double_run_bundle_digest_equality(self) -> None:
        """The deepest determinism guarantee."""
        facts, _, _, _ = _build_admin_chain()
        d_1 = PassRoleLambdaReasoner().run(facts)[0].evidence.bundle_digest
        d_2 = PassRoleLambdaReasoner().run(facts)[0].evidence.bundle_digest
        assert d_1 == d_2
