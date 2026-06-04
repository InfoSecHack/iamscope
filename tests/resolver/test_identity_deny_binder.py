"""Tests for identity-policy Deny resolver binding."""

from __future__ import annotations

from iamscope.collector.account import AccountData
from iamscope.constants import (
    CONFIDENCE_Q_COMPLETE_BLOCKING,
    CONFIDENCE_Q_PARTIAL,
    CONSTRAINT_TYPE_IDENTITY_DENY,
    CONSTRAINT_TYPE_SCP,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    GOVERNANCE_CONFIDENCE_PARTIAL,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    AccountInfo,
    Constraint,
    Edge,
    Node,
    NodeRef,
    OrgData,
    PermissionDenyResult,
    PermissionParseResult,
)
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.resolver.identity_deny_binder import (
    bind_all_identity_denies,
    bind_identity_deny_to_edge,
    build_identity_deny_constraints,
)

PRINCIPAL_ARN = "arn:aws:iam::111111\u003111111:user/Admin"
OTHER_PRINCIPAL_ARN = "arn:aws:iam::111111\u003111111:user/Other"
TARGET_ROLE_ARN = "arn:aws:iam::222222\u003222222:role/ProdDeploy"
POLICY_ARN = "arn:aws:iam::111111\u003111111:policy/DenyPolicy"


def _deny_result(
    *,
    principal_arn: str = PRINCIPAL_ARN,
    policy_arn: str = POLICY_ARN,
    statement_id: str = "DenyStmt",
    deny_actions: list[str] | None = None,
    resource_patterns: list[str] | None = None,
    has_conditions: bool = False,
    raw_conditions: dict | None = None,
    parse_status: str = "complete",
) -> PermissionDenyResult:
    return PermissionDenyResult(
        principal_arn=principal_arn,
        policy_arn=policy_arn,
        statement_id=statement_id,
        deny_actions=deny_actions if deny_actions is not None else ["sts:AssumeRole"],
        resource_patterns=resource_patterns or ["*"],
        has_conditions=has_conditions,
        raw_conditions=raw_conditions or {},
        parse_status=parse_status,
    )


def _constraint(
    deny_result: PermissionDenyResult | None = None,
) -> Constraint:
    return build_identity_deny_constraints([deny_result or _deny_result()])[0]


def _edge(
    *,
    action: str = "sts:AssumeRole",
    src_id: str = PRINCIPAL_ARN,
    dst_id: str = TARGET_ROLE_ARN,
    edge_type: str | None = None,
) -> Edge:
    return Edge(
        edge_type=edge_type or f"{action}_permission",
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=src_id,
            region=REGION_GLOBAL,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=dst_id,
            region=REGION_GLOBAL,
        ),
        region=REGION_GLOBAL,
        features={"layer": "permission"},
    )


def _scp_constraint() -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod",
        policy_id="p-001",
        statement_id="DenyStmt",
        properties={"deny_actions": ["sts:AssumeRole"]},
    )


class TestBuildIdentityDenyConstraints:
    def test_complete_unconditional_deny_confidence_q(self) -> None:
        constraints = build_identity_deny_constraints([_deny_result()])

        assert constraints[0].confidence_q == CONFIDENCE_Q_COMPLETE_BLOCKING

    def test_conditional_deny_confidence_q(self) -> None:
        constraints = build_identity_deny_constraints(
            [
                _deny_result(
                    has_conditions=True,
                    raw_conditions={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
                ),
            ]
        )

        assert constraints[0].confidence_q == CONFIDENCE_Q_PARTIAL

    def test_partial_parse_confidence_q(self) -> None:
        constraints = build_identity_deny_constraints(
            [
                _deny_result(parse_status="partial"),
            ]
        )

        assert constraints[0].confidence_q == CONFIDENCE_Q_PARTIAL

    def test_constraint_type_identity_deny(self) -> None:
        constraints = build_identity_deny_constraints([_deny_result()])

        assert constraints[0].constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY

    def test_scope_type_principal(self) -> None:
        constraints = build_identity_deny_constraints([_deny_result()])

        assert constraints[0].scope_type == "Principal"
        assert constraints[0].scope_id == PRINCIPAL_ARN


class TestBindIdentityDenyToEdge:
    def test_matching_action_binds(self) -> None:
        edge = _edge()
        constraint = _constraint()

        binding = bind_identity_deny_to_edge(edge, constraint)

        assert binding is not None
        assert binding.edge_id == edge.edge_id
        assert binding.constraint_id == constraint.constraint_id
        assert binding.likely_blocking is True

    def test_wildcard_action_binds(self) -> None:
        edge = _edge()
        constraint = _constraint(_deny_result(deny_actions=["sts:*"]))

        assert bind_identity_deny_to_edge(edge, constraint) is not None

    def test_star_action_binds(self) -> None:
        edge = _edge(action="iam:PassRole")
        constraint = _constraint(_deny_result(deny_actions=["*"]))

        assert bind_identity_deny_to_edge(edge, constraint) is not None

    def test_non_matching_action_no_bind(self) -> None:
        edge = _edge(action="iam:PassRole")
        constraint = _constraint(_deny_result(deny_actions=["sts:AssumeRole"]))

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_wrong_principal_no_bind(self) -> None:
        edge = _edge(src_id=OTHER_PRINCIPAL_ARN)
        constraint = _constraint()

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_resource_mismatch_no_bind(self) -> None:
        edge = _edge(dst_id=TARGET_ROLE_ARN)
        constraint = _constraint(
            _deny_result(
                resource_patterns=["arn:aws:iam::222222\u003222222:role/Other"],
            )
        )

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_conditional_deny_governance_needs_review(self) -> None:
        edge = _edge()
        constraint = _constraint(
            _deny_result(
                has_conditions=True,
                raw_conditions={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
            )
        )

        binding = bind_identity_deny_to_edge(edge, constraint)

        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_NEEDS_REVIEW
        assert binding.likely_blocking is True

    def test_complete_deny_governance_complete(self) -> None:
        edge = _edge()
        constraint = _constraint()

        binding = bind_identity_deny_to_edge(edge, constraint)

        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_COMPLETE
        assert binding.likely_blocking is True

    def test_partial_deny_governance_partial(self) -> None:
        edge = _edge()
        constraint = _constraint(_deny_result(parse_status="partial"))

        binding = bind_identity_deny_to_edge(edge, constraint)

        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_PARTIAL
        assert binding.likely_blocking is True

    def test_partial_parse_action_mismatch_no_bind(self) -> None:
        edge = _edge(action="sts:AssumeRole")
        constraint = _constraint(_deny_result(deny_actions=["s3:*"], parse_status="partial"))

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_partial_parse_matching_action_binds_partial(self) -> None:
        edge = _edge(action="sts:AssumeRole")
        constraint = _constraint(_deny_result(deny_actions=["sts:AssumeRole"], parse_status="partial"))

        binding = bind_identity_deny_to_edge(edge, constraint)

        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_PARTIAL
        assert binding.likely_blocking is True

    def test_partial_parse_empty_deny_actions_no_broad_bind(self) -> None:
        edge = _edge(action="iam:PassRole")
        constraint = _constraint(_deny_result(deny_actions=[], parse_status="partial"))

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_conditional_deny_action_mismatch_no_bind(self) -> None:
        edge = _edge(action="iam:PassRole")
        constraint = _constraint(
            _deny_result(
                deny_actions=["sts:AssumeRole"],
                has_conditions=True,
                raw_conditions={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
            )
        )

        assert bind_identity_deny_to_edge(edge, constraint) is None

    def test_non_permission_edge_no_bind(self) -> None:
        edge = _edge(edge_type="sts:AssumeRole_trust")
        constraint = _constraint()

        assert bind_identity_deny_to_edge(edge, constraint) is None


class TestBindAllIdentityDenies:
    def test_no_deny_constraints_returns_empty(self) -> None:
        assert bind_all_identity_denies([_edge()], []) == []

    def test_single_match(self) -> None:
        edge = _edge()
        constraint = _constraint()

        bindings = bind_all_identity_denies([edge], [constraint])

        assert len(bindings) == 1
        assert bindings[0].edge_id == edge.edge_id

    def test_multiple_edges_selective_binding(self) -> None:
        matching = _edge(src_id=PRINCIPAL_ARN)
        other = _edge(src_id=OTHER_PRINCIPAL_ARN)
        constraint = _constraint()

        bindings = bind_all_identity_denies([matching, other], [constraint])

        assert len(bindings) == 1
        assert bindings[0].edge_id == matching.edge_id

    def test_non_identity_deny_constraints_filtered(self) -> None:
        edge = _edge()

        assert bind_all_identity_denies([edge], [_scp_constraint()]) == []

    def test_multiple_deny_stmts_multiple_bindings(self) -> None:
        edge = _edge()
        constraints = build_identity_deny_constraints(
            [
                _deny_result(statement_id="DenyAssumeRole"),
                _deny_result(statement_id="DenySTS", deny_actions=["sts:*"]),
            ]
        )

        bindings = bind_all_identity_denies([edge], constraints)

        assert len(bindings) == 2
        assert {b.constraint_id for b in bindings} == {c.constraint_id for c in constraints}


class TestPipelineIdentityDenyWiring:
    def test_run_resolution_consumes_raw_deny_results(self) -> None:
        source_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=PRINCIPAL_ARN,
            region=REGION_GLOBAL,
            properties={"account_id": "111111\u003111111"},
        )
        target_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=TARGET_ROLE_ARN,
            region=REGION_GLOBAL,
            properties={"account_id": "222222\u003222222"},
        )
        acct = AccountData(
            account_id="111111\u003111111",
            nodes=[source_node, target_node],
            permission_results=[
                PermissionParseResult(
                    statement_index=0,
                    effect="Allow",
                    action="sts:AssumeRole",
                    resource_pattern=TARGET_ROLE_ARN,
                    is_wildcard_resource=False,
                    source_arn=PRINCIPAL_ARN,
                    source_node_type=NODE_TYPE_IAM_USER,
                    source_account_id="111111\u003111111",
                    policy_source="inline",
                    policy_name="AllowAssumeRole",
                ),
            ],
            raw_deny_results=[_deny_result(resource_patterns=[TARGET_ROLE_ARN])],
            role_arns=[TARGET_ROLE_ARN],
        )
        org_data = OrgData(
            org_id="standalone",
            root_id="standalone",
            accounts=[
                AccountInfo(
                    account_id="111111\u003111111",
                    name="standalone",
                    email="",
                    status="ACTIVE",
                    parent_id="standalone",
                ),
            ],
        )

        _nodes, _edges, constraints, edge_constraints, _budget_hit = _run_resolution(
            org_data,
            [acct],
            PipelineConfig(),
            service_nodes=[],
            service_edges=[],
        )

        deny_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY]
        assert len(deny_constraints) == 1
        assert acct.permission_deny_constraints == deny_constraints
        assert any(ec.constraint_id == deny_constraints[0].constraint_id for ec in edge_constraints)
