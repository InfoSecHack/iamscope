"""CC-1 identity-policy Deny integration tests.

These tests exercise the parser -> resolver -> scenario emission -> FactGraph
path for identity-policy Deny, then run reasoners over the emitted scenario
objects. They deliberately avoid hand-crafted scenario dictionaries so the
pipeline wiring and binding metadata sidecar stay covered.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from iamscope.collector.account import AccountData
from iamscope.constants import (
    CONSTRAINT_TYPE_IDENTITY_DENY,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    AccountInfo,
    Constraint,
    Edge,
    EdgeConstraint,
    Node,
    OrgData,
    PermissionParseResult,
    ScenarioMetadata,
)
from iamscope.output.scenario_json import emit_binding_metadata, emit_scenario
from iamscope.parser.permission_policy import parse_permission_denies, parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.reasoner import AdminReachabilityReasoner, AssumeRoleChainReasoner, FactGraph
from iamscope.reasoner.cross_reasoner_consistency import apply_cross_reasoner_demotions
from iamscope.reasoner.verdict import Finding

_ACCOUNT = "111111111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_BOB_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Bob"
_DEVOPS_ARN = f"arn:aws:iam::{_ACCOUNT}:role/DevOps"
_ADMIN_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Admin"


@dataclass(frozen=True)
class _PipelineCase:
    nodes: list[Node]
    edges: list[Edge]
    constraints: list[Constraint]
    edge_constraints: list[EdgeConstraint]
    facts: FactGraph
    scenario: dict[str, Any]
    binding_metadata: list[dict[str, Any]]
    account: AccountData


def _node(node_type: str, arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=node_type,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": _ACCOUNT},
    )


def _trust_doc(principal_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _allow_doc(action: str, resource: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": resource,
            }
        ],
    }


def _deny_doc(
    *,
    action: str | None = "sts:AssumeRole",
    not_action: str | None = None,
    resource: str = _DEVOPS_ARN,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stmt: dict[str, Any] = {"Effect": "Deny", "Resource": resource}
    if action is not None:
        stmt["Action"] = action
    if not_action is not None:
        stmt["NotAction"] = not_action
    if condition is not None:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _permission_results(
    principal_arn: str,
    principal_type: str,
    policy_doc: dict[str, Any],
    policy_name: str,
) -> list[PermissionParseResult]:
    return parse_permission_policy(
        policy_doc,
        source_arn=principal_arn,
        source_node_type=principal_type,
        source_account_id=_ACCOUNT,
        policy_source="inline",
        policy_name=policy_name,
    )


def _build_case(
    *,
    deny_principal_arn: str | None = None,
    deny_policy_doc: dict[str, Any] | None = None,
) -> _PipelineCase:
    alice = _node(NODE_TYPE_IAM_USER, _ALICE_ARN)
    devops = _node(NODE_TYPE_IAM_ROLE, _DEVOPS_ARN)
    admin = _node(NODE_TYPE_IAM_ROLE, _ADMIN_ARN)

    permission_results = []
    permission_results.extend(
        _permission_results(
            _ALICE_ARN,
            NODE_TYPE_IAM_USER,
            _allow_doc("sts:AssumeRole", _DEVOPS_ARN),
            "AliceAssumeDevOps",
        )
    )
    permission_results.extend(
        _permission_results(
            _DEVOPS_ARN,
            NODE_TYPE_IAM_ROLE,
            _allow_doc("sts:AssumeRole", _ADMIN_ARN),
            "DevOpsAssumeAdmin",
        )
    )
    permission_results.extend(
        _permission_results(
            _ADMIN_ARN,
            NODE_TYPE_IAM_ROLE,
            _allow_doc("*", "*"),
            "AdminAccess",
        )
    )

    raw_deny_results = []
    if deny_principal_arn is not None and deny_policy_doc is not None:
        raw_deny_results = parse_permission_denies(
            deny_policy_doc,
            principal_arn=deny_principal_arn,
            policy_id=f"inline:{deny_principal_arn}:DenyPolicy",
        )

    trust_results = [(devops, tr) for tr in parse_trust_policy(_trust_doc(_ALICE_ARN), _DEVOPS_ARN, _ACCOUNT)]
    trust_results.extend((admin, tr) for tr in parse_trust_policy(_trust_doc(_DEVOPS_ARN), _ADMIN_ARN, _ACCOUNT))

    account = AccountData(
        account_id=_ACCOUNT,
        nodes=[alice, devops, admin],
        trust_results=trust_results,
        permission_results=permission_results,
        raw_deny_results=raw_deny_results,
        role_arns=[_DEVOPS_ARN, _ADMIN_ARN],
    )
    org = OrgData(
        org_id="o-test",
        root_id="r-test",
        accounts=[
            AccountInfo(
                account_id=_ACCOUNT,
                name="test",
                email="test@example.com",
                status="ACTIVE",
                parent_id="r-test",
            )
        ],
    )

    nodes, edges, constraints, edge_constraints, budget_hit = _run_resolution(
        org,
        [account],
        PipelineConfig(),
        service_nodes=[],
        service_edges=[],
    )
    assert budget_hit is False

    metadata = ScenarioMetadata(
        org_id="o-test",
        accounts_collected=1,
        accounts_skipped=0,
        collection_timestamp="2026-01-01T00:00:00Z",
        collection_duration_seconds=0.0,
        graph_stats={
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_constraints": len(constraints),
            "total_edge_constraints": len(edge_constraints),
        },
    )
    scenario_bytes, scenario_hash = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=metadata,
    )
    facts = FactGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        constraints=tuple(constraints),
        edge_constraints=tuple(edge_constraints),
        scenario_hash=scenario_hash,
        edge_budget_exhausted=False,
    )
    return _PipelineCase(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        facts=facts,
        scenario=json.loads(scenario_bytes),
        binding_metadata=json.loads(emit_binding_metadata(edge_constraints)),
        account=account,
    )


def _identity_deny_constraints(case: _PipelineCase) -> list[Constraint]:
    return [c for c in case.constraints if c.constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY]


def _alice_to_devops_edge(case: _PipelineCase) -> Edge:
    return next(
        e
        for e in case.edges
        if e.edge_type == "sts:AssumeRole_permission"
        and e.src.provider_id == _ALICE_ARN
        and e.dst.provider_id == _DEVOPS_ARN
    )


def _alice_admin_arc_finding(case: _PipelineCase) -> Finding:
    findings = AssumeRoleChainReasoner().run(case.facts)
    return next(f for f in findings if f.source.provider_id == _ALICE_ARN and f.target.provider_id == _ADMIN_ARN)


def test_pipeline_deny_produces_blocked_finding_and_cross_reasoner_demotes() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(resource=_DEVOPS_ARN),
    )

    arc = _alice_admin_arc_finding(case)
    assert arc.verdict.value == "blocked"
    assert arc.severity == "info"
    assert any(b.kind == "identity_deny" for b in arc.blockers_observed)

    admin_reachability = AdminReachabilityReasoner().run(case.facts)
    reconciled = apply_cross_reasoner_demotions([arc, *admin_reachability])
    ar = next(
        f
        for f in reconciled
        if f.pattern_id == "admin_reachability"
        and f.source.provider_id == _ALICE_ARN
        and f.target.provider_id == _ADMIN_ARN
    )
    assert ar.verdict.value == "inconclusive"
    assert any(b.kind == "cross_reasoner_blocked" for b in ar.blockers_observed)


def test_pipeline_deny_constraint_in_fact_graph() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(resource=_DEVOPS_ARN),
    )

    constraints = _identity_deny_constraints(case)
    assert len(constraints) == 1
    assert case.facts.constraint_by_id(constraints[0].constraint_id) == constraints[0]
    assert case.account.permission_deny_constraints == constraints
    assert case.scenario["constraints"][0]["constraint_type"] == CONSTRAINT_TYPE_IDENTITY_DENY


def test_pipeline_deny_binding_in_fact_graph() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(resource=_DEVOPS_ARN),
    )
    constraint = _identity_deny_constraints(case)[0]
    edge = _alice_to_devops_edge(case)

    bindings = case.facts.bindings_for_edge(edge.edge_id)
    assert any(b.constraint_id == constraint.constraint_id for b in bindings)


def test_pipeline_conditional_deny_inconclusive() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(
            resource=_DEVOPS_ARN,
            condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        ),
    )

    finding = _alice_admin_arc_finding(case)
    assert finding.verdict.value == "inconclusive"
    check = next(c for c in finding.required_checks if c.name == "no_identity_deny_blocks_any_hop")
    assert check.state.value == "unknown"


def test_pipeline_notaction_deny_conservative() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(action=None, not_action="s3:*", resource=_DEVOPS_ARN),
    )

    constraint = _identity_deny_constraints(case)[0]
    assert constraint.properties["parse_status"] == "partial"
    binding = next(iter(case.facts.bindings_for_edge(_alice_to_devops_edge(case).edge_id)))
    assert binding.governance_confidence == "partial"
    finding = _alice_admin_arc_finding(case)
    assert finding.verdict.value == "inconclusive"


def test_pipeline_deny_wrong_principal_no_effect() -> None:
    case = _build_case(
        deny_principal_arn=_BOB_ARN,
        deny_policy_doc=_deny_doc(resource=_DEVOPS_ARN),
    )

    assert len(_identity_deny_constraints(case)) == 1
    assert case.edge_constraints == []
    finding = _alice_admin_arc_finding(case)
    assert finding.verdict.value == "validated"


def test_pipeline_no_deny_stmts_clean_run() -> None:
    case = _build_case()

    assert _identity_deny_constraints(case) == []
    assert case.edge_constraints == []
    finding = _alice_admin_arc_finding(case)
    assert finding.verdict.value == "validated"
    assert finding.severity == "high"


def test_binding_metadata_includes_deny_bindings() -> None:
    case = _build_case(
        deny_principal_arn=_ALICE_ARN,
        deny_policy_doc=_deny_doc(resource=_DEVOPS_ARN),
    )
    constraint = _identity_deny_constraints(case)[0]

    entry = next(item for item in case.binding_metadata if item["constraint_id"] == constraint.constraint_id)
    metadata = entry["binding_metadata"]
    assert metadata["governance_confidence"] == "complete"
    assert metadata["likely_blocking"] is True
    assert "identity policy Deny" in metadata["binding_reason"]
