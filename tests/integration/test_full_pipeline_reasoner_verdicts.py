from dataclasses import dataclass
from pathlib import Path

from iamscope.collector.account import AccountData
from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    CONSTRAINT_TYPE_TRUST_CONDITION,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_S3_BUCKET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import AccountInfo, Constraint, Edge, EdgeConstraint, Node, OrgData, ScenarioMetadata
from iamscope.output.scenario_json import emit_binding_metadata, emit_scenario
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _materialize_dangling_endpoints, _run_resolution
from iamscope.reasoner import FactGraph
from iamscope.reasoner.cross_account_trust import CrossAccountTrustReasoner
from iamscope.reasoner.passrole_lambda import PassRoleLambdaReasoner
from iamscope.reasoner.replay import run_reasoners_on_frozen_artifacts
from iamscope.reasoner.s3_bucket_takeover import S3BucketTakeoverReasoner
from iamscope.reasoner.verdict import CheckState, Verdict


@dataclass(frozen=True)
class PipelineBundle:
    facts: FactGraph
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    constraints: tuple[Constraint, ...]
    edge_constraints: tuple[EdgeConstraint, ...]


def _account(digit: str) -> str:
    return digit * 12


def _role_arn(account_id: str, role_name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _user_arn(account_id: str, user_name: str) -> str:
    return f"arn:aws:iam::{account_id}:user/{user_name}"


def _policy_arn(account_id: str, policy_name: str) -> str:
    return f"arn:aws:iam::{account_id}:policy/{policy_name}"


def _account_root_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _role_node(account_id: str, role_name: str, **properties: object) -> Node:
    role_arn = _role_arn(account_id, role_name)
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=role_arn,
        region=REGION_GLOBAL,
        properties={"account_id": account_id, "path": "/", **properties},
    )


def _user_node(account_id: str, user_name: str) -> Node:
    user_arn = _user_arn(account_id, user_name)
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=user_arn,
        region=REGION_GLOBAL,
        properties={"account_id": account_id, "path": "/"},
    )


def _org_data(
    account_ids: list[str],
    *,
    scp_constraints: list[Constraint] | None = None,
    ou_account_map: dict[str, set[str]] | None = None,
) -> OrgData:
    return OrgData(
        org_id="o-pipeline-verdict-regression",
        root_id="r-pipeline",
        accounts=[
            AccountInfo(
                account_id=account_id,
                name=f"PipelineRegression{index}",
                email=f"pipeline-regression-{index}@example.invalid",
                status="ACTIVE",
                parent_id="r-pipeline",
            )
            for index, account_id in enumerate(account_ids)
        ],
        scp_constraints=scp_constraints or [],
        ou_account_map=ou_account_map or {account_id: {account_id} for account_id in account_ids},
    )


def _facts(
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...],
    edge_constraints: tuple[EdgeConstraint, ...],
    *,
    scenario_hash: str = "pipeline-shaped-verdict-regression",
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash=scenario_hash,
        edge_budget_exhausted=False,
    )


def _run_pipeline_resolution(org_data: OrgData, accounts: list[AccountData]) -> PipelineBundle:
    nodes, edges, constraints, edge_constraints, _ = _run_resolution(
        org_data,
        accounts,
        PipelineConfig(global_expansion_mode="warn"),
    )
    materialized_nodes = tuple(nodes) + tuple(_materialize_dangling_endpoints(nodes, edges))
    constraints_tuple = tuple(constraints)
    edge_constraints_tuple = tuple(edge_constraints)
    return PipelineBundle(
        facts=_facts(materialized_nodes, tuple(edges), constraints_tuple, edge_constraints_tuple),
        nodes=materialized_nodes,
        edges=tuple(edges),
        constraints=constraints_tuple,
        edge_constraints=edge_constraints_tuple,
    )


def _check(finding, name: str):
    for check in finding.required_checks:
        if check.name == name:
            return check
    raise AssertionError(f"missing check {name!r} in {finding.finding_id}")


def _edge_action(edge: Edge) -> str:
    if edge.edge_type.endswith("_permission"):
        return edge.edge_type.removesuffix("_permission")
    if edge.edge_type.endswith("_trust"):
        return edge.edge_type.removesuffix("_trust")
    return edge.edge_type


def _single_finding(findings, *, pattern_id: str, source: str | None = None, target: str | None = None):
    matches = [
        finding
        for finding in findings
        if finding.pattern_id == pattern_id
        and (source is None or finding.source.provider_id == source)
        and (target is None or finding.target.provider_id == target)
    ]
    assert len(matches) == 1
    return matches[0]


def _passrole_lambda_bundle(passed_to_service_pattern: str) -> PipelineBundle:
    account_id = _account("1")
    source = _user_node(account_id, "PipelinePassRoleSource")
    target = _role_node(account_id, "PipelineLambdaExecutionRole")
    trust_result = parse_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        role_arn=target.provider_id,
        role_account_id=account_id,
    )[0]
    permission_results = parse_permission_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CreateFunction",
                    "Effect": "Allow",
                    "Action": "lambda:CreateFunction",
                    "Resource": "*",
                },
                {
                    "Sid": "PassExecutionRole",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": target.provider_id,
                    "Condition": {
                        "StringLike": {
                            "iam:PassedToService": passed_to_service_pattern,
                        }
                    },
                },
            ],
        },
        source.provider_id,
        NODE_TYPE_IAM_USER,
        account_id,
        policy_source="inline",
        policy_name="PipelinePassRolePolicy",
    )
    account = AccountData(
        account_id=account_id,
        nodes=[source, target],
        trust_results=[(target, trust_result)],
        permission_results=permission_results,
        role_arns=[target.provider_id],
    )
    return _run_pipeline_resolution(_org_data([account_id]), [account])


def _scenario_metadata(bundle: PipelineBundle) -> ScenarioMetadata:
    return ScenarioMetadata(
        collector="iamscope-test",
        collector_version="pipeline-shaped-verdict-regression",
        org_id="o-pipeline-verdict-regression",
        accounts_collected=1,
        accounts_skipped=0,
        collection_timestamp="2026-01-01T00:00:00+00:00",
        collection_duration_seconds=0.0,
        graph_stats={
            "nodes": len(bundle.nodes),
            "edges": len(bundle.edges),
            "constraints": len(bundle.constraints),
            "edge_constraints": len(bundle.edge_constraints),
        },
        collection_failures=[],
        policy_parse_failures=[],
    )


def test_passrole_lambda_passed_to_service_stringlike_glob_replays(tmp_path: Path) -> None:
    bundle = _passrole_lambda_bundle("*")
    direct_findings = PassRoleLambdaReasoner().run(bundle.facts)

    target = _role_arn(_account("1"), "PipelineLambdaExecutionRole")
    source = _user_arn(_account("1"), "PipelinePassRoleSource")
    finding = _single_finding(
        direct_findings,
        pattern_id="passrole_lambda",
        source=source,
        target=target,
    )

    passed_to_service = _check(finding, "passrole_condition_scoped_to_lambda_or_absent")
    assert finding.pattern_id == "passrole_lambda"
    assert finding.source.node_type == NODE_TYPE_IAM_USER
    assert finding.target.node_type == NODE_TYPE_IAM_ROLE
    assert finding.verdict is not Verdict.PRECONDITION_ONLY
    assert passed_to_service.state is CheckState.PASS
    assert any(
        _edge_action(edge) == "iam:PassRole" and edge.edge_id in passed_to_service.evidence_refs
        for edge in bundle.edges
    )

    scenario_bytes, scenario_hash = emit_scenario(
        bundle.nodes,
        bundle.edges,
        bundle.constraints,
        bundle.edge_constraints,
        _scenario_metadata(bundle),
    )
    scenario_path = tmp_path / "scenario.json"
    binding_metadata_path = tmp_path / "binding_metadata.json"
    scenario_path.write_bytes(scenario_bytes)
    binding_metadata_path.write_bytes(emit_binding_metadata(bundle.edge_constraints))

    replay_result = run_reasoners_on_frozen_artifacts(
        scenario_path=scenario_path,
        binding_metadata_path=binding_metadata_path,
        probe_overlay_path=None,
        reasoner_instances=(PassRoleLambdaReasoner(),),
        apply_consistency=False,
    )
    replayed = _single_finding(
        replay_result.findings,
        pattern_id="passrole_lambda",
        source=source,
        target=target,
    )
    replayed_check = _check(replayed, "passrole_condition_scoped_to_lambda_or_absent")

    assert scenario_hash
    assert replayed.verdict == finding.verdict
    assert replayed_check.state is CheckState.PASS


def test_passrole_lambda_passed_to_service_ec2_glob_does_not_validate_lambda() -> None:
    bundle = _passrole_lambda_bundle("ec2.*")
    findings = PassRoleLambdaReasoner().run(bundle.facts)

    finding = _single_finding(
        findings,
        pattern_id="passrole_lambda",
        source=_user_arn(_account("1"), "PipelinePassRoleSource"),
        target=_role_arn(_account("1"), "PipelineLambdaExecutionRole"),
    )
    passed_to_service = _check(finding, "passrole_condition_scoped_to_lambda_or_absent")

    assert finding.verdict is not Verdict.VALIDATED
    assert passed_to_service.state is CheckState.FAIL
    assert any(blocker.kind == "passed_to_service" for blocker in finding.blockers_observed)


def _scp_constraint(scope_id: str, *, deny_action: str = "sts:AssumeRole") -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="Account",
        scope_id=scope_id,
        policy_id="pipeline-deny-assume-role",
        statement_id="scp-deny-assume-role",
        properties={
            "effect": "Deny",
            "deny_actions": [deny_action],
            "deny_not_actions": [],
            "resource_patterns": ["*"],
            "parse_status": "complete",
        },
    )


def _cross_account_bundle(*, scp_scope_account: str | None = None) -> PipelineBundle:
    source_account = _account("1")
    target_account = _account("2")
    boundary_arn = _policy_arn(target_account, "PipelineTargetBoundary")
    target = _role_node(
        target_account,
        "PipelineExternalIdTrustTarget",
        permission_boundary_arn=boundary_arn,
    )
    trust_result = parse_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": _account_root_arn(source_account)},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "pipeline-regression-external-id",
                        }
                    },
                }
            ],
        },
        role_arn=target.provider_id,
        role_account_id=target_account,
    )[0]
    account = AccountData(
        account_id=target_account,
        nodes=[target],
        trust_results=[(target, trust_result)],
        role_arns=[target.provider_id],
        permission_boundary_policies={
            boundary_arn: {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "*",
                    }
                ],
            }
        },
    )
    scp_constraints = [_scp_constraint(scp_scope_account)] if scp_scope_account else []
    org = _org_data(
        [target_account],
        scp_constraints=scp_constraints,
        ou_account_map={scp_scope_account: {scp_scope_account}} if scp_scope_account else {},
    )
    return _run_pipeline_resolution(org, [account])


def test_cross_account_trust_ignores_non_scp_bindings_for_scp_check() -> None:
    bundle = _cross_account_bundle()
    findings = CrossAccountTrustReasoner().run(bundle.facts)

    target = _role_arn(_account("2"), "PipelineExternalIdTrustTarget")
    finding = _single_finding(findings, pattern_id="cross_account_trust", target=target)
    scp_check = _check(finding, "no_scp_blocks_sts_assumerole")
    trust_edge = next(
        edge for edge in bundle.edges if edge.dst.provider_id == target and _edge_action(edge) == "sts:AssumeRole"
    )
    bound_constraint_types = {
        bundle.facts.constraint_by_id(binding.constraint_id).constraint_type
        for binding in bundle.facts.bindings_for_edge(trust_edge.edge_id)
    }

    assert CONSTRAINT_TYPE_TRUST_CONDITION in bound_constraint_types
    assert CONSTRAINT_TYPE_PERMISSION_BOUNDARY not in bound_constraint_types
    assert CONSTRAINT_TYPE_SCP not in bound_constraint_types
    assert scp_check.state is CheckState.PASS
    assert not any(blocker.kind == "scp" for blocker in finding.blockers_observed)
    assert trust_edge.edge_id in finding.evidence.edge_refs


def test_cross_account_trust_defensively_ignores_malformed_non_scp_trust_binding() -> None:
    bundle = _cross_account_bundle()
    target = _role_arn(_account("2"), "PipelineExternalIdTrustTarget")
    trust_edge = next(
        edge for edge in bundle.edges if edge.dst.provider_id == target and _edge_action(edge) == "sts:AssumeRole"
    )
    boundary_constraint = next(
        constraint
        for constraint in bundle.constraints
        if constraint.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY
    )
    malformed_boundary_binding = EdgeConstraint(
        edge_id=trust_edge.edge_id,
        constraint_id=boundary_constraint.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason="malformed legacy boundary binding on trust edge",
    )
    facts = _facts(
        bundle.nodes,
        bundle.edges,
        bundle.constraints,
        bundle.edge_constraints + (malformed_boundary_binding,),
    )

    findings = CrossAccountTrustReasoner().run(facts)
    finding = _single_finding(findings, pattern_id="cross_account_trust", target=target)
    scp_check = _check(finding, "no_scp_blocks_sts_assumerole")
    bound_constraint_types = {
        facts.constraint_by_id(binding.constraint_id).constraint_type
        for binding in facts.bindings_for_edge(trust_edge.edge_id)
    }

    assert CONSTRAINT_TYPE_PERMISSION_BOUNDARY in bound_constraint_types
    assert CONSTRAINT_TYPE_SCP not in bound_constraint_types
    assert scp_check.state is CheckState.PASS
    assert not any(blocker.kind == "scp" for blocker in finding.blockers_observed)


def test_cross_account_trust_real_scp_binding_blocks_scp_check() -> None:
    source_account = _account("1")
    bundle = _cross_account_bundle(scp_scope_account=source_account)
    findings = CrossAccountTrustReasoner().run(bundle.facts)

    target = _role_arn(_account("2"), "PipelineExternalIdTrustTarget")
    finding = _single_finding(findings, pattern_id="cross_account_trust", target=target)
    scp_check = _check(finding, "no_scp_blocks_sts_assumerole")
    scp_constraint = next(
        constraint for constraint in bundle.constraints if constraint.constraint_type == CONSTRAINT_TYPE_SCP
    )

    assert finding.verdict is Verdict.BLOCKED
    assert scp_check.state is CheckState.FAIL
    assert scp_constraint.constraint_id in scp_check.evidence_refs
    assert scp_constraint.constraint_id in finding.evidence.constraint_refs
    assert any(blocker.kind == "scp" for blocker in finding.blockers_observed)


def test_scp_binder_uses_source_account_scope_not_target_account_scope() -> None:
    source_scoped = _cross_account_bundle(scp_scope_account=_account("1"))
    target_scoped = _cross_account_bundle(scp_scope_account=_account("2"))

    source_edge = next(edge for edge in source_scoped.edges if _edge_action(edge) == "sts:AssumeRole")
    target_edge = next(edge for edge in target_scoped.edges if _edge_action(edge) == "sts:AssumeRole")

    assert [
        binding
        for binding in source_scoped.facts.bindings_for_edge(source_edge.edge_id)
        if source_scoped.facts.constraint_by_id(binding.constraint_id).constraint_type == CONSTRAINT_TYPE_SCP
    ]
    assert not [
        binding
        for binding in target_scoped.facts.bindings_for_edge(target_edge.edge_id)
        if target_scoped.facts.constraint_by_id(binding.constraint_id).constraint_type == CONSTRAINT_TYPE_SCP
    ]


def _s3_dangling_bundle() -> PipelineBundle:
    account_id = _account("3")
    source = _user_node(account_id, "PipelineBucketPolicySource")
    bucket_arn = "arn:aws:s3:::pipeline-dangling-bucket"
    permission_results = parse_permission_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutBucketPolicy",
                    "Resource": bucket_arn,
                }
            ],
        },
        source.provider_id,
        NODE_TYPE_IAM_USER,
        account_id,
        policy_source="inline",
        policy_name="PipelineS3BucketPolicy",
    )
    account = AccountData(
        account_id=account_id,
        nodes=[source],
        permission_results=permission_results,
    )
    return _run_pipeline_resolution(_org_data([account_id]), [account])


def test_dangling_s3_bucket_reference_demotes_takeover_to_inconclusive() -> None:
    bundle = _s3_dangling_bundle()
    findings = S3BucketTakeoverReasoner().run(bundle.facts)

    finding = _single_finding(
        findings,
        pattern_id="s3_bucket_takeover",
        source=_user_arn(_account("3"), "PipelineBucketPolicySource"),
        target="arn:aws:s3:::pipeline-dangling-bucket",
    )
    target_collected = _check(finding, "target_bucket_collected")
    put_bucket_edge = next(edge for edge in bundle.edges if _edge_action(edge) == "s3:PutBucketPolicy")
    bucket_node = bundle.facts.node_by_provider_id(finding.target.provider_id)

    assert finding.target.node_type == NODE_TYPE_S3_BUCKET
    assert bucket_node.properties.get("is_dangling_reference") is True
    assert finding.verdict is Verdict.INCONCLUSIVE
    assert target_collected.state is CheckState.UNKNOWN
    assert put_bucket_edge.edge_id in finding.evidence.edge_refs
