"""Cross-account trust reasoner semantics for tri-state org membership."""

from __future__ import annotations

from iamscope.collector.account import AccountData
from iamscope.constants import NODE_TYPE_IAM_ROLE, PROVIDER_AWS, REGION_GLOBAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from iamscope.models import AccountInfo, Node, OrgData
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.reasoner import CheckState, CrossAccountTrustReasoner, FactGraph, Verdict

TARGET_ACCOUNT = "1" * 12
SOURCE_ACCOUNT = "2" * 12
SKIPPED_ACCOUNT = "3" * 12


def _role_arn(account_id: str, role_name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _root_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _target_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_role_arn(TARGET_ACCOUNT, "TrustTarget"),
        region=REGION_GLOBAL,
        properties={"account_id": TARGET_ACCOUNT, "path": "/", "is_synthetic": False},
    )


def _org_data(account_ids: list[str]) -> OrgData:
    return OrgData(
        org_id="o-org-membership-status",
        root_id="r-root",
        accounts=[
            AccountInfo(
                account_id=account_id,
                name=f"Account{index}",
                email=f"account{index}@example.invalid",
                status="ACTIVE",
                parent_id="r-root",
            )
            for index, account_id in enumerate(account_ids)
        ],
    )


def _finding_for_principal(principal: object, org_account_ids: list[str]):
    target = _target_role_node()
    trust_result = parse_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": principal,
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        role_arn=target.provider_id,
        role_account_id=TARGET_ACCOUNT,
    )[0]
    account_data = AccountData(
        account_id=TARGET_ACCOUNT,
        nodes=[target],
        trust_results=[(target, trust_result)],
        permission_results=[],
        role_arns=[target.provider_id],
    )
    nodes, edges, constraints, edge_constraints, _budget = _run_resolution(
        _org_data(org_account_ids),
        [account_data],
        PipelineConfig(),
    )
    facts = FactGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        constraints=tuple(constraints),
        edge_constraints=tuple(edge_constraints),
        scenario_hash="org-membership-status-regression",
        edge_budget_exhausted=False,
    )
    findings = CrossAccountTrustReasoner().run(facts)
    assert len(findings) == 1
    return findings[0], nodes


def _check(finding, name: str):
    for check in finding.required_checks:
        if check.name == name:
            return check
    raise AssertionError(f"missing check {name!r}")


def _org_trace(finding):
    return next(trace for trace in finding.evidence.reasoning_trace if trace.action == "evaluate_source_org_membership")


def test_member_status_preserves_same_org_downgrade() -> None:
    finding, _nodes = _finding_for_principal(
        {"AWS": _root_arn(SOURCE_ACCOUNT)},
        [TARGET_ACCOUNT, SOURCE_ACCOUNT],
    )

    assert finding.pattern_id == "cross_account_trust"
    assert finding.source.provider_id == _root_arn(SOURCE_ACCOUNT)
    assert finding.target.provider_id == _role_arn(TARGET_ACCOUNT, "TrustTarget")
    assert finding.verdict is Verdict.VALIDATED
    assert finding.severity == SEVERITY_MEDIUM
    assert "same-org cross-account" in finding.title
    assert "severity downgraded" in finding.reasoner_exit_reason
    assert _check(finding, "source_principal_resolvable").state is CheckState.PASS
    org_trace = _org_trace(finding)
    assert org_trace.result == "SAME_ORG"
    assert "org_membership_status=member" in org_trace.reason
    assert finding.assumptions == ()


def test_non_member_status_preserves_confirmed_external_wording() -> None:
    finding, _nodes = _finding_for_principal(
        {"AWS": _root_arn(SOURCE_ACCOUNT)},
        [TARGET_ACCOUNT],
    )

    assert finding.verdict is Verdict.VALIDATED
    assert finding.severity == SEVERITY_HIGH
    assert "external cross-account" in finding.title
    assert "truly external source" in finding.reasoner_exit_reason
    org_trace = _org_trace(finding)
    assert org_trace.result == "EXTERNAL"
    assert "org_membership_status=non_member" in org_trace.reason
    assert "confirmed external/non-member" in org_trace.reason
    assert finding.assumptions == ()


def test_unknown_status_is_visible_without_confirmed_external_wording() -> None:
    finding, nodes = _finding_for_principal(
        {"AWS": _root_arn(SOURCE_ACCOUNT)},
        [TARGET_ACCOUNT, SKIPPED_ACCOUNT],
    )

    source_node = next(node for node in nodes if node.provider_id == _root_arn(SOURCE_ACCOUNT))
    assert source_node.properties["org_membership_status"] == "unknown"
    assert finding.verdict is Verdict.INCONCLUSIVE
    assert finding.severity == SEVERITY_HIGH
    assert "unknown-membership cross-account" in finding.title
    assert "external cross-account" not in finding.title
    assert "truly external source" not in finding.reasoner_exit_reason
    assert "org_membership_status unknown" in finding.reasoner_exit_reason
    assert _check(finding, "source_principal_resolvable").state is CheckState.PASS
    org_trace = _org_trace(finding)
    assert org_trace.result == "UNKNOWN"
    assert "org_membership_status=unknown" in org_trace.reason
    assert "partial, filtered, or standalone" in org_trace.reason
    assert len(finding.assumptions) == 1
    assert finding.assumptions[0].kind == "org_membership_status"
    assert "not treated as confirmed external/non-member" in finding.assumptions[0].detail


def test_wildcard_principal_remains_confirmed_external() -> None:
    finding, _nodes = _finding_for_principal(
        "*",
        [TARGET_ACCOUNT],
    )

    assert finding.verdict is Verdict.VALIDATED
    assert "external cross-account" in finding.title
    org_trace = _org_trace(finding)
    assert org_trace.result == "EXTERNAL"
    assert "org_membership_status=non_member" in org_trace.reason
    assert finding.assumptions == ()
