"""Tests for Phase 2 confounded judgments."""

from __future__ import annotations

from iamscope.constants import ACTION_CLASS_STS_ASSUME_ROLE, CONSTRAINT_TYPE_SCP, PROVIDER_AWS
from iamscope.models import AccountInfo, Constraint, OrgData
from iamscope.truth.confounded import judge_account_confounding, judge_edge_confounding
from iamscope.truth.org_controls import normalize_effective_org_controls


def _constraint(scope_type: str = "OU", scope_id: str = "ou-prod") -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_id="p-deny-prod-assume",
        statement_id="DenyAssumeRole",
        properties={
            "policy_name": "DenyCrossAccountAssumeRoleProd",
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "resource_patterns": ["*"],
            "policy_document_raw": '{"Statement":[{"Action":"sts:AssumeRole","Effect":"Deny"}]}',
        },
    )


def _org_data() -> OrgData:
    return OrgData(
        org_id="o-example",
        root_id="r-root",
        accounts=[
            AccountInfo("111111\u003111111", "dev", "dev@example.com", "ACTIVE", "ou-dev"),
            AccountInfo("222222\u003222222", "prod", "prod@example.com", "ACTIVE", "ou-prod"),
        ],
        scp_constraints=[_constraint()],
        ou_account_map={
            "r-root": {"111111\u003111111", "222222\u003222222"},
            "ou-dev": {"111111\u003111111"},
            "ou-prod": {"222222\u003222222"},
            "111111\u003111111": {"111111\u003111111"},
            "222222\u003222222": {"222222\u003222222"},
        },
    )


def test_account_confounding_positive_and_negative() -> None:
    controls = normalize_effective_org_controls(_org_data())

    prod = judge_account_confounding("222222\u003222222", controls)
    dev = judge_account_confounding("111111\u003111111", controls)

    assert prod.confounded is True
    assert prod.contributing_scps == ("p-deny-prod-assume",)
    assert prod.evidence_level == "heuristic"
    assert dev.confounded is False


def test_edge_confounding_cites_bound_inherited_scp() -> None:
    edge = {
        "edge_id": "edge-1",
        "edge_type": "sts:AssumeRole_trust",
        "src": {"provider_id": "arn:aws:iam::111111\u003111111:role/Dev"},
        "dst": {"provider_id": "arn:aws:iam::222222\u003222222:role/Prod"},
    }
    constraint = _constraint().to_dict()
    edge_constraints = [{"edge_id": "edge-1", "constraint_id": constraint["constraint_id"]}]

    judgment = judge_edge_confounding(
        edge,
        constraints=[constraint],
        edge_constraints=edge_constraints,
        action_class=ACTION_CLASS_STS_ASSUME_ROLE,
    )

    assert judgment.confounded is True
    assert judgment.reason == "inherited_org_control_governs_sts_assumerole"
    assert judgment.contributing_scps == ("p-deny-prod-assume",)


def test_edge_confounding_ignores_account_attached_scp() -> None:
    edge = {
        "edge_id": "edge-1",
        "edge_type": "sts:AssumeRole_trust",
        "src": {"provider_id": "arn:aws:iam::111111\u003111111:role/Dev"},
        "dst": {"provider_id": "arn:aws:iam::222222\u003222222:role/Prod"},
    }
    constraint = _constraint(scope_type="ACCOUNT", scope_id="222222\u003222222").to_dict()
    edge_constraints = [{"edge_id": "edge-1", "constraint_id": constraint["constraint_id"]}]

    judgment = judge_edge_confounding(edge, [constraint], edge_constraints)

    assert judgment.confounded is False
