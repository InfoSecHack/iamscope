"""Tests for identity-policy Deny parsing."""

from __future__ import annotations

from iamscope.parser.permission_policy import parse_permission_denies

PRINCIPAL_ARN = "arn:aws:iam::111111\u003111111:user/Admin"
POLICY_ID = "inline:admin-policy"


def _parse(doc: dict) -> list:
    return parse_permission_denies(
        doc,
        principal_arn=PRINCIPAL_ARN,
        policy_id=POLICY_ID,
    )


def test_plain_deny_single_action() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}],
        }
    )

    assert len(results) == 1
    deny = results[0]
    assert deny.principal_arn == PRINCIPAL_ARN
    assert deny.policy_arn == POLICY_ID
    assert deny.deny_actions == ["sts:AssumeRole"]
    assert deny.resource_patterns == ["*"]
    assert deny.has_conditions is False
    assert deny.raw_conditions == {}
    assert deny.parse_status == "complete"


def test_plain_deny_wildcard_action() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "Action": "sts:*", "Resource": "*"}],
        }
    )

    assert results[0].deny_actions == ["sts:*"]
    assert results[0].parse_status == "complete"


def test_plain_deny_star_action() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
    )

    assert results[0].deny_actions == ["*"]


def test_plain_deny_multiple_actions() -> None:
    results = _parse(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["sts:AssumeRole", "iam:PassRole"],
                    "Resource": "*",
                }
            ],
        }
    )

    assert results[0].deny_actions == ["sts:AssumeRole", "iam:PassRole"]


def test_plain_deny_specific_resource() -> None:
    resource = "arn:aws:iam::222222\u003222222:role/ProdDeploy"
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": resource}],
        }
    )

    assert results[0].resource_patterns == [resource]


def test_conditional_deny_has_conditions_true() -> None:
    results = _parse(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
                }
            ],
        }
    )

    assert results[0].has_conditions is True
    assert results[0].parse_status == "complete"


def test_conditional_deny_raw_conditions_preserved() -> None:
    conditions = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    results = _parse(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                    "Condition": conditions,
                }
            ],
        }
    )

    assert results[0].raw_conditions == conditions


def test_notaction_deny_parse_status_partial() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}],
        }
    )

    assert results[0].deny_actions == ["s3:GetObject"]
    assert results[0].parse_status == "partial"


def test_notresource_deny_parse_status_unsupported() -> None:
    results = _parse(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "NotResource": "arn:aws:iam::222222\u003222222:role/Allowed",
                }
            ],
        }
    )

    assert results[0].resource_patterns == ["*"]
    assert results[0].parse_status == "unsupported"


def test_allow_stmts_skipped() -> None:
    results = _parse(
        {
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }
    )

    assert len(results) == 1
    assert results[0].deny_actions == ["iam:PassRole"]


def test_no_deny_stmts() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
        }
    )

    assert results == []


def test_empty_policy() -> None:
    assert _parse({}) == []


def test_sid_used_when_present() -> None:
    results = _parse(
        {
            "Statement": [
                {
                    "Sid": "BlockAssumeRole",
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                }
            ],
        }
    )

    assert results[0].statement_id == "BlockAssumeRole"


def test_auto_sid_generated() -> None:
    results = _parse(
        {
            "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}],
        }
    )

    assert results[0].statement_id == "_stmt0"


def test_multiple_deny_stmts() -> None:
    results = _parse(
        {
            "Statement": [
                {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }
    )

    assert len(results) == 2
    assert [result.statement_id for result in results] == ["_stmt0", "_stmt1"]
    assert [result.deny_actions for result in results] == [["sts:AssumeRole"], ["iam:PassRole"]]
