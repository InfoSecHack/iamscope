"""Tests for permission policy parser — extracts AssumeRole and PassRole grants.

Tests cover architecture doc §5.7, R08:
- AssumeRole grant from specific resource
- AssumeRole grant from wildcard resource
- PassRole grant from specific resource
- PassRole grant from wildcard resource
- Admin policy (Action: "*") → all relevant actions
- sts:* wildcard → all STS actions
- iam:* wildcard → PassRole
- Deny statement skipped
- NotAction handling
- Multiple resources → multiple results
- Conditions extracted
- Case insensitive action matching
- Malformed/empty/None policy → graceful empty list
- Multiple statements
- AssumeRoleWithSAML and AssumeRoleWithWebIdentity
"""

import json
from pathlib import Path

from iamscope.constants import NODE_TYPE_IAM_USER
from iamscope.parser.permission_policy import parse_permission_policy

FIXTURES = Path(__file__).parent / "fixtures" / "permission_policies"

SRC_ARN = "arn:aws:iam::111111111111:user/Admin"
SRC_TYPE = NODE_TYPE_IAM_USER
SRC_ACCT = "111111111111"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _parse(doc, **kwargs):
    defaults = {
        "source_arn": SRC_ARN,
        "source_node_type": SRC_TYPE,
        "source_account_id": SRC_ACCT,
        "policy_source": "inline",
        "policy_name": "test-policy",
    }
    defaults.update(kwargs)
    return parse_permission_policy(doc, **defaults)


class TestAssumeRoleGrants:
    """Tests for sts:AssumeRole permission extraction."""

    def test_specific_assume_role(self) -> None:
        """Specific resource AssumeRole creates one result."""
        doc = _load("assume_role_specific.json")
        results = _parse(doc)

        assert len(results) == 1
        r = results[0]
        assert r.action == "sts:AssumeRole"
        assert r.resource_pattern == "arn:aws:iam::222222222222:role/ProdDeploy"
        assert r.is_wildcard_resource is False
        assert r.action_matched_via == "exact"
        assert r.source_arn == SRC_ARN

    def test_wildcard_assume_role(self) -> None:
        """Wildcard resource AssumeRole creates one result with is_wildcard=True."""
        doc = _load("assume_role_wildcard.json")
        results = _parse(doc)

        assert len(results) == 1
        assert results[0].is_wildcard_resource is True
        assert results[0].resource_pattern == "*"

    def test_multiple_resources(self) -> None:
        """Multiple resources create multiple results."""
        doc = _load("multiple_resources.json")
        results = _parse(doc)

        assert len(results) == 3
        arns = {r.resource_pattern for r in results}
        assert "arn:aws:iam::222222222222:role/RoleA" in arns
        assert "arn:aws:iam::222222222222:role/RoleB" in arns
        assert "arn:aws:iam::333333333333:role/RoleC" in arns


class TestPassRoleGrants:
    """Tests for iam:PassRole permission extraction."""

    def test_specific_passrole(self) -> None:
        """Specific resource PassRole creates one result."""
        doc = _load("passrole_specific.json")
        results = _parse(doc)

        assert len(results) == 1
        assert results[0].action == "iam:PassRole"
        assert results[0].is_wildcard_resource is False

    def test_wildcard_passrole(self) -> None:
        """Wildcard resource PassRole creates one result."""
        doc = _load("passrole_wildcard.json")
        results = _parse(doc)

        assert len(results) == 1
        assert results[0].action == "iam:PassRole"
        assert results[0].is_wildcard_resource is True


class TestWildcardActions:
    """Tests for wildcard action matching."""

    def test_admin_policy_matches_all(self) -> None:
        """Action: '*' matches all relevant actions."""
        doc = _load("admin_policy.json")
        results = _parse(doc)

        actions = {r.action for r in results}
        assert "sts:AssumeRole" in actions
        assert "sts:AssumeRoleWithSAML" in actions
        assert "sts:AssumeRoleWithWebIdentity" in actions
        assert "iam:PassRole" in actions
        # All matched via wildcard_star
        assert all(r.action_matched_via == "wildcard_star" for r in results)

    def test_sts_wildcard(self) -> None:
        """Action: 'sts:*' matches all STS actions but NOT iam:PassRole."""
        doc = _load("sts_wildcard.json")
        results = _parse(doc)

        actions = {r.action for r in results}
        assert "sts:AssumeRole" in actions
        assert "sts:AssumeRoleWithSAML" in actions
        assert "sts:AssumeRoleWithWebIdentity" in actions
        assert "iam:PassRole" not in actions
        assert all(r.action_matched_via == "wildcard_sts" for r in results)

    def test_iam_wildcard(self) -> None:
        """Action: 'iam:*' matches PassRole but NOT STS actions."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
        }
        results = _parse(doc)

        actions = {r.action for r in results}
        assert "iam:PassRole" in actions
        assert "sts:AssumeRole" not in actions


class TestNotAction:
    """Tests for NotAction handling."""

    def test_not_action_allows_relevant(self) -> None:
        """NotAction excluding S3 actions → all relevant IAM/STS actions allowed."""
        doc = _load("not_action.json")
        results = _parse(doc)

        actions = {r.action for r in results}
        assert "sts:AssumeRole" in actions
        assert "iam:PassRole" in actions
        assert all(r.action_matched_via == "not_action" for r in results)

    def test_not_action_excluding_sts(self) -> None:
        """NotAction excluding STS actions → STS NOT allowed, PassRole IS allowed."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"],
                    "Resource": "*",
                }
            ],
        }
        results = _parse(doc)

        actions = {r.action for r in results}
        assert "sts:AssumeRole" not in actions
        assert "iam:PassRole" in actions


class TestDenyAndEffects:
    """Tests for Deny statement handling."""

    def test_deny_statement_skipped(self) -> None:
        """Deny statements produce no results."""
        doc = _load("deny_only.json")
        results = _parse(doc)
        assert results == []

    def test_mixed_allow_deny(self) -> None:
        """Only Allow statements produce results."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"},
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            ],
        }
        results = _parse(doc)

        assert len(results) == 1
        assert results[0].action == "iam:PassRole"


class TestConditions:
    """Tests for condition extraction."""

    def test_conditions_extracted(self) -> None:
        """Conditions are captured in the result."""
        doc = _load("with_conditions.json")
        results = _parse(doc)

        assert len(results) == 1
        assert results[0].has_conditions is True
        assert "StringEquals" in results[0].raw_conditions

    def test_no_conditions(self) -> None:
        """No conditions → has_conditions=False, empty raw_conditions."""
        doc = _load("assume_role_specific.json")
        results = _parse(doc)

        assert results[0].has_conditions is False
        assert results[0].raw_conditions == {}


class TestCaseInsensitive:
    """Tests for case-insensitive action matching."""

    def test_uppercase_action(self) -> None:
        """Action 'STS:ASSUMEROLE' matches."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "STS:ASSUMEROLE", "Resource": "*"}],
        }
        results = _parse(doc)
        assert len(results) == 1
        assert results[0].action == "sts:AssumeRole"

    def test_mixed_case(self) -> None:
        """Action 'Iam:passRole' matches."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "Iam:passRole", "Resource": "*"}],
        }
        results = _parse(doc)
        assert len(results) == 1
        assert results[0].action == "iam:PassRole"


class TestMalformedInput:
    """Tests for malformed/edge-case inputs."""

    def test_none_policy(self) -> None:
        assert _parse(None) == []

    def test_empty_string(self) -> None:
        assert _parse("") == []

    def test_invalid_json(self) -> None:
        assert _parse("{invalid json}") == []

    def test_no_statements(self) -> None:
        assert _parse({"Version": "2012-10-17"}) == []

    def test_no_matching_actions(self) -> None:
        """Policy with only S3 actions produces no results."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        assert _parse(doc) == []


class TestPolicySourceTracking:
    """Tests for policy source metadata."""

    def test_policy_source_propagated(self) -> None:
        """Policy source and name are propagated to results."""
        doc = _load("assume_role_specific.json")
        results = _parse(
            doc,
            policy_source="managed",
            policy_name="AdminAccess",
            policy_arn="arn:aws:iam::aws:policy/Admin",
        )

        assert results[0].policy_source == "managed"
        assert results[0].policy_name == "AdminAccess"
        assert results[0].policy_arn == "arn:aws:iam::aws:policy/Admin"
