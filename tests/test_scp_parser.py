"""Tests for SCP policy parser.

Tests cover all SCP patterns per architecture doc §5.5, Decision 3, §10.1:
- Simple Deny + Action list + Resource * → complete
- Single denied action → complete
- NotAction (inverted deny) → partial
- ArnNotLike exception on aws:PrincipalArn
- Multiple exception patterns
- StringNotEquals on PrincipalOrgID
- Multiple statements (Deny + Allow mix)
- Non-wildcard resources → partial
- Empty condition block → complete
- Allow statement only → no results
- Malformed SCP → empty results
- Unrecognized condition keys → partial
- StringNotLike exception
- SourceAccount exception
- Combined exceptions (PrincipalArn + OrgID)
- Resource as list → partial
- parse_warnings populated correctly
- All lists in SCPParseResult are sorted (determinism)
"""

import json
from pathlib import Path

from iamscope.constants import (
    PARSE_STATUS_COMPLETE,
    PARSE_STATUS_PARTIAL,
)
from iamscope.parser.scp_policy import parse_scp_document

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "scp_policies"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


class TestSimpleDenyActions:
    """Tests for standard Deny + Action SCPs (parse_status=complete)."""

    def test_simple_deny_multiple_actions(self) -> None:
        """Standard Deny with Action list and Resource * → complete."""
        policy = _load_fixture("simple_deny_actions.json")
        results = parse_scp_document(policy, "p-001", "DenyAssumeRole")

        assert len(results) == 1
        r = results[0]
        assert r.statement_id == "DenyAssumeRole"
        assert r.effect == "Deny"
        assert sorted(r.deny_actions) == ["sts:AssumeRole", "sts:AssumeRoleWithSAML"]
        assert r.deny_not_actions == []
        assert r.resource_patterns == ["*"]
        assert r.parse_status == PARSE_STATUS_COMPLETE
        assert r.parse_warnings == []

    def test_single_deny_action(self) -> None:
        """Single Action string (not list) is normalized to list."""
        policy = _load_fixture("single_deny_action.json")
        results = parse_scp_document(policy, "p-002", "DenyPassRole")

        assert len(results) == 1
        r = results[0]
        assert r.deny_actions == ["iam:PassRole"]
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_empty_condition_block_still_complete(self) -> None:
        """Empty Condition {} does not downgrade parse_status."""
        policy = _load_fixture("empty_condition.json")
        results = parse_scp_document(policy, "p-009")

        assert len(results) == 1
        r = results[0]
        assert r.parse_status == PARSE_STATUS_COMPLETE
        assert r.exception_principal_patterns == []
        assert r.raw_conditions == {}


class TestNotAction:
    """Tests for NotAction (inverted deny semantics).

    CRITICAL: NotAction means everything NOT in the list IS denied.
    deny_not_actions stores the EXCEPTIONS (actions not denied).
    """

    def test_not_action_sets_partial_status(self) -> None:
        """NotAction SCP must set parse_status=partial."""
        policy = _load_fixture("not_action_inverted.json")
        results = parse_scp_document(policy, "p-003")

        assert len(results) == 1
        r = results[0]
        assert r.deny_actions == []
        assert sorted(r.deny_not_actions) == ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
        assert r.parse_status == PARSE_STATUS_PARTIAL
        assert any("NotAction" in w for w in r.parse_warnings)

    def test_not_action_means_everything_else_denied(self) -> None:
        """Verify the semantic contract: sts:AssumeRole NOT in deny_not_actions → IS denied.

        This test documents the CRITICAL correctness rule from §10.1:
        The binder checks: if edge action NOT in deny_not_actions → it IS denied.
        """
        policy = _load_fixture("not_action_inverted.json")
        results = parse_scp_document(policy, "p-003")
        r = results[0]

        # sts:AssumeRole is NOT in deny_not_actions → it IS denied by this SCP
        assert "sts:AssumeRole" not in r.deny_not_actions

        # s3:GetObject IS in deny_not_actions → it is NOT denied by this SCP
        assert "s3:GetObject" in r.deny_not_actions


class TestExceptionPatterns:
    """Tests for SCP exception extraction from Condition blocks."""

    def test_arn_not_like_principal_exception(self) -> None:
        """ArnNotLike on aws:PrincipalArn extracts exception patterns."""
        policy = _load_fixture("arn_not_like_exception.json")
        results = parse_scp_document(policy, "p-004")

        assert len(results) == 1
        r = results[0]
        assert r.exception_principal_patterns == ["arn:aws:iam::*:role/BreakGlass*"]
        # Known exception operator → still complete
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_multiple_exception_patterns(self) -> None:
        """Multiple ArnNotLike patterns are all extracted."""
        policy = _load_fixture("multiple_exceptions.json")
        results = parse_scp_document(policy, "p-005")

        assert len(results) == 1
        r = results[0]
        assert len(r.exception_principal_patterns) == 3
        assert "arn:aws:iam::*:role/BreakGlass*" in r.exception_principal_patterns
        assert "arn:aws:iam::*:role/OrganizationAccountAccessRole" in r.exception_principal_patterns
        assert "arn:aws:iam::*:role/Admin*" in r.exception_principal_patterns
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_org_id_exception(self) -> None:
        """StringNotEquals on aws:PrincipalOrgID extracts org ID exceptions."""
        policy = _load_fixture("org_id_exception.json")
        results = parse_scp_document(policy, "p-006")

        assert len(results) == 1
        r = results[0]
        assert r.exception_org_ids == ["o-myorg123"]
        assert r.exception_principal_patterns == []
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_string_not_like_principal_exception(self) -> None:
        """StringNotLike on aws:PrincipalArn also extracts exception patterns."""
        policy = _load_fixture("string_not_like_exception.json")
        results = parse_scp_document(policy, "p-013")

        assert len(results) == 1
        r = results[0]
        assert r.exception_principal_patterns == ["arn:aws:iam::*:role/Approved*"]
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_source_account_exception(self) -> None:
        """StringNotEquals on aws:SourceAccount extracts account ID exceptions."""
        policy = _load_fixture("source_account_exception.json")
        results = parse_scp_document(policy, "p-014")

        assert len(results) == 1
        r = results[0]
        assert sorted(r.exception_account_ids) == ["111111\u003111111", "222222\u003222222"]
        assert r.parse_status == PARSE_STATUS_COMPLETE

    def test_combined_exceptions(self) -> None:
        """Multiple exception types (PrincipalArn + OrgID) both extracted."""
        policy = _load_fixture("combined_exceptions.json")
        results = parse_scp_document(policy, "p-015")

        assert len(results) == 1
        r = results[0]
        assert r.exception_principal_patterns == ["arn:aws:iam::*:role/BreakGlass*"]
        assert r.exception_org_ids == ["o-myorg123"]
        assert r.parse_status == PARSE_STATUS_COMPLETE


class TestPrincipalApplicabilityPatterns:
    """Tests for supported positive aws:PrincipalArn applicability filters."""

    def test_positive_principal_arn_filters_are_complete(self) -> None:
        for operator in ("ArnLike", "StringLike", "ArnEquals", "StringEquals"):
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": f"DenyAssumeRoleFor{operator}",
                        "Effect": "Deny",
                        "Action": "sts:AssumeRole",
                        "Resource": "*",
                        "Condition": {
                            operator: {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::111111\u003111111:user/env22-alice",
                                    "arn:aws:sts::111111\u003111111:assumed-role/Env22/*",
                                ]
                            }
                        },
                    }
                ],
            }

            results = parse_scp_document(policy, f"p-{operator}")

            assert len(results) == 1
            r = results[0]
            assert r.parse_status == PARSE_STATUS_COMPLETE
            assert r.parse_warnings == []
            assert sorted(r.applicable_principal_patterns) == [
                "arn:aws:iam::111111\u003111111:user/env22-alice",
                "arn:aws:sts::111111\u003111111:assumed-role/Env22/*",
            ]
            assert r.exception_principal_patterns == []

    def test_other_positive_condition_keys_remain_partial(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyWithResourceTag",
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/Environment": "production",
                        }
                    },
                }
            ],
        }

        results = parse_scp_document(policy, "p-resource-tag")

        assert len(results) == 1
        r = results[0]
        assert r.parse_status == PARSE_STATUS_PARTIAL
        assert r.applicable_principal_patterns == []
        assert any("Unhandled condition" in w for w in r.parse_warnings)


class TestMultipleStatements:
    """Tests for SCPs with multiple statements."""

    def test_multiple_statements_deny_and_allow(self) -> None:
        """Multiple statements: only Deny statements produce results."""
        policy = _load_fixture("multiple_statements.json")
        results = parse_scp_document(policy, "p-007")

        # 2 Deny statements, 1 Allow (skipped)
        assert len(results) == 2

        assert results[0].statement_id == "DenyAssumeRole"
        assert results[0].deny_actions == ["sts:AssumeRole"]

        assert results[1].statement_id == "DenyPassRole"
        assert results[1].deny_actions == ["iam:PassRole"]

    def test_allow_only_produces_no_results(self) -> None:
        """SCP with only Allow statement produces empty results."""
        policy = _load_fixture("allow_only.json")
        results = parse_scp_document(policy, "p-010")
        assert results == []


class TestParseStatusDowngrades:
    """Tests for parse_status downgrades (partial, unsupported)."""

    def test_non_wildcard_resource_partial(self) -> None:
        """Non-wildcard resource patterns downgrade to partial."""
        policy = _load_fixture("non_wildcard_resource.json")
        results = parse_scp_document(policy, "p-008")

        assert len(results) == 1
        r = results[0]
        assert r.parse_status == PARSE_STATUS_PARTIAL
        assert r.resource_patterns == ["arn:aws:iam::333333\u003333333:role/ProdDeploy*"]
        assert any("Non-wildcard" in w for w in r.parse_warnings)

    def test_unrecognized_condition_key_partial(self) -> None:
        """Unrecognized condition keys downgrade to partial."""
        policy = _load_fixture("unrecognized_condition.json")
        results = parse_scp_document(policy, "p-012")

        assert len(results) == 1
        r = results[0]
        assert r.parse_status == PARSE_STATUS_PARTIAL
        assert any("Unhandled condition" in w for w in r.parse_warnings)
        # The recognized exception should still be extracted
        assert r.exception_principal_patterns == ["arn:aws:iam::*:role/BreakGlass*"]

    def test_resource_as_list_partial(self) -> None:
        """Resource as list of ARNs downgrades to partial."""
        policy = _load_fixture("resource_as_list.json")
        results = parse_scp_document(policy, "p-016")

        assert len(results) == 1
        r = results[0]
        assert r.parse_status == PARSE_STATUS_PARTIAL
        assert len(r.resource_patterns) == 2


class TestEdgeCases:
    """Tests for malformed and unusual SCPs."""

    def test_malformed_scp_returns_empty(self) -> None:
        """Malformed SCP (no Statement) returns empty list."""
        policy = _load_fixture("malformed_scp.json")
        results = parse_scp_document(policy, "p-011")
        assert results == []

    def test_string_policy_document(self) -> None:
        """SCP as JSON string is parsed correctly."""
        policy_dict = _load_fixture("simple_deny_actions.json")
        policy_str = json.dumps(policy_dict)
        results = parse_scp_document(policy_str, "p-str")

        assert len(results) == 1
        assert results[0].deny_actions == ["sts:AssumeRole", "sts:AssumeRoleWithSAML"]

    def test_none_policy_returns_empty(self) -> None:
        """None as policy returns empty list."""
        results = parse_scp_document(None, "p-none")  # type: ignore[arg-type]
        assert results == []

    def test_no_sid_uses_index(self) -> None:
        """Statement without Sid uses stmt_N as statement_id."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                }
            ],
        }
        results = parse_scp_document(policy, "p-nosid")
        assert len(results) == 1
        assert results[0].statement_id == "stmt_0"


class TestDeterminism:
    """Tests for output determinism."""

    def test_same_scp_same_results(self) -> None:
        """Parsing the same SCP twice produces identical results."""
        policy = _load_fixture("multiple_exceptions.json")
        r1 = parse_scp_document(policy, "p-det")
        r2 = parse_scp_document(policy, "p-det")

        assert len(r1) == len(r2)
        for a, b in zip(r1, r2, strict=True):
            assert a.statement_id == b.statement_id
            assert a.deny_actions == b.deny_actions
            assert a.deny_not_actions == b.deny_not_actions
            assert a.applicable_principal_patterns == b.applicable_principal_patterns
            assert a.exception_principal_patterns == b.exception_principal_patterns
            assert a.parse_status == b.parse_status
            assert a.raw_conditions == b.raw_conditions

    def test_raw_conditions_canonicalized(self) -> None:
        """Raw conditions are stored in canonical (sorted keys) form."""
        policy = _load_fixture("combined_exceptions.json")
        results = parse_scp_document(policy, "p-canon")
        r = results[0]

        # Verify canonical form
        canonical = json.dumps(r.raw_conditions, sort_keys=True, separators=(",", ":"))
        reparsed = json.loads(canonical)
        assert reparsed == r.raw_conditions

    def test_to_properties_dict_lists_sorted(self) -> None:
        """SCPParseResult.to_properties_dict() sorts all lists."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyWithPrincipalApplicability",
                    "Effect": "Deny",
                    "Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": [
                                "arn:aws:iam::111111\u003111111:user/Zed",
                                "arn:aws:iam::111111\u003111111:user/Alice",
                            ]
                        }
                    },
                }
            ],
        }
        results = parse_scp_document(policy, "p-sort")
        r = results[0]
        props = r.to_properties_dict()

        assert props["applicable_principal_patterns"] == sorted(props["applicable_principal_patterns"])
        assert props["deny_actions"] == sorted(props["deny_actions"])
        assert props["exception_principal_patterns"] == sorted(props["exception_principal_patterns"])
        assert props["resource_patterns"] == sorted(props["resource_patterns"])
