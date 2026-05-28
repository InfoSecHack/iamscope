"""Tests for condition key extraction and classification.

Tests verify:
- Each known condition key sets the correct boolean flag
- Unknown keys are collected in unknown_keys
- All condition keys are listed (sorted) in condition_keys
- Empty/None condition blocks return default ConditionSet
- Multiple conditions from different operators are merged
- Case-insensitive key matching
"""

from iamscope.parser.condition_extractor import extract_conditions


class TestExtractConditions:
    """Tests for the extract_conditions function."""

    def test_empty_condition_block(self) -> None:
        """None or empty condition block returns default ConditionSet."""
        result = extract_conditions(None)
        assert result.has_external_id is False
        assert result.has_source_account_condition is False
        assert result.has_source_ip_condition is False
        assert result.has_source_vpc_condition is False
        assert result.has_org_id_condition is False
        assert result.has_mfa_condition is False
        # COND-1 additions: new flags must default to False.
        assert result.has_passed_to_service_condition is False
        assert result.has_associated_resource_arn_condition is False
        assert result.has_principal_tag_condition is False
        assert result.has_request_tag_condition is False
        assert result.has_resource_account_condition is False
        assert result.has_resource_org_id_condition is False
        assert result.condition_keys == []
        assert result.unknown_keys == []

        result2 = extract_conditions({})
        assert result2.condition_keys == []

    def test_external_id(self) -> None:
        """sts:ExternalId sets has_external_id flag."""
        cond = {"StringEquals": {"sts:ExternalId": "my-external-id"}}
        result = extract_conditions(cond)
        assert result.has_external_id is True
        assert "sts:ExternalId" in result.condition_keys

    def test_source_account(self) -> None:
        """aws:SourceAccount sets has_source_account_condition flag."""
        cond = {"StringEquals": {"aws:SourceAccount": "111111111111"}}
        result = extract_conditions(cond)
        assert result.has_source_account_condition is True
        assert "aws:SourceAccount" in result.condition_keys

    def test_source_ip(self) -> None:
        """aws:SourceIp sets has_source_ip_condition flag."""
        cond = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
        result = extract_conditions(cond)
        assert result.has_source_ip_condition is True

    def test_vpc_source_ip(self) -> None:
        """aws:VpcSourceIp also sets has_source_ip_condition flag."""
        cond = {"IpAddress": {"aws:VpcSourceIp": "10.0.0.0/8"}}
        result = extract_conditions(cond)
        assert result.has_source_ip_condition is True

    def test_source_vpc(self) -> None:
        """aws:SourceVpc sets has_source_vpc_condition flag."""
        cond = {"StringEquals": {"aws:SourceVpc": "vpc-12345678"}}
        result = extract_conditions(cond)
        assert result.has_source_vpc_condition is True

    def test_source_vpce(self) -> None:
        """aws:SourceVpce also sets has_source_vpc_condition flag."""
        cond = {"StringEquals": {"aws:SourceVpce": "vpce-abcdefgh"}}
        result = extract_conditions(cond)
        assert result.has_source_vpc_condition is True

    def test_org_id(self) -> None:
        """aws:PrincipalOrgID sets has_org_id_condition flag."""
        cond = {"StringEquals": {"aws:PrincipalOrgID": "o-myorg123"}}
        result = extract_conditions(cond)
        assert result.has_org_id_condition is True

    def test_mfa(self) -> None:
        """aws:MultiFactorAuthPresent sets has_mfa_condition flag."""
        cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        result = extract_conditions(cond)
        assert result.has_mfa_condition is True

    def test_mfa_age(self) -> None:
        """aws:MultiFactorAuthAge also sets has_mfa_condition flag."""
        cond = {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}
        result = extract_conditions(cond)
        assert result.has_mfa_condition is True

    def test_multiple_conditions(self) -> None:
        """Multiple condition keys from different operators are all extracted."""
        cond = {
            "StringEquals": {"sts:ExternalId": "ext-123", "aws:PrincipalOrgID": "o-myorg"},
            "Bool": {"aws:MultiFactorAuthPresent": "true"},
            "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        }
        result = extract_conditions(cond)
        assert result.has_external_id is True
        assert result.has_org_id_condition is True
        assert result.has_mfa_condition is True
        assert result.has_source_ip_condition is True
        assert len(result.condition_keys) == 4

    def test_condition_keys_sorted(self) -> None:
        """condition_keys must be sorted for determinism."""
        cond = {"StringEquals": {"sts:ExternalId": "x", "aws:SourceAccount": "111", "aws:PrincipalOrgID": "o-test"}}
        result = extract_conditions(cond)
        assert result.condition_keys == sorted(result.condition_keys)

    def test_unknown_keys_collected(self) -> None:
        """Unrecognized condition keys are collected in unknown_keys."""
        cond = {"StringEquals": {"custom:MyCondition": "value", "sts:ExternalId": "ext-123"}}
        result = extract_conditions(cond)
        assert result.has_external_id is True
        assert "custom:MyCondition" in result.unknown_keys
        assert "sts:ExternalId" not in result.unknown_keys

    def test_saml_aud_known_informational(self) -> None:
        """SAML:aud is known (informational) and should NOT appear in unknown_keys."""
        cond = {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}
        result = extract_conditions(cond)
        assert result.unknown_keys == []
        assert "SAML:aud" in result.condition_keys

    def test_github_actions_oidc_known(self) -> None:
        """GitHub Actions OIDC keys are known informational."""
        cond = {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"}}
        result = extract_conditions(cond)
        assert result.unknown_keys == []

    def test_non_dict_condition_block(self) -> None:
        """Non-dict condition block returns empty ConditionSet."""
        result = extract_conditions("not a dict")  # type: ignore[arg-type]
        assert result.condition_keys == []

    def test_non_dict_operator_value(self) -> None:
        """Non-dict operator value is skipped gracefully."""
        cond = {"StringEquals": "not a dict"}
        result = extract_conditions(cond)
        assert result.condition_keys == []


class TestCond1NewConditionKeys:
    """COND-1 regression tests: six condition keys that gate real PassRole usage.

    These keys distinguish "PassRole to Lambda specifically" from "PassRole to
    anything" and are the evaluation substrate for passrole_lambda check 8.
    Each test asserts two things: (a) the correct boolean flag flips, and
    (b) the key does NOT appear in `unknown_keys` (the exit-criterion invariant).
    """

    def test_passed_to_service(self) -> None:
        """iam:PassedToService sets has_passed_to_service_condition."""
        cond = {
            "StringEquals": {
                "iam:PassedToService": "lambda.amazonaws.com",
            }
        }
        result = extract_conditions(cond)
        assert result.has_passed_to_service_condition is True
        assert "iam:PassedToService" in result.condition_keys
        assert "iam:PassedToService" not in result.unknown_keys
        assert result.unknown_keys == []

    def test_associated_resource_arn(self) -> None:
        """iam:AssociatedResourceArn sets has_associated_resource_arn_condition."""
        cond = {
            "ArnLike": {
                "iam:AssociatedResourceArn": "arn:aws:lambda:us-east-1:111111111111:function:*",
            }
        }
        result = extract_conditions(cond)
        assert result.has_associated_resource_arn_condition is True
        assert "iam:AssociatedResourceArn" in result.condition_keys
        assert "iam:AssociatedResourceArn" not in result.unknown_keys
        assert result.unknown_keys == []

    def test_principal_tag_bare_and_prefix(self) -> None:
        """aws:PrincipalTag (bare) and aws:PrincipalTag/Team (prefix) both flip the flag.

        Real policies always use the prefix form; bare form is legal but rare.
        """
        bare = extract_conditions({"StringEquals": {"aws:PrincipalTag": "anything"}})
        assert bare.has_principal_tag_condition is True
        assert bare.unknown_keys == []

        prefixed = extract_conditions({"StringEquals": {"aws:PrincipalTag/Team": "platform"}})
        assert prefixed.has_principal_tag_condition is True
        assert "aws:PrincipalTag/Team" in prefixed.condition_keys
        assert prefixed.unknown_keys == []

    def test_request_tag_bare_and_prefix(self) -> None:
        """aws:RequestTag (bare) and aws:RequestTag/Environment (prefix) both flip the flag."""
        bare = extract_conditions({"StringEquals": {"aws:RequestTag": "anything"}})
        assert bare.has_request_tag_condition is True
        assert bare.unknown_keys == []

        prefixed = extract_conditions({"StringEquals": {"aws:RequestTag/Environment": "prod"}})
        assert prefixed.has_request_tag_condition is True
        assert "aws:RequestTag/Environment" in prefixed.condition_keys
        assert prefixed.unknown_keys == []

    def test_resource_account(self) -> None:
        """aws:ResourceAccount sets has_resource_account_condition."""
        cond = {
            "StringEquals": {
                "aws:ResourceAccount": "222222222222",
            }
        }
        result = extract_conditions(cond)
        assert result.has_resource_account_condition is True
        assert "aws:ResourceAccount" in result.condition_keys
        assert "aws:ResourceAccount" not in result.unknown_keys
        assert result.unknown_keys == []

    def test_resource_org_id(self) -> None:
        """aws:ResourceOrgID sets has_resource_org_id_condition."""
        cond = {
            "StringEquals": {
                "aws:ResourceOrgID": "o-abcdef1234",
            }
        }
        result = extract_conditions(cond)
        assert result.has_resource_org_id_condition is True
        assert "aws:ResourceOrgID" in result.condition_keys
        assert "aws:ResourceOrgID" not in result.unknown_keys
        assert result.unknown_keys == []

    def test_six_new_keys_not_in_unknown_keys(self) -> None:
        """Exit-criterion invariant: all 6 COND-1 keys present → unknown_keys empty.

        Merges all six new keys into one policy condition block and asserts
        that none of them land in unknown_keys. This is the literal statement
        of the S02 Phase 5 exit criterion.
        """
        cond = {
            "StringEquals": {
                "iam:PassedToService": "lambda.amazonaws.com",
                "aws:PrincipalTag/Team": "platform",
                "aws:RequestTag/Environment": "prod",
                "aws:ResourceAccount": "222222222222",
                "aws:ResourceOrgID": "o-abcdef1234",
            },
            "ArnLike": {
                "iam:AssociatedResourceArn": "arn:aws:lambda:*:*:function:*",
            },
        }
        result = extract_conditions(cond)
        assert result.has_passed_to_service_condition is True
        assert result.has_associated_resource_arn_condition is True
        assert result.has_principal_tag_condition is True
        assert result.has_request_tag_condition is True
        assert result.has_resource_account_condition is True
        assert result.has_resource_org_id_condition is True
        assert result.unknown_keys == [], f"S02 exit criterion violated: {result.unknown_keys}"

    def test_case_insensitive_passed_to_service(self) -> None:
        """Lowercase iam:passedtoservice also flips the flag (parity with existing pattern)."""
        cond = {
            "StringEquals": {
                "iam:passedtoservice": "lambda.amazonaws.com",
            }
        }
        result = extract_conditions(cond)
        assert result.has_passed_to_service_condition is True
        assert result.unknown_keys == []
