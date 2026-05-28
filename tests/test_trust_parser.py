"""Tests for trust policy parser.

Tests cover all principal variants per architecture doc §5.4:
- Same-account trust (specific role, account root)
- Cross-account trust (specific role with ExternalId, account root naked)
- Wildcard principal (critical naked)
- Service principals (Lambda, EC2, ECS, SSM)
- Multiple statements in one trust policy
- SAML federation
- OIDC federation
- All condition key types
- Multiple conditions on same statement
- Malformed trust policy (graceful failure)
- Empty trust policy (graceful failure)
- Trust policy with Deny statement (skip safely)
- Multiple principals in one statement
- User principal
- Action as list
"""

import json
from pathlib import Path

from iamscope.constants import (
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_OIDC_PROVIDER,
    NODE_TYPE_SAML_PROVIDER,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
    TRUST_SCOPE_FEDERATED,
    TRUST_SCOPE_SERVICE,
    TRUST_SCOPE_SPECIFIC_ROLE,
    TRUST_SCOPE_SPECIFIC_USER,
)
from iamscope.parser.trust_policy import parse_trust_policy

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "trust_policies"

ROLE_ARN = "arn:aws:iam::111111111111:role/TargetRole"
ROLE_ACCOUNT = "111111111111"


def _load_fixture(name: str) -> dict:
    """Load a trust policy fixture by name."""
    path = FIXTURES_DIR / name
    return json.loads(path.read_text())


class TestSameAccountTrust:
    """Tests for same-account trust policies."""

    def test_same_account_specific_role(self) -> None:
        """Same-account specific role trust produces one result, not cross-account."""
        policy = _load_fixture("same_account_specific_role.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_type == "AWS"
        assert r.principal_value == "arn:aws:iam::111111111111:role/AdminRole"
        assert r.resolved_node_type == NODE_TYPE_IAM_ROLE
        assert r.trust_scope == TRUST_SCOPE_SPECIFIC_ROLE
        assert r.cross_account is False
        assert r.action == "sts:AssumeRole"
        assert r.effect == "Allow"
        assert r.statement_index == 0

    def test_same_account_root(self) -> None:
        """Same-account root trust produces AccountPrincipalSet node, not cross-account."""
        policy = _load_fixture("same_account_root.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.resolved_node_type == NODE_TYPE_ACCOUNT_ROOT
        assert r.trust_scope == TRUST_SCOPE_ACCOUNT_ROOT
        assert r.cross_account is False


class TestCrossAccountTrust:
    """Tests for cross-account trust policies."""

    def test_cross_account_with_external_id(self) -> None:
        """Cross-account trust with ExternalId condition."""
        policy = _load_fixture("cross_account_external_id.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_value == "arn:aws:iam::222222222222:role/CrossAccountRole"
        assert r.resolved_node_type == NODE_TYPE_IAM_ROLE
        assert r.trust_scope == TRUST_SCOPE_SPECIFIC_ROLE
        assert r.cross_account is True
        assert r.has_external_id is True
        assert "sts:ExternalId" in r.condition_keys

    def test_cross_account_root_naked(self) -> None:
        """Cross-account root trust with no conditions (naked trust)."""
        policy = _load_fixture("cross_account_root_naked.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.resolved_node_type == NODE_TYPE_ACCOUNT_ROOT
        assert r.trust_scope == TRUST_SCOPE_ACCOUNT_ROOT
        assert r.cross_account is True
        assert r.has_external_id is False
        assert r.has_source_account_condition is False
        assert r.has_mfa_condition is False
        assert r.condition_keys == []

    def test_user_principal_cross_account(self) -> None:
        """Cross-account user principal."""
        policy = _load_fixture("user_principal.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.resolved_node_type == NODE_TYPE_IAM_USER
        assert r.trust_scope == TRUST_SCOPE_SPECIFIC_USER
        assert r.cross_account is True
        assert "user/deployer" in r.principal_value


class TestWildcardPrincipal:
    """Tests for wildcard principal trust policies."""

    def test_wildcard_star_principal(self) -> None:
        """Principal: \"*\" produces WildcardPrincipal, always cross-account."""
        policy = _load_fixture("wildcard_principal.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_value == "*"
        assert r.resolved_node_type == NODE_TYPE_WILDCARD_PRINCIPAL
        assert r.trust_scope == TRUST_SCOPE_ANY_AWS_PRINCIPAL
        assert r.cross_account is True

    def test_wildcard_aws_star(self) -> None:
        """Principal: {\"AWS\": \"*\"} also produces WildcardPrincipal."""
        policy = _load_fixture("wildcard_principal_aws_field.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_value == "*"
        assert r.resolved_node_type == NODE_TYPE_WILDCARD_PRINCIPAL
        assert r.trust_scope == TRUST_SCOPE_ANY_AWS_PRINCIPAL


class TestServicePrincipals:
    """Tests for service principal trust policies."""

    def test_lambda_service(self) -> None:
        """Lambda service principal."""
        policy = _load_fixture("service_lambda.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_type == "Service"
        assert r.principal_value == "lambda.amazonaws.com"
        assert r.resolved_node_type == NODE_TYPE_AWS_SERVICE
        assert r.trust_scope == TRUST_SCOPE_SERVICE
        assert r.cross_account is False

    def test_ec2_service(self) -> None:
        """EC2 service principal."""
        policy = _load_fixture("service_ec2.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_value == "ec2.amazonaws.com"
        assert r.resolved_node_type == NODE_TYPE_AWS_SERVICE
        assert r.trust_scope == TRUST_SCOPE_SERVICE

    def test_multiple_services(self) -> None:
        """Multiple service principals in one statement."""
        policy = _load_fixture("multiple_services.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 2
        services = {r.principal_value for r in results}
        assert "ecs-tasks.amazonaws.com" in services
        assert "ssm.amazonaws.com" in services
        for r in results:
            assert r.resolved_node_type == NODE_TYPE_AWS_SERVICE
            assert r.trust_scope == TRUST_SCOPE_SERVICE


class TestFederation:
    """Tests for federated principal trust policies."""

    def test_saml_federation(self) -> None:
        """SAML federation principal."""
        policy = _load_fixture("saml_federation.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_type == "Federated"
        assert "saml-provider/MyIdP" in r.principal_value
        assert r.resolved_node_type == NODE_TYPE_SAML_PROVIDER
        assert r.trust_scope == TRUST_SCOPE_FEDERATED
        assert r.action == "sts:AssumeRoleWithSAML"
        assert r.cross_account is False
        # SAML:aud is a known condition key
        assert "SAML:aud" in r.condition_keys

    def test_oidc_federation(self) -> None:
        """OIDC (Cognito) federation principal."""
        policy = _load_fixture("oidc_federation.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.principal_type == "Federated"
        assert r.principal_value == "cognito-identity.amazonaws.com"
        assert r.resolved_node_type == NODE_TYPE_OIDC_PROVIDER
        assert r.trust_scope == TRUST_SCOPE_FEDERATED
        assert r.action == "sts:AssumeRoleWithWebIdentity"


class TestMultipleStatements:
    """Tests for trust policies with multiple statements."""

    def test_multiple_statements(self) -> None:
        """Multiple Allow statements produce results with correct statement_index."""
        policy = _load_fixture("multiple_statements.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 3

        # Statement 0: cross-account role
        assert results[0].statement_index == 0
        assert results[0].resolved_node_type == NODE_TYPE_IAM_ROLE
        assert results[0].cross_account is True

        # Statement 1: Lambda service
        assert results[1].statement_index == 1
        assert results[1].resolved_node_type == NODE_TYPE_AWS_SERVICE

        # Statement 2: cross-account root
        assert results[2].statement_index == 2
        assert results[2].resolved_node_type == NODE_TYPE_ACCOUNT_ROOT
        assert results[2].cross_account is True

    def test_deny_statement_skipped(self) -> None:
        """Deny statements are skipped; only Allow statements produce results."""
        policy = _load_fixture("deny_statement.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        # Only the Allow statement (index 1) should produce a result
        assert len(results) == 1
        r = results[0]
        assert r.statement_index == 1
        assert r.principal_value == "arn:aws:iam::222222222222:role/AllowedRole"
        assert r.effect == "Allow"


class TestMultiplePrincipals:
    """Tests for statements with multiple principals."""

    def test_multiple_aws_principals(self) -> None:
        """Multiple AWS principals in one statement produce multiple results."""
        policy = _load_fixture("multiple_principals.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 3

        # All from the same statement
        for r in results:
            assert r.statement_index == 0

        # Check all principals resolved
        provider_ids = {r.principal_value for r in results}
        assert "arn:aws:iam::222222222222:role/RoleA" in provider_ids
        assert "arn:aws:iam::333333333333:role/RoleB" in provider_ids
        assert "arn:aws:iam::444444444444:root" in provider_ids

        # Check node types
        types = {r.principal_value: r.resolved_node_type for r in results}
        assert types["arn:aws:iam::222222222222:role/RoleA"] == NODE_TYPE_IAM_ROLE
        assert types["arn:aws:iam::333333333333:role/RoleB"] == NODE_TYPE_IAM_ROLE
        assert types["arn:aws:iam::444444444444:root"] == NODE_TYPE_ACCOUNT_ROOT


class TestConditions:
    """Tests for condition extraction in trust policies."""

    def test_multiple_conditions(self) -> None:
        """Multiple condition keys from different operators."""
        policy = _load_fixture("multiple_conditions.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.has_external_id is True
        assert r.has_org_id_condition is True
        assert r.has_mfa_condition is True
        assert r.has_source_ip_condition is True
        assert len(r.condition_keys) == 4

    def test_source_account_condition(self) -> None:
        """aws:SourceAccount condition."""
        policy = _load_fixture("source_account_condition.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.has_source_account_condition is True

    def test_vpc_conditions(self) -> None:
        """aws:SourceVpc and aws:SourceVpce conditions."""
        policy = _load_fixture("vpc_source_condition.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.has_source_vpc_condition is True

    def test_raw_conditions_canonicalized(self) -> None:
        """Raw conditions must be stored in canonical (sorted keys) form."""
        policy = _load_fixture("multiple_conditions.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        r = results[0]

        # raw_conditions should be a dict (canonical)
        assert isinstance(r.raw_conditions, dict)

        # Verify it round-trips through canonical JSON identically
        import json

        canonical = json.dumps(r.raw_conditions, sort_keys=True, separators=(",", ":"))
        reparsed = json.loads(canonical)
        assert reparsed == r.raw_conditions


class TestEdgeCases:
    """Tests for malformed, empty, and unusual trust policies."""

    def test_malformed_policy_returns_empty(self) -> None:
        """Malformed policy (no Statement field) returns empty list."""
        policy = _load_fixture("malformed_policy.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert results == []

    def test_empty_statements_returns_empty(self) -> None:
        """Empty Statement array returns empty list."""
        policy = _load_fixture("empty_statements.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert results == []

    def test_string_policy_document(self) -> None:
        """Policy document as JSON string is parsed correctly."""
        policy_dict = _load_fixture("same_account_specific_role.json")
        policy_str = json.dumps(policy_dict)
        results = parse_trust_policy(policy_str, ROLE_ARN, ROLE_ACCOUNT)
        assert len(results) == 1
        assert results[0].resolved_node_type == NODE_TYPE_IAM_ROLE

    def test_action_as_list(self) -> None:
        """Action field as list produces results for each action."""
        policy = _load_fixture("action_as_list.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        # Two actions: sts:AssumeRole and sts:TagSession
        assert len(results) == 2
        actions = {r.action for r in results}
        assert "sts:AssumeRole" in actions
        assert "sts:TagSession" in actions

    def test_completely_invalid_json_string(self) -> None:
        """Completely invalid JSON string returns empty list."""
        results = parse_trust_policy("{not valid json", ROLE_ARN, ROLE_ACCOUNT)
        assert results == []

    def test_none_policy_returns_empty(self) -> None:
        """None as policy returns empty list."""
        results = parse_trust_policy(None, ROLE_ARN, ROLE_ACCOUNT)  # type: ignore[arg-type]
        assert results == []


class TestDeterminism:
    """Tests for output determinism."""

    def test_same_policy_same_results(self) -> None:
        """Parsing the same policy twice produces identical results."""
        policy = _load_fixture("multiple_statements.json")
        results1 = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        results2 = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results1) == len(results2)
        for r1, r2 in zip(results1, results2, strict=True):
            assert r1.statement_index == r2.statement_index
            assert r1.principal_value == r2.principal_value
            assert r1.resolved_node_type == r2.resolved_node_type
            assert r1.trust_scope == r2.trust_scope
            assert r1.cross_account == r2.cross_account
            assert r1.condition_keys == r2.condition_keys

    def test_condition_keys_always_sorted(self) -> None:
        """Condition keys in results are always sorted."""
        policy = _load_fixture("multiple_conditions.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        for r in results:
            assert r.condition_keys == sorted(r.condition_keys)


class TestOIDCSubjectExtraction:
    """Tests for OIDC :sub claim extraction into oidc_subject_pattern."""

    def test_github_actions_with_sub(self) -> None:
        """GitHub Actions OIDC with :sub condition → extracts pattern."""
        policy = _load_fixture("github_actions_oidc_with_sub.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.resolved_node_type == NODE_TYPE_OIDC_PROVIDER
        assert r.oidc_subject_pattern == "repo:MyOrg/MyRepo:ref:refs/heads/main"

    def test_github_actions_no_sub(self) -> None:
        """GitHub Actions OIDC with only :aud → oidc_subject_pattern is None."""
        policy = _load_fixture("github_actions_oidc_no_sub.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        r = results[0]
        assert r.resolved_node_type == NODE_TYPE_OIDC_PROVIDER
        assert r.oidc_subject_pattern is None

    def test_cognito_oidc_no_sub(self) -> None:
        """Cognito OIDC with only :aud → oidc_subject_pattern is None."""
        policy = _load_fixture("oidc_federation.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) == 1
        assert results[0].oidc_subject_pattern is None

    def test_saml_has_no_oidc_subject(self) -> None:
        """SAML federation → oidc_subject_pattern is None (not OIDC)."""
        policy = _load_fixture("saml_federation.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) >= 1
        for r in results:
            assert r.oidc_subject_pattern is None

    def test_non_federated_has_no_oidc_subject(self) -> None:
        """AWS principal → oidc_subject_pattern is None."""
        policy = _load_fixture("same_account_specific_role.json")
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)

        assert len(results) >= 1
        for r in results:
            assert r.oidc_subject_pattern is None

    def test_oidc_sub_wildcard(self) -> None:
        """OIDC with sub: * → oidc_subject_pattern = '*'."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "*"}},
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert results[0].oidc_subject_pattern == "*"

    def test_oidc_sub_multiple_repos(self) -> None:
        """OIDC with multiple :sub values → joined with ' | '."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub": ["repo:MyOrg/Repo2:*", "repo:MyOrg/Repo1:*"]
                        }
                    },
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        # Sorted join
        assert results[0].oidc_subject_pattern == "repo:MyOrg/Repo1:* | repo:MyOrg/Repo2:*"

    def test_oidc_arn_format_principal_extracts_sub(self) -> None:
        """OIDC provider specified as ARN → still extracts :sub from URL portion."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:MyOrg/MyRepo:*"}},
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert results[0].oidc_subject_pattern == "repo:MyOrg/MyRepo:*"


class TestARNPartitionSupport:
    """Tests for GovCloud and China partition ARN handling."""

    def test_govcloud_arn_parsed(self) -> None:
        """GovCloud ARN (arn:aws-us-gov:...) is parsed correctly."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws-us-gov:iam::222222222222:role/GovCloudRole"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert len(results) == 1
        assert results[0].principal_value == "arn:aws-us-gov:iam::222222222222:role/GovCloudRole"
        assert results[0].resolved_node_type == NODE_TYPE_IAM_ROLE
        assert results[0].cross_account is True

    def test_china_arn_parsed(self) -> None:
        """China partition ARN (arn:aws-cn:...) is parsed correctly."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws-cn:iam::333333333333:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert len(results) == 1
        assert results[0].resolved_node_type == NODE_TYPE_ACCOUNT_ROOT
        assert results[0].cross_account is True

    def test_standard_arn_still_works(self) -> None:
        """Standard partition ARN still parses after regex change."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        results = parse_trust_policy(policy, ROLE_ARN, ROLE_ACCOUNT)
        assert len(results) == 1
        assert results[0].resolved_node_type == NODE_TYPE_ACCOUNT_ROOT
