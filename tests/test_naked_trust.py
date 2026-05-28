"""Tests for naked trust classifier — exposure level classification.

Tests cover architecture doc §5.8:
- CRITICAL_NAKED: wildcard, no conditions
- BROAD_NAKED: cross-account root no conditions; wildcard with conditions
- NARROW_NAKED: cross-account specific role no conditions; root with weak condition
- CONDITIONED: cross-account with OrgID; with MFA; with multiple weak conditions
- INTRA_ACCOUNT: same-account; service principal; federated
"""

from iamscope.constants import (
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NAKED_NARROW,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_OIDC_PROVIDER,
    NODE_TYPE_SAML_PROVIDER,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
    TRUST_SCOPE_FEDERATED,
    TRUST_SCOPE_SERVICE,
    TRUST_SCOPE_SPECIFIC_ROLE,
)
from iamscope.models import TrustParseResult
from iamscope.resolver.naked_trust import classify_naked_trust


def _make_tr(**overrides) -> TrustParseResult:
    defaults = {
        "statement_index": 0,
        "effect": "Allow",
        "action": "sts:AssumeRole",
        "principal_type": "AWS",
        "principal_value": "arn:aws:iam::222222222222:root",
        "resolved_node_type": NODE_TYPE_ACCOUNT_ROOT,
        "trust_scope": TRUST_SCOPE_ACCOUNT_ROOT,
        "cross_account": True,
    }
    defaults.update(overrides)
    return TrustParseResult(**defaults)


class TestCriticalNaked:
    """CRITICAL_NAKED: Principal * with NO conditions."""

    def test_wildcard_no_conditions(self) -> None:
        """Wildcard principal with no conditions → CRITICAL_NAKED."""
        tr = _make_tr(
            principal_value="*",
            resolved_node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
            trust_scope=TRUST_SCOPE_ANY_AWS_PRINCIPAL,
        )
        assert classify_naked_trust(tr) == NAKED_CRITICAL


class TestBroadNaked:
    """BROAD_NAKED: Cross-account root no conditions; wildcard with conditions."""

    def test_cross_account_root_no_conditions(self) -> None:
        """Cross-account root with no conditions → BROAD_NAKED."""
        tr = _make_tr()
        assert classify_naked_trust(tr) == NAKED_BROAD

    def test_wildcard_with_single_condition(self) -> None:
        """Wildcard with conditions → BROAD_NAKED (downgraded from critical)."""
        tr = _make_tr(
            principal_value="*",
            resolved_node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
            trust_scope=TRUST_SCOPE_ANY_AWS_PRINCIPAL,
            has_source_ip_condition=True,
        )
        assert classify_naked_trust(tr) == NAKED_BROAD


class TestNarrowNaked:
    """NARROW_NAKED: Cross-account specific role no conditions; root with weak condition."""

    def test_cross_account_role_no_conditions(self) -> None:
        """Cross-account specific role with no conditions → NARROW_NAKED."""
        tr = _make_tr(
            principal_value="arn:aws:iam::222222222222:role/SomeRole",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
        )
        assert classify_naked_trust(tr) == NAKED_NARROW

    def test_cross_account_root_with_external_id_only(self) -> None:
        """Cross-account root with ExternalId only → NARROW_NAKED (weak condition)."""
        tr = _make_tr(has_external_id=True)
        assert classify_naked_trust(tr) == NAKED_NARROW

    def test_cross_account_role_with_external_id(self) -> None:
        """Cross-account role with ExternalId → NARROW_NAKED."""
        tr = _make_tr(
            principal_value="arn:aws:iam::222222222222:role/SomeRole",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
            has_external_id=True,
        )
        assert classify_naked_trust(tr) == NAKED_NARROW


class TestConditioned:
    """CONDITIONED: Cross-account with strong conditions."""

    def test_cross_account_root_with_org_id(self) -> None:
        """Cross-account root with OrgID → CONDITIONED."""
        tr = _make_tr(has_org_id_condition=True)
        assert classify_naked_trust(tr) == NAKED_CONDITIONED

    def test_cross_account_root_with_mfa(self) -> None:
        """Cross-account root with MFA → CONDITIONED."""
        tr = _make_tr(has_mfa_condition=True)
        assert classify_naked_trust(tr) == NAKED_CONDITIONED

    def test_cross_account_root_with_multiple_weak_conditions(self) -> None:
        """Cross-account root with 2+ weak conditions → CONDITIONED (defense in depth)."""
        tr = _make_tr(
            has_external_id=True,
            has_source_ip_condition=True,
        )
        assert classify_naked_trust(tr) == NAKED_CONDITIONED

    def test_cross_account_role_with_org_id(self) -> None:
        """Cross-account role with OrgID → CONDITIONED."""
        tr = _make_tr(
            principal_value="arn:aws:iam::222222222222:role/SomeRole",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
            has_org_id_condition=True,
        )
        assert classify_naked_trust(tr) == NAKED_CONDITIONED


class TestIntraAccount:
    """INTRA_ACCOUNT: Same-account, service, or federated trust."""

    def test_same_account_root(self) -> None:
        """Same-account trust → INTRA_ACCOUNT."""
        tr = _make_tr(cross_account=False)
        assert classify_naked_trust(tr) == NAKED_INTRA_ACCOUNT

    def test_same_account_role(self) -> None:
        """Same-account specific role → INTRA_ACCOUNT."""
        tr = _make_tr(
            principal_value="arn:aws:iam::111111111111:role/SameAcct",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
            cross_account=False,
        )
        assert classify_naked_trust(tr) == NAKED_INTRA_ACCOUNT

    def test_service_principal(self) -> None:
        """Service principal → INTRA_ACCOUNT (always, even if marked cross-account)."""
        tr = _make_tr(
            principal_value="lambda.amazonaws.com",
            resolved_node_type=NODE_TYPE_AWS_SERVICE,
            trust_scope=TRUST_SCOPE_SERVICE,
            cross_account=False,
        )
        assert classify_naked_trust(tr) == NAKED_INTRA_ACCOUNT

    def test_federated_principal(self) -> None:
        """Federated principal → INTRA_ACCOUNT."""
        tr = _make_tr(
            principal_value="arn:aws:iam::111111111111:saml-provider/MyIdP",
            resolved_node_type=NODE_TYPE_SAML_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
        )
        assert classify_naked_trust(tr) == NAKED_INTRA_ACCOUNT


class TestDeterminism:
    """Determinism tests."""

    def test_same_input_same_classification(self) -> None:
        """Same TrustParseResult → same classification across calls."""
        tr = _make_tr(has_external_id=True, has_source_ip_condition=True)
        c1 = classify_naked_trust(tr)
        c2 = classify_naked_trust(tr)
        assert c1 == c2


class TestOIDCTrust:
    """OIDC federated trust classification based on :sub claim."""

    def test_oidc_no_sub_claim_is_broad_naked(self) -> None:
        """OIDC trust with NO :sub condition → BROAD_NAKED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern=None,
        )
        assert classify_naked_trust(tr) == NAKED_BROAD

    def test_oidc_wildcard_sub_is_broad_naked(self) -> None:
        """OIDC trust with sub: * → BROAD_NAKED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern="*",
        )
        assert classify_naked_trust(tr) == NAKED_BROAD

    def test_oidc_specific_sub_is_conditioned(self) -> None:
        """OIDC trust with specific :sub → CONDITIONED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern="repo:MyOrg/MyRepo:ref:refs/heads/main",
        )
        assert classify_naked_trust(tr) == NAKED_CONDITIONED

    def test_oidc_wildcard_sub_with_spaces(self) -> None:
        """OIDC trust with ' * ' (padded wildcard) → BROAD_NAKED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern=" * ",
        )
        assert classify_naked_trust(tr) == NAKED_BROAD

    def test_oidc_cognito_no_sub(self) -> None:
        """Cognito OIDC with no sub → BROAD_NAKED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="cognito-identity.amazonaws.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern=None,
        )
        assert classify_naked_trust(tr) == NAKED_BROAD

    def test_oidc_multi_repo_sub_is_conditioned(self) -> None:
        """OIDC with multiple specific repo patterns → CONDITIONED."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
            oidc_subject_pattern="repo:MyOrg/Repo1:* | repo:MyOrg/Repo2:*",
        )
        assert classify_naked_trust(tr) == NAKED_CONDITIONED

    def test_saml_still_intra_account(self) -> None:
        """SAML federated trust → still INTRA_ACCOUNT (not affected by OIDC change)."""
        tr = _make_tr(
            principal_type="Federated",
            principal_value="arn:aws:iam::111111111111:saml-provider/MyIdP",
            resolved_node_type=NODE_TYPE_SAML_PROVIDER,
            trust_scope=TRUST_SCOPE_FEDERATED,
            cross_account=False,
        )
        assert classify_naked_trust(tr) == NAKED_INTRA_ACCOUNT
