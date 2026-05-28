"""Tests for cross-account resolver — synthetic node creation and trust edge building.

Tests cover architecture doc §5.3, §5.6:
- Creates AccountPrincipalSet synthetic nodes
- Deduplicates identical principals
- Creates WildcardPrincipal node
- Creates AWSService nodes
- Creates ExternalAccount for unrecognized principals
- Creates SAML/OIDC nodes
- Creates cross-account IAMRole/IAMUser synthetics
- Skips same-account IAMRole (will be collected directly)
- Builds trust edges with correct src/dst/type
- Populates edge features (cross_account, naked_trust, conditions)
- Applies noise filter to edges
"""

from iamscope.constants import (
    EDGE_LAYER_TRUST,
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_OIDC_PROVIDER,
    NODE_TYPE_SAML_PROVIDER,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    PROVIDER_AWS,
    REGION_GLOBAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
    TRUST_SCOPE_SERVICE,
    TRUST_SCOPE_SPECIFIC_ROLE,
)
from iamscope.models import Node, TrustParseResult
from iamscope.resolver.cross_account import build_trust_edges, resolve_synthetic_nodes


def _make_trust_result(**overrides) -> TrustParseResult:
    """Helper to create a TrustParseResult with defaults."""
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


def _make_role_node(
    arn: str = "arn:aws:iam::111111111111:role/TargetRole",
    account_id: str = "111111111111",
) -> Node:
    """Helper to create a role Node."""
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": account_id, "is_synthetic": False, "path": "/"},
    )


class TestResolveSyntheticNodes:
    """Tests for resolve_synthetic_nodes."""

    def test_creates_account_root_node(self) -> None:
        """Cross-account root principal creates AccountPrincipalSet synthetic node."""
        tr = _make_trust_result()
        nodes = resolve_synthetic_nodes([tr], {"111111111111"})

        assert len(nodes) == 1
        n = nodes[0]
        assert n.node_type == NODE_TYPE_ACCOUNT_ROOT
        assert n.provider_id == "arn:aws:iam::222222222222:root"
        assert n.properties["is_synthetic"] is True
        assert n.properties["account_id"] == "222222222222"
        assert n.properties["is_external"] is True
        assert n.properties["org_member"] is False

    def test_deduplicates_same_principal(self) -> None:
        """Identical principals from multiple statements produce one node."""
        tr1 = _make_trust_result(statement_index=0)
        tr2 = _make_trust_result(statement_index=1)
        nodes = resolve_synthetic_nodes([tr1, tr2])

        assert len(nodes) == 1

    def test_creates_wildcard_node(self) -> None:
        """Wildcard principal creates WildcardPrincipal node with provider_id '*'."""
        tr = _make_trust_result(
            principal_value="*",
            resolved_node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
            trust_scope=TRUST_SCOPE_ANY_AWS_PRINCIPAL,
        )
        nodes = resolve_synthetic_nodes([tr])

        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_WILDCARD_PRINCIPAL
        assert nodes[0].provider_id == "*"

    def test_creates_service_node(self) -> None:
        """Service principal creates AWSService synthetic node."""
        tr = _make_trust_result(
            principal_type="Service",
            principal_value="lambda.amazonaws.com",
            resolved_node_type=NODE_TYPE_AWS_SERVICE,
            trust_scope=TRUST_SCOPE_SERVICE,
            cross_account=False,
        )
        nodes = resolve_synthetic_nodes([tr])

        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_AWS_SERVICE
        assert nodes[0].provider_id == "lambda.amazonaws.com"
        assert nodes[0].properties["service_name"] == "lambda.amazonaws.com"

    def test_creates_saml_node(self) -> None:
        """SAML provider creates SAMLProvider synthetic node."""
        tr = _make_trust_result(
            principal_type="Federated",
            principal_value="arn:aws:iam::111111111111:saml-provider/MyIdP",
            resolved_node_type=NODE_TYPE_SAML_PROVIDER,
            trust_scope="federated",
            cross_account=False,
        )
        nodes = resolve_synthetic_nodes([tr])

        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_SAML_PROVIDER

    def test_creates_oidc_node(self) -> None:
        """OIDC provider creates OIDCProvider synthetic node."""
        tr = _make_trust_result(
            principal_type="Federated",
            principal_value="cognito-identity.amazonaws.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope="federated",
            cross_account=False,
        )
        nodes = resolve_synthetic_nodes([tr])

        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_OIDC_PROVIDER

    def test_creates_cross_account_role_synthetic(self) -> None:
        """Cross-account IAMRole creates synthetic node (won't be collected)."""
        tr = _make_trust_result(
            principal_value="arn:aws:iam::222222222222:role/CrossRole",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
            cross_account=True,
        )
        nodes = resolve_synthetic_nodes([tr], {"111111111111"})

        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_IAM_ROLE
        assert nodes[0].properties["is_synthetic"] is True
        assert nodes[0].properties["is_external"] is True
        assert nodes[0].properties["org_member"] is False

    def test_skips_same_account_role(self) -> None:
        """Same-account IAMRole does NOT create synthetic node (will be collected)."""
        tr = _make_trust_result(
            principal_value="arn:aws:iam::111111111111:role/SameAcctRole",
            resolved_node_type=NODE_TYPE_IAM_ROLE,
            trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
            cross_account=False,
        )
        nodes = resolve_synthetic_nodes([tr], {"111111111111"})

        assert len(nodes) == 0

    def test_marks_known_account_as_internal(self) -> None:
        """Account root for a known account is marked is_external=False."""
        tr = _make_trust_result(
            principal_value="arn:aws:iam::222222222222:root",
        )
        nodes = resolve_synthetic_nodes([tr], {"111111111111", "222222222222"})

        assert len(nodes) == 1
        assert nodes[0].properties["is_external"] is False
        assert nodes[0].properties["org_member"] is True

    def test_mixed_principals_all_created(self) -> None:
        """Multiple different principal types all create their respective nodes."""
        trs = [
            _make_trust_result(
                principal_value="arn:aws:iam::222222222222:root",
                resolved_node_type=NODE_TYPE_ACCOUNT_ROOT,
            ),
            _make_trust_result(
                principal_value="*",
                resolved_node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
                trust_scope=TRUST_SCOPE_ANY_AWS_PRINCIPAL,
            ),
            _make_trust_result(
                principal_value="lambda.amazonaws.com",
                resolved_node_type=NODE_TYPE_AWS_SERVICE,
                trust_scope=TRUST_SCOPE_SERVICE,
                cross_account=False,
            ),
        ]
        nodes = resolve_synthetic_nodes(trs)

        assert len(nodes) == 3
        types = {n.node_type for n in nodes}
        assert types == {NODE_TYPE_ACCOUNT_ROOT, NODE_TYPE_WILDCARD_PRINCIPAL, NODE_TYPE_AWS_SERVICE}

    def test_output_sorted_by_node_id(self) -> None:
        """Output nodes are sorted by node_id for determinism."""
        trs = [
            _make_trust_result(
                principal_value="lambda.amazonaws.com",
                resolved_node_type=NODE_TYPE_AWS_SERVICE,
                trust_scope=TRUST_SCOPE_SERVICE,
                cross_account=False,
            ),
            _make_trust_result(
                principal_value="arn:aws:iam::222222222222:root",
                resolved_node_type=NODE_TYPE_ACCOUNT_ROOT,
            ),
        ]
        nodes = resolve_synthetic_nodes(trs)
        node_ids = [n.node_id for n in nodes]
        assert node_ids == sorted(node_ids)


class TestBuildTrustEdges:
    """Tests for build_trust_edges."""

    def test_builds_basic_trust_edge(self) -> None:
        """Basic trust edge has correct src, dst, type."""
        tr = _make_trust_result()
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert len(edges) == 1
        e = edges[0]
        assert e.edge_type == f"sts:AssumeRole_{EDGE_LAYER_TRUST}"
        assert e.src.provider_id == "arn:aws:iam::222222222222:root"
        assert e.src.node_type == NODE_TYPE_ACCOUNT_ROOT
        assert e.dst.provider_id == "arn:aws:iam::111111111111:role/TargetRole"
        assert e.dst.node_type == NODE_TYPE_IAM_ROLE

    def test_edge_features_populated(self) -> None:
        """Edge features contain all expected fields."""
        tr = _make_trust_result(
            has_external_id=True,
            has_org_id_condition=True,
            cross_account=True,
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        f = edges[0].features
        assert f["cross_account"] is True
        assert f["has_external_id"] is True
        assert f["has_org_id_condition"] is True
        assert f["layer"] == EDGE_LAYER_TRUST
        assert f["trust_scope"] == TRUST_SCOPE_ACCOUNT_ROOT
        assert f["statement_index"] == 0
        assert isinstance(f["naked_trust"], str)

    def test_naked_trust_classification_in_features(self) -> None:
        """Edge features include naked trust classification."""
        # Wildcard, no conditions → CRITICAL_NAKED
        tr = _make_trust_result(
            principal_value="*",
            resolved_node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
            trust_scope=TRUST_SCOPE_ANY_AWS_PRINCIPAL,
            cross_account=True,
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert edges[0].features["naked_trust"] == NAKED_CRITICAL

    def test_multiple_results_produce_multiple_edges(self) -> None:
        """Multiple trust results produce multiple edges."""
        trs = [
            _make_trust_result(statement_index=0),
            _make_trust_result(
                statement_index=1,
                principal_value="lambda.amazonaws.com",
                resolved_node_type=NODE_TYPE_AWS_SERVICE,
                trust_scope=TRUST_SCOPE_SERVICE,
                cross_account=False,
            ),
        ]
        role = _make_role_node()
        edges = build_trust_edges(trs, role)

        assert len(edges) == 2
        assert edges[0].features["statement_index"] == 0
        assert edges[1].features["statement_index"] == 1

    def test_noise_filter_applied(self) -> None:
        """Noise filter callback can exclude edges."""
        role = _make_role_node()
        # Self-trust: role trusts its own account root (same account)
        tr_same = _make_trust_result(
            principal_value="arn:aws:iam::111111111111:root",
            cross_account=False,
        )
        # Cross-account trust
        tr_cross = _make_trust_result(
            principal_value="arn:aws:iam::333333333333:root",
            cross_account=True,
        )

        # Filter that excludes same-account edges
        def filter_fn(src_acct: str, dst_acct: str, is_self: bool) -> bool:
            return src_acct != dst_acct

        edges = build_trust_edges([tr_same, tr_cross], role, noise_filter_fn=filter_fn)

        # Only the cross-account edge should survive
        assert len(edges) == 1
        assert edges[0].src.provider_id == "arn:aws:iam::333333333333:root"

    def test_saml_edge_action(self) -> None:
        """SAML trust edge uses sts:AssumeRoleWithSAML action."""
        tr = _make_trust_result(
            action="sts:AssumeRoleWithSAML",
            principal_type="Federated",
            principal_value="arn:aws:iam::111111111111:saml-provider/MyIdP",
            resolved_node_type=NODE_TYPE_SAML_PROVIDER,
            trust_scope="federated",
            cross_account=False,
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert edges[0].edge_type == f"sts:AssumeRoleWithSAML_{EDGE_LAYER_TRUST}"


class TestOIDCEdgeIntegration:
    """Integration tests: OIDC subject pattern flows through to edge features."""

    def test_oidc_with_sub_in_edge_features(self) -> None:
        """OIDC trust with :sub → oidc_subject_pattern in features, CONDITIONED."""
        tr = _make_trust_result(
            action="sts:AssumeRoleWithWebIdentity",
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope="federated",
            cross_account=False,
            oidc_subject_pattern="repo:MyOrg/MyRepo:ref:refs/heads/main",
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert len(edges) == 1
        f = edges[0].features
        assert f["oidc_subject_pattern"] == "repo:MyOrg/MyRepo:ref:refs/heads/main"
        assert f["naked_trust"] == NAKED_CONDITIONED

    def test_oidc_no_sub_in_edge_features(self) -> None:
        """OIDC trust without :sub → oidc_subject_pattern None, BROAD_NAKED."""
        tr = _make_trust_result(
            action="sts:AssumeRoleWithWebIdentity",
            principal_type="Federated",
            principal_value="token.actions.githubusercontent.com",
            resolved_node_type=NODE_TYPE_OIDC_PROVIDER,
            trust_scope="federated",
            cross_account=False,
            oidc_subject_pattern=None,
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert len(edges) == 1
        f = edges[0].features
        assert f["oidc_subject_pattern"] is None
        assert f["naked_trust"] == NAKED_BROAD

    def test_saml_edge_has_no_oidc_subject(self) -> None:
        """SAML trust edge → oidc_subject_pattern None, INTRA_ACCOUNT."""
        tr = _make_trust_result(
            action="sts:AssumeRoleWithSAML",
            principal_type="Federated",
            principal_value="arn:aws:iam::111111111111:saml-provider/MyIdP",
            resolved_node_type=NODE_TYPE_SAML_PROVIDER,
            trust_scope="federated",
            cross_account=False,
        )
        role = _make_role_node()
        edges = build_trust_edges([tr], role)

        assert edges[0].features["oidc_subject_pattern"] is None
        assert edges[0].features["naked_trust"] == NAKED_INTRA_ACCOUNT
