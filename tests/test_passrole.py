"""Tests for permission edge builder — expansion controls and hyperedge creation.

Tests cover architecture doc R08:
- Specific resource → individual _permission edge
- Wildcard + expand mode → N individual edges
- Wildcard + warn mode → single __hyperedge__
- Wildcard + skip mode → nothing
- Hard limit 500 forces warn mode
- Mixed specific + wildcard
- __hyperedge__ node created with correct properties
- Edge features populated correctly
- PassRole uses passrole_mode from expansion controller
- Deterministic output ordering
"""

from iamscope.collector.passrole import build_permission_edges
from iamscope.constants import (
    EDGE_LAYER_PERMISSION,
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_USER,
)
from iamscope.controls.expansion import ExpansionController
from iamscope.models import PermissionParseResult


def _make_pr(
    action: str = "sts:AssumeRole",
    resource: str = "*",
    is_wildcard: bool = True,
    source_arn: str = "arn:aws:iam::111111\u003111111:user/Admin",
    **overrides,
) -> PermissionParseResult:
    defaults = {
        "statement_index": 0,
        "effect": "Allow",
        "action": action,
        "resource_pattern": resource,
        "is_wildcard_resource": is_wildcard,
        "source_arn": source_arn,
        "source_node_type": NODE_TYPE_IAM_USER,
        "source_account_id": "111111\u003111111",
        "policy_source": "inline",
        "policy_name": "test-policy",
        "action_matched_via": "exact",
    }
    defaults.update(overrides)
    return PermissionParseResult(**defaults)


KNOWN_ROLES = [
    "arn:aws:iam::111111\u003111111:role/RoleA",
    "arn:aws:iam::111111\u003111111:role/RoleB",
    "arn:aws:iam::111111\u003111111:role/RoleC",
]


class TestSpecificResource:
    """Tests for specific resource permission grants."""

    def test_specific_resource_creates_edge(self) -> None:
        """Specific resource ARN creates one _permission edge."""
        pr = _make_pr(
            resource="arn:aws:iam::222222\u003222222:role/ProdDeploy",
            is_wildcard=False,
        )
        ec = ExpansionController(global_mode="warn")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert len(nodes) == 0
        e = edges[0]
        assert e.edge_type == f"sts:AssumeRole_{EDGE_LAYER_PERMISSION}"
        assert e.src.provider_id == "arn:aws:iam::111111\u003111111:user/Admin"
        assert e.dst.provider_id == "arn:aws:iam::222222\u003222222:role/ProdDeploy"
        assert e.features["is_wildcard_resource"] is False

    def test_specific_resource_registers_edge_count(self) -> None:
        """Specific resource edge is registered with expansion controller."""
        pr = _make_pr(
            resource="arn:aws:iam::222222\u003222222:role/ProdDeploy",
            is_wildcard=False,
        )
        ec = ExpansionController(global_mode="warn")
        build_permission_edges([pr], ec, KNOWN_ROLES)

        assert ec.total_edges == 1


class TestExpandMode:
    """Tests for wildcard resource with expand mode."""

    def test_wildcard_expand_creates_individual_edges(self) -> None:
        """Wildcard resource + expand mode → one edge per known role."""
        pr = _make_pr()
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 3
        assert len(nodes) == 0
        dst_arns = {e.dst.provider_id for e in edges}
        assert dst_arns == set(KNOWN_ROLES)

    def test_expanded_edges_have_wildcard_flag(self) -> None:
        """Expanded edges are marked as expanded_from_wildcard."""
        pr = _make_pr()
        ec = ExpansionController(global_mode="expand")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        for e in edges:
            assert e.features["expanded_from_wildcard"] is True
            assert e.features["is_wildcard_resource"] is True


class TestWarnMode:
    """Tests for wildcard resource with warn mode."""

    def test_wildcard_warn_creates_hyperedge(self) -> None:
        """Wildcard resource + warn mode → single __hyperedge__."""
        pr = _make_pr()
        ec = ExpansionController(global_mode="warn")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert len(nodes) == 1

        e = edges[0]
        assert e.dst.node_type == NODE_TYPE_HYPEREDGE
        assert e.features["suppressed"] is True
        assert e.features["would_expand_to"] == 3
        assert e.features["expansion_mode"] == "warn"

    def test_hyperedge_node_properties(self) -> None:
        """__hyperedge__ node has correct type and properties."""
        pr = _make_pr()
        ec = ExpansionController(global_mode="warn")
        _, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        n = nodes[0]
        assert n.node_type == NODE_TYPE_HYPEREDGE
        assert n.properties["expansion_type"] == "wildcard_assume_role"
        assert n.properties["account_id"] == "111111\u003111111"


class TestSkipMode:
    """Tests for wildcard resource with skip mode."""

    def test_wildcard_skip_creates_nothing(self) -> None:
        """Wildcard resource + skip mode → no edges, no nodes."""
        pr = _make_pr()
        ec = ExpansionController(global_mode="skip")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert edges == []
        assert nodes == []


class TestPassRole:
    """Tests for iam:PassRole edge building."""

    def test_passrole_specific(self) -> None:
        """Specific PassRole creates one edge."""
        pr = _make_pr(
            action="iam:PassRole",
            resource="arn:aws:iam::111111\u003111111:role/LambdaExec",
            is_wildcard=False,
        )
        ec = ExpansionController(global_mode="warn")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert edges[0].edge_type == f"iam:PassRole_{EDGE_LAYER_PERMISSION}"

    def test_passrole_wildcard_warn(self) -> None:
        """Wildcard PassRole + warn → hyperedge."""
        pr = _make_pr(action="iam:PassRole")
        ec = ExpansionController(global_mode="warn")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert edges[0].features["expansion_type"] == "wildcard_passrole"
        assert len(nodes) == 1

    def test_passrole_mode_override(self) -> None:
        """passrole_mode overrides global_mode for PassRole."""
        pr = _make_pr(action="iam:PassRole")
        ec = ExpansionController(global_mode="warn", passrole_mode="expand")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        # passrole_mode=expand overrides global warn → individual edges
        assert len(edges) == 3
        assert len(nodes) == 0


class TestHardLimits:
    """Tests for expansion hard limits."""

    def test_over_500_forces_warn(self) -> None:
        """>500 would-be expansions forces warn mode even if expand requested."""
        # Create 501 known roles
        many_roles = [f"arn:aws:iam::111111\u003111111:role/Role{i:04d}" for i in range(501)]
        pr = _make_pr()
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges([pr], ec, many_roles)

        # Hard limit forces warn → hyperedge
        assert len(edges) == 1
        assert edges[0].dst.node_type == NODE_TYPE_HYPEREDGE
        assert edges[0].features["would_expand_to"] == 501
        assert len(nodes) == 1


class TestMixedGrants:
    """Tests for mixed specific and wildcard grants."""

    def test_mixed_specific_and_wildcard(self) -> None:
        """Specific + wildcard grants in same batch."""
        pr_specific = _make_pr(
            resource="arn:aws:iam::222222\u003222222:role/ProdDeploy",
            is_wildcard=False,
        )
        pr_wildcard = _make_pr()
        ec = ExpansionController(global_mode="warn")
        edges, nodes = build_permission_edges([pr_specific, pr_wildcard], ec, KNOWN_ROLES)

        # 1 specific edge + 1 hyperedge
        assert len(edges) == 2
        assert len(nodes) == 1

        # Specific edge points to actual role
        specific = [e for e in edges if not e.features.get("suppressed")]
        assert len(specific) == 1
        assert specific[0].dst.provider_id == "arn:aws:iam::222222\u003222222:role/ProdDeploy"


class TestEdgeFeatures:
    """Tests for edge feature population."""

    def test_features_include_permission_metadata(self) -> None:
        """Edge features include permission source tracking."""
        pr = _make_pr(
            resource="arn:aws:iam::222222\u003222222:role/Target",
            is_wildcard=False,
            policy_source="managed",
            policy_name="AdminAccess",
            action_matched_via="wildcard_star",
        )
        ec = ExpansionController(global_mode="warn")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        f = edges[0].features
        assert f["layer"] == EDGE_LAYER_PERMISSION
        assert f["permission_source"] == "managed"
        assert f["policy_name"] == "AdminAccess"
        assert f["action_matched_via"] == "wildcard_star"


class TestDeterminism:
    """Tests for deterministic output."""

    def test_output_sorted_by_edge_id(self) -> None:
        """Output edges are sorted by edge_id."""
        prs = [_make_pr(resource=f"arn:aws:iam::222222\u003222222:role/Role{i}", is_wildcard=False) for i in range(5)]
        ec = ExpansionController(global_mode="warn")
        edges, _ = build_permission_edges(prs, ec, KNOWN_ROLES)

        edge_ids = [e.edge_id for e in edges]
        assert edge_ids == sorted(edge_ids)

    def test_same_input_same_output(self) -> None:
        """Same inputs produce identical outputs."""
        prs = [_make_pr()]
        ec1 = ExpansionController(global_mode="expand")
        ec2 = ExpansionController(global_mode="expand")
        e1, n1 = build_permission_edges(prs, ec1, KNOWN_ROLES)
        e2, n2 = build_permission_edges(prs, ec2, KNOWN_ROLES)

        assert [e.edge_id for e in e1] == [e.edge_id for e in e2]


class TestCumulativePassRoleBudget:
    """Tests for per-principal cumulative expansion budget.

    Prevents the N² blowup: multiple wildcard grants from the same principal
    can silently produce hundreds of edges without triggering the per-expansion
    500 limit. The cumulative budget warns at 200 and hard-caps at 500.
    """

    def test_under_warn_threshold_expands_normally(self) -> None:
        """Under 200 cumulative edges: no intervention."""
        # 50 roles × 1 grant = 50 edges, well under threshold
        roles = [f"arn:aws:iam::111111\u003111111:role/Role{i}" for i in range(50)]
        prs = [_make_pr(action="iam:PassRole")]
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges(prs, ec, roles)
        assert len(edges) == 50
        assert len(nodes) == 0

    def test_cumulative_across_multiple_grants_forces_warn(self) -> None:
        """Two wildcard grants from same principal exceeding cap → second forced to warn."""
        # 300 roles. First PassRole grant expands to 300 (under 500 per-expansion).
        # Second grant from same principal would bring total to 600 → forced warn.
        roles = [f"arn:aws:iam::111111\u003111111:role/Role{i}" for i in range(300)]
        source = "arn:aws:iam::111111\u003111111:user/DevOps"
        pr1 = _make_pr(action="iam:PassRole", source_arn=source)
        pr2 = _make_pr(action="sts:AssumeRole", source_arn=source)
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges([pr1, pr2], ec, roles)

        # First grant: 300 expanded edges
        # Second grant: forced to warn → 1 hyperedge
        expanded = [e for e in edges if not e.features.get("suppressed")]
        hyperedges = [e for e in edges if e.features.get("suppressed")]
        assert len(expanded) == 300
        assert len(hyperedges) == 1

    def test_different_principals_have_independent_budgets(self) -> None:
        """Different source principals track independently."""
        roles = [f"arn:aws:iam::111111\u003111111:role/Role{i}" for i in range(300)]
        pr1 = _make_pr(
            action="iam:PassRole",
            source_arn="arn:aws:iam::111111\u003111111:user/UserA",
        )
        pr2 = _make_pr(
            action="iam:PassRole",
            source_arn="arn:aws:iam::111111\u003111111:user/UserB",
        )
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges([pr1, pr2], ec, roles)

        # Both under 500 each, both expand normally
        assert len(edges) == 600
        assert len(nodes) == 0

    def test_warn_threshold_logged(self) -> None:
        """Between 200-500 cumulative: warn logged but still expands."""
        roles = [f"arn:aws:iam::111111\u003111111:role/Role{i}" for i in range(250)]
        prs = [_make_pr(action="iam:PassRole")]
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges(prs, ec, roles)

        # 250 is above warn (200) but below cap (500) — still expands
        assert len(edges) == 250
        assert len(nodes) == 0

    def test_exact_cap_boundary(self) -> None:
        """Exactly at 500 cumulative: no intervention (cap is >500)."""
        roles = [f"arn:aws:iam::111111\u003111111:role/Role{i}" for i in range(250)]
        source = "arn:aws:iam::111111\u003111111:user/DevOps"
        pr1 = _make_pr(action="iam:PassRole", source_arn=source)
        pr2 = _make_pr(action="sts:AssumeRole", source_arn=source)
        ec = ExpansionController(global_mode="expand")
        edges, nodes = build_permission_edges([pr1, pr2], ec, roles)

        # 250 + 250 = 500 exactly — should still expand (cap is >500)
        assert len(edges) == 500
        assert len(nodes) == 0


class TestRawConditionsPropagation:
    """PR-1 regression tests: every _permission edge must carry raw_conditions.

    The passrole_lambda reasoner (S12) hard-gates on `"raw_conditions" in
    sample.features`. These tests lock in the invariant that every code path
    in `collector/passrole.py` — specific, expanded, and hyperedge — writes
    the parser's condition block through to the edge features dict.
    """

    # Representative condition block mirroring what parser/permission_policy.py
    # emits when it sees `"Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}`.
    _COND = {
        "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"},
    }

    def test_specific_edge_propagates_raw_conditions(self) -> None:
        """Specific-resource path must carry the parser's raw_conditions dict.

        Fails if PR-1 regresses on the non-wildcard path (original defect).
        """
        pr = _make_pr(
            action="iam:PassRole",
            resource="arn:aws:iam::222222\u003222222:role/LambdaExec",
            is_wildcard=False,
            has_conditions=True,
            raw_conditions=self._COND,
        )
        ec = ExpansionController(global_mode="warn", passrole_mode="expand")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert "raw_conditions" in edges[0].features
        assert edges[0].features["raw_conditions"] == self._COND

    def test_expanded_edge_propagates_raw_conditions(self) -> None:
        """Wildcard-expanded path must carry raw_conditions on every edge.

        Fails if PR-1 regresses on the wildcard expansion path.
        """
        pr = _make_pr(
            action="iam:PassRole",
            resource="*",
            is_wildcard=True,
            has_conditions=True,
            raw_conditions=self._COND,
        )
        ec = ExpansionController(global_mode="expand", passrole_mode="expand")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == len(KNOWN_ROLES)
        for e in edges:
            assert "raw_conditions" in e.features
            assert e.features["raw_conditions"] == self._COND

    def test_hyperedge_propagates_raw_conditions(self) -> None:
        """Suppressed hyperedge path must also carry raw_conditions.

        Fails if wildcard grants that warn-suppress to a hyperedge silently
        drop the condition block, which would break the passrole_lambda
        precondition gate for any grant exceeding the expansion budget.
        """
        pr = _make_pr(
            action="iam:PassRole",
            resource="*",
            is_wildcard=True,
            has_conditions=True,
            raw_conditions=self._COND,
        )
        # warn mode at both levels forces the hyperedge branch deterministically.
        ec = ExpansionController(global_mode="warn", passrole_mode="warn")
        edges, nodes = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert len(nodes) == 1
        e = edges[0]
        assert e.features.get("suppressed") is True
        assert "raw_conditions" in e.features
        assert e.features["raw_conditions"] == self._COND

    def test_empty_conditions_propagate_as_empty_dict(self) -> None:
        """Unconditioned grants must emit raw_conditions = {}, not None.

        Fails if the empty case emits None, which would make the reasoner's
        `"raw_conditions" in features` gate pass while downstream code that
        expects a dict crashes on attribute access.
        """
        pr = _make_pr(
            action="iam:PassRole",
            resource="arn:aws:iam::222222\u003222222:role/LambdaExec",
            is_wildcard=False,
            has_conditions=False,
            raw_conditions={},
        )
        ec = ExpansionController(global_mode="warn", passrole_mode="expand")
        edges, _ = build_permission_edges([pr], ec, KNOWN_ROLES)

        assert len(edges) == 1
        assert edges[0].features["raw_conditions"] == {}
        assert edges[0].features["raw_conditions"] is not None

    def test_raw_conditions_key_present_on_all_permission_edges(self) -> None:
        """Exit-criterion invariant: 100% of _permission edges have raw_conditions.

        Exercises specific, wildcard-expanded, and warn-suppressed paths in
        one call and asserts the invariant across the full returned set.
        Fails if any emitting path in the collector is ever added without
        propagating raw_conditions — the 100% guarantee the reasoner layer
        depends on.
        """
        specific = _make_pr(
            action="iam:PassRole",
            resource="arn:aws:iam::222222\u003222222:role/LambdaExec",
            is_wildcard=False,
            has_conditions=True,
            raw_conditions=self._COND,
            source_arn="arn:aws:iam::111111\u003111111:user/Alice",
        )
        wildcard_expand = _make_pr(
            action="sts:AssumeRole",
            resource="*",
            is_wildcard=True,
            has_conditions=False,
            raw_conditions={},
            source_arn="arn:aws:iam::111111\u003111111:user/Bob",
        )
        wildcard_warn = _make_pr(
            action="iam:PassRole",
            resource="*",
            is_wildcard=True,
            has_conditions=True,
            raw_conditions=self._COND,
            source_arn="arn:aws:iam::111111\u003111111:user/Carol",
        )
        # Mixed config: assume_role expands, passrole warns. Exercises all three
        # emitter branches in one pass.
        ec = ExpansionController(global_mode="expand", passrole_mode="warn")
        edges, _ = build_permission_edges(
            [specific, wildcard_expand, wildcard_warn],
            ec,
            KNOWN_ROLES,
        )

        # Must touch all three branches: specific + N expanded + 1 hyperedge.
        assert any(not e.features.get("is_wildcard_resource") for e in edges)
        assert any(e.features.get("expanded_from_wildcard") for e in edges)
        assert any(e.features.get("suppressed") for e in edges)

        # The 100% invariant.
        for e in edges:
            assert e.features.get("layer") == EDGE_LAYER_PERMISSION
            assert "raw_conditions" in e.features, f"Edge missing raw_conditions: {e.edge_type} {e.features}"
            assert isinstance(e.features["raw_conditions"], dict)


class TestTyp1NodeTypeInference:
    """TYP-1 regression tests: _infer_node_type_from_arn maps common resource ARNs.

    Pre-S04 the function returned NODE_TYPE_IAM_ROLE for every non-role ARN,
    silently typing Lambda functions, ECS clusters, EC2 instances, and Secrets
    Manager secrets as IAMRole nodes. Post-S04 the four named patterns map to
    their correct node types. Unknown patterns still fall back to IAMRole so
    that resource types outside the TYP-1 scope don't break existing behaviour.
    """

    def test_lambda_function_arn_maps_to_lambda_function(self) -> None:
        """Real Lambda ARN (:function: colon form) → LambdaFunction."""
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_LAMBDA_FUNCTION

        arn = "arn:aws:lambda:us-east-1:111111\u003111111:function:MyFunc"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_LAMBDA_FUNCTION
        # Wildcard form still canonical
        wildcard = "arn:aws:lambda:*:*:function:*"
        assert _infer_node_type_from_arn(wildcard) == NODE_TYPE_LAMBDA_FUNCTION

    def test_ecs_cluster_arn_maps_to_ecs_cluster(self) -> None:
        """ECS cluster ARN (:cluster/ slash form) → ECSCluster."""
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_ECS_CLUSTER

        arn = "arn:aws:ecs:us-east-1:111111\u003111111:cluster/prod"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_ECS_CLUSTER

    def test_ec2_instance_arn_maps_to_ec2_instance(self) -> None:
        """EC2 instance ARN (:instance/ slash form) → EC2Instance.

        Distinct from NODE_TYPE_EC2_INSTANCE_PROFILE — this is the actual
        compute instance, not the IAM instance profile that wraps a role.
        """
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_EC2_INSTANCE

        arn = "arn:aws:ec2:us-east-1:111111\u003111111:instance/i-0abc123def"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_EC2_INSTANCE

    def test_secrets_manager_arn_maps_to_secret(self) -> None:
        """Secrets Manager secret ARN (:secret: colon form) → SecretsManagerSecret."""
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_SECRETS_MANAGER_SECRET

        arn = "arn:aws:secretsmanager:us-east-1:111111\u003111111:secret:db-creds-xYz9Q"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_SECRETS_MANAGER_SECRET

    def test_role_arn_still_maps_to_iam_role(self) -> None:
        """Regression: role ARNs must still return IAMRole.

        Guards against the TYP-1 rewrite accidentally shadowing the :role/
        branch with one of the new substrings.
        """
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_IAM_ROLE

        arn = "arn:aws:iam::222222\u003222222:role/LambdaExec"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_IAM_ROLE

    def test_unknown_arn_falls_back_to_iam_role(self) -> None:
        """Unrecognised ARN pattern preserves the legacy IAMRole default.

        Documents the TYP-1 scope as "map these — leave the rest alone."
        A DynamoDB table ARN has no currently-mapped substring and falls
        back. A future session can extend the table; until then, legacy
        behaviour is preserved so existing callers don't get surprise
        type changes.

        v0.2.26 update: S3 bucket ARNs are now recognised (see
        `test_s3_bucket_arn_maps_to_s3_bucket`). This test uses a
        DynamoDB table ARN as the truly-unknown example.
        """
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_IAM_ROLE

        arn = "arn:aws:dynamodb:us-east-1:111111\u003111111:table/my-table"
        assert _infer_node_type_from_arn(arn) == NODE_TYPE_IAM_ROLE

    def test_s3_bucket_arn_maps_to_s3_bucket(self) -> None:
        """S3 bucket ARNs are classified as S3Bucket (v0.2.26)."""
        from iamscope.collector.passrole import _infer_node_type_from_arn
        from iamscope.constants import NODE_TYPE_S3_BUCKET

        # Bucket-level ARN
        assert _infer_node_type_from_arn("arn:aws:s3:::my-bucket") == NODE_TYPE_S3_BUCKET
        # Object-level ARN (also contains :s3::: substring)
        assert _infer_node_type_from_arn("arn:aws:s3:::my-bucket/path/to/key.txt") == NODE_TYPE_S3_BUCKET
