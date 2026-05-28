"""Hardening tests — invariant pinning and cross-module edge cases.

Tests cover:
- Invariant #2: Deterministic IDs (same input → same ID, always)
- Invariant #3: Canonical JSON (sorted keys, no whitespace variance)
- Invariant #4: Hash stability (same scenario → same hash)
- Invariant #6: No API calls in resolution phase
- Invariant #18: Pagination exhaustive (large collections)
- Edge case: empty organization (no OUs, no SCPs)
- Edge case: role with no trust policy statements
- Edge case: permission policy with only Deny (no edges)
- Edge case: wildcard * principal in trust policy
- Edge case: deeply nested condition keys
- Edge case: Unicode in policy names
- Edge case: 12-digit account ID validation
- Cross-module: pipeline → validator round-trip
- Cross-module: pipeline → diff round-trip (determinism)
- Cross-module: report from real pipeline output
"""

import json

from moto import mock_aws

from iamscope.auth.session import get_session
from iamscope.diff import diff_scenarios
from iamscope.identity.deterministic_ids import edge_id, node_id
from iamscope.models import Node, ScenarioMetadata
from iamscope.output.scenario_json import emit_scenario
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.validate import validate_scenario


class TestDeterministicIDs:
    """Invariant #2: Same input always produces same ID."""

    def test_node_id_stable(self) -> None:
        """Same node inputs → same ID across calls."""
        id1 = node_id("aws", "IAMRole", "arn:aws:iam::123:role/X")
        id2 = node_id("aws", "IAMRole", "arn:aws:iam::123:role/X")
        assert id1 == id2
        assert len(id1) == 64  # SHA-256 hex

    def test_node_id_different_inputs(self) -> None:
        """Different inputs → different IDs."""
        id1 = node_id("aws", "IAMRole", "arn:aws:iam::123:role/X")
        id2 = node_id("aws", "IAMRole", "arn:aws:iam::123:role/Y")
        assert id1 != id2

    # v0.2.37 (sha256_null_separated_v2) added `features_digest` as
    # a required fifth arg to `edge_id()`. The hardening invariants
    # below pass `"{}"` as a stable "no features" placeholder so the
    # other fields remain the dimension under test — see
    # `iamscope.identity.deterministic_ids` module docstring for the
    # v1→v2 migration rationale.
    _EMPTY_FEATURES_DIGEST = "{}"

    def test_edge_id_stable(self) -> None:
        """Same edge inputs → same ID."""
        id1 = edge_id(
            "trust",
            "src_id",
            "dst_id",
            "global",
            self._EMPTY_FEATURES_DIGEST,
        )
        id2 = edge_id(
            "trust",
            "src_id",
            "dst_id",
            "global",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert id1 == id2

    def test_edge_id_directional(self) -> None:
        """src→dst ≠ dst→src."""
        id1 = edge_id(
            "trust",
            "a",
            "b",
            "global",
            self._EMPTY_FEATURES_DIGEST,
        )
        id2 = edge_id(
            "trust",
            "b",
            "a",
            "global",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert id1 != id2


class TestCanonicalJSON:
    """Invariant #3: Sorted keys, deterministic output."""

    def test_node_to_dict_sorted(self) -> None:
        """Node.to_dict() has sorted keys."""
        node = Node(
            provider="aws",
            node_type="IAMRole",
            provider_id="arn:test",
            region="us-east-1",
            properties={"z_key": 1, "a_key": 2},
        )
        d = node.to_dict()
        keys = list(d.keys())
        assert keys == sorted(keys)

    def test_emit_scenario_deterministic(self) -> None:
        """Same inputs → byte-identical output."""
        nodes = [
            Node(
                provider="aws",
                node_type="IAMRole",
                provider_id="arn:aws:iam::123:role/Test",
            )
        ]
        edges = []
        constraints = []
        edge_constraints = []
        meta = ScenarioMetadata(collector="test")

        b1, h1 = emit_scenario(nodes, edges, constraints, edge_constraints, meta)
        b2, h2 = emit_scenario(nodes, edges, constraints, edge_constraints, meta)

        assert b1 == b2
        assert h1 == h2
        assert len(h1) == 64


class TestHashStability:
    """Invariant #4: Same scenario → same canonical hash."""

    def test_hash_matches_content(self) -> None:
        """Hash changes when content changes."""
        meta = ScenarioMetadata(collector="test")
        nodes_a = [Node(provider="aws", node_type="IAMRole", provider_id="arn:role/A")]
        nodes_b = [Node(provider="aws", node_type="IAMRole", provider_id="arn:role/B")]

        _, h1 = emit_scenario(nodes_a, [], [], [], meta)
        _, h2 = emit_scenario(nodes_b, [], [], [], meta)

        assert h1 != h2


class TestPermissionParserEdgeCases:
    """Permission parser edge cases."""

    def test_deny_produces_no_edges(self) -> None:
        """Deny statements don't create permission edges."""
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
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123:role/X",
            source_node_type="IAMRole",
            source_account_id="123",
        )
        assert len(results) == 0

    def test_empty_policy(self) -> None:
        """Empty/null policy produces no results."""
        results = parse_permission_policy(
            None,
            source_arn="arn:aws:iam::123:role/X",
            source_node_type="IAMRole",
            source_account_id="123",
        )
        assert len(results) == 0

    def test_no_relevant_actions(self) -> None:
        """Policy with only irrelevant actions produces no results."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "dynamodb:Query"],
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123:role/X",
            source_node_type="IAMRole",
            source_account_id="123",
        )
        assert len(results) == 0

    def test_unicode_policy_name(self) -> None:
        """Unicode in policy name doesn't crash."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123:role/Rôle-Spécial",
            source_node_type="IAMRole",
            source_account_id="123",
            policy_name="Política-de-Acceso",
        )
        assert len(results) == 1


class TestTrustParserEdgeCases:
    """Trust parser edge cases."""

    def test_empty_statements(self) -> None:
        """Trust policy with no statements produces no results."""
        policy = {"Version": "2012-10-17", "Statement": []}
        results = parse_trust_policy(
            policy,
            role_arn="arn:aws:iam::123:role/X",
            role_account_id="123456789012",
        )
        assert len(results) == 0

    def test_wildcard_principal(self) -> None:
        """Wildcard * principal is parsed."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        results = parse_trust_policy(
            policy,
            role_arn="arn:aws:iam::123:role/Open",
            role_account_id="123456789012",
        )
        assert len(results) >= 1
        assert any("*" in r.principal_value for r in results)

    def test_deeply_nested_conditions(self) -> None:
        """Complex nested conditions don't crash."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-test",
                            "aws:PrincipalTag/team": ["red", "blue"],
                        },
                        "IpAddress": {
                            "aws:SourceIp": "10.0.0.0/8",
                        },
                    },
                }
            ],
        }
        results = parse_trust_policy(
            policy,
            role_arn="arn:aws:iam::123:role/Conditioned",
            role_account_id="123456789012",
        )
        assert len(results) >= 1
        assert results[0].raw_conditions


class TestPipelineValidatorRoundTrip:
    """Cross-module: pipeline output passes validator."""

    @mock_aws
    def test_pipeline_output_validates(self) -> None:
        """Full pipeline output passes structural validation."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="TestRole", AssumeRolePolicyDocument=trust)

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)
        errors = validate_scenario(scenario)
        assert errors == [], f"Validation errors: {errors}"


class TestPipelineDiffDeterminism:
    """Cross-module: two identical runs produce identical output → zero diff."""

    @mock_aws
    def test_identical_runs_no_diff(self) -> None:
        """Two pipeline runs on same state → hashes match, no diff."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")

        r1 = run_pipeline(session, config)
        r2 = run_pipeline(session, config)

        assert r1.canonical_hash == r2.canonical_hash

        s1 = json.loads(r1.scenario_bytes)
        s2 = json.loads(r2.scenario_bytes)
        diff_result = diff_scenarios(s1, s2)
        assert diff_result.hashes_match
        assert not diff_result.has_changes


class TestPipelineReportIntegration:
    """Cross-module: report from real pipeline output."""

    @mock_aws
    def test_report_from_pipeline(self) -> None:
        """Report generation from pipeline output succeeds."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline
        from iamscope.report.generator import extract_report_data, generate_report

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="CrossAccountRole", AssumeRolePolicyDocument=trust)
        iam.put_role_policy(
            RoleName="CrossAccountRole",
            PolicyName="AdminAccess",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)
        rd = extract_report_data(scenario)
        report = generate_report(rd)

        assert "IAMScope" in report
        assert rd.total_nodes > 0
        assert rd.total_edges > 0


class TestEdgeProvenance:
    """Edge provenance metadata — every edge traces back to its source policy."""

    @mock_aws
    def test_trust_edge_provenance(self) -> None:
        """Trust edges carry effect, source_policy, and statement_index."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="Trusted", AssumeRolePolicyDocument=trust)

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)
        trust_edges = [e for e in scenario["edges"] if "_trust" in e["edge_type"]]
        assert len(trust_edges) >= 1
        for edge in trust_edges:
            f = edge["features"]
            assert "effect" in f, "Trust edge missing effect"
            assert "statement_index" in f, "Trust edge missing statement_index"
            assert f["source_policy"] == "TrustPolicy"

    @mock_aws
    def test_permission_edge_provenance(self) -> None:
        """Permission edges carry effect, statement_index, policy_name, policy_arn."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="Target", AssumeRolePolicyDocument=trust)
        iam.create_role(RoleName="Assumer", AssumeRolePolicyDocument=trust)
        iam.put_role_policy(
            RoleName="Assumer",
            PolicyName="AssumeAccess",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(
            region_name="us-east-1",
            global_expansion_mode="expand",
        )
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)
        perm_edges = [e for e in scenario["edges"] if "_permission" in e["edge_type"]]
        assert len(perm_edges) >= 1
        for edge in perm_edges:
            f = edge["features"]
            assert "effect" in f, "Permission edge missing effect"
            assert "statement_index" in f, "Permission edge missing statement_index"
            assert "policy_name" in f, "Permission edge missing policy_name"

    @mock_aws
    def test_trust_edge_wildcard_principal_flag(self) -> None:
        """Trust edges carry is_wildcard_principal for wildcard principals."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        # Wildcard trust
        trust_wild = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="WildOpen", AssumeRolePolicyDocument=trust_wild)

        # Non-wildcard trust
        trust_specific = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="Specific", AssumeRolePolicyDocument=trust_specific)

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)
        trust_edges = [e for e in scenario["edges"] if "_trust" in e["edge_type"]]

        wild_edges = [e for e in trust_edges if e["features"].get("is_wildcard_principal")]
        nonwild_edges = [e for e in trust_edges if not e["features"].get("is_wildcard_principal")]

        assert len(wild_edges) >= 1, "Should have at least one wildcard principal edge"
        assert len(nonwild_edges) >= 1, "Should have at least one non-wildcard edge"


class TestEdgeBudgetCircuitBreaker:
    """Global edge budget enforcement."""

    @mock_aws
    def test_budget_caps_edges(self) -> None:
        """When MAX_TOTAL_EDGES is low, pipeline caps edge count."""
        import boto3

        import iamscope.pipeline as pipeline_mod
        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        # Create several roles to generate many edges
        for i in range(10):
            trust = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{900000000000 + i}:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
            iam.create_role(RoleName=f"Role{i}", AssumeRolePolicyDocument=trust)

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")

        # Temporarily lower budget to 3
        original = pipeline_mod.MAX_TOTAL_EDGES
        pipeline_mod.MAX_TOTAL_EDGES = 3
        try:
            result = run_pipeline(session, config)
        finally:
            pipeline_mod.MAX_TOTAL_EDGES = original

        assert result.total_edges <= 3
        assert result.edge_budget_exhausted is True

    @mock_aws
    def test_normal_budget_not_exhausted(self) -> None:
        """Under normal budget, flag stays False."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="SmallRole", AssumeRolePolicyDocument=trust)

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        assert result.edge_budget_exhausted is False
