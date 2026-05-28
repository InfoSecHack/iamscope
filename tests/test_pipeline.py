"""Tests for pipeline orchestrator — end-to-end integration.

Moto-based tests with a complete organization:
- 2 accounts (management + member)
- 1 OU with SCP attached
- Roles with trust policies + permission policies in each account
- Full resolution: trust edges, permission edges, SCP bindings

Tests cover:
- Full pipeline produces valid scenario.json
- Phase 1 org data propagated
- Phase 2 account data collected for all accounts
- Phase 3 trust edges created from trust policies
- Phase 3 permission edges created from permission policies
- Phase 3 SCP bindings created
- Lambda/EC2 service edges in Phase 2
- Synthetic nodes created for external principals
- Account filtering works
- Skip accounts works
- Deterministic output
"""

import json

import pytest
from moto import mock_aws

from iamscope.auth.session import get_session
from iamscope.collector.account import AccountData
from iamscope.constants import CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT, NODE_TYPE_IAM_ROLE, PROVIDER_AWS
from iamscope.models import AccountInfo, Node, OrgData
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _run_resolution, run_pipeline


@pytest.fixture
def full_org_setup():
    """Create a complete AWS Organization with IAM resources in moto.

    Org structure:
        Root
        └── Production OU
            └── Management account (auto)
            └── SCP: DenyDeleteBucket (deny s3:DeleteBucket)

    Management account IAM:
        - Role: CrossAccountTarget
          - Trust: Allow from 999999999999:root (external account)
          - Inline policy: sts:AssumeRole → * (wildcard)
        - User: admin
          - Inline policy: iam:PassRole → *
    """
    with mock_aws():
        session = get_session(region_name="us-east-1")
        org_client = session.client("organizations", region_name="us-east-1")
        iam = session.client("iam")
        sts = session.client("sts")

        mgmt_id = sts.get_caller_identity()["Account"]

        # Create org
        org = org_client.create_organization(FeatureSet="ALL")
        org_id = org["Organization"]["Id"]
        roots = org_client.list_roots()["Roots"]
        root_id = roots[0]["Id"]

        # Create OU
        prod_ou = org_client.create_organizational_unit(ParentId=root_id, Name="Production")
        prod_ou_id = prod_ou["OrganizationalUnit"]["Id"]

        # Create SCP and attach to OU
        scp_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyDeleteBucket",
                        "Effect": "Deny",
                        "Action": "s3:DeleteBucket",
                        "Resource": "*",
                    }
                ],
            }
        )
        scp = org_client.create_policy(
            Content=scp_doc,
            Description="Deny bucket delete",
            Name="DenyDeleteBucket",
            Type="SERVICE_CONTROL_POLICY",
        )
        scp_id = scp["Policy"]["PolicySummary"]["Id"]
        org_client.attach_policy(PolicyId=scp_id, TargetId=prod_ou_id)

        # Create IAM role with cross-account trust
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
        iam.create_role(
            RoleName="CrossAccountTarget",
            AssumeRolePolicyDocument=trust,
        )

        # Inline permission policy on role
        role_policy = json.dumps(
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
        )
        iam.put_role_policy(
            RoleName="CrossAccountTarget",
            PolicyName="AssumeAll",
            PolicyDocument=role_policy,
        )

        # Create user with PassRole
        iam.create_user(UserName="admin")
        user_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "*",
                    }
                ],
            }
        )
        iam.put_user_policy(
            UserName="admin",
            PolicyName="PassRoleAll",
            PolicyDocument=user_policy,
        )

        yield {
            "session": session,
            "mgmt_id": mgmt_id,
            "org_id": org_id,
            "root_id": root_id,
            "prod_ou_id": prod_ou_id,
            "scp_id": scp_id,
        }


class TestFullPipeline:
    """End-to-end pipeline tests."""

    def test_pipeline_produces_valid_scenario(self, full_org_setup) -> None:
        """Full pipeline produces valid, parseable scenario.json."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        assert result.scenario_bytes
        scenario = json.loads(result.scenario_bytes)
        assert "nodes" in scenario
        assert "edges" in scenario
        assert "constraints" in scenario
        assert "edge_constraints" in scenario
        assert "metadata" in scenario

    def test_canonical_hash_populated(self, full_org_setup) -> None:
        """Pipeline produces a non-empty canonical hash."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        assert len(result.canonical_hash) == 64

    def test_deterministic_output(self, full_org_setup) -> None:
        """Same org produces identical output on two runs."""
        config = PipelineConfig(region_name="us-east-1")
        r1 = run_pipeline(full_org_setup["session"], config)
        r2 = run_pipeline(full_org_setup["session"], config)

        assert r1.canonical_hash == r2.canonical_hash


class TestPhase1Integration:
    """Tests for organization data propagation."""

    def test_org_data_collected(self, full_org_setup) -> None:
        """Org data is populated in the result."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        assert result.org_data is not None
        assert result.org_data.org_id == full_org_setup["org_id"]

    def test_scp_constraints_in_scenario(self, full_org_setup) -> None:
        """SCP constraints appear in scenario.json."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        assert result.total_constraints >= 1
        assert len(scenario["constraints"]) >= 1


class TestPhase2Integration:
    """Tests for per-account collection."""

    def test_management_account_collected(self, full_org_setup) -> None:
        """Management account is collected (no AssumeRole needed)."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        assert result.accounts_collected >= 1

    def test_nodes_in_scenario(self, full_org_setup) -> None:
        """IAM nodes appear in scenario.json."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        assert len(scenario["nodes"]) >= 2  # At least role + user


class TestPhase3Resolution:
    """Tests for resolution pipeline results."""

    def test_trust_edges_created(self, full_org_setup) -> None:
        """Trust edges created from trust policies."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        trust_edges = [e for e in scenario["edges"] if e["edge_type"].endswith("_trust")]
        assert len(trust_edges) >= 1

    def test_synthetic_nodes_created(self, full_org_setup) -> None:
        """Synthetic nodes created for external principals."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        synthetic = [n for n in scenario["nodes"] if n.get("properties", {}).get("is_synthetic") is True]
        # Should have synthetic node for 999999999999:root
        assert len(synthetic) >= 1

    def test_permission_edges_created(self, full_org_setup) -> None:
        """Permission edges created from permission policies."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        perm_edges = [e for e in scenario["edges"] if "_permission" in e["edge_type"]]
        # At least: AssumeRole_permission from role, PassRole_permission from user
        assert len(perm_edges) >= 1


class TestAccountFiltering:
    """Tests for account scope filtering."""

    def test_account_filter_limits_collection(self, full_org_setup) -> None:
        """--accounts flag limits which accounts are collected."""
        config = PipelineConfig(
            region_name="us-east-1",
            account_filter={full_org_setup["mgmt_id"]},
        )
        result = run_pipeline(full_org_setup["session"], config)
        assert result.accounts_collected == 1

    def test_skip_accounts(self, full_org_setup) -> None:
        """--skip-accounts excludes specific accounts."""
        config = PipelineConfig(
            region_name="us-east-1",
            skip_accounts={full_org_setup["mgmt_id"]},
        )
        result = run_pipeline(full_org_setup["session"], config)
        # Management account is skipped, but other moto accounts might not
        # have the collection role, so they'll be skipped too
        collected_ids = {ad.account_id for ad in result.account_data}
        assert full_org_setup["mgmt_id"] not in collected_ids


class TestPipelineResult:
    """Tests for PipelineResult statistics."""

    def test_stats_populated(self, full_org_setup) -> None:
        """PipelineResult stats match scenario.json."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        assert result.total_nodes == len(scenario["nodes"])
        assert result.total_edges == len(scenario["edges"])
        assert result.total_constraints == len(scenario["constraints"])

    def test_duration_positive(self, full_org_setup) -> None:
        """Pipeline duration is positive."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)
        assert result.duration_seconds > 0

    def test_binding_metadata_sidecar(self, full_org_setup) -> None:
        """Binding metadata sidecar is produced."""
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(full_org_setup["session"], config)

        # Should be valid JSON (even if empty array)
        sidecar = json.loads(result.binding_metadata_bytes)
        assert isinstance(sidecar, list)


# ---------------------------------------------------------------------------
# Standalone (single-account) mode tests
# ---------------------------------------------------------------------------


@pytest.fixture
def standalone_setup():
    """Create IAM resources WITHOUT an AWS Organization.

    This simulates the standalone use case: a single account with
    no org membership, or an operator without organizations:* perms.

    IAM resources:
        - Role: DeployRole
          - Trust: GitHub Actions OIDC with :sub condition
          - Inline policy: sts:AssumeRole → * (wildcard)
        - Role: LambdaExecRole
          - Trust: Lambda service
        - User: cicd-user
          - Inline policy: iam:PassRole → *
    """
    with mock_aws():
        session = get_session(region_name="us-east-1")
        iam = session.client("iam")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # OIDC-trusted role (GitHub Actions)
        oidc_trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "token.actions.githubusercontent.com",
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringLike": {
                                "token.actions.githubusercontent.com:sub": "repo:MyOrg/MyRepo:ref:refs/heads/main",
                            },
                            "StringEquals": {
                                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            },
                        },
                    }
                ],
            }
        )
        iam.create_role(
            RoleName="DeployRole",
            AssumeRolePolicyDocument=oidc_trust,
        )
        iam.put_role_policy(
            RoleName="DeployRole",
            PolicyName="AssumeAll",
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

        # Lambda execution role
        lambda_trust = json.dumps(
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
        iam.create_role(
            RoleName="LambdaExecRole",
            AssumeRolePolicyDocument=lambda_trust,
        )

        # User with PassRole
        iam.create_user(UserName="cicd-user")
        iam.put_user_policy(
            UserName="cicd-user",
            PolicyName="PassRoleAll",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        yield {
            "session": session,
            "account_id": account_id,
        }


class TestStandaloneMode:
    """Tests for standalone (single-account) mode — no org access needed."""

    def test_standalone_produces_valid_scenario(self, standalone_setup) -> None:
        """Standalone pipeline produces valid scenario.json."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        assert result.scenario_bytes
        scenario = json.loads(result.scenario_bytes)
        assert "nodes" in scenario
        assert "edges" in scenario
        assert "constraints" in scenario
        assert "edge_constraints" in scenario
        assert "metadata" in scenario

    def test_standalone_collects_one_account(self, standalone_setup) -> None:
        """Standalone collects exactly one account."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        assert result.accounts_collected == 1
        assert result.accounts_skipped == 0

    def test_standalone_no_scp_constraints(self, standalone_setup) -> None:
        """Standalone mode produces zero SCP constraints."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        constraints = scenario.get("constraints", [])
        assert not any("scp" in json.dumps(constraint).lower() for constraint in constraints)

    def test_standalone_org_id_is_standalone(self, standalone_setup) -> None:
        """Metadata org_id is 'standalone'."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        assert scenario["metadata"]["org_id"] == "standalone"

    def test_standalone_iam_nodes_collected(self, standalone_setup) -> None:
        """IAM roles and users appear as nodes."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        node_ids = [n["provider_id"] for n in scenario["nodes"]]
        # Should contain our roles and user
        deploy_role = [n for n in node_ids if "DeployRole" in n]
        cicd_user = [n for n in node_ids if "cicd-user" in n]
        assert len(deploy_role) >= 1
        assert len(cicd_user) >= 1

    def test_standalone_trust_edges_created(self, standalone_setup) -> None:
        """Trust edges created from trust policies in standalone mode."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        trust_edges = [e for e in scenario["edges"] if e["edge_type"].endswith("_trust")]
        # At least: OIDC → DeployRole, lambda.amazonaws.com → LambdaExecRole
        assert len(trust_edges) >= 2

    def test_standalone_oidc_subject_in_features(self, standalone_setup) -> None:
        """OIDC trust edge features include oidc_subject_pattern."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        oidc_edges = [e for e in scenario["edges"] if e.get("src", {}).get("node_type") == "OIDCProvider"]
        assert len(oidc_edges) >= 1
        features = oidc_edges[0]["features"]
        assert features["oidc_subject_pattern"] == "repo:MyOrg/MyRepo:ref:refs/heads/main"
        assert features["naked_trust"] == "CONDITIONED"

    def test_standalone_permission_edges_created(self, standalone_setup) -> None:
        """Permission edges created in standalone mode."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        perm_edges = [e for e in scenario["edges"] if "_permission" in e["edge_type"]]
        assert len(perm_edges) >= 1

    def test_standalone_deterministic(self, standalone_setup) -> None:
        """Standalone mode produces deterministic output."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        r1 = run_pipeline(standalone_setup["session"], config)
        r2 = run_pipeline(standalone_setup["session"], config)

        assert r1.canonical_hash == r2.canonical_hash

    def test_standalone_metadata_shows_standalone(self, standalone_setup) -> None:
        """Metadata noise_filter includes standalone: true."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        assert scenario["metadata"]["noise_filter"]["standalone"] is True

    def test_standalone_report_generates(self, standalone_setup) -> None:
        """Report generates from standalone scenario.json."""
        from iamscope.report.generator import extract_report_data, generate_report

        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)
        scenario = json.loads(result.scenario_bytes)

        rd = extract_report_data(scenario)
        report = generate_report(rd)

        assert "IAMScope Security Assessment Report" in report
        assert rd.trust_edges >= 2
        assert rd.oidc_trust >= 1

    def test_standalone_own_account_not_external(self, standalone_setup) -> None:
        """Standalone mode marks own account's principals as org_member=True."""
        config = PipelineConfig(
            region_name="us-east-1",
            standalone=True,
        )
        result = run_pipeline(standalone_setup["session"], config)

        scenario = json.loads(result.scenario_bytes)
        # Lambda service principal → synthetic node, should be present
        # Any AccountPrincipalSet for the caller's account should NOT be org_member=False
        acct_id = standalone_setup["account_id"]
        for node in scenario["nodes"]:
            pid = node.get("provider_id", "")
            props = node.get("properties", {})
            if acct_id in pid and props.get("is_synthetic"):
                # Own account's synthetic nodes should be org_member=True
                assert props.get("org_member") is not False, (
                    f"Standalone mode marked own account node as external: {pid}"
                )


class TestNf1NoiseFilterWiring:
    """NF-1 regression: _run_resolution wires NoiseFilter into build_trust_edges.

    Pre-S06 the pipeline passed no filter callback, so every trust edge —
    including self-trust (role trusts itself) — landed in the graph. Post-S06
    the NoiseFilter is constructed from PipelineConfig and its `to_filter_fn()`
    output is passed to build_trust_edges, which defaults to excluding self-
    trust edges.

    These tests call _run_resolution directly with minimal synthetic OrgData
    and AccountData rather than spinning up a moto-based full pipeline run.
    The synthetic approach makes the assertion about self-trust exclusion a
    per-function unit test rather than relying on a specific moto fixture
    happening to generate a self-trust edge.
    """

    @staticmethod
    def _make_minimal_inputs(self_trust: bool) -> tuple:
        """Construct OrgData + one AccountData that produces one trust edge.

        If self_trust=True, the role trusts itself (src == dst), which the
        default NoiseFilter should exclude. If False, the role trusts a
        cross-account root, which should always be included.
        """
        from iamscope.collector.account import AccountData
        from iamscope.constants import (
            NODE_TYPE_ACCOUNT_ROOT,
            NODE_TYPE_IAM_ROLE,
            PROVIDER_AWS,
            REGION_GLOBAL,
            TRUST_SCOPE_ACCOUNT_ROOT,
        )
        from iamscope.models import (
            AccountInfo,
            Node,
            OrgData,
            TrustParseResult,
        )

        account_id = "111111111111"
        role_arn = f"arn:aws:iam::{account_id}:role/TargetRole"
        role_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            region=REGION_GLOBAL,
            properties={"account_id": account_id, "is_synthetic": False, "path": "/"},
        )

        if self_trust:
            # Role trusts itself: src principal ARN == role_arn.
            principal_value = role_arn
            principal_type = "AWS"
            resolved_node_type = NODE_TYPE_IAM_ROLE
            cross_account = False
        else:
            # Role trusts a different account's root.
            principal_value = "arn:aws:iam::222222222222:root"
            principal_type = "AWS"
            resolved_node_type = NODE_TYPE_ACCOUNT_ROOT
            cross_account = True

        tr = TrustParseResult(
            statement_index=0,
            effect="Allow",
            action="sts:AssumeRole",
            principal_type=principal_type,
            principal_value=principal_value,
            resolved_node_type=resolved_node_type,
            trust_scope=TRUST_SCOPE_ACCOUNT_ROOT,
            raw_conditions={},
            cross_account=cross_account,
        )

        acct_data = AccountData(
            account_id=account_id,
            nodes=[role_node],
            trust_results=[(role_node, tr)],
            permission_results=[],
            role_arns=[role_arn],
        )

        org = OrgData(
            org_id="o-test",
            root_id="r-root",
            accounts=[
                AccountInfo(
                    account_id=account_id,
                    name="TestAccount",
                    email="test@example.com",
                    status="ACTIVE",
                    parent_id="r-root",
                ),
            ],
        )
        return org, acct_data

    def test_self_trust_edge_excluded_by_default_in_resolution(self) -> None:
        """Default _run_resolution run drops a self-trust edge.

        Fails if the NoiseFilter is not wired into build_trust_edges, or if
        the filter is wired but `exclude_self_trust` is not the default.
        """
        from iamscope.pipeline import PipelineConfig, _run_resolution

        org, acct_data = self._make_minimal_inputs(self_trust=True)
        config = PipelineConfig()  # defaults

        nodes, edges, _constraints, _edge_constraints, _budget = _run_resolution(
            org_data=org,
            all_account_data=[acct_data],
            config=config,
        )

        # Self-trust edge must be absent from the result.
        trust_edges = [e for e in edges if "_trust" in e.edge_type]
        for e in trust_edges:
            assert e.src.provider_id != e.dst.provider_id, (
                f"NF-1 regression: self-trust edge survived in scenario ({e.src.provider_id} → {e.dst.provider_id})"
            )

    def test_cross_account_trust_edge_kept_in_resolution(self) -> None:
        """Control test: a cross-account trust edge must still be kept.

        Regression guard against the filter being too aggressive and dropping
        every trust edge rather than just self-trust ones.
        """
        from iamscope.pipeline import PipelineConfig, _run_resolution

        org, acct_data = self._make_minimal_inputs(self_trust=False)
        config = PipelineConfig()

        _nodes, edges, _constraints, _edge_constraints, _budget = _run_resolution(
            org_data=org,
            all_account_data=[acct_data],
            config=config,
        )

        trust_edges = [e for e in edges if "_trust" in e.edge_type]
        assert len(trust_edges) == 1
        assert trust_edges[0].src.provider_id == "arn:aws:iam::222222222222:root"
        assert trust_edges[0].dst.provider_id == "arn:aws:iam::111111111111:role/TargetRole"


class TestStalePrincipalDriftResolution:
    """Focused regression for stale principal drift wiring in resolution."""

    def test_run_resolution_emits_stale_principal_drift_constraint(self) -> None:
        account_id = "111111111111"
        role_arn = f"arn:aws:iam::{account_id}:role/Target"
        role_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            properties={"account_id": account_id},
        )
        trust_results = parse_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "AROAABCDEFGHIJKLMNOP"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            role_arn=role_arn,
            role_account_id=account_id,
        )
        account_data = AccountData(
            account_id=account_id,
            nodes=[role_node],
            trust_results=[(role_node, trust_results[0])],
            role_arns=[role_arn],
        )
        org_data = OrgData(
            org_id="o-example",
            root_id="r-root",
            accounts=[
                AccountInfo(
                    account_id=account_id,
                    name="Example",
                    email="example@example.com",
                    status="ACTIVE",
                    parent_id="r-root",
                )
            ],
        )

        _nodes, edges, constraints, edge_constraints, _budget = _run_resolution(
            org_data,
            [account_data],
            PipelineConfig(),
        )

        stale_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT]
        assert len(stale_constraints) == 1
        assert stale_constraints[0].properties["principal_id"] == "AROAABCDEFGHIJKLMNOP"
        assert any(binding.constraint_id == stale_constraints[0].constraint_id for binding in edge_constraints)
        assert any(edge.src.provider_id == "AROAABCDEFGHIJKLMNOP" for edge in edges)
