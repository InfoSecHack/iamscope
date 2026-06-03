"""Tests for report generator — ReportData extraction and Markdown formatting.

Tests cover:
- extract_report_data counts nodes, edges, constraints correctly
- Trust edge classification (cross-account, OIDC, service, naked)
- Permission edge breakdown (AssumeRole, PassRole, Lambda, EC2, wildcard)
- Service edge counting (Lambda, EC2)
- Feasibility edge counting
- Metadata extraction (org_id, hash, timestamp)
- generate_report produces valid Markdown
- Executive summary identifies high-risk findings
- Enrichment results appear in report
- generate_report_from_files round-trip
"""

import json

from iamscope.report.generator import (
    ReportData,
    extract_report_data,
    generate_report,
    generate_report_from_files,
)


def _make_scenario(
    nodes=None,
    edges=None,
    constraints=None,
    edge_constraints=None,
    metadata=None,
) -> dict:
    """Build a scenario dict for testing."""
    return {
        "nodes": nodes or [],
        "edges": edges or [],
        "constraints": constraints or [],
        "edge_constraints": edge_constraints or [],
        "metadata": metadata or {},
    }


def _make_edge(edge_type, src_type="IAMRole", src_id="arn:role", dst_id="arn:dst", **features):
    """Build an edge dict for testing."""
    return {
        "edge_id": f"{edge_type}_{src_id}_{dst_id}",
        "edge_type": edge_type,
        "src": {"node_type": src_type, "provider_id": src_id},
        "dst": {"node_type": "IAMRole", "provider_id": dst_id},
        "features": features,
    }


class TestExtractReportData:
    """Tests for extract_report_data metric extraction."""

    def test_empty_scenario(self) -> None:
        """Empty scenario produces zero counts."""
        rd = extract_report_data(_make_scenario())
        assert rd.total_nodes == 0
        assert rd.total_edges == 0

    def test_node_count(self) -> None:
        """Nodes are counted correctly."""
        scenario = _make_scenario(
            nodes=[
                {"node_type": "IAMRole"},
                {"node_type": "IAMUser"},
            ]
        )
        rd = extract_report_data(scenario)
        assert rd.total_nodes == 2

    def test_node_type_breakdown(self) -> None:
        """Node types are counted in breakdown."""
        scenario = _make_scenario(
            nodes=[
                {"node_type": "IAMRole"},
                {"node_type": "IAMRole"},
                {"node_type": "IAMUser"},
            ]
        )
        rd = extract_report_data(scenario)
        assert rd.node_types["IAMRole"] == 2
        assert rd.node_types["IAMUser"] == 1

    def test_trust_edge_counting(self) -> None:
        """Trust edges counted correctly."""
        edges = [
            _make_edge("sts:AssumeRole_trust"),
            _make_edge("sts:AssumeRole_trust", cross_account=True),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.trust_edges == 2
        assert rd.cross_account_trust == 1

    def test_oidc_trust_detection(self) -> None:
        """OIDC trust detected by src node_type."""
        edges = [
            _make_edge(
                "sts:AssumeRoleWithWebIdentity_trust",
                src_type="OIDCProvider",
            )
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.oidc_trust == 1

    def test_service_trust_detection(self) -> None:
        """AWS service trust detected by src node_type."""
        edges = [
            _make_edge(
                "sts:AssumeRole_trust",
                src_type="AWSService",
                src_id="lambda.amazonaws.com",
            )
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.service_trust == 1

    def test_naked_trust_classification(self) -> None:
        """Naked trust counts and details collected."""
        edges = [
            _make_edge("sts:AssumeRole_trust", naked_trust="CRITICAL_NAKED"),
            _make_edge("sts:AssumeRole_trust", naked_trust="BROAD_NAKED", src_id="arn:other"),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.naked_trust_counts["CRITICAL_NAKED"] == 1
        assert rd.naked_trust_counts["BROAD_NAKED"] == 1
        assert len(rd.naked_trust_edges) == 2

    def test_permission_edge_breakdown(self) -> None:
        """Permission edges broken down by action type."""
        edges = [
            _make_edge("sts:AssumeRole_permission", action="sts:AssumeRole"),
            _make_edge("iam:PassRole_permission", action="iam:PassRole"),
            _make_edge("lambda:InvokeFunction_permission", action="lambda:InvokeFunction"),
            _make_edge("ec2:RunInstances_permission", action="ec2:RunInstances"),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.permission_edges == 4
        assert rd.assume_role_perm_edges == 1
        assert rd.passrole_edges == 1
        assert rd.lambda_perm_edges == 1
        assert rd.ec2_perm_edges == 1

    def test_wildcard_permission_tracking(self) -> None:
        """Wildcard resource permissions tracked."""
        edges = [
            _make_edge("sts:AssumeRole_permission", is_wildcard_resource=True, action="sts:AssumeRole"),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.wildcard_permission_edges == 1
        assert len(rd.wildcard_permission_details) == 1

    def test_service_edge_counting(self) -> None:
        """Lambda and EC2 service edges counted."""
        edges = [
            _make_edge("lambda:ExecutionRole_service"),
            _make_edge("ec2:InstanceProfile_service", src_id="arn:profile"),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))
        assert rd.lambda_service_edges == 1
        assert rd.ec2_service_edges == 1

    def test_metadata_extraction(self) -> None:
        """Metadata fields extracted."""
        metadata = {
            "org_id": "o-test123",
            "accounts_collected": 5,
            "collection_timestamp": "2025-01-01T00:00:00Z",
            "canonical_hash": "abc123def456",
        }
        rd = extract_report_data(_make_scenario(metadata=metadata))
        assert rd.org_id == "o-test123"
        assert rd.accounts_collected == 5
        assert rd.canonical_hash == "abc123def456"

    def test_enrichment_passthrough(self) -> None:
        """Enrichment results stored in ReportData."""
        enrichment = [
            {
                "edge_id": "e1",
                "binding_metadata": {
                    "enrichment_confidence": "compromised",
                },
            }
        ]
        rd = extract_report_data(_make_scenario(), enrichment=enrichment)
        assert len(rd.enrichment_results) == 1


class TestGenerateReport:
    """Tests for Markdown report generation."""

    def test_produces_markdown(self) -> None:
        """Report is non-empty Markdown string."""
        rd = ReportData()
        report = generate_report(rd)
        assert isinstance(report, str)
        assert "# IAMScope Security Assessment Report" in report

    def test_metadata_in_header(self) -> None:
        """Org ID and hash appear in report header."""
        rd = ReportData(org_id="o-test", canonical_hash="a" * 64)
        report = generate_report(rd)
        assert "o-test" in report
        assert "aaaaaaaaaaaaaaaa..." in report

    def test_executive_summary_clean(self) -> None:
        """No risks → clean executive summary."""
        rd = ReportData()
        report = generate_report(rd)
        assert "No critical trust or permission risks" in report

    def test_executive_summary_risks(self) -> None:
        """Risks appear in executive summary."""
        rd = ReportData(
            naked_trust_edges=[{"src": "a", "dst": "b", "classification": "CRITICAL_NAKED", "cross_account": False}],
            wildcard_permission_edges=3,
        )
        report = generate_report(rd)
        assert "1 naked trust" in report
        assert "3 wildcard permission" in report

    def test_graph_overview_table(self) -> None:
        """Graph overview includes node/edge counts."""
        rd = ReportData(total_nodes=10, total_edges=20)
        report = generate_report(rd)
        assert "| Nodes | 10 |" in report
        assert "| Edges | 20 |" in report

    def test_service_edges_section(self) -> None:
        """Service edges section appears when present."""
        rd = ReportData(lambda_service_edges=5, ec2_service_edges=3)
        report = generate_report(rd)
        assert "Lateral Movement" in report
        assert "| Lambda" in report
        assert "| EC2" in report

    def test_no_service_edges_section_when_empty(self) -> None:
        """Service edges section omitted when no data."""
        rd = ReportData()
        report = generate_report(rd)
        assert "Lateral Movement" not in report

    def test_enrichment_section(self) -> None:
        """GhostGates enrichment section appears."""
        rd = ReportData(
            enrichment_results=[
                {
                    "edge_id": "e1",
                    "binding_metadata": {
                        "enrichment_confidence": "compromised",
                        "subject_claim": "repo:Org/app:ref:refs/heads/main",
                        "matched_repos": ["Org/app"],
                        "bypass_details": [{"repo": "Org/app", "branch": "main", "bypass_reasons": ["no reviews"]}],
                    },
                },
            ]
        )
        report = generate_report(rd)
        assert "GhostGates" in report
        assert "Compromised" in report

    def test_scp_coverage_section(self) -> None:
        """SCP governance section appears."""
        rd = ReportData(total_constraints=3, total_edge_constraints=10)
        report = generate_report(rd)
        assert "SCP Governance" in report
        assert "3" in report


class TestGenerateReportFromFiles:
    """Tests for file-based report generation."""

    def test_round_trip(self, tmp_path) -> None:
        """Write scenario to file, generate report from it."""
        scenario = _make_scenario(
            nodes=[{"node_type": "IAMRole"}],
            edges=[_make_edge("sts:AssumeRole_trust")],
            metadata={"org_id": "o-roundtrip"},
        )
        scenario_path = str(tmp_path / "scenario.json")
        with open(scenario_path, "w") as f:
            json.dump(scenario, f)

        report = generate_report_from_files(scenario_path)
        assert "o-roundtrip" in report
        assert "IAMScope" in report


class TestPermissionBoundaryReport:
    """Permission boundary sections in report."""

    def test_boundary_constraint_counting(self) -> None:
        """Counts SCP and PermissionBoundary constraints separately."""
        constraints = [
            {"constraint_type": "SCP", "constraint_id": "c1"},
            {"constraint_type": "PERMISSION_BOUNDARY", "constraint_id": "c2"},
            {"constraint_type": "PERMISSION_BOUNDARY", "constraint_id": "c3"},
        ]
        rd = extract_report_data(_make_scenario(constraints=constraints))
        assert rd.scp_constraints == 1
        assert rd.permission_boundary_constraints == 2

    def test_boundary_bound_edges_counted(self) -> None:
        """Edges bound to permission boundary constraints are counted."""
        constraints = [
            {"constraint_type": "PERMISSION_BOUNDARY", "constraint_id": "pb1"},
        ]
        edge_constraints = [
            {"edge_id": "e1", "constraint_id": "pb1"},
            {"edge_id": "e2", "constraint_id": "pb1"},
        ]
        scenario = _make_scenario(
            constraints=constraints,
            edge_constraints=edge_constraints,
        )
        rd = extract_report_data(scenario)
        assert rd.boundary_bound_edges == 2

    def test_boundary_section_in_report(self) -> None:
        """Permission Boundaries section appears when constraints exist."""
        rd = ReportData(permission_boundary_constraints=2, boundary_bound_edges=5)
        report = generate_report(rd)
        assert "Permission Boundaries" in report
        assert "2" in report
        assert "5" in report

    def test_no_boundary_section_when_zero(self) -> None:
        """Section absent when no boundaries."""
        rd = ReportData()
        report = generate_report(rd)
        assert "Permission Boundaries" not in report


class TestOIDCReportSection:
    """Tests for OIDC Federation Details in the report."""

    def test_oidc_details_extracted(self) -> None:
        """OIDC trust edges populate oidc_trust_details."""
        edges = [
            _make_edge(
                "sts:AssumeRoleWithWebIdentity_trust",
                src_type="OIDCProvider",
                src_id="token.actions.githubusercontent.com",
                dst_id="arn:aws:iam::111111\u003111111:role/DeployRole",
                naked_trust="CONDITIONED",
                oidc_subject_pattern="repo:MyOrg/MyRepo:ref:refs/heads/main",
            ),
            _make_edge(
                "sts:AssumeRoleWithWebIdentity_trust",
                src_type="OIDCProvider",
                src_id="token.actions.githubusercontent.com",
                dst_id="arn:aws:iam::111111\u003111111:role/UnsafeRole",
                naked_trust="BROAD_NAKED",
                oidc_subject_pattern=None,
            ),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))

        assert len(rd.oidc_trust_details) == 2
        assert rd.oidc_trust == 2

        # Check detail fields
        conditioned = [d for d in rd.oidc_trust_details if d["naked_trust"] == "CONDITIONED"]
        broad = [d for d in rd.oidc_trust_details if d["naked_trust"] == "BROAD_NAKED"]
        assert len(conditioned) == 1
        assert conditioned[0]["oidc_subject_pattern"] == "repo:MyOrg/MyRepo:ref:refs/heads/main"
        assert len(broad) == 1
        assert broad[0]["oidc_subject_pattern"] is None

    def test_oidc_section_in_report(self) -> None:
        """OIDC section appears with unrestricted and restricted subsections."""
        rd = ReportData(
            oidc_trust_details=[
                {
                    "provider": "token.actions.githubusercontent.com",
                    "role": "arn:aws:iam::111111\u003111111:role/DeployRole",
                    "oidc_subject_pattern": "repo:MyOrg/MyRepo:*",
                    "naked_trust": "CONDITIONED",
                },
                {
                    "provider": "token.actions.githubusercontent.com",
                    "role": "arn:aws:iam::111111\u003111111:role/UnsafeRole",
                    "oidc_subject_pattern": None,
                    "naked_trust": "BROAD_NAKED",
                },
            ],
        )
        report = generate_report(rd)

        assert "OIDC Federation Details" in report
        assert "1 OIDC trust(s) WITHOUT `:sub` restriction" in report
        assert "1 OIDC trust(s) with `:sub` restriction" in report
        assert "UnsafeRole" in report
        assert "repo:MyOrg/MyRepo:*" in report

    def test_oidc_section_absent_when_no_oidc(self) -> None:
        """OIDC section absent when no OIDC trusts."""
        rd = ReportData()
        report = generate_report(rd)
        assert "OIDC Federation Details" not in report

    def test_oidc_all_restricted(self) -> None:
        """Only restricted subsection when all OIDC trusts have :sub."""
        rd = ReportData(
            oidc_trust_details=[
                {
                    "provider": "token.actions.githubusercontent.com",
                    "role": "arn:aws:iam::111111\u003111111:role/SafeRole",
                    "oidc_subject_pattern": "repo:MyOrg/MyRepo:ref:refs/heads/main",
                    "naked_trust": "CONDITIONED",
                },
            ],
        )
        report = generate_report(rd)

        assert "OIDC Federation Details" in report
        assert "WITHOUT `:sub` restriction" not in report
        assert "with `:sub` restriction" in report

    def test_oidc_all_unrestricted(self) -> None:
        """Only unrestricted subsection when no OIDC trusts have :sub."""
        rd = ReportData(
            oidc_trust_details=[
                {
                    "provider": "cognito-identity.amazonaws.com",
                    "role": "arn:aws:iam::111111\u003111111:role/CognitoRole",
                    "oidc_subject_pattern": None,
                    "naked_trust": "BROAD_NAKED",
                },
            ],
        )
        report = generate_report(rd)

        assert "OIDC Federation Details" in report
        assert "WITHOUT `:sub` restriction" in report
        assert "with `:sub` restriction" not in report

    def test_naked_trust_edges_use_correct_constants(self) -> None:
        """CRITICAL_NAKED and BROAD_NAKED edges collected, others excluded."""
        edges = [
            _make_edge("sts:AssumeRole_trust", naked_trust="CRITICAL_NAKED"),
            _make_edge("sts:AssumeRole_trust", naked_trust="BROAD_NAKED", src_id="arn:broad"),
            _make_edge("sts:AssumeRole_trust", naked_trust="NARROW_NAKED", src_id="arn:narrow"),
            _make_edge("sts:AssumeRole_trust", naked_trust="CONDITIONED", src_id="arn:cond"),
            _make_edge("sts:AssumeRole_trust", naked_trust="INTRA_ACCOUNT", src_id="arn:intra"),
        ]
        rd = extract_report_data(_make_scenario(edges=edges))

        # Only CRITICAL and BROAD end up in the high-risk list
        assert len(rd.naked_trust_edges) == 2
        classifications = {e["classification"] for e in rd.naked_trust_edges}
        assert classifications == {"CRITICAL_NAKED", "BROAD_NAKED"}
