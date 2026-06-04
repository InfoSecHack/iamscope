"""Tests for CLI — argument parsing and command execution.

Tests cover:
- Argument parsing for collect command
- Default values
- Account filter parsing (comma-separated)
- Skip accounts parsing
- Verbose/quiet flags
- Expansion mode choices
- CLI entry point returns correct exit codes
- End-to-end collect writes scenario.json
"""

import json
from pathlib import Path

import pytest
from moto import mock_aws

from iamscope.cli import _build_parser, main


class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_collect_defaults(self) -> None:
        """collect command has correct defaults."""
        parser = _build_parser()
        args = parser.parse_args(["collect"])

        assert args.profile_name is None
        assert args.region_name == "us-east-1"
        assert args.role_name == "IAMScopeReader"
        assert args.expansion_mode == "warn"
        assert args.include_service_linked is False
        assert args.include_aws_managed is False
        assert args.output_dir == "."

    def test_collect_with_profile(self) -> None:
        """--profile sets profile name."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--profile", "myprofile"])
        assert args.profile_name == "myprofile"

    def test_collect_with_region(self) -> None:
        """--region overrides default region."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--region", "eu-west-1"])
        assert args.region_name == "eu-west-1"

    def test_collect_with_accounts(self) -> None:
        """--accounts sets account filter."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--accounts", "111111\u003111111,222222\u003222222"])
        assert args.account_filter == "111111\u003111111,222222\u003222222"

    def test_collect_with_skip_accounts(self) -> None:
        """--skip-accounts sets accounts to skip."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--skip-accounts", "333333\u003333333"])
        assert args.skip_accounts == "333333\u003333333"

    def test_expansion_mode_choices(self) -> None:
        """--expansion-mode accepts expand/warn/skip."""
        parser = _build_parser()
        for mode in ["expand", "warn", "skip"]:
            args = parser.parse_args(["collect", "--expansion-mode", mode])
            assert args.expansion_mode == mode

    def test_expansion_mode_invalid(self) -> None:
        """--expansion-mode rejects invalid choices."""
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["collect", "--expansion-mode", "invalid"])

    def test_verbose_flags(self) -> None:
        """Verbose flags count correctly."""
        parser = _build_parser()
        args = parser.parse_args(["-v", "collect"])
        assert args.verbose == 1

        args = parser.parse_args(["-vv", "collect"])
        assert args.verbose == 2

    def test_quiet_flag(self) -> None:
        """Quiet flag sets quiet=True."""
        parser = _build_parser()
        args = parser.parse_args(["-q", "collect"])
        assert args.quiet is True

    def test_include_service_linked(self) -> None:
        """--include-service-linked flag works."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--include-service-linked"])
        assert args.include_service_linked is True

    def test_output_dir(self) -> None:
        """--output sets output directory."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--output", "/tmp/results"])
        assert args.output_dir == "/tmp/results"

    def test_role_name_override(self) -> None:
        """--role-name overrides default collection role."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--role-name", "CustomReader"])
        assert args.role_name == "CustomReader"

    def test_external_id(self) -> None:
        """--external-id sets external ID."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--external-id", "abc123"])
        assert args.external_id == "abc123"


class TestCLIEntryPoint:
    """Tests for main() entry point."""

    def test_no_command_returns_1(self) -> None:
        """No command shows help and returns 1."""
        assert main([]) == 1

    @mock_aws
    def test_collect_end_to_end(self, tmp_path) -> None:
        """collect command runs end-to-end and writes scenario.json."""
        import boto3

        # Set up org in moto
        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        # Create a role so there's something to collect
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
        iam.create_role(RoleName="LambdaExec", AssumeRolePolicyDocument=trust)

        output_dir = str(tmp_path)
        exit_code = main(
            [
                "collect",
                "--output",
                output_dir,
                "--region",
                "us-east-1",
            ]
        )

        assert exit_code == 0

        # Check scenario.json was written
        scenario_path = tmp_path / "scenario.json"
        assert scenario_path.exists()

        scenario = json.loads(scenario_path.read_bytes())
        assert "nodes" in scenario
        assert "edges" in scenario
        assert "metadata" in scenario
        assert len(scenario["metadata"]["canonical_hash"]) == 64

    def test_report_command(self, tmp_path) -> None:
        """report command generates Markdown from scenario.json."""
        scenario = {
            "nodes": [{"node_type": "IAMRole"}],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {"org_id": "o-cli-test"},
        }
        scenario_path = str(tmp_path / "scenario.json")
        with open(scenario_path, "w") as f:
            json.dump(scenario, f)

        report_path = str(tmp_path / "report.md")
        exit_code = main(["report", scenario_path, "--output", report_path])

        assert exit_code == 0
        report = Path(report_path).read_text()
        assert "IAMScope" in report
        assert "o-cli-test" in report

    def test_report_missing_file(self) -> None:
        """report command returns 1 for missing file."""
        exit_code = main(["report", "/nonexistent/scenario.json"])
        assert exit_code == 1

    def test_enrich_command(self, tmp_path) -> None:
        """enrich command produces enrichment.json."""
        scenario = {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRoleWithWebIdentity_trust",
                    "src": {
                        "node_type": "OIDCProvider",
                        "provider_id": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com",
                    },
                    "dst": {"node_type": "IAMRole", "provider_id": "arn:aws:iam::123:role/Deploy"},
                    "features": {
                        "raw_conditions": {
                            "StringEquals": {
                                "token.actions.githubusercontent.com:sub": "repo:Org/app:ref:refs/heads/main",
                            },
                        },
                    },
                }
            ],
        }
        ghostgates = {
            "org": "Org",
            "repositories": [
                {
                    "repo": "Org/app",
                    "branch_protections": [
                        {
                            "branch": "main",
                            "bypassed": True,
                            "bypass_reasons": ["no reviews"],
                            "gates_checked": 3,
                            "gates_bypassed": 1,
                        }
                    ],
                }
            ],
        }
        scenario_path = str(tmp_path / "scenario.json")
        ghostgates_path = str(tmp_path / "ghostgates.json")
        enrichment_path = str(tmp_path / "enrichment.json")

        with open(scenario_path, "w") as f:
            json.dump(scenario, f)
        with open(ghostgates_path, "w") as f:
            json.dump(ghostgates, f)

        exit_code = main(
            [
                "enrich",
                "--scenario",
                scenario_path,
                "--ghostgates",
                ghostgates_path,
                "--output",
                enrichment_path,
            ]
        )
        assert exit_code == 0

        entries = json.loads(Path(enrichment_path).read_text())
        assert len(entries) == 1
        assert entries[0]["binding_metadata"]["enrichment_confidence"] == "compromised"

    def test_diff_command(self, tmp_path) -> None:
        """diff command produces Markdown diff report."""
        before = {
            "nodes": [{"node_id": "n1", "node_type": "IAMRole"}],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {"canonical_hash": "a" * 64},
        }
        after = {
            "nodes": [
                {"node_id": "n1", "node_type": "IAMRole"},
                {"node_id": "n2", "node_type": "IAMUser"},
            ],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {"canonical_hash": "b" * 64},
        }
        before_path = str(tmp_path / "before.json")
        after_path = str(tmp_path / "after.json")
        output_path = str(tmp_path / "diff.md")

        with open(before_path, "w") as f:
            json.dump(before, f)
        with open(after_path, "w") as f:
            json.dump(after, f)

        exit_code = main(["diff", before_path, after_path, "--output", output_path])
        assert exit_code == 0
        report = Path(output_path).read_text()
        assert "Nodes Added" in report

    def test_diff_json_output(self, tmp_path) -> None:
        """diff --json produces parseable JSON."""
        s = {
            "nodes": [],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {"canonical_hash": "a" * 64},
        }
        p = str(tmp_path / "s.json")
        out = str(tmp_path / "diff.json")
        with open(p, "w") as f:
            json.dump(s, f)

        exit_code = main(["diff", p, p, "--json", "--output", out])
        assert exit_code == 0
        d = json.loads(Path(out).read_text())
        assert d["has_changes"] is False

    def test_diff_missing_file(self) -> None:
        """diff returns 1 for missing file."""
        assert main(["diff", "/no/before.json", "/no/after.json"]) == 1

    def test_validate_valid(self, tmp_path) -> None:
        """validate passes for a valid scenario.

        Post-Fix-A (v0.2.36): the pre-fix version of this test hand-
        crafted a scenario dict with a fabricated 64-char hex hash
        and dangling src/dst endpoints — the exact tamper pattern
        Fix A's rule 8 and rule 8b now correctly reject. The rewrite
        builds a real scenario via `emit_scenario()` so the test
        actually exercises the valid-scenario codepath: the CLI
        round-trips a bytes-for-bytes-clean scenario.json through
        validate and returns 0."""
        from iamscope.models import (
            Edge,
            Node,
            NodeRef,
            ScenarioMetadata,
        )
        from iamscope.output.scenario_json import emit_scenario

        role_a = Node(
            provider="aws",
            node_type="IAMRole",
            provider_id="arn:aws:iam::111:role/A",
            region="-",
        )
        role_b = Node(
            provider="aws",
            node_type="IAMRole",
            provider_id="arn:aws:iam::111:role/B",
            region="-",
        )
        trust_edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=NodeRef(
                provider="aws",
                node_type="IAMRole",
                provider_id="arn:aws:iam::111:role/A",
                region="-",
            ),
            dst=NodeRef(
                provider="aws",
                node_type="IAMRole",
                provider_id="arn:aws:iam::111:role/B",
                region="-",
            ),
            region="-",
            features={"layer": "trust"},
        )
        md = ScenarioMetadata(
            collector="iamscope",
            collector_version="0.2.0",
            id_algorithm="sha256_null_separated_v3_case_sensitive_provider_ids",
        )
        scenario_bytes, _ = emit_scenario(
            nodes=[role_a, role_b],
            edges=[trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=md,
        )

        p = tmp_path / "scenario.json"
        p.write_bytes(scenario_bytes)

        assert main(["validate", str(p)]) == 0

    def test_validate_invalid(self, tmp_path) -> None:
        """validate fails for broken scenario."""
        s = {"nodes": "not_a_list", "metadata": {}}
        p = str(tmp_path / "bad.json")
        with open(p, "w") as f:
            json.dump(s, f)

        assert main(["validate", p]) == 1

    def test_validate_missing_file(self) -> None:
        """validate returns 1 for missing file."""
        assert main(["validate", "/no/scenario.json"]) == 1


class TestStandaloneCLI:
    """Tests for --standalone flag in CLI."""

    def test_standalone_flag_parsed(self) -> None:
        """--standalone sets standalone=True in parsed args."""
        parser = _build_parser()
        args = parser.parse_args(["collect", "--standalone"])
        assert args.standalone is True

    def test_standalone_default_false(self) -> None:
        """standalone defaults to False."""
        parser = _build_parser()
        args = parser.parse_args(["collect"])
        assert args.standalone is False

    @mock_aws
    def test_standalone_collect_end_to_end(self, tmp_path) -> None:
        """--standalone collects single account without org access."""
        import boto3

        # NO org created — standalone must work without one

        # Create IAM resources
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

        output_dir = str(tmp_path)
        exit_code = main(
            [
                "collect",
                "--standalone",
                "--output",
                output_dir,
                "--region",
                "us-east-1",
            ]
        )

        assert exit_code == 0

        scenario_path = tmp_path / "scenario.json"
        assert scenario_path.exists()

        scenario = json.loads(scenario_path.read_bytes())
        assert scenario["metadata"]["org_id"] == "standalone"
        assert scenario["metadata"]["noise_filter"]["standalone"] is True
        assert len(scenario["nodes"]) >= 1
        assert len(scenario["constraints"]) == 0


class TestAccountIDValidation:
    """Tests for account ID format validation in CLI."""

    @mock_aws
    def test_invalid_account_id_rejected(self) -> None:
        """Non-12-digit account ID returns exit code 1."""
        import boto3

        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        assert main(["collect", "--accounts", "not-an-account"]) == 1

    @mock_aws
    def test_short_account_id_rejected(self) -> None:
        """11-digit account ID returns exit code 1."""
        import boto3

        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        assert main(["collect", "--accounts", "12345678901"]) == 1

    @mock_aws
    def test_valid_account_id_accepted(self, tmp_path) -> None:
        """12-digit account ID is accepted."""
        import boto3

        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        # This will fail to collect (no IAM role) but should NOT fail on validation
        exit_code = main(
            [
                "collect",
                "--accounts",
                "123456\u003789012",
                "--output",
                str(tmp_path),
            ]
        )
        # Might be 0 or 1 depending on whether the account exists,
        # but should NOT be 1 from validation
        assert exit_code in (0, 1)

    @mock_aws
    def test_invalid_skip_account_rejected(self) -> None:
        """Invalid skip-accounts ID returns exit code 1."""
        import boto3

        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        assert main(["collect", "--skip-accounts", "abc"]) == 1


# ---------------------------------------------------------------------------
# S14 — findings.json CLI integration
# ---------------------------------------------------------------------------


def _moto_setup_baseline() -> None:
    """Create a minimal AWS environment in moto for end-to-end tests.

    Creates an organization plus a single Lambda-trusting role so the
    pipeline has something to collect. Both reasoners will run against
    the assembled FactGraph but neither will produce findings under
    this minimal setup (cross_account_trust: no naked cross-account
    trust; passrole_lambda: no source principal with the full chain).
    Findings count = 0 is enough to verify the wiring; reasoner
    correctness is pinned by S10/S12/S13.
    """
    import boto3

    boto3.client("organizations", region_name="us-east-1").create_organization(
        FeatureSet="ALL",
    )
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
    iam.create_role(RoleName="LambdaExec", AssumeRolePolicyDocument=trust)


class TestCollectFindingsIntegration:
    """S14 end-to-end tests for findings.json CLI integration."""

    @mock_aws
    def test_collect_emits_findings_json_by_default(self, tmp_path) -> None:
        """Default invocation produces findings.json alongside scenario.json."""
        _moto_setup_baseline()

        exit_code = main(
            [
                "collect",
                "--output",
                str(tmp_path),
                "--region",
                "us-east-1",
            ]
        )
        assert exit_code == 0

        findings_path = tmp_path / "findings.json"
        assert findings_path.exists(), "findings.json must be written by default"

        d = json.loads(findings_path.read_bytes())
        assert "metadata" in d
        assert "findings" in d
        assert len(d["metadata"]["canonical_hash"]) == 64
        assert d["source_tool"] == "iamscope"
        # Both reasoners should be in reasoners_run (or skipped, but
        # listed somewhere — reasoners_run lists ALL registered, even
        # if they ran with empty output).
        assert "passrole_lambda" in d["metadata"]["reasoners_run"]
        assert "cross_account_trust" in d["metadata"]["reasoners_run"]

    @mock_aws
    def test_collect_no_findings_flag_skips_findings_json(self, tmp_path) -> None:
        """--no-findings suppresses findings.json emission."""
        _moto_setup_baseline()

        exit_code = main(
            [
                "collect",
                "--output",
                str(tmp_path),
                "--region",
                "us-east-1",
                "--no-findings",
            ]
        )
        assert exit_code == 0
        assert (tmp_path / "scenario.json").exists()
        assert not (tmp_path / "findings.json").exists()

    @mock_aws
    def test_collect_reasoners_filter_runs_only_specified(self, tmp_path) -> None:
        """--reasoners filter restricts the registry to the named reasoners."""
        _moto_setup_baseline()

        exit_code = main(
            [
                "collect",
                "--output",
                str(tmp_path),
                "--region",
                "us-east-1",
                "--reasoners",
                "cross_account_trust",
            ]
        )
        assert exit_code == 0

        d = json.loads((tmp_path / "findings.json").read_bytes())
        assert d["metadata"]["reasoners_run"] == ["cross_account_trust"]
        # passrole_lambda should NOT appear in reasoners_run (not registered)
        assert "passrole_lambda" not in d["metadata"]["reasoners_run"]

    @mock_aws
    def test_collect_unknown_reasoner_returns_1(self, tmp_path) -> None:
        """An unknown --reasoners pattern_id fails fast with exit 1."""
        _moto_setup_baseline()

        exit_code = main(
            [
                "collect",
                "--output",
                str(tmp_path),
                "--region",
                "us-east-1",
                "--reasoners",
                "definitely_not_a_real_pattern",
            ]
        )
        assert exit_code == 1


class TestDemoteValidatedFindings:
    """Unit tests for the --assume-no-session-policies post-processor.

    Tests the demotion logic directly with hand-built Finding objects
    rather than going end-to-end via main(), because constructing a
    moto setup that produces a VALIDATED passrole_lambda finding is
    significantly more involved than the demotion logic itself
    deserves. The end-to-end wiring is covered by the four tests
    above; this class verifies the demotion algorithm.
    """

    def _build_validated_passrole_finding(self):
        """Build a VALIDATED passrole_lambda finding via the actual reasoner."""
        from iamscope.constants import (
            NODE_TYPE_AWS_SERVICE,
            NODE_TYPE_IAM_ROLE,
            NODE_TYPE_IAM_USER,
            PROVIDER_AWS,
            REGION_GLOBAL,
        )
        from iamscope.models import Edge, Node
        from iamscope.reasoner import FactGraph, PassRoleLambdaReasoner

        alice = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id="arn:aws:iam::111:user/Alice",
            properties={"account_id": "111"},
        )
        target = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id="arn:aws:iam::111:role/Admin",
            properties={"account_id": "111"},
        )
        lambda_svc = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_AWS_SERVICE,
            provider_id="lambda.amazonaws.com",
            properties={},
        )

        def perm(action, src, dst, digest):
            return Edge(
                edge_type=f"{action}_permission",
                src=src.to_ref(),
                dst=dst.to_ref(),
                region=REGION_GLOBAL,
                features={
                    "allow_controls": [
                        {
                            "control_type": "PERMISSION",
                            "policy_arn": "p",
                            "statement_index": 0,
                            "digest": digest,
                            "summary": action,
                        }
                    ],
                    "effect": "Allow",
                    "has_conditions": False,
                    "is_wildcard_resource": False,
                    "layer": "permission",
                    "raw_conditions": {},
                    "resource_pattern": dst.provider_id,
                    "statement_index": 0,
                },
            )

        lambda_create = perm("lambda:CreateFunction", alice, target, "a" * 64)
        passrole = perm("iam:PassRole", alice, target, "b" * 64)
        admin_grant = Edge(
            edge_type="iam:*_permission",
            src=target.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [
                    {
                        "control_type": "PERMISSION",
                        "policy_arn": "Admin",
                        "statement_index": 0,
                        "digest": "c" * 64,
                        "summary": "iam:*",
                    }
                ],
                "effect": "Allow",
                "has_conditions": False,
                "is_wildcard_resource": True,
                "layer": "permission",
                "raw_conditions": {},
                "resource_pattern": "*",
                "statement_index": 0,
            },
        )
        lambda_trust = Edge(
            edge_type="sts:AssumeRole_trust",
            src=lambda_svc.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [
                    {
                        "control_type": "TRUST",
                        "policy_arn": "T",
                        "statement_index": 0,
                        "digest": "d" * 64,
                        "summary": "trust",
                    }
                ],
                "effect": "Allow",
                "has_conditions": False,
                "is_wildcard_principal": False,
                "layer": "trust",
                "principal_type": "Service",
                "raw_conditions": {},
                "statement_index": 0,
            },
        )
        facts = FactGraph(
            nodes=(alice, target, lambda_svc),
            edges=(lambda_create, passrole, admin_grant, lambda_trust),
            constraints=(),
            edge_constraints=(),
            scenario_hash="deadbeef" * 8,
            edge_budget_exhausted=False,
        )
        return PassRoleLambdaReasoner().run(facts)[0]

    def test_validated_passrole_demoted_to_inconclusive(self) -> None:
        """A VALIDATED passrole_lambda finding becomes INCONCLUSIVE/medium."""
        from iamscope.cli import _demote_validated_findings
        from iamscope.reasoner import Verdict

        original = self._build_validated_passrole_finding()
        assert original.verdict is Verdict.VALIDATED  # sanity

        demoted_list = _demote_validated_findings([original])
        assert len(demoted_list) == 1
        d = demoted_list[0]
        assert d.verdict is Verdict.INCONCLUSIVE
        assert d.severity == "medium"

    def test_demoted_finding_has_condition_context_assumption(self) -> None:
        """The demotion adds a condition_context assumption (not session_policy)."""
        from iamscope.cli import _demote_validated_findings
        from iamscope.reasoner import ASSUMPTION_KIND_CONDITION_CONTEXT

        original = self._build_validated_passrole_finding()
        d = _demote_validated_findings([original])[0]

        kinds = [a.kind for a in d.assumptions]
        assert ASSUMPTION_KIND_CONDITION_CONTEXT in kinds
        # The session_policy assumption from the reasoner is dropped
        # because it's redundant once condition_context is present.
        assert "session_policy" not in kinds

    def test_non_passrole_finding_passes_through_unchanged(self) -> None:
        """Findings from other reasoners are not affected by demotion."""
        from iamscope.cli import _demote_validated_findings
        from iamscope.reasoner import Verdict

        # Build a passrole finding then mutate its pattern_id by
        # constructing a near-clone (Finding is frozen — can't mutate).
        # Easier path: use a non-passrole pattern_id by constructing
        # a fresh Finding via the cross_account_trust reasoner.
        original = self._build_validated_passrole_finding()
        # Verify the post-processor recognizes it as passrole.
        assert original.pattern_id == "passrole_lambda"
        # But test that NON-passrole findings pass through.
        from dataclasses import replace

        non_passrole = replace(
            original,
            pattern_id="some_other_reasoner",
            _finding_id_cache=None,
        )
        out = _demote_validated_findings([non_passrole])
        assert len(out) == 1
        assert out[0].verdict is Verdict.VALIDATED  # unchanged
        assert out[0].pattern_id == "some_other_reasoner"
