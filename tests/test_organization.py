"""Tests for organization collector — Phase 1 pipeline.

Moto-based tests with realistic org setup:
- 3 accounts (management + 2 member accounts)
- 2 OUs (Production, Development) under root
- 2 SCPs attached to Production OU
- 1 account in Production, 1 in Development

Tests cover:
- OU tree discovery with paths
- Account listing and parent assignment
- SCP collection and parsing
- OU-to-account recursive mapping
- Default FullAWSAccess SCP skipped
- SCP targets (OU attachment) resolved correctly
- Constraint properties populated correctly
- Invariant #15: OU inheritance is recursive downward only
- Invariant #18: exhaustive pagination (verified via complete results)
"""

import json

import pytest
from moto import mock_aws

from iamscope.auth.session import get_session
from iamscope.collector.organization import (
    _compute_ou_account_map,
    collect_organization,
)
from iamscope.constants import NODE_TYPE_IAM_ROLE, NODE_TYPE_IAM_USER, PROVIDER_AWS, REGION_GLOBAL
from iamscope.models import AccountInfo, Edge, NodeRef, OUInfo
from iamscope.resolver.scp_binder import bind_scp_to_edge


@pytest.fixture
def org_setup():
    """Create a realistic AWS Organization in moto.

    Structure:
        Root
        ├── Production OU
        │   └── Account: prod-account (333333333333 or similar)
        │   └── SCP: DenyAssumeRole (deny sts:AssumeRole)
        │   └── SCP: DenyS3Delete (deny s3:DeleteObject)
        └── Development OU
            └── Account: dev-account (444444444444 or similar)
    """
    with mock_aws():
        session = get_session(region_name="us-east-1")
        org_client = session.client("organizations", region_name="us-east-1")

        # Create org
        org = org_client.create_organization(FeatureSet="ALL")
        org_id = org["Organization"]["Id"]

        # Get root
        roots = org_client.list_roots()["Roots"]
        root_id = roots[0]["Id"]

        # Create OUs
        prod_ou = org_client.create_organizational_unit(ParentId=root_id, Name="Production")
        prod_ou_id = prod_ou["OrganizationalUnit"]["Id"]

        dev_ou = org_client.create_organizational_unit(ParentId=root_id, Name="Development")
        dev_ou_id = dev_ou["OrganizationalUnit"]["Id"]

        # Create member accounts
        prod_acct = org_client.create_account(Email="prod@example.com", AccountName="ProdAccount")
        prod_acct_id = prod_acct["CreateAccountStatus"]["AccountId"]

        dev_acct = org_client.create_account(Email="dev@example.com", AccountName="DevAccount")
        dev_acct_id = dev_acct["CreateAccountStatus"]["AccountId"]

        # Move accounts to OUs
        org_client.move_account(
            AccountId=prod_acct_id,
            SourceParentId=root_id,
            DestinationParentId=prod_ou_id,
        )
        org_client.move_account(
            AccountId=dev_acct_id,
            SourceParentId=root_id,
            DestinationParentId=dev_ou_id,
        )

        # Create SCPs and attach to Production OU
        scp1_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyAssumeRole",
                        "Effect": "Deny",
                        "Action": "sts:AssumeRole",
                        "Resource": "*",
                    }
                ],
            }
        )
        scp1 = org_client.create_policy(
            Content=scp1_doc,
            Description="Deny AssumeRole in Prod",
            Name="DenyAssumeRole",
            Type="SERVICE_CONTROL_POLICY",
        )
        scp1_id = scp1["Policy"]["PolicySummary"]["Id"]
        org_client.attach_policy(PolicyId=scp1_id, TargetId=prod_ou_id)

        scp2_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyS3Delete",
                        "Effect": "Deny",
                        "Action": "s3:DeleteObject",
                        "Resource": "*",
                    }
                ],
            }
        )
        scp2 = org_client.create_policy(
            Content=scp2_doc,
            Description="Deny S3 deletes",
            Name="DenyS3Delete",
            Type="SERVICE_CONTROL_POLICY",
        )
        scp2_id = scp2["Policy"]["PolicySummary"]["Id"]
        org_client.attach_policy(PolicyId=scp2_id, TargetId=prod_ou_id)

        scp3_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyAssumeRoleForBlockedPrincipal",
                        "Effect": "Deny",
                        "Action": "sts:AssumeRole",
                        "Resource": "*",
                        "Condition": {
                            "ArnLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::222222222222:role/Blocked*",
                                    "arn:aws:sts::222222222222:assumed-role/Blocked*/*",
                                ]
                            }
                        },
                    }
                ],
            }
        )
        scp3 = org_client.create_policy(
            Content=scp3_doc,
            Description="Deny AssumeRole for one blocked PrincipalArn family",
            Name="DenyAssumeRoleForBlockedPrincipal",
            Type="SERVICE_CONTROL_POLICY",
        )
        scp3_id = scp3["Policy"]["PolicySummary"]["Id"]
        org_client.attach_policy(PolicyId=scp3_id, TargetId=prod_ou_id)

        # Get management account ID
        sts = session.client("sts")
        mgmt_acct_id = sts.get_caller_identity()["Account"]

        yield {
            "session": session,
            "org_id": org_id,
            "root_id": root_id,
            "prod_ou_id": prod_ou_id,
            "dev_ou_id": dev_ou_id,
            "prod_acct_id": prod_acct_id,
            "dev_acct_id": dev_acct_id,
            "mgmt_acct_id": mgmt_acct_id,
            "scp1_id": scp1_id,
            "scp2_id": scp2_id,
            "scp3_id": scp3_id,
        }


class TestOrganizationDiscovery:
    """Tests for OU tree and account discovery."""

    def test_org_id_collected(self, org_setup) -> None:
        """Organization ID is collected."""
        result = collect_organization(org_setup["session"])
        assert result.org_id == org_setup["org_id"]

    def test_root_id_collected(self, org_setup) -> None:
        """Root ID is collected."""
        result = collect_organization(org_setup["session"])
        assert result.root_id == org_setup["root_id"]

    def test_two_ous_discovered(self, org_setup) -> None:
        """Both Production and Development OUs discovered."""
        result = collect_organization(org_setup["session"])
        ou_names = {ou.name for ou in result.ous}
        assert "Production" in ou_names
        assert "Development" in ou_names
        assert len(result.ous) == 2

    def test_ou_paths_correct(self, org_setup) -> None:
        """OU paths reflect the hierarchy."""
        result = collect_organization(org_setup["session"])
        ou_by_name = {ou.name: ou for ou in result.ous}
        assert ou_by_name["Production"].ou_path == "/Root/Production"
        assert ou_by_name["Development"].ou_path == "/Root/Development"

    def test_accounts_discovered(self, org_setup) -> None:
        """All accounts discovered (management + 2 members)."""
        result = collect_organization(org_setup["session"])
        acct_ids = {a.account_id for a in result.accounts}
        assert org_setup["prod_acct_id"] in acct_ids
        assert org_setup["dev_acct_id"] in acct_ids
        assert org_setup["mgmt_acct_id"] in acct_ids

    def test_accounts_assigned_to_parents(self, org_setup) -> None:
        """Accounts are assigned to their correct parent OU."""
        result = collect_organization(org_setup["session"])
        acct_by_id = {a.account_id: a for a in result.accounts}

        prod_acct = acct_by_id[org_setup["prod_acct_id"]]
        assert prod_acct.parent_id == org_setup["prod_ou_id"]

        dev_acct = acct_by_id[org_setup["dev_acct_id"]]
        assert dev_acct.parent_id == org_setup["dev_ou_id"]


class TestSCPCollection:
    """Tests for SCP collection and parsing."""

    def test_scps_collected(self, org_setup) -> None:
        """Custom SCPs are collected (FullAWSAccess skipped)."""
        result = collect_organization(org_setup["session"])
        # 3 SCPs × 1 target each = 3 constraints
        assert len(result.scp_constraints) == 3

    def test_fullawsaccess_skipped(self, org_setup) -> None:
        """Default FullAWSAccess SCP is not in constraints."""
        result = collect_organization(org_setup["session"])
        names = {c.properties.get("policy_name", "") for c in result.scp_constraints}
        assert "FullAWSAccess" not in names

    def test_scp_properties_populated(self, org_setup) -> None:
        """SCP constraints have correct properties from parsing."""
        result = collect_organization(org_setup["session"])

        # Find the DenyAssumeRole constraint
        deny_assume = [c for c in result.scp_constraints if c.properties.get("policy_name") == "DenyAssumeRole"]
        assert len(deny_assume) == 1
        c = deny_assume[0]
        assert c.constraint_type == "SCP"
        assert "sts:AssumeRole" in c.properties["deny_actions"]
        assert c.properties["parse_status"] == "complete"
        assert c.status == "ACTIVE"

    def test_positive_principal_arn_applicability_patterns_preserved(self, org_setup) -> None:
        result = collect_organization(org_setup["session"])

        deny_scoped = [
            c for c in result.scp_constraints if c.properties.get("policy_name") == "DenyAssumeRoleForBlockedPrincipal"
        ]

        assert len(deny_scoped) == 1
        c = deny_scoped[0]
        assert c.properties["parse_status"] == "complete"
        assert c.properties["parse_warnings"] == []
        assert c.properties["applicable_principal_patterns"] == [
            "arn:aws:iam::222222222222:role/Blocked*",
            "arn:aws:sts::222222222222:assumed-role/Blocked*/*",
        ]

    def test_collected_nonmatching_principal_arn_scp_does_not_bind_unrelated_trust_edge(self, org_setup) -> None:
        result = collect_organization(org_setup["session"])
        scp = next(
            c for c in result.scp_constraints if c.properties.get("policy_name") == "DenyAssumeRoleForBlockedPrincipal"
        )
        edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=NodeRef(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_IAM_USER,
                provider_id="arn:aws:iam::222222222222:user/iamscope-test/env22-alice",
            ),
            dst=NodeRef(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_IAM_ROLE,
                provider_id="arn:aws:iam::333333333333:role/iamscope-test/env22-admin",
            ),
            region=REGION_GLOBAL,
            features={"layer": "trust"},
        )

        assert bind_scp_to_edge(edge, scp) is None

    def test_scp_scope_is_ou(self, org_setup) -> None:
        """SCPs attached to OU have scope_type=OU and correct scope_id."""
        result = collect_organization(org_setup["session"])

        for c in result.scp_constraints:
            assert c.scope_type == "OU"
            assert c.scope_id == org_setup["prod_ou_id"]


class TestOUAccountMap:
    """Tests for ou_account_map — recursive OU→account inheritance."""

    def test_root_contains_all_accounts(self, org_setup) -> None:
        """Root scope contains all accounts."""
        result = collect_organization(org_setup["session"])
        root_accounts = result.ou_account_map.get(org_setup["root_id"], set())
        assert org_setup["prod_acct_id"] in root_accounts
        assert org_setup["dev_acct_id"] in root_accounts
        assert org_setup["mgmt_acct_id"] in root_accounts

    def test_prod_ou_contains_prod_account(self, org_setup) -> None:
        """Production OU scope contains only the prod account."""
        result = collect_organization(org_setup["session"])
        prod_accounts = result.ou_account_map.get(org_setup["prod_ou_id"], set())
        assert org_setup["prod_acct_id"] in prod_accounts
        assert org_setup["dev_acct_id"] not in prod_accounts

    def test_dev_ou_contains_dev_account(self, org_setup) -> None:
        """Development OU scope contains only the dev account."""
        result = collect_organization(org_setup["session"])
        dev_accounts = result.ou_account_map.get(org_setup["dev_ou_id"], set())
        assert org_setup["dev_acct_id"] in dev_accounts
        assert org_setup["prod_acct_id"] not in dev_accounts

    def test_individual_account_scopes(self, org_setup) -> None:
        """Individual account IDs are also scopes (for account-level SCPs)."""
        result = collect_organization(org_setup["session"])
        assert org_setup["prod_acct_id"] in result.ou_account_map
        assert result.ou_account_map[org_setup["prod_acct_id"]] == {org_setup["prod_acct_id"]}

    def test_sibling_ous_dont_inherit(self, org_setup) -> None:
        """Invariant #15: siblings do NOT inherit from each other."""
        result = collect_organization(org_setup["session"])
        prod_accounts = result.ou_account_map.get(org_setup["prod_ou_id"], set())
        dev_accounts = result.ou_account_map.get(org_setup["dev_ou_id"], set())
        # No overlap between sibling OU scopes
        assert prod_accounts & dev_accounts == set()


class TestOUAccountMapUnit:
    """Unit tests for _compute_ou_account_map without moto."""

    def test_nested_ou_inheritance(self) -> None:
        """Grandchild accounts are in grandparent scope."""
        ous = [
            OUInfo(ou_id="ou-parent", name="Parent", parent_id="r-root", ou_path="/Root/Parent", account_ids=[]),
            OUInfo(
                ou_id="ou-child",
                name="Child",
                parent_id="ou-parent",
                ou_path="/Root/Parent/Child",
                account_ids=["acct-deep"],
            ),
        ]
        accounts = [
            AccountInfo(account_id="acct-deep", name="Deep", email="", status="ACTIVE", parent_id="ou-child"),
            AccountInfo(account_id="acct-root", name="Root", email="", status="ACTIVE", parent_id="r-root"),
        ]

        result = _compute_ou_account_map("r-root", ous, accounts)

        assert "acct-deep" in result["ou-parent"]  # Inherited up
        assert "acct-deep" in result["ou-child"]  # Direct
        assert "acct-deep" in result["r-root"]  # Root gets everything
        assert "acct-root" in result["r-root"]

    def test_empty_ou(self) -> None:
        """OU with no accounts produces empty set."""
        ous = [
            OUInfo(ou_id="ou-empty", name="Empty", parent_id="r-root", ou_path="/Root/Empty", account_ids=[]),
        ]
        accounts = [
            AccountInfo(account_id="acct-root", name="Root", email="", status="ACTIVE", parent_id="r-root"),
        ]

        result = _compute_ou_account_map("r-root", ous, accounts)
        assert result["ou-empty"] == set()
        assert "acct-root" in result["r-root"]


class TestOrgDataProperties:
    """Tests for OrgData convenience properties."""

    def test_account_ids_property(self, org_setup) -> None:
        """OrgData.account_ids returns all account IDs."""
        result = collect_organization(org_setup["session"])
        assert len(result.account_ids) >= 3  # mgmt + 2 member

    def test_active_account_ids(self, org_setup) -> None:
        """OrgData.active_account_ids returns only ACTIVE accounts."""
        result = collect_organization(org_setup["session"])
        # All moto accounts are ACTIVE
        assert result.active_account_ids == result.account_ids
