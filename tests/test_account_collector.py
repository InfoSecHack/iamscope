"""Tests for account collector — Phase 2 per-account IAM collection.

Moto-based tests with realistic IAM setup:
- 2 roles (ProdDeploy with trust+permissions, ServiceLinkedRole to skip)
- 1 user (deployer) in 1 group (Deployers)
- Group has inline policy granting sts:AssumeRole
- User inherits group permissions (R10)
- Role has inline + managed permission policies

Tests cover:
- Role node creation with properties
- Trust policy parsed into TrustParseResult
- Permission policies parsed (inline + managed)
- User node creation with group memberships
- Group-inherited permission policies (R10)
- Service-linked role filtering
- Group node creation
- AccountData role_arns populated
- Skipped role counting
- Raw trust policy canonicalized (Invariant #10)
- Permission boundary detection
"""

import json

import pytest
from moto import mock_aws

from iamscope.auth.session import get_session
from iamscope.collector.account import collect_account
from iamscope.constants import (
    NODE_TYPE_IAM_GROUP,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
)


@pytest.fixture
def account_setup():
    """Create realistic IAM resources in a single account via moto.

    Resources:
    - Role: ProdDeploy
      - Trust: cross-account from 222222\u003222222 + lambda service
      - Inline policy: CrossAccountAccess (sts:AssumeRole → specific role)
      - Managed policy: PassRoleAccess (iam:PassRole → *)
    - Role: AWSServiceRoleForOrganizations (service-linked, should be skipped)
    - User: deployer
      - Member of group: Deployers
    - Group: Deployers
      - Inline policy: GroupAssumeAll (sts:AssumeRole → *)
    """
    with mock_aws():
        session = get_session(region_name="us-east-1")
        iam = session.client("iam")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # Role 1: ProdDeploy with trust + permissions
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
                        "Action": "sts:AssumeRole",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    },
                ],
            }
        )
        iam.create_role(RoleName="ProdDeploy", Path="/app/", AssumeRolePolicyDocument=trust)

        # Inline policy on role
        inline = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::333333\u003333333:role/Target",
                    }
                ],
            }
        )
        iam.put_role_policy(RoleName="ProdDeploy", PolicyName="CrossAccountAccess", PolicyDocument=inline)

        # Managed policy on role
        managed = json.dumps(
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
        pol = iam.create_policy(PolicyName="PassRoleAccess", PolicyDocument=managed)
        managed_arn = pol["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="ProdDeploy", PolicyArn=managed_arn)

        # Role 2: Service-linked role (should be filtered)
        slr_trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "organizations.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(
            RoleName="AWSServiceRoleForOrganizations",
            Path="/aws-service-role/organizations.amazonaws.com/",
            AssumeRolePolicyDocument=slr_trust,
        )

        # User + Group
        iam.create_user(UserName="deployer")
        iam.create_group(GroupName="Deployers")
        iam.add_user_to_group(GroupName="Deployers", UserName="deployer")

        # Group inline policy
        group_pol = json.dumps(
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
        iam.put_group_policy(GroupName="Deployers", PolicyName="GroupAssumeAll", PolicyDocument=group_pol)

        yield {
            "session": session,
            "account_id": account_id,
            "managed_arn": managed_arn,
        }


class TestRoleCollection:
    """Tests for role discovery and processing."""

    def test_role_node_created(self, account_setup) -> None:
        """ProdDeploy role creates a node with correct type."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        role_nodes = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_ROLE]
        assert len(role_nodes) == 1  # SLR filtered out
        assert "ProdDeploy" in role_nodes[0].provider_id

    def test_role_properties(self, account_setup) -> None:
        """Role node properties include account_id, path, is_synthetic."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        role = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_ROLE][0]
        assert role.properties["account_id"] == account_setup["account_id"]
        assert role.properties["path"] == "/app/"
        assert role.properties["is_synthetic"] is False

    def test_role_arns_populated(self, account_setup) -> None:
        """AccountData.role_arns contains the collected role ARN."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        assert len(data.role_arns) == 1
        assert "ProdDeploy" in data.role_arns[0]

    def test_trust_policy_raw_canonicalized(self, account_setup) -> None:
        """Trust policy is stored as canonical JSON (Invariant #10)."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        role = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_ROLE][0]
        raw = role.properties["trust_policy_raw"]
        # Should be valid JSON
        parsed = json.loads(raw)
        # Should be canonical (sorted keys, compact)
        recanon = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        assert raw == recanon


class TestTrustParsing:
    """Tests for trust policy parsing integration."""

    def test_trust_results_created(self, account_setup) -> None:
        """Trust policy produces TrustParseResult objects."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        # 2 statements: one AWS principal, one Service principal
        assert len(data.trust_results) == 2

    def test_trust_result_principal_types(self, account_setup) -> None:
        """Trust results have correct principal types."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        principal_types = {tr.principal_type for _, tr in data.trust_results}
        assert "AWS" in principal_types
        assert "Service" in principal_types

    def test_trust_result_linked_to_role_node(self, account_setup) -> None:
        """Each trust result is paired with its role node."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        for node, _tr in data.trust_results:
            assert node.node_type == NODE_TYPE_IAM_ROLE
            assert "ProdDeploy" in node.provider_id


class TestPermissionParsing:
    """Tests for permission policy parsing (roles)."""

    def test_role_inline_permissions_parsed(self, account_setup) -> None:
        """Role inline policy (CrossAccountAccess) produces permission results."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        # Find results from the inline policy
        inline_prs = [
            pr
            for pr in data.permission_results
            if pr.policy_source == "inline" and pr.source_node_type == NODE_TYPE_IAM_ROLE
        ]
        assert len(inline_prs) >= 1
        # Should have sts:AssumeRole → specific target
        assert any(pr.action == "sts:AssumeRole" for pr in inline_prs)
        assert any("333333\u003333333" in pr.resource_pattern for pr in inline_prs)

    def test_role_managed_permissions_parsed(self, account_setup) -> None:
        """Role managed policy (PassRoleAccess) produces permission results."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        managed_prs = [
            pr
            for pr in data.permission_results
            if pr.policy_source == "managed" and pr.source_node_type == NODE_TYPE_IAM_ROLE
        ]
        assert len(managed_prs) >= 1
        assert any(pr.action == "iam:PassRole" for pr in managed_prs)


class TestServiceLinkedRoleFilter:
    """Tests for service-linked role noise filtering."""

    def test_slr_filtered_by_default(self, account_setup) -> None:
        """Service-linked roles are skipped by default."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        role_names = [n.properties.get("role_name", "") for n in data.nodes if n.node_type == NODE_TYPE_IAM_ROLE]
        assert "AWSServiceRoleForOrganizations" not in role_names

    def test_slr_included_when_requested(self, account_setup) -> None:
        """Service-linked roles included when include_service_linked=True."""
        data = collect_account(
            account_setup["session"],
            account_setup["account_id"],
            include_service_linked=True,
        )
        role_names = [n.properties.get("role_name", "") for n in data.nodes if n.node_type == NODE_TYPE_IAM_ROLE]
        assert "AWSServiceRoleForOrganizations" in role_names

    def test_skipped_count(self, account_setup) -> None:
        """Skipped roles are counted."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        assert data.skipped_roles >= 1


class TestUserCollection:
    """Tests for user discovery and permission inheritance."""

    def test_user_node_created(self, account_setup) -> None:
        """User creates a node with correct type."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        user_nodes = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_USER]
        assert len(user_nodes) == 1
        assert "deployer" in user_nodes[0].provider_id

    def test_user_group_memberships(self, account_setup) -> None:
        """User node records group memberships."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        user = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_USER][0]
        assert "Deployers" in user.properties["group_memberships"]

    def test_user_inherits_group_permissions(self, account_setup) -> None:
        """User gets permission results from group policies (R10)."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        # Find group-inherited results for the user
        group_prs = [
            pr
            for pr in data.permission_results
            if pr.policy_source == "group_inline" and pr.source_node_type == NODE_TYPE_IAM_USER
        ]
        assert len(group_prs) >= 1
        assert any(pr.action == "sts:AssumeRole" for pr in group_prs)

    def test_group_permissions_attributed_to_user(self, account_setup) -> None:
        """Group-inherited permissions are attributed to the user via R10 inheritance.

        After v0.2.25, group policies are ALSO emitted as group-sourced
        edges to support `iam_group_membership_escalation` (which needs
        to walk groups' outgoing permission edges for admin-equivalence
        detection). So the `group_inline` policy_source now appears on
        BOTH user-sourced AND group-sourced permission results — the
        test verifies at least one user-sourced result exists.
        """
        data = collect_account(account_setup["session"], account_setup["account_id"])
        group_prs = [pr for pr in data.permission_results if pr.policy_source == "group_inline"]
        user_sourced = [pr for pr in group_prs if pr.source_node_type == NODE_TYPE_IAM_USER]
        assert len(user_sourced) > 0, "R10 user inheritance must still produce user-sourced group permission results"
        for pr in user_sourced:
            assert "deployer" in pr.source_arn


class TestGroupCollection:
    """Tests for group node creation."""

    def test_group_node_created(self, account_setup) -> None:
        """Group creates a node."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        group_nodes = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_GROUP]
        assert len(group_nodes) == 1
        assert "Deployers" in group_nodes[0].provider_id

    def test_group_properties(self, account_setup) -> None:
        """Group node has correct properties."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        group = [n for n in data.nodes if n.node_type == NODE_TYPE_IAM_GROUP][0]
        assert group.properties["group_name"] == "Deployers"
        assert group.properties["is_synthetic"] is False


class TestAccountDataIntegrity:
    """Tests for overall AccountData integrity."""

    def test_all_node_types_present(self, account_setup) -> None:
        """AccountData has role, user, and group nodes."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        types = {n.node_type for n in data.nodes}
        assert NODE_TYPE_IAM_ROLE in types
        assert NODE_TYPE_IAM_USER in types
        assert NODE_TYPE_IAM_GROUP in types

    def test_account_id_set(self, account_setup) -> None:
        """AccountData has correct account_id."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        assert data.account_id == account_setup["account_id"]

    def test_total_node_count(self, account_setup) -> None:
        """Total nodes = 1 role + 1 user + 1 group = 3 (SLR filtered)."""
        data = collect_account(account_setup["session"], account_setup["account_id"])
        assert len(data.nodes) == 3
