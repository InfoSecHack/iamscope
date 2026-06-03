"""Tests for permission boundary constraint builder.

Tests cover:
- build_permission_boundary_constraints from policy docs
- bind_permission_boundaries to trust and permission edges
- Empty policies produce no constraints
- Multiple boundaries deduplication
- Pipeline integration with boundary-attached role
"""

import json

from moto import mock_aws

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node, NodeRef
from iamscope.resolver.permission_boundary import (
    bind_permission_boundaries,
    build_permission_boundary_constraints,
)


def _make_node(
    provider_id: str,
    node_type: str = NODE_TYPE_IAM_ROLE,
    boundary_arn: str = "",
) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=node_type,
        provider_id=provider_id,
        region=REGION_GLOBAL,
        properties={
            "has_permission_boundary": bool(boundary_arn),
            "permission_boundary_arn": boundary_arn,
        },
    )


def _make_edge(edge_type: str, src_id: str, dst_id: str) -> Edge:
    return Edge(
        edge_type=edge_type,
        src=NodeRef(provider=PROVIDER_AWS, node_type=NODE_TYPE_IAM_ROLE, provider_id=src_id, region=REGION_GLOBAL),
        dst=NodeRef(provider=PROVIDER_AWS, node_type=NODE_TYPE_IAM_ROLE, provider_id=dst_id, region=REGION_GLOBAL),
        region=REGION_GLOBAL,
    )


class TestBuildConstraints:
    """Tests for build_permission_boundary_constraints."""

    def test_single_boundary(self) -> None:
        """Single boundary creates one constraint."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*",
                }
            ],
        }
        constraints = build_permission_boundary_constraints(
            {
                "arn:aws:iam::123:policy/MyBoundary": policy,
            }
        )
        assert len(constraints) == 1
        c = constraints[0]
        assert c.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY
        assert c.properties["boundary_arn"] == "arn:aws:iam::123:policy/MyBoundary"
        assert c.properties["allowed_actions"] == ["s3:GetObject", "s3:PutObject"]
        assert c.properties["statement_count"] == 1

    def test_empty_policies(self) -> None:
        """No policies → no constraints."""
        assert build_permission_boundary_constraints({}) == []

    def test_multiple_boundaries(self) -> None:
        """Multiple boundaries create multiple constraints."""
        p1 = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            ],
        }
        p2 = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
            ],
        }
        constraints = build_permission_boundary_constraints(
            {
                "arn:boundary1": p1,
                "arn:boundary2": p2,
            }
        )
        assert len(constraints) == 2
        arns = {c.properties["boundary_arn"] for c in constraints}
        assert arns == {"arn:boundary1", "arn:boundary2"}

    def test_deny_statements_excluded(self) -> None:
        """Only Allow statements contribute to allowed_actions."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
            ],
        }
        constraints = build_permission_boundary_constraints({"arn:b": policy})
        assert constraints[0].properties["allowed_actions"] == ["s3:GetObject"]
        assert constraints[0].properties["statement_count"] == 1


class TestBindBoundaries:
    """Tests for bind_permission_boundaries."""

    def test_trust_edge_dst_has_boundary(self) -> None:
        """Trust edge bound when dst role has the boundary."""
        dst_node = _make_node("arn:role/Target", boundary_arn="arn:boundary")
        edge = _make_edge("sts:AssumeRole_trust", "arn:src", "arn:role/Target")

        constraints = build_permission_boundary_constraints(
            {
                "arn:boundary": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    ]
                },
            }
        )
        ecs = bind_permission_boundaries([edge], [dst_node], constraints)
        assert len(ecs) == 1
        assert ecs[0].edge_id == edge.edge_id
        assert ecs[0].constraint_id == constraints[0].constraint_id

    def test_permission_edge_src_has_boundary(self) -> None:
        """Permission edge bound when src principal has the boundary."""
        src_node = _make_node("arn:role/Assumer", boundary_arn="arn:boundary")
        edge = _make_edge("sts:AssumeRole_permission", "arn:role/Assumer", "arn:role/Target")

        constraints = build_permission_boundary_constraints(
            {
                "arn:boundary": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                    ]
                },
            }
        )
        ecs = bind_permission_boundaries([edge], [src_node], constraints)
        assert len(ecs) == 1

    def test_no_boundary_no_binding(self) -> None:
        """Edges without boundary principals get no binding."""
        node = _make_node("arn:role/NoBoundary")
        edge = _make_edge("sts:AssumeRole_trust", "arn:src", "arn:role/NoBoundary")

        constraints = build_permission_boundary_constraints(
            {
                "arn:boundary": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    ]
                },
            }
        )
        ecs = bind_permission_boundaries([edge], [node], constraints)
        assert len(ecs) == 0

    def test_empty_constraints(self) -> None:
        """No constraints → no bindings."""
        ecs = bind_permission_boundaries([], [], [])
        assert ecs == []

    def test_service_edges_not_bound(self) -> None:
        """Service edges are not bound to boundaries."""
        node = _make_node("arn:role/Target", boundary_arn="arn:boundary")
        edge = _make_edge("lambda:ExecutionRole_service", "arn:fn", "arn:role/Target")

        constraints = build_permission_boundary_constraints(
            {
                "arn:boundary": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    ]
                },
            }
        )
        ecs = bind_permission_boundaries([edge], [node], constraints)
        assert len(ecs) == 0


class TestPipelineIntegration:
    """Permission boundary in full pipeline."""

    @mock_aws
    def test_boundary_creates_constraint(self) -> None:
        """Role with permission boundary produces constraint in pipeline output."""
        import boto3

        from iamscope.auth.session import get_session
        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        iam = boto3.client("iam")

        # Create boundary policy
        boundary_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:*", "sts:AssumeRole"],
                        "Resource": "*",
                    }
                ],
            }
        )
        iam.create_policy(
            PolicyName="S3Boundary",
            PolicyDocument=boundary_doc,
        )
        # Get the ARN
        boundary_arn = f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:policy/S3Boundary"

        # Create role with boundary
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999\u003999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(
            RoleName="BoundedRole",
            AssumeRolePolicyDocument=trust,
            PermissionsBoundary=boundary_arn,
        )

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)

        # Should have a PERMISSION_BOUNDARY constraint
        pb_constraints = [c for c in scenario["constraints"] if c["constraint_type"] == "PERMISSION_BOUNDARY"]
        assert len(pb_constraints) >= 1
        assert pb_constraints[0]["properties"]["boundary_arn"] == boundary_arn


class TestBND1ActionIntersection:
    """BND-1 regression tests: boundary binding must intersect allowed_actions.

    Pre-S03 the binder emitted likely_blocking=False / needs_review for every
    boundary binding regardless of whether the boundary actually permitted the
    edge's action. Post-S03 the decision table is:

      parse_status=complete + action in allowed   → False / complete
      parse_status=complete + action NOT in allowed → True  / complete
      parse_status != complete                    → False / needs_review
    """

    @staticmethod
    def _bind(boundary_arn: str, allowed_actions: list[str], edge_type: str, parse_status: str = "complete") -> list:
        """Helper: build a node + edge + boundary constraint and bind them."""
        src_id = "arn:aws:iam::111111\u003111111:role/Src"
        dst_id = "arn:aws:iam::222222\u003222222:role/Dst"
        # Boundary applies to src for permission edges, dst for trust edges.
        constrained_id = src_id if "_permission" in edge_type else dst_id
        node = _make_node(constrained_id, boundary_arn=boundary_arn)
        edge = _make_edge(edge_type, src_id, dst_id)
        # Build a policy doc that will yield the exact allowed_actions list
        # we pass in. Sorted-set semantics in _extract_allowed_actions mean
        # we pre-sort the input for stable comparison.
        policy_doc = (
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": sorted(set(allowed_actions)),
                        "Resource": "*",
                    }
                ]
            }
            if allowed_actions
            else {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [],
                        "Resource": "*",
                    }
                ]
            }
        )
        constraints = build_permission_boundary_constraints({boundary_arn: policy_doc})
        # Inject parse_status into the constructed constraint's properties
        # without touching the builder. Exercises the binder's read-with-default.
        constraints[0].properties["parse_status"] = parse_status
        return bind_permission_boundaries([edge], [node], constraints)

    def test_boundary_allows_action_not_blocking(self) -> None:
        """complete + action in allowed_actions → False / complete."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/AllowPassRole",
            allowed_actions=["iam:PassRole"],
            edge_type="iam:PassRole_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"

    def test_boundary_denies_action_exact_miss_blocking(self) -> None:
        """complete + action NOT in allowed_actions → True / complete (exact miss)."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/S3Only",
            allowed_actions=["s3:GetObject"],
            edge_type="iam:PassRole_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is True
        assert ecs[0].governance_confidence == "complete"
        assert "iam:PassRole" in ecs[0].binding_reason

    def test_boundary_denies_wildcard_miss_blocking(self) -> None:
        """Exit-criterion spot-check: boundary ["s3:*"] against lambda:CreateFunction."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/S3Wildcard",
            allowed_actions=["s3:*"],
            edge_type="lambda:CreateFunction_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is True
        assert ecs[0].governance_confidence == "complete"

    def test_parse_status_partial_emits_needs_review(self) -> None:
        """parse_status != complete → False / needs_review regardless of actions."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/Partial",
            allowed_actions=[],  # would otherwise block everything
            edge_type="iam:PassRole_permission",
            parse_status="partial",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "needs_review"
        assert "partial" in ecs[0].binding_reason

    def test_wildcard_service_matches_action(self) -> None:
        """complete + lambda:* matches lambda:CreateFunction → False / complete."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/LambdaWildcard",
            allowed_actions=["lambda:*"],
            edge_type="lambda:CreateFunction_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"

    def test_boundaries_are_positive_list_only(self) -> None:
        """Boundary with [*] allows every action.

        Documents that boundaries have no NotAction semantics — the full
        wildcard is the only way to universally permit.
        """
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/FullAdmin",
            allowed_actions=["*"],
            edge_type="iam:PassRole_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"

    def test_action_case_insensitive_match(self) -> None:
        """Case insensitivity: IAM:PassRole in allowed matches iam:PassRole edge."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/MixedCase",
            allowed_actions=["IAM:PassRole"],
            edge_type="iam:PassRole_permission",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"

    def test_empty_allowed_actions_blocks_everything(self) -> None:
        """Empty allowed_actions + complete → every action blocked."""
        ecs = self._bind(
            boundary_arn="arn:aws:iam::111111\u003111111:policy/Nothing",
            allowed_actions=[],
            edge_type="iam:PassRole_permission",
            parse_status="complete",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is True
        assert ecs[0].governance_confidence == "complete"

    def test_boundary_resource_miss_blocks_action(self) -> None:
        """Action match is not enough: Resource must match the edge target."""
        src_id = "arn:aws:iam::111111\u003111111:role/Src"
        dst_id = "arn:aws:iam::222222\u003222222:role/Dst"
        node = _make_node(src_id, boundary_arn="arn:aws:iam::111111\u003111111:policy/OtherRoleOnly")
        edge = _make_edge("sts:AssumeRole_permission", src_id, dst_id)
        constraints = build_permission_boundary_constraints(
            {
                "arn:aws:iam::111111\u003111111:policy/OtherRoleOnly": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::222222\u003222222:role/Other",
                        }
                    ],
                },
            }
        )

        ecs = bind_permission_boundaries([edge], [node], constraints)

        assert len(ecs) == 1
        assert ecs[0].likely_blocking is True
        assert ecs[0].governance_confidence == "complete"
        assert "no boundary Allow matches action sts:AssumeRole" in ecs[0].binding_reason

    def test_boundary_resource_match_allows_action(self) -> None:
        """Resource-aware intersection permits matching action and target ARN."""
        src_id = "arn:aws:iam::111111\u003111111:role/Src"
        dst_id = "arn:aws:iam::222222\u003222222:role/Dst"
        node = _make_node(src_id, boundary_arn="arn:aws:iam::111111\u003111111:policy/DstOnly")
        edge = _make_edge("sts:AssumeRole_permission", src_id, dst_id)
        constraints = build_permission_boundary_constraints(
            {
                "arn:aws:iam::111111\u003111111:policy/DstOnly": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": dst_id,
                        }
                    ],
                },
            }
        )

        ecs = bind_permission_boundaries([edge], [node], constraints)

        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"

    def test_boundary_conditional_allow_is_needs_review(self) -> None:
        """Conditional boundary allows are not treated as unconditional proof."""
        src_id = "arn:aws:iam::111111\u003111111:role/Src"
        dst_id = "arn:aws:iam::222222\u003222222:role/Dst"
        node = _make_node(src_id, boundary_arn="arn:aws:iam::111111\u003111111:policy/Conditional")
        edge = _make_edge("sts:AssumeRole_permission", src_id, dst_id)
        constraints = build_permission_boundary_constraints(
            {
                "arn:aws:iam::111111\u003111111:policy/Conditional": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": dst_id,
                            "Condition": {"StringEquals": {"aws:PrincipalTag/team": "red"}},
                        }
                    ],
                },
            }
        )

        ecs = bind_permission_boundaries([edge], [node], constraints)

        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "needs_review"
        assert "conditional" in ecs[0].binding_reason

    def test_boundary_explicit_deny_blocks_even_with_allow(self) -> None:
        """Explicit Deny in the boundary wins over matching Allow."""
        src_id = "arn:aws:iam::111111\u003111111:role/Src"
        dst_id = "arn:aws:iam::222222\u003222222:role/Dst"
        node = _make_node(src_id, boundary_arn="arn:aws:iam::111111\u003111111:policy/DenyDst")
        edge = _make_edge("sts:AssumeRole_permission", src_id, dst_id)
        constraints = build_permission_boundary_constraints(
            {
                "arn:aws:iam::111111\u003111111:policy/DenyDst": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                        {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": dst_id},
                    ],
                },
            }
        )

        ecs = bind_permission_boundaries([edge], [node], constraints)

        assert len(ecs) == 1
        assert ecs[0].likely_blocking is True
        assert ecs[0].governance_confidence == "complete"
        assert "explicit boundary Deny" in ecs[0].binding_reason

    def test_trust_edge_also_action_intersected(self) -> None:
        """BND-1 fix applies symmetrically to _trust edges (dst-constrained).

        Not in the plan's 8-test list; added as a regression guard because the
        binding logic handles both edge layers and both should be exercised.
        """
        ecs = self._bind(
            boundary_arn="arn:aws:iam::222222\u003222222:policy/AssumeRoleOnly",
            allowed_actions=["sts:AssumeRole"],
            edge_type="sts:AssumeRole_trust",
        )
        assert len(ecs) == 1
        assert ecs[0].likely_blocking is False
        assert ecs[0].governance_confidence == "complete"
