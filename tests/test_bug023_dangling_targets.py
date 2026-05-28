"""BUG-023 regression tests: dangling-reference target materialization.

Caught by the second real-world OriginX run (v0.2.32 fixed BUG-022,
which unblocked the pipeline enough to reach this bug). The crash
observed:

    ERROR iamscope.cli: Pipeline failed: Edge secretsmanager:GetSecretValue_permission
    dst references non-existent node: provider=aws, node_type=SecretsManagerSecret,
    provider_id=arn:aws:secretsmanager:us-east-1:379322108695:secret:
      rds!cluster-f5bc238b-6204-4ea1-9160-0a18758cbe3c-bKPSTv

Root cause: RDS-managed SecretsManager secrets (prefix `rds!`) are
owned by the RDS service. They're referenced by IAM policies that
grant principals database credential access, but they are NOT
returned by `secretsmanager:ListSecrets` for most principals — only
the RDS service itself can enumerate them. The collector therefore
has zero `rds!` secrets in its fact graph, but the permission parser
still creates edges pointing at the literal ARN from the policy, and
the scenario.json referential-integrity validator rejects them.

The `_materialize_dangling_endpoints` helper scans edges after
resolution and synthesizes a placeholder node for every unresolvable
endpoint (src or dst) with `is_dangling_reference=True`. Downstream
reasoners can check this flag and demote verdicts to INCONCLUSIVE.
The Fix A symmetric-src extension is exercised in
`tests/test_validate_fix_a.py::TestDanglingSrcMaterialization`.

Same pattern triggers on: Lambda functions in unscanned regions,
deleted resources referenced by stale policies, cross-account
resources the collector has list perms on but doesn't walk.
"""

from __future__ import annotations

from iamscope.constants import (
    NODE_TYPE_IAM_USER,
    NODE_TYPE_SECRETS_MANAGER_SECRET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node, NodeRef
from iamscope.pipeline import (
    _extract_account_id_from_arn,
    _materialize_dangling_endpoints,
)

_ACCOUNT = "379322108695"
_USER_ARN = f"arn:aws:iam::{_ACCOUNT}:user/TestUser"
# The exact rds! secret ARN from the OriginX crash, minus the account-
# specific cluster GUID which we don't need for the test.
_RDS_SECRET_ARN = (
    f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!cluster-f5bc238b-6204-4ea1-9160-0a18758cbe3c-bKPSTv"
)


def _user_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=_USER_ARN,
        region=REGION_GLOBAL,
        properties={"account_id": _ACCOUNT, "is_synthetic": False},
    )


def _get_secret_edge(dst_arn: str) -> Edge:
    """Build a permission edge pointing at a (possibly dangling)
    secret ARN. Mirrors the shape the passrole.build_permission_edges
    helper emits for a `secretsmanager:GetSecretValue` grant with a
    literal resource ARN."""
    return Edge(
        edge_type="secretsmanager:GetSecretValue_permission",
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=_USER_ARN,
            region=REGION_GLOBAL,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
            provider_id=dst_arn,
            region=REGION_GLOBAL,
        ),
        region=REGION_GLOBAL,
        features={
            "effect": "Allow",
            "layer": "permission",
            "resource_pattern": dst_arn,
            "is_wildcard_resource": False,
            "has_conditions": False,
            "raw_conditions": {},
        },
    )


class TestBug023RdsSecretDanglingReference:
    """The exact OriginX crash shape — an rds! secret referenced by
    an IAM policy but not in the collected secret set."""

    def test_rds_secret_materializes_synthetic_node(self) -> None:
        user = _user_node()
        edge = _get_secret_edge(_RDS_SECRET_ARN)

        # Input: graph contains the user but NOT the rds! secret.
        synthetic = _materialize_dangling_endpoints(
            nodes=[user],
            edges=[edge],
        )

        assert len(synthetic) == 1
        s = synthetic[0]
        assert s.node_type == NODE_TYPE_SECRETS_MANAGER_SECRET
        assert s.provider_id == _RDS_SECRET_ARN
        assert s.properties["is_synthetic"] is True
        assert s.properties["is_dangling_reference"] is True
        assert s.properties["collection_status"] == "not_collected"
        assert s.properties["account_id"] == _ACCOUNT
        assert "dangling_reason" in s.properties

    def test_materialized_set_satisfies_validator_invariant(self) -> None:
        """The scenario_json validator demands that every edge dst
        reference a node in the graph. After materialization, the
        combined (original + synthetic) node set must contain a
        node matching the edge's dst key."""
        user = _user_node()
        edge = _get_secret_edge(_RDS_SECRET_ARN)
        synthetic = _materialize_dangling_endpoints(
            nodes=[user],
            edges=[edge],
        )

        combined = [user] + synthetic
        node_keys = {(n.provider, n.node_type, n.provider_id) for n in combined}
        dst_key = (
            edge.dst.provider,
            edge.dst.node_type,
            edge.dst.provider_id,
        )
        assert dst_key in node_keys


class TestBug023Deduplication:
    """Multiple edges pointing at the same dangling ARN must
    produce exactly one synthetic node, not duplicates."""

    def test_two_edges_same_dangling_dst_one_node(self) -> None:
        user = _user_node()
        edge1 = _get_secret_edge(_RDS_SECRET_ARN)
        edge2 = _get_secret_edge(_RDS_SECRET_ARN)
        # edge2 has the same edge_id as edge1 by construction
        # (same src/dst/features), but that's fine — the helper
        # dedupes at the dst-key level regardless.

        synthetic = _materialize_dangling_endpoints(
            nodes=[user],
            edges=[edge1, edge2],
        )
        assert len(synthetic) == 1

    def test_two_edges_different_dangling_dsts_two_nodes(self) -> None:
        user = _user_node()
        arn1 = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!cluster-one"
        arn2 = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!cluster-two"
        synthetic = _materialize_dangling_endpoints(
            nodes=[user],
            edges=[_get_secret_edge(arn1), _get_secret_edge(arn2)],
        )
        assert len(synthetic) == 2
        ids = {n.provider_id for n in synthetic}
        assert ids == {arn1, arn2}


class TestBug023NoFalsePositives:
    """Edges whose dst DOES resolve must not produce synthetic
    nodes. This guards against the helper over-materializing."""

    def test_resolvable_edge_produces_no_synthetic(self) -> None:
        """Happy path: the secret is already in the node set, so
        the helper should emit zero synthetic nodes."""
        user = _user_node()
        real_secret = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
            provider_id=_RDS_SECRET_ARN,
            region=REGION_GLOBAL,
            properties={"account_id": _ACCOUNT, "is_synthetic": False},
        )
        edge = _get_secret_edge(_RDS_SECRET_ARN)
        synthetic = _materialize_dangling_endpoints(
            nodes=[user, real_secret],
            edges=[edge],
        )
        assert synthetic == []

    def test_no_edges_no_synthetic(self) -> None:
        user = _user_node()
        synthetic = _materialize_dangling_endpoints(nodes=[user], edges=[])
        assert synthetic == []


class TestBug023Determinism:
    """The materialized list must be sorted by node_id so the
    scenario canonical hash is stable across runs."""

    def test_output_sorted_by_node_id(self) -> None:
        user = _user_node()
        # Build 5 dangling ARNs in intentionally non-sorted order.
        arns = [
            f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!z-cluster",
            f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!a-cluster",
            f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!m-cluster",
            f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!c-cluster",
            f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!t-cluster",
        ]
        edges = [_get_secret_edge(a) for a in arns]
        synthetic1 = _materialize_dangling_endpoints(
            nodes=[user],
            edges=edges,
        )
        synthetic2 = _materialize_dangling_endpoints(
            nodes=[user],
            edges=list(reversed(edges)),
        )

        # Both runs should produce the same ordering — sorted by
        # node_id. Iteration order of the input edges must not
        # affect the output.
        ids1 = [n.node_id for n in synthetic1]
        ids2 = [n.node_id for n in synthetic2]
        assert ids1 == ids2
        assert ids1 == sorted(ids1)


class TestBug023AccountIdExtractor:
    """The helper's ARN account-id extraction is load-bearing —
    synthetic nodes with a wrong account_id would route into the
    wrong scope filters downstream."""

    def test_standard_secret_arn(self) -> None:
        arn = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:abc"
        assert _extract_account_id_from_arn(arn) == _ACCOUNT

    def test_standard_lambda_arn(self) -> None:
        arn = f"arn:aws:lambda:us-east-1:{_ACCOUNT}:function:my-func"
        assert _extract_account_id_from_arn(arn) == _ACCOUNT

    def test_standard_role_arn(self) -> None:
        arn = f"arn:aws:iam::{_ACCOUNT}:role/SpecificRole"
        assert _extract_account_id_from_arn(arn) == _ACCOUNT

    def test_s3_bucket_arn_no_account(self) -> None:
        """S3 bucket ARNs omit the account ID (global namespace).
        Helper should return empty string rather than crash."""
        arn = "arn:aws:s3:::my-bucket"
        assert _extract_account_id_from_arn(arn) == ""

    def test_non_arn_returns_empty(self) -> None:
        assert _extract_account_id_from_arn("not-an-arn") == ""
        assert _extract_account_id_from_arn("") == ""
        # Deleted-principal bare ID shouldn't accidentally parse
        assert _extract_account_id_from_arn("AROAYEKP5XW36XB3V7AON") == ""

    def test_non_12_digit_returns_empty(self) -> None:
        """Defensive: an ARN with a malformed account field shouldn't
        crash the helper or produce a bogus account_id."""
        arn = "arn:aws:lambda:us-east-1:notanaccount:function:x"
        assert _extract_account_id_from_arn(arn) == ""
