"""Session 2 Step 0 reproducer: edge_id collision on differing features.

Reviewer Top 10 #2 — canonical defect.

`Edge.edge_id` in `iamscope/models.py` is currently derived from
`(edge_type, src.provider_id, dst.provider_id, region)` only. It does
NOT include `features`, statement digest, conditions, or any other
provenance signal. The consequence is that two semantically DIFFERENT
edges between the same principals — for example, an MFA-conditioned
trust and an unconditioned trust, or a wildcard-resource permission
edge and a literal-ARN permission edge — collide on a single
`edge_id`.

Downstream this collision silently corrupts every evidence path that
keys on `edge_id`:

- `EdgeConstraint` bindings (SCP, permission boundary, condition
  scoping) attach to ONE of the two colliding edges, depending on
  dict iteration order of the pre-dedup `edges` list.
- Reasoner findings that cite `edge_id` in their evidence chain
  can't tell the two edges apart, so an MFA-protected trust is
  indistinguishable from a naked trust in the emitted report.
- The scenario-wide dedup pass (`pipeline.py` around lines 644-650
  in v0.2.36: `seen_edge_ids: set[str]`) DROPS one of the two
  edges outright, because they have the same `edge_id`. The
  surviving edge is whichever appears first in iteration order —
  non-deterministic silent data loss.

This test pins the broken behavior as a reproducer. Step 0 scope:
only this one assertion, only on `edge_id` inequality. The fix is
Session 2's actual work and lives in `iamscope/identity/
deterministic_ids.py` and `iamscope/models.py` — this file will
grow assertions for the fix once the core behavior change lands.

Expected state in v0.2.36 (BEFORE the fix): this test FAILS with
an AssertionError showing that `edge_id_mfa == edge_id_no_mfa`.
That failure is the Step 0 reproducer the operator reviews before
Session 2 proceeds to the fix.
"""

from __future__ import annotations

from iamscope.models import Edge, NodeRef

_ACCOUNT = "111111111111"
_ROLE_A_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Trustor"
_ROLE_B_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Trustee"


def _make_trust_edge(*, has_mfa: bool) -> Edge:
    """Build a trust edge between role A (src) and role B (dst) with
    a features dict that differs ONLY in `has_mfa_condition`. All
    other inputs to the broken edge_id computation (edge_type, src
    provider_id, dst provider_id, region) are held identical so the
    collision is attributable to missing features-in-edge_id, not
    to some other input difference."""
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id=_ROLE_A_ARN,
            region="-",
        ),
        dst=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id=_ROLE_B_ARN,
            region="-",
        ),
        region="-",
        features={"has_mfa_condition": has_mfa},
    )


class TestEdgeIdFeatureCollision:
    """Reproducer for reviewer Top 10 #2.

    Two edges between the same (src, dst, edge_type, region) with
    semantically different `features` must NOT share the same
    `edge_id`. Pre-fix they do — this test fails on v0.2.36 and
    passes once Session 2's edge-identity redesign lands."""

    def test_mfa_and_unconditioned_trust_edges_have_distinct_ids(
        self,
    ) -> None:
        edge_mfa = _make_trust_edge(has_mfa=True)
        edge_no_mfa = _make_trust_edge(has_mfa=False)

        id_mfa = edge_mfa.edge_id
        id_no_mfa = edge_no_mfa.edge_id

        assert id_mfa != id_no_mfa, (
            f"edge_id collision: MFA-conditioned and unconditioned "
            f"trust edges between the same principals share the "
            f"same edge_id. This is reviewer Top 10 #2.\n"
            f"  edge_mfa.edge_id    = {id_mfa}\n"
            f"  edge_no_mfa.edge_id = {id_no_mfa}\n"
            f"  (src, dst, edge_type, region) held identical:\n"
            f"    src  = {edge_mfa.src.provider_id}\n"
            f"    dst  = {edge_mfa.dst.provider_id}\n"
            f"    type = {edge_mfa.edge_type}\n"
            f"    region = {edge_mfa.region!r}\n"
            f"  features differ on has_mfa_condition only:\n"
            f"    edge_mfa.features    = {edge_mfa.features}\n"
            f"    edge_no_mfa.features = {edge_no_mfa.features}"
        )


def _make_edge(*, features: dict) -> Edge:
    """Build a trust edge with caller-specified features. All other
    inputs (edge_type, src, dst, region) are held constant so the
    test isolates the features→edge_id relationship."""
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id=_ROLE_A_ARN,
            region="-",
        ),
        dst=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id=_ROLE_B_ARN,
            region="-",
        ),
        region="-",
        features=features,
    )


class TestEdgeIdDeterminism:
    """Post-fix determinism checks for features-in-edge_id.

    The Step 0 reproducer (TestEdgeIdFeatureCollision) verifies that
    DIFFERENT features produce different edge_ids. These tests verify
    the converse: IDENTICAL features — including when the dict key
    order or nested key order varies at the Python level — must
    produce the SAME edge_id. Together they pin the full contract:
    canonical_json_bytes sort_keys makes edge_id depend on features
    content, not on Python dict insertion order."""

    def test_same_features_produce_same_edge_id(self) -> None:
        """Two edges with byte-identical features must hash to the
        same edge_id. Pins determinism on identical inputs — if this
        fails, the memoization or the hash is non-deterministic."""
        e1 = _make_edge(features={"a": 1, "b": 2})
        e2 = _make_edge(features={"a": 1, "b": 2})
        assert e1.edge_id == e2.edge_id, (
            f"identical features produced different edge_ids:\n"
            f"  e1.edge_id = {e1.edge_id}\n"
            f"  e2.edge_id = {e2.edge_id}\n"
            f"  features   = {e1.features}"
        )

    def test_feature_key_order_independent(self) -> None:
        """Two edges where the features dict has the same keys and
        values but different Python insertion order must hash to the
        same edge_id. Pins that canonical_json_bytes(sort_keys=True)
        neutralizes insertion-order differences."""
        e1 = _make_edge(features={"a": 1, "b": 2})
        e2 = _make_edge(features={"b": 2, "a": 1})
        assert e1.edge_id == e2.edge_id, (
            f"feature key order produced different edge_ids:\n"
            f"  e1.edge_id   = {e1.edge_id}\n"
            f"  e2.edge_id   = {e2.edge_id}\n"
            f"  e1.features  = {e1.features}\n"
            f"  e2.features  = {e2.features}"
        )

    def test_nested_feature_order_independent(self) -> None:
        """Two edges with nested dicts inside features where the inner
        dict key order differs must hash to the same edge_id. Pins
        that sort_keys=True in json.dumps recurses into nested dicts
        — which is the standard behavior, but worth verifying since
        one level of nesting is the deepest observed in real feature
        data (allow_controls contains dicts from ControlRef.to_dict)."""
        e1 = _make_edge(
            features={"allow_controls": [{"type": "scp", "id": "x"}]},
        )
        e2 = _make_edge(
            features={"allow_controls": [{"id": "x", "type": "scp"}]},
        )
        assert e1.edge_id == e2.edge_id, (
            f"nested feature key order produced different edge_ids:\n"
            f"  e1.edge_id   = {e1.edge_id}\n"
            f"  e2.edge_id   = {e2.edge_id}\n"
            f"  e1.features  = {e1.features}\n"
            f"  e2.features  = {e2.features}"
        )
