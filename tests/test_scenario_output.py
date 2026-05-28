"""Tests for scenario.json output — determinism, structure, referential integrity.

Tests verify:
- Minimal scenario produces valid JSON structure
- All keys are sorted lexicographically
- All arrays are sorted by canonical sort keys
- Two emissions with same input produce identical bytes and hash
- No trailing newline
- Metadata excluded from canonical hash
- Referential integrity enforced (edges reference existing nodes)
"""

import json

import pytest

from iamscope.constants import (
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    Constraint,
    Edge,
    EdgeConstraint,
    Node,
    ScenarioMetadata,
)
from iamscope.output.scenario_json import (
    assert_scenario_canonical_hash_stable,
    emit_scenario,
    recompute_scenario_canonical_hash,
)


class TestMinimalScenario:
    """Tests for minimal scenario output (2 nodes, 1 edge, 0 constraints)."""

    def test_minimal_structure(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Minimal scenario must have all top-level keys."""
        scenario_bytes, canonical_hash = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)

        assert "metadata" in scenario
        assert "nodes" in scenario
        assert "edges" in scenario
        assert "constraints" in scenario
        assert "edge_constraints" in scenario
        assert "objectives" in scenario
        assert "observations" in scenario

        assert len(scenario["nodes"]) == 2
        assert len(scenario["edges"]) == 1
        assert len(scenario["constraints"]) == 0
        assert len(scenario["edge_constraints"]) == 0
        assert scenario["objectives"] == []
        assert scenario["observations"] == []

    def test_nodes_have_node_id(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Every node must have a node_id field (per R07)."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)

        for node in scenario["nodes"]:
            assert "node_id" in node
            assert len(node["node_id"]) == 64  # SHA-256 hex

    def test_edges_have_edge_id(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Every edge must have an edge_id field (per R07)."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)

        for edge in scenario["edges"]:
            assert "edge_id" in edge
            assert len(edge["edge_id"]) == 64


class TestDeterminism:
    """Tests for byte-level output determinism."""

    def test_byte_stable_across_runs(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Two emissions with same input must produce identical bytes and hash."""
        bytes1, hash1 = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        bytes2, hash2 = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        assert bytes1 == bytes2
        assert hash1 == hash2

    def test_input_order_does_not_affect_output(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Node order in input must not affect output (sorted by node_id)."""
        bytes_ab, hash_ab = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        bytes_ba, hash_ba = emit_scenario(
            nodes=[minimal_account_root_node, minimal_role_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        assert bytes_ab == bytes_ba
        assert hash_ab == hash_ba

    def test_metadata_excluded_from_hash(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
    ) -> None:
        """Different metadata must produce same canonical hash."""
        meta1 = ScenarioMetadata(
            collection_timestamp="2026-01-01T00:00:00Z",
            collection_duration_seconds=5.0,
        )
        meta2 = ScenarioMetadata(
            collection_timestamp="2026-06-15T12:34:56Z",
            collection_duration_seconds=99.0,
        )

        _, hash1 = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=meta1,
        )
        _, hash2 = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=meta2,
        )
        assert hash1 == hash2

    def test_frozen_scenario_hash_stable_across_array_and_metadata_order(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
    ) -> None:
        """Frozen replay recomputes the same graph hash despite volatile metadata."""
        scenario_bytes, canonical_hash = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=ScenarioMetadata(collection_timestamp="2026-01-01T00:00:00Z"),
        )
        scenario = json.loads(scenario_bytes)
        replay_shape = dict(scenario)
        replay_shape["metadata"] = dict(scenario["metadata"])
        replay_shape["metadata"]["collection_timestamp"] = "2026-04-19T12:34:56Z"
        replay_shape["metadata"]["collection_duration_seconds"] = 123.456
        replay_shape["nodes"] = list(reversed(scenario["nodes"]))
        replay_shape["edges"] = list(reversed(scenario["edges"]))

        assert recompute_scenario_canonical_hash(replay_shape) == canonical_hash
        replay_shape["metadata"]["canonical_hash"] = canonical_hash
        assert assert_scenario_canonical_hash_stable(replay_shape) == canonical_hash

    def test_metadata_change_changes_bytes(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
    ) -> None:
        """Different metadata DOES change the raw bytes (but not the hash)."""
        meta1 = ScenarioMetadata(collection_timestamp="2026-01-01T00:00:00Z")
        meta2 = ScenarioMetadata(collection_timestamp="2026-12-31T23:59:59Z")

        bytes1, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=meta1,
        )
        bytes2, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=meta2,
        )
        assert bytes1 != bytes2


class TestCanonicalJson:
    """Tests for canonical JSON formatting."""

    def test_no_trailing_newline(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Output must NOT end with a trailing newline (pinned)."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        assert not scenario_bytes.endswith(b"\n")

    def test_sorted_top_level_keys(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Top-level JSON keys must be sorted lexicographically."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        # Parse and check key order by re-serializing with sorted keys
        scenario = json.loads(scenario_bytes)
        keys = list(scenario.keys())
        assert keys == sorted(keys)

    def test_compact_separators(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Output must use compact separators (',', ':') — no spaces."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        text = scenario_bytes.decode("utf-8")
        # Should not contain ": " (space after colon) at dict level
        # But might contain ": " inside string values, so check structure
        scenario_reserialized = json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        assert text == scenario_reserialized

    def test_nodes_sorted_by_node_id(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Nodes array must be sorted by node_id."""
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)
        node_ids = [n["node_id"] for n in scenario["nodes"]]
        assert node_ids == sorted(node_ids)

    def test_edges_sorted_by_edge_id(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Edges array must be sorted by edge_id when multiple edges exist."""
        edge_trust = Edge(
            edge_type="sts:AssumeRole_trust",
            src=minimal_account_root_node.to_ref(),
            dst=minimal_role_node.to_ref(),
            region=REGION_GLOBAL,
            features={"layer": "trust"},
        )
        edge_perm = Edge(
            edge_type="sts:AssumeRole_permission",
            src=minimal_account_root_node.to_ref(),
            dst=minimal_role_node.to_ref(),
            region=REGION_GLOBAL,
            features={"layer": "permission"},
        )

        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[edge_perm, edge_trust],  # Deliberately reverse order
            constraints=[],
            edge_constraints=[],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)
        edge_ids = [e["edge_id"] for e in scenario["edges"]]
        assert edge_ids == sorted(edge_ids)


class TestReferentialIntegrity:
    """Tests for referential integrity validation."""

    def test_edge_references_missing_src_node(
        self,
        minimal_role_node: Node,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Edge referencing non-existent src node must raise ValueError."""
        orphan_ref = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_ACCOUNT_ROOT,
            provider_id="arn:aws:iam::999999999999:root",
        )
        edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=orphan_ref.to_ref(),
            dst=minimal_role_node.to_ref(),
        )

        with pytest.raises(ValueError, match="non-existent node"):
            emit_scenario(
                nodes=[minimal_role_node],  # Missing the src node
                edges=[edge],
                constraints=[],
                edge_constraints=[],
                metadata=minimal_metadata,
            )

    def test_edge_references_missing_dst_node(
        self,
        minimal_account_root_node: Node,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Edge referencing non-existent dst node must raise ValueError."""
        orphan_role = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id="arn:aws:iam::999:role/Ghost",
        )
        edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=minimal_account_root_node.to_ref(),
            dst=orphan_role.to_ref(),
        )

        with pytest.raises(ValueError, match="non-existent node"):
            emit_scenario(
                nodes=[minimal_account_root_node],  # Missing dst node
                edges=[edge],
                constraints=[],
                edge_constraints=[],
                metadata=minimal_metadata,
            )

    def test_edge_constraint_references_missing_edge(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_constraint: Constraint,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """EdgeConstraint referencing non-existent edge must raise ValueError."""
        ec = EdgeConstraint(
            edge_id="0000000000000000000000000000000000000000000000000000000000000000",
            constraint_id=minimal_constraint.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
        )

        with pytest.raises(ValueError, match="non-existent edge_id"):
            emit_scenario(
                nodes=[minimal_role_node, minimal_account_root_node],
                edges=[],
                constraints=[minimal_constraint],
                edge_constraints=[ec],
                metadata=minimal_metadata,
            )

    def test_edge_constraint_references_missing_constraint(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """EdgeConstraint referencing non-existent constraint must raise ValueError."""
        ec = EdgeConstraint(
            edge_id=minimal_trust_edge.edge_id,
            constraint_id="0000000000000000000000000000000000000000000000000000000000000000",
            governance_confidence="complete",
            likely_blocking=True,
        )

        with pytest.raises(ValueError, match="non-existent constraint_id"):
            emit_scenario(
                nodes=[minimal_role_node, minimal_account_root_node],
                edges=[minimal_trust_edge],
                constraints=[],
                edge_constraints=[ec],
                metadata=minimal_metadata,
            )


class TestFullScenario:
    """Tests for full scenario with all components."""

    def test_full_scenario_with_constraints(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_constraint: Constraint,
        minimal_edge_constraint: EdgeConstraint,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Full scenario with nodes, edges, constraints, edge_constraints."""
        scenario_bytes, canonical_hash = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[minimal_constraint],
            edge_constraints=[minimal_edge_constraint],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)

        assert len(scenario["nodes"]) == 2
        assert len(scenario["edges"]) == 1
        assert len(scenario["constraints"]) == 1
        assert len(scenario["edge_constraints"]) == 1

        # Constraint has constraint_id
        assert "constraint_id" in scenario["constraints"][0]
        assert len(scenario["constraints"][0]["constraint_id"]) == 64

        # Edge constraint references edge and constraint by ID only
        # (ARF-RT uses extra="forbid" — no binding_metadata in scenario.json)
        ec = scenario["edge_constraints"][0]
        assert "edge_id" in ec
        assert "constraint_id" in ec
        assert "binding_metadata" not in ec  # ARF-RT compatibility

        # Canonical hash in metadata
        assert scenario["metadata"]["canonical_hash"] == canonical_hash
        assert len(canonical_hash) == 64

    def test_constraints_sorted_by_constraint_id(self) -> None:
        """Constraints array must be sorted by constraint_id."""
        c1 = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-aaa",
            policy_id="p-111",
            statement_id="stmt_0",
        )
        c2 = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-bbb",
            policy_id="p-222",
            statement_id="stmt_0",
        )

        # Create minimal nodes/edges for valid scenario
        node_a = Node(provider=PROVIDER_AWS, node_type=NODE_TYPE_IAM_ROLE, provider_id="arn:aws:iam::111:role/A")
        node_b = Node(provider=PROVIDER_AWS, node_type=NODE_TYPE_ACCOUNT_ROOT, provider_id="arn:aws:iam::222:root")
        edge = Edge(edge_type="sts:AssumeRole_trust", src=node_b.to_ref(), dst=node_a.to_ref())

        scenario_bytes, _ = emit_scenario(
            nodes=[node_a, node_b],
            edges=[edge],
            constraints=[c2, c1],  # Deliberately reverse order
            edge_constraints=[],
            metadata=ScenarioMetadata(),
        )
        scenario = json.loads(scenario_bytes)
        cids = [c["constraint_id"] for c in scenario["constraints"]]
        assert cids == sorted(cids)

    def test_edge_constraints_sorted_by_composite_key(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """Edge constraints must be sorted by (edge_id, constraint_id) tuple."""
        c1 = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-aaa",
            policy_id="p-111",
            statement_id="s1",
        )
        c2 = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-bbb",
            policy_id="p-222",
            statement_id="s2",
        )

        ec1 = EdgeConstraint(
            edge_id=minimal_trust_edge.edge_id,
            constraint_id=c1.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
        )
        ec2 = EdgeConstraint(
            edge_id=minimal_trust_edge.edge_id,
            constraint_id=c2.constraint_id,
            governance_confidence="partial",
            likely_blocking=False,
        )

        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[c1, c2],
            edge_constraints=[ec2, ec1],  # Deliberately reverse order
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)
        ec_keys = [(ec["edge_id"], ec["constraint_id"]) for ec in scenario["edge_constraints"]]
        assert ec_keys == sorted(ec_keys)


class TestARFRTCompatibility:
    """Tests for ARF-RT extra='forbid' compatibility.

    ARF-RT's EdgeConstraintInput only accepts edge_ref, constraint_ref,
    and relation_type. Any extra fields (like binding_metadata) cause a
    hard Pydantic validation error. The binding metadata is instead
    emitted in a sidecar file via emit_binding_metadata().
    """

    def test_edge_constraint_to_dict_has_no_binding_metadata(self) -> None:
        """EdgeConstraint.to_dict() must NOT include binding_metadata."""
        ec = EdgeConstraint(
            edge_id="abc123",
            constraint_id="def456",
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="test reason",
        )
        d = ec.to_dict()
        assert "binding_metadata" not in d
        assert set(d.keys()) == {"edge_id", "constraint_id"}

    def test_edge_constraint_to_binding_dict_has_metadata(self) -> None:
        """EdgeConstraint.to_binding_dict() includes full governance data."""
        ec = EdgeConstraint(
            edge_id="abc123",
            constraint_id="def456",
            governance_confidence="partial",
            likely_blocking=False,
            binding_reason="parse_status is partial",
        )
        d = ec.to_binding_dict()
        assert "binding_metadata" in d
        bm = d["binding_metadata"]
        assert bm["governance_confidence"] == "partial"
        assert bm["likely_blocking"] is False
        assert bm["binding_reason"] == "parse_status is partial"

    def test_emit_binding_metadata_sidecar(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """emit_binding_metadata() produces sorted sidecar with governance data."""
        from iamscope.output.scenario_json import emit_binding_metadata

        c = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-aaa",
            policy_id="p-111",
            statement_id="s1",
        )
        ec1 = EdgeConstraint(
            edge_id=minimal_trust_edge.edge_id,
            constraint_id=c.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="action in deny_actions",
        )
        sidecar_bytes = emit_binding_metadata([ec1])
        sidecar = json.loads(sidecar_bytes)

        assert len(sidecar) == 1
        entry = sidecar[0]
        assert entry["edge_id"] == ec1.edge_id
        assert entry["constraint_id"] == ec1.constraint_id
        assert entry["binding_metadata"]["likely_blocking"] is True
        assert entry["binding_metadata"]["governance_confidence"] == "complete"

    def test_scenario_json_edge_constraints_are_clean(
        self,
        minimal_role_node: Node,
        minimal_account_root_node: Node,
        minimal_trust_edge: Edge,
        minimal_metadata: ScenarioMetadata,
    ) -> None:
        """scenario.json edge_constraints contain ONLY edge_id + constraint_id."""
        c = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-x",
            policy_id="p-x",
            statement_id="s0",
        )
        ec = EdgeConstraint(
            edge_id=minimal_trust_edge.edge_id,
            constraint_id=c.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
        )
        scenario_bytes, _ = emit_scenario(
            nodes=[minimal_role_node, minimal_account_root_node],
            edges=[minimal_trust_edge],
            constraints=[c],
            edge_constraints=[ec],
            metadata=minimal_metadata,
        )
        scenario = json.loads(scenario_bytes)
        for entry in scenario["edge_constraints"]:
            assert set(entry.keys()) == {"edge_id", "constraint_id"}
