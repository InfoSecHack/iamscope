"""Tests for scenario diff engine.

Tests cover:
- Identical scenarios produce no changes
- Node added/removed/modified detection
- Edge added/removed/modified detection
- Constraint added/removed detection
- Edge constraint added/removed detection
- Hash comparison (match/mismatch)
- has_changes property
- summary counts
- to_dict serialization
- format_diff_report Markdown output
- diff_scenarios_from_files file round-trip
- Empty scenarios handled gracefully
"""

import json

from iamscope.diff import (
    DiffResult,
    diff_scenarios,
    diff_scenarios_from_files,
    format_diff_report,
)


def _scenario(
    nodes=None,
    edges=None,
    constraints=None,
    edge_constraints=None,
    canonical_hash="",
):
    """Build a minimal scenario dict."""
    return {
        "nodes": nodes or [],
        "edges": edges or [],
        "constraints": constraints or [],
        "edge_constraints": edge_constraints or [],
        "metadata": {"canonical_hash": canonical_hash},
    }


def _node(node_id, node_type="IAMRole", **props):
    return {"node_id": node_id, "node_type": node_type, "properties": props}


def _edge(edge_id, edge_type="trust", src_id="s", dst_id="d", **features):
    return {
        "edge_id": edge_id,
        "edge_type": edge_type,
        "src": {"provider_id": src_id},
        "dst": {"provider_id": dst_id},
        "features": features,
    }


def _constraint(cid):
    return {"constraint_id": cid, "constraint_type": "scp"}


def _ec(edge_id, constraint_id):
    return {"edge_id": edge_id, "constraint_id": constraint_id}


class TestIdenticalScenarios:
    """Identical scenarios produce no diff."""

    def test_empty_scenarios(self) -> None:
        result = diff_scenarios(_scenario(), _scenario())
        assert not result.has_changes

    def test_matching_hashes(self) -> None:
        h = "a" * 64
        result = diff_scenarios(
            _scenario(canonical_hash=h),
            _scenario(canonical_hash=h),
        )
        assert result.hashes_match

    def test_identical_nodes(self) -> None:
        nodes = [_node("n1"), _node("n2")]
        result = diff_scenarios(
            _scenario(nodes=nodes),
            _scenario(nodes=nodes),
        )
        assert not result.nodes_added
        assert not result.nodes_removed
        assert not result.nodes_modified


class TestNodeDiff:
    """Node add/remove/modify detection."""

    def test_node_added(self) -> None:
        before = _scenario(nodes=[_node("n1")])
        after = _scenario(nodes=[_node("n1"), _node("n2")])
        result = diff_scenarios(before, after)
        assert len(result.nodes_added) == 1
        assert result.nodes_added[0]["node_id"] == "n2"

    def test_node_removed(self) -> None:
        before = _scenario(nodes=[_node("n1"), _node("n2")])
        after = _scenario(nodes=[_node("n1")])
        result = diff_scenarios(before, after)
        assert len(result.nodes_removed) == 1
        assert result.nodes_removed[0]["node_id"] == "n2"

    def test_node_modified(self) -> None:
        before = _scenario(nodes=[_node("n1", foo="old")])
        after = _scenario(nodes=[_node("n1", foo="new")])
        result = diff_scenarios(before, after)
        assert len(result.nodes_modified) == 1
        assert result.nodes_modified[0]["id"] == "n1"
        assert result.nodes_modified[0]["changes"][0]["field"] == "properties"

    def test_node_unchanged(self) -> None:
        before = _scenario(nodes=[_node("n1", x=1)])
        after = _scenario(nodes=[_node("n1", x=1)])
        result = diff_scenarios(before, after)
        assert not result.nodes_modified


class TestEdgeDiff:
    """Edge add/remove/modify detection."""

    def test_edge_added(self) -> None:
        before = _scenario(edges=[])
        after = _scenario(edges=[_edge("e1")])
        result = diff_scenarios(before, after)
        assert len(result.edges_added) == 1

    def test_edge_removed(self) -> None:
        before = _scenario(edges=[_edge("e1")])
        after = _scenario(edges=[])
        result = diff_scenarios(before, after)
        assert len(result.edges_removed) == 1

    def test_edge_modified(self) -> None:
        before = _scenario(edges=[_edge("e1", severity="low")])
        after = _scenario(edges=[_edge("e1", severity="high")])
        result = diff_scenarios(before, after)
        assert len(result.edges_modified) == 1


class TestConstraintDiff:
    """Constraint add/remove detection."""

    def test_constraint_added(self) -> None:
        before = _scenario(constraints=[])
        after = _scenario(constraints=[_constraint("c1")])
        result = diff_scenarios(before, after)
        assert len(result.constraints_added) == 1

    def test_constraint_removed(self) -> None:
        before = _scenario(constraints=[_constraint("c1")])
        after = _scenario(constraints=[])
        result = diff_scenarios(before, after)
        assert len(result.constraints_removed) == 1


class TestEdgeConstraintDiff:
    """Edge constraint add/remove detection."""

    def test_edge_constraint_added(self) -> None:
        before = _scenario(edge_constraints=[])
        after = _scenario(edge_constraints=[_ec("e1", "c1")])
        result = diff_scenarios(before, after)
        assert len(result.edge_constraints_added) == 1

    def test_edge_constraint_removed(self) -> None:
        before = _scenario(edge_constraints=[_ec("e1", "c1")])
        after = _scenario(edge_constraints=[])
        result = diff_scenarios(before, after)
        assert len(result.edge_constraints_removed) == 1


class TestDiffResultProperties:
    """Tests for DiffResult properties and serialization."""

    def test_has_changes_true(self) -> None:
        result = DiffResult(nodes_added=[{"node_id": "n1"}])
        assert result.has_changes

    def test_has_changes_false(self) -> None:
        result = DiffResult()
        assert not result.has_changes

    def test_summary_counts(self) -> None:
        result = DiffResult(
            nodes_added=[{}, {}],
            edges_removed=[{}],
            nodes_modified=[{}],
        )
        s = result.summary
        assert s["nodes_added"] == 2
        assert s["edges_removed"] == 1
        assert s["nodes_modified"] == 1

    def test_to_dict(self) -> None:
        result = DiffResult(hash_before="abc", hash_after="def")
        d = result.to_dict()
        assert d["hash_before"] == "abc"
        assert "has_changes" in d
        assert "summary" in d


class TestFormatDiffReport:
    """Tests for Markdown diff report."""

    def test_no_changes(self) -> None:
        result = DiffResult(
            hash_before="a" * 64,
            hash_after="a" * 64,
            hashes_match=True,
        )
        report = format_diff_report(result)
        assert "No changes detected" in report

    def test_with_changes(self) -> None:
        result = DiffResult(
            hash_before="a" * 64,
            hash_after="b" * 64,
            nodes_added=[{"node_id": "n1", "node_type": "IAMRole", "provider_id": "arn:test"}],
            edges_removed=[
                {"edge_id": "e1", "edge_type": "trust", "src": {"provider_id": "a"}, "dst": {"provider_id": "b"}}
            ],
        )
        report = format_diff_report(result)
        assert "Nodes Added" in report
        assert "Edges Removed" in report
        assert "Summary" in report

    def test_no_structural_changes(self) -> None:
        result = DiffResult(
            hash_before="a" * 64,
            hash_after="b" * 64,
        )
        report = format_diff_report(result)
        assert "No structural changes" in report


class TestDiffFromFiles:
    """Tests for file-based diff."""

    def test_round_trip(self, tmp_path) -> None:
        before = _scenario(nodes=[_node("n1")], canonical_hash="a" * 64)
        after = _scenario(nodes=[_node("n1"), _node("n2")], canonical_hash="b" * 64)

        before_path = str(tmp_path / "before.json")
        after_path = str(tmp_path / "after.json")

        with open(before_path, "w") as f:
            json.dump(before, f)
        with open(after_path, "w") as f:
            json.dump(after, f)

        result = diff_scenarios_from_files(before_path, after_path)
        assert len(result.nodes_added) == 1
        assert not result.hashes_match
