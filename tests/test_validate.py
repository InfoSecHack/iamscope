"""Tests for scenario validator — structural integrity checks.

Tests cover:
- Valid scenario passes
- Missing top-level keys detected
- Duplicate node_ids detected
- Duplicate edge_ids detected
- Duplicate constraint_ids detected
- Edge constraint dangling edge_id reference
- Edge constraint dangling constraint_id reference
- Missing canonical_hash
- Invalid canonical_hash format
- Empty node_id/edge_id detected
- Sort order violation detected
- Non-list arrays rejected
- Edge missing src/dst provider_id
"""

import json

from iamscope.models import Edge, Node, NodeRef, ScenarioMetadata
from iamscope.output.scenario_json import emit_scenario
from iamscope.validate import validate_scenario


def _emit_valid_scenario() -> dict:
    """Build a genuinely valid scenario via `emit_scenario()` so it
    round-trips cleanly through Fix A's canonical-hash recomputation
    and rule 8b referential-integrity checks. Fix A, v0.2.36 — the
    pre-Fix-A hand-crafted dict with a fabricated hash and dangling
    src/dst endpoints only passed validation because those checks
    didn't exist yet. See test_validate_fix_a.py for the patterned
    `_build_clean_scenario()` this mirrors."""
    role_a = Node(
        provider="aws",
        node_type="IAMRole",
        provider_id="arn:aws:iam::123:role/A",
        region="-",
    )
    role_b = Node(
        provider="aws",
        node_type="IAMRole",
        provider_id="arn:aws:iam::123:role/B",
        region="-",
    )
    trust_edge = Edge(
        edge_type="sts:AssumeRole_trust",
        src=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id="arn:aws:iam::123:role/A",
            region="-",
        ),
        dst=NodeRef(
            provider="aws",
            node_type="IAMRole",
            provider_id="arn:aws:iam::123:role/B",
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
    return json.loads(scenario_bytes.decode("utf-8"))


def _valid_scenario():
    """Hand-crafted minimal scenario used by intentional-mutation tests.

    This scenario does NOT carry a real canonical hash and references
    src/dst node_ids that don't exist, so Fix A's rule 8 (hash) and
    rule 8b (referential integrity) will fire against it. That is
    intentionally OK for the mutation tests below — each of them
    asserts that a SPECIFIC error fires (via `any("X" in e ...)`),
    not that the scenario is fully valid. Tests that need a genuinely
    valid scenario MUST use `_emit_valid_scenario()` instead so they
    exercise the real emit → validate round-trip."""
    return {
        "nodes": [
            {"node_id": "aaa", "node_type": "IAMRole", "properties": {}, "provider_id": "arn:aws:iam::123:role/A"},
        ],
        "edges": [
            {
                "edge_id": "eee",
                "edge_type": "trust",
                "src": {"provider_id": "arn:src"},
                "dst": {"provider_id": "arn:dst"},
                "features": {},
            },
        ],
        "constraints": [
            {"constraint_id": "ccc", "constraint_type": "scp"},
        ],
        "edge_constraints": [
            {"edge_id": "eee", "constraint_id": "ccc"},
        ],
        "metadata": {"canonical_hash": "a" * 64},
    }


class TestValidScenario:
    """Valid scenario passes all checks."""

    def test_valid_passes(self) -> None:
        """Post-Fix-A: the scenario must round-trip through emit and
        validate with ZERO errors. Pre-Fix-A this test hand-crafted a
        dict with a fabricated hash, which was exactly the tamper
        pattern Fix A now correctly rejects — rewriting it to use
        `emit_scenario()` tests the ACTUAL valid-scenario codepath."""
        errors = validate_scenario(_emit_valid_scenario())
        assert errors == [], f"valid scenario had errors: {errors}"


class TestMissingKeys:
    """Missing top-level keys detected."""

    def test_missing_nodes(self) -> None:
        s = _valid_scenario()
        del s["nodes"]
        errors = validate_scenario(s)
        assert any("Missing top-level" in e for e in errors)

    def test_missing_metadata(self) -> None:
        s = _valid_scenario()
        del s["metadata"]
        errors = validate_scenario(s)
        assert any("Missing top-level" in e for e in errors)


class TestDuplicateIds:
    """Duplicate IDs detected."""

    def test_duplicate_node_id(self) -> None:
        s = _valid_scenario()
        s["nodes"].append(s["nodes"][0].copy())
        errors = validate_scenario(s)
        assert any("Duplicate node_id" in e for e in errors)

    def test_duplicate_edge_id(self) -> None:
        s = _valid_scenario()
        s["edges"].append(s["edges"][0].copy())
        errors = validate_scenario(s)
        assert any("Duplicate edge_id" in e for e in errors)

    def test_duplicate_constraint_id(self) -> None:
        s = _valid_scenario()
        s["constraints"].append(s["constraints"][0].copy())
        errors = validate_scenario(s)
        assert any("Duplicate constraint_id" in e for e in errors)


class TestDanglingReferences:
    """Edge constraint dangling references."""

    def test_dangling_edge_ref(self) -> None:
        s = _valid_scenario()
        s["edge_constraints"] = [{"edge_id": "nonexistent", "constraint_id": "ccc"}]
        errors = validate_scenario(s)
        assert any("non-existent edge" in e for e in errors)

    def test_dangling_constraint_ref(self) -> None:
        s = _valid_scenario()
        s["edge_constraints"] = [{"edge_id": "eee", "constraint_id": "nonexistent"}]
        errors = validate_scenario(s)
        assert any("non-existent constraint" in e for e in errors)


class TestCanonicalHash:
    """Canonical hash validation."""

    def test_missing_hash(self) -> None:
        s = _valid_scenario()
        s["metadata"] = {}
        errors = validate_scenario(s)
        assert any("canonical_hash" in e for e in errors)

    def test_invalid_hash_format(self) -> None:
        s = _valid_scenario()
        s["metadata"]["canonical_hash"] = "not-a-hash"
        errors = validate_scenario(s)
        assert any("SHA-256" in e for e in errors)

    def test_valid_hash(self) -> None:
        """Post-Fix-A: a scenario emitted by `emit_scenario()` must
        carry a canonical hash that validates cleanly. Pre-Fix-A this
        test hand-crafted `"ab" * 32` as the hash, which was never
        the real content hash — it only passed because the validator
        was checking hex shape, not actual hash equivalence. The
        rewrite uses the emit path so the hash is real."""
        errors = validate_scenario(_emit_valid_scenario())
        hash_errors = [e for e in errors if "hash" in e.lower()]
        assert hash_errors == []


class TestEmptyIds:
    """Empty IDs detected."""

    def test_empty_node_id(self) -> None:
        s = _valid_scenario()
        s["nodes"] = [{"node_id": "", "node_type": "IAMRole"}]
        errors = validate_scenario(s)
        assert any("empty node_id" in e for e in errors)

    def test_empty_edge_id(self) -> None:
        s = _valid_scenario()
        s["edges"] = [{"edge_id": "", "edge_type": "trust", "src": {"provider_id": "a"}, "dst": {"provider_id": "b"}}]
        errors = validate_scenario(s)
        assert any("empty edge_id" in e for e in errors)


class TestSortOrder:
    """Sort order (determinism) checks."""

    def test_unsorted_nodes(self) -> None:
        s = _valid_scenario()
        s["nodes"] = [
            {"node_id": "zzz", "node_type": "IAMRole"},
            {"node_id": "aaa", "node_type": "IAMUser"},
        ]
        errors = validate_scenario(s)
        assert any("not sorted" in e for e in errors)

    def test_sorted_nodes_pass(self) -> None:
        s = _valid_scenario()
        s["nodes"] = [
            {"node_id": "aaa", "node_type": "IAMRole"},
            {"node_id": "zzz", "node_type": "IAMUser"},
        ]
        errors = validate_scenario(s)
        sort_errors = [e for e in errors if "sorted" in e]
        assert sort_errors == []


class TestTypeChecks:
    """Non-list arrays rejected."""

    def test_nodes_not_list(self) -> None:
        s = _valid_scenario()
        s["nodes"] = "not a list"
        errors = validate_scenario(s)
        assert any("must be a list" in e for e in errors)


class TestEdgeSrcDst:
    """Edge src/dst validation."""

    def test_missing_src_provider_id(self) -> None:
        s = _valid_scenario()
        s["edges"] = [{"edge_id": "e1", "edge_type": "trust", "src": {}, "dst": {"provider_id": "b"}}]
        errors = validate_scenario(s)
        assert any("src has no provider_id" in e for e in errors)

    def test_missing_dst_provider_id(self) -> None:
        s = _valid_scenario()
        s["edges"] = [{"edge_id": "e1", "edge_type": "trust", "src": {"provider_id": "a"}, "dst": {}}]
        errors = validate_scenario(s)
        assert any("dst has no provider_id" in e for e in errors)
