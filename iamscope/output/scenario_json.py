"""Scenario JSON emitter — canonical, deterministic, byte-stable.

Emits scenario.json in the exact ARF-RT format with:
- Canonical JSON: sorted keys, compact separators, ensure_ascii
- All arrays sorted by their canonical sort key
- Deterministic hash computed over canonical form (excludes metadata)
- No trailing newline (pinned)

Output determinism contract:
    Same input models → same output bytes → same output hash.

Hash scope:
    The canonical hash covers: constraints, edge_constraints, edges,
    nodes, objectives, observations. The metadata block is EXCLUDED
    because it contains non-deterministic fields (timestamps, duration).
"""

from typing import Any

from iamscope.constants import JSON_TRAILING_NEWLINE
from iamscope.identity.canonical import canonical_json_bytes, compute_hash
from iamscope.models import (
    Constraint,
    Edge,
    EdgeConstraint,
    Node,
    ScenarioMetadata,
)


def emit_scenario(
    nodes: list[Node],
    edges: list[Edge],
    constraints: list[Constraint],
    edge_constraints: list[EdgeConstraint],
    metadata: ScenarioMetadata,
) -> tuple[bytes, str]:
    """Emit scenario.json as canonical bytes with deterministic hash.

    Sorting contract (pinned):
    - nodes[] → sorted by node_id (lexicographic)
    - edges[] → sorted by edge_id (lexicographic)
    - constraints[] → sorted by constraint_id (lexicographic)
    - edge_constraints[] → sorted by (edge_id, constraint_id) tuple
    - objectives[] → empty, sorted by objective_id
    - observations[] → empty, sorted by obs_id

    Hash scope:
    - Hash covers: constraints, edge_constraints, edges, nodes,
      objectives, observations (sorted top-level keys, metadata excluded).
    - Hash is stored in metadata.canonical_hash for self-verification.

    Args:
        nodes: List of Node objects.
        edges: List of Edge objects.
        constraints: List of Constraint objects.
        edge_constraints: List of EdgeConstraint objects.
        metadata: ScenarioMetadata object.

    Returns:
        Tuple of (scenario_json_bytes, canonical_hash_hex).

    Raises:
        ValueError: If an edge references a node_id not in nodes[].
    """
    # --- Validate referential integrity ---
    _validate_referential_integrity(nodes, edges, constraints, edge_constraints)

    # --- Sort all arrays by canonical sort keys ---
    sorted_nodes = sorted(nodes, key=lambda n: n.node_id)
    sorted_edges = sorted(edges, key=lambda e: e.edge_id)
    sorted_constraints = sorted(constraints, key=lambda c: c.constraint_id)
    sorted_edge_constraints = sorted(edge_constraints, key=lambda ec: ec.sort_key)

    # --- Serialize to dicts ---
    nodes_dicts = [n.to_dict() for n in sorted_nodes]
    edges_dicts = [e.to_dict() for e in sorted_edges]
    constraints_dicts = [c.to_dict() for c in sorted_constraints]
    edge_constraints_dicts = [ec.to_dict() for ec in sorted_edge_constraints]

    # --- Compute canonical hash (excludes metadata) ---
    hash_payload = {
        "constraints": constraints_dicts,
        "edge_constraints": edge_constraints_dicts,
        "edges": edges_dicts,
        "nodes": nodes_dicts,
        "objectives": [],
        "observations": [],
    }
    canonical_bytes = canonical_json_bytes(hash_payload)
    canonical_hash = compute_hash(canonical_bytes)

    # --- Build full scenario with metadata ---
    metadata_dict = metadata.to_dict()
    metadata_dict["canonical_hash"] = canonical_hash

    scenario = {
        "constraints": constraints_dicts,
        "edge_constraints": edge_constraints_dicts,
        "edges": edges_dicts,
        "metadata": metadata_dict,
        "nodes": nodes_dicts,
        "objectives": [],
        "observations": [],
    }

    # --- Emit final bytes ---
    scenario_bytes = canonical_json_bytes(scenario)

    if JSON_TRAILING_NEWLINE:
        scenario_bytes += b"\n"

    return scenario_bytes, canonical_hash


def recompute_scenario_canonical_hash(scenario: dict[str, Any]) -> str:
    """Recompute the scenario canonical hash from a frozen scenario dict.

    The hash scope is exactly the same as emit_scenario(): graph arrays only,
    with metadata excluded. This gives replay tooling and regression tests a
    stable way to verify that a frozen artifact's metadata.canonical_hash still
    matches its graph payload without recollecting AWS.
    """
    hash_payload = {
        "constraints": sorted(
            scenario.get("constraints", []),
            key=lambda c: str(c.get("constraint_id", "")),
        ),
        "edge_constraints": sorted(
            scenario.get("edge_constraints", []),
            key=lambda ec: (str(ec.get("edge_id", "")), str(ec.get("constraint_id", ""))),
        ),
        "edges": sorted(
            scenario.get("edges", []),
            key=lambda e: str(e.get("edge_id", "")),
        ),
        "nodes": sorted(
            scenario.get("nodes", []),
            key=lambda n: str(n.get("node_id", "")),
        ),
        "objectives": sorted(
            scenario.get("objectives", []),
            key=lambda o: str(o.get("objective_id", "")),
        ),
        "observations": sorted(
            scenario.get("observations", []),
            key=lambda o: str(o.get("obs_id", "")),
        ),
    }
    return compute_hash(canonical_json_bytes(hash_payload))


def assert_scenario_canonical_hash_stable(scenario: dict[str, Any]) -> str:
    """Return the recomputed hash or raise if metadata.canonical_hash mismatches."""
    expected = str(scenario.get("metadata", {}).get("canonical_hash", ""))
    actual = recompute_scenario_canonical_hash(scenario)
    if expected != actual:
        raise ValueError(
            "scenario metadata.canonical_hash does not match graph payload "
            f"(metadata={expected!r}, recomputed={actual!r})"
        )
    return actual


def _validate_referential_integrity(
    nodes: list[Node],
    edges: list[Edge],
    constraints: list[Constraint],
    edge_constraints: list[EdgeConstraint],
) -> None:
    """Validate that all edge references point to existing nodes.

    Checks:
    1. Every edge's src and dst node_id exists in the nodes[] set.
    2. Every edge_constraint's edge_id exists in edges[].
    3. Every edge_constraint's constraint_id exists in constraints[].

    Args:
        nodes: List of Node objects.
        edges: List of Edge objects.
        constraints: List of Constraint objects.
        edge_constraints: List of EdgeConstraint objects.

    Raises:
        ValueError: If any referential integrity violation is found.
    """
    # Build lookup sets
    node_id_set: set[str] = set()
    node_provider_id_set: set[tuple[str, str, str]] = set()
    for n in nodes:
        node_id_set.add(n.node_id)
        node_provider_id_set.add((n.provider, n.node_type, n.provider_id))

    # Check edge src/dst references
    for e in edges:
        src_key = (e.src.provider, e.src.node_type, e.src.provider_id)
        if src_key not in node_provider_id_set:
            raise ValueError(
                f"Edge {e.edge_type} src references non-existent node: "
                f"provider={e.src.provider}, node_type={e.src.node_type}, "
                f"provider_id={e.src.provider_id}"
            )
        dst_key = (e.dst.provider, e.dst.node_type, e.dst.provider_id)
        if dst_key not in node_provider_id_set:
            raise ValueError(
                f"Edge {e.edge_type} dst references non-existent node: "
                f"provider={e.dst.provider}, node_type={e.dst.node_type}, "
                f"provider_id={e.dst.provider_id}"
            )

    # Check edge_constraint references
    edge_id_set = {e.edge_id for e in edges}
    constraint_id_set = {c.constraint_id for c in constraints}

    for ec in edge_constraints:
        if ec.edge_id not in edge_id_set:
            raise ValueError(f"EdgeConstraint references non-existent edge_id: {ec.edge_id}")
        if ec.constraint_id not in constraint_id_set:
            raise ValueError(f"EdgeConstraint references non-existent constraint_id: {ec.constraint_id}")


def emit_binding_metadata(
    edge_constraints: list,
) -> bytes:
    """Emit binding_metadata.json sidecar file.

    ARF-RT's EdgeConstraintInput uses extra="forbid", so binding_metadata
    cannot be included in scenario.json's edge_constraints array. This
    sidecar file stores the per-edge-per-constraint governance data
    (governance_confidence, likely_blocking, binding_reason) separately.

    When ARF-RT adds binding_metadata support, this data can be merged
    back into scenario.json.

    Args:
        edge_constraints: List of EdgeConstraint objects.

    Returns:
        Canonical JSON bytes of the binding metadata array.
    """
    sorted_ecs = sorted(edge_constraints, key=lambda ec: ec.sort_key)
    entries = [ec.to_binding_dict() for ec in sorted_ecs]
    return canonical_json_bytes(entries)
