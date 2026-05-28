"""Scenario validator — structural integrity checks for scenario.json.

Validates invariants that must hold for any valid IAMScope scenario:

1. Required top-level keys present
2. All node_ids unique
3. All edge_ids unique
4. All constraint_ids unique
5. Edge src/dst reference valid node_ids (synthetic endpoints are
   materialized as real nodes by the pipeline before emission)
6. Edge constraint edge_id references exist in edges[]
7. Edge constraint constraint_id references exist in constraints[]
8. Metadata canonical_hash is present AND matches a re-hash of the
   content (Fix A, v0.2.36)
8b. Edge src/dst endpoints each resolve to a real node in `nodes`
    (Fix A, v0.2.36; pipeline materializes dangling endpoints —
    BUG-023 dst case + Fix A src case — before scenario emission)
9. No empty IDs
10. Node/edge/constraint arrays are lists
11. Deterministic ID format (sha256 hex, 64 chars)

Returns a list of error strings. Empty list = valid.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from iamscope.identity.canonical import canonical_json_bytes, compute_hash

logger = logging.getLogger(__name__)

REQUIRED_TOP_LEVEL_KEYS = {"nodes", "edges", "constraints", "edge_constraints", "metadata"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_scenario(scenario: dict[str, Any]) -> list[str]:
    """Validate a parsed scenario.json for structural integrity.

    Args:
        scenario: Parsed scenario.json dict.

    Returns:
        List of error strings. Empty list means valid.
    """
    errors: list[str] = []

    # 1. Required top-level keys
    missing = REQUIRED_TOP_LEVEL_KEYS - set(scenario.keys())
    if missing:
        errors.append(f"Missing top-level keys: {sorted(missing)}")

    # Type checks
    for array_key in ["nodes", "edges", "constraints", "edge_constraints"]:
        val = scenario.get(array_key)
        if val is not None and not isinstance(val, list):
            errors.append(f"'{array_key}' must be a list, got {type(val).__name__}")

    nodes = scenario.get("nodes", [])
    edges = scenario.get("edges", [])
    constraints = scenario.get("constraints", [])
    edge_constraints = scenario.get("edge_constraints", [])
    metadata = scenario.get("metadata", {})

    # Short-circuit if arrays are wrong type
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []
    if not isinstance(constraints, list):
        constraints = []
    if not isinstance(edge_constraints, list):
        edge_constraints = []

    # 2. Unique node_ids
    _check_unique_ids(nodes, "node_id", "nodes", errors)

    # 3. Unique edge_ids
    edge_ids = _check_unique_ids(edges, "edge_id", "edges", errors)

    # 4. Unique constraint_ids
    constraint_ids = _check_unique_ids(constraints, "constraint_id", "constraints", errors)

    # 5. Edge src/dst reference valid nodes.
    # Defensive handling of non-dict endpoints: a tampered or
    # malformed scenario.json may have `src` or `dst` as a non-dict
    # (string, list, null). The validator's job is to REPORT these
    # as errors, not crash with an AttributeError. Fix A, v0.2.36.
    for edge in edges:
        edge_id = edge.get("edge_id", "?")
        src = edge.get("src", {})
        dst = edge.get("dst", {})

        if not isinstance(src, dict):
            errors.append(f"Edge {edge_id}: src is not a dict (got {type(src).__name__})")
            src = {}
        if not isinstance(dst, dict):
            errors.append(f"Edge {edge_id}: dst is not a dict (got {type(dst).__name__})")
            dst = {}

        src_id = src.get("provider_id", "")
        dst_id = dst.get("provider_id", "")

        if not src_id:
            errors.append(f"Edge {edge_id}: src has no provider_id")
        if not dst_id:
            errors.append(f"Edge {edge_id}: dst has no provider_id")

    # 6 & 7. Edge constraint references
    for ec in edge_constraints:
        ec_edge_id = ec.get("edge_id", "")
        ec_constraint_id = ec.get("constraint_id", "")

        if ec_edge_id and ec_edge_id not in edge_ids:
            errors.append(f"Edge constraint references non-existent edge: {ec_edge_id}")
        if ec_constraint_id and ec_constraint_id not in constraint_ids:
            errors.append(f"Edge constraint references non-existent constraint: {ec_constraint_id}")

    # 8. Metadata hash — recompute from content (Fix A, v0.2.36)
    # Pre-fix this only checked the hash was hex-shaped, never whether it
    # matched the content. A tampered scenario.json with a plausible 64-char
    # hex string passed validation. Now we recompute the canonical hash using
    # the exact same payload shape as emit_scenario and reject mismatches.
    canonical_hash = metadata.get("canonical_hash", "")
    if not canonical_hash:
        errors.append("Metadata missing canonical_hash")
    elif not SHA256_PATTERN.match(canonical_hash):
        errors.append(f"canonical_hash is not valid SHA-256 hex: {canonical_hash[:20]}...")
    else:
        hash_payload = {
            "constraints": constraints,
            "edge_constraints": edge_constraints,
            "edges": edges,
            "nodes": nodes,
            "objectives": scenario.get("objectives", []),
            "observations": scenario.get("observations", []),
        }
        recomputed = compute_hash(canonical_json_bytes(hash_payload))
        if recomputed != canonical_hash:
            errors.append(
                f"canonical_hash mismatch: metadata has "
                f"{canonical_hash[:16]}... but content hashes to "
                f"{recomputed[:16]}... (scenario may have been tampered "
                f"with or content modified without rehashing)"
            )

    # 8b. Edge src/dst referential integrity — Fix A, v0.2.36
    # Pre-fix validate.py never checked that edge src/dst provider_ids
    # actually resolve to nodes in the graph. Build a (provider,
    # node_type, provider_id) set and verify every edge endpoint is in it.
    # Errors report `edge_id` (not list index) so operators triaging a
    # failed scan can grep the scenario.json directly for the offender.
    node_keys = {(n.get("provider", ""), n.get("node_type", ""), n.get("provider_id", "")) for n in nodes}
    for edge in edges:
        edge_id = edge.get("edge_id", "?")
        for endpoint in ("src", "dst"):
            ref = edge.get(endpoint, {})
            if not isinstance(ref, dict):
                # Already reported in rule 5; skip to avoid emitting a
                # duplicate "non-existent node" error that would confuse
                # an operator triaging a malformed scenario.
                continue
            key = (
                ref.get("provider", ""),
                ref.get("node_type", ""),
                ref.get("provider_id", ""),
            )
            if key not in node_keys:
                errors.append(
                    f"Edge {edge_id} ({edge.get('edge_type', '?')}) "
                    f"{endpoint} references non-existent node: "
                    f"provider={key[0]}, node_type={key[1]}, "
                    f"provider_id={key[2]}"
                )

    # 9. No empty IDs
    for i, node in enumerate(nodes):
        if not node.get("node_id"):
            errors.append(f"Node at index {i} has empty node_id")

    for i, edge in enumerate(edges):
        if not edge.get("edge_id"):
            errors.append(f"Edge at index {i} has empty edge_id")

    # 10. Sorted order (determinism check)
    _check_sorted(nodes, "node_id", "nodes", errors)
    _check_sorted(edges, "edge_id", "edges", errors)
    _check_sorted(constraints, "constraint_id", "constraints", errors)

    if errors:
        logger.warning("Validation found %d error(s)", len(errors))
    else:
        logger.info("Validation passed")

    return errors


def _check_unique_ids(
    items: list[dict],
    id_key: str,
    label: str,
    errors: list[str],
) -> set[str]:
    """Check that all IDs in a list are unique. Returns set of IDs."""
    ids: set[str] = set()
    for item in items:
        item_id = item.get(id_key, "")
        if item_id in ids:
            errors.append(f"Duplicate {id_key} in {label}: {item_id}")
        ids.add(item_id)
    return ids


def _check_sorted(
    items: list[dict],
    id_key: str,
    label: str,
    errors: list[str],
) -> None:
    """Check that items are sorted by ID (determinism invariant)."""
    ids = [item.get(id_key, "") for item in items]
    sorted_ids = sorted(ids)
    if ids != sorted_ids:
        errors.append(f"{label} not sorted by {id_key} (determinism violation)")
