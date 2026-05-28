"""Scenario diff engine — compares two scenario.json snapshots.

Produces a structured diff showing what changed between two collection
runs. Designed for drift detection, change review, and audit trails.

Diff categories:
- Nodes: added, removed, modified (properties changed)
- Edges: added, removed, modified (features changed)
- Constraints: added, removed
- Edge constraints: added, removed
- Metadata: hash comparison, collection delta

All comparisons use deterministic IDs (node_id, edge_id, constraint_id)
so results are stable regardless of ordering.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Structured diff between two scenario snapshots."""

    # Nodes
    nodes_added: list[dict[str, Any]] = field(default_factory=list)
    nodes_removed: list[dict[str, Any]] = field(default_factory=list)
    nodes_modified: list[dict[str, Any]] = field(default_factory=list)

    # Edges
    edges_added: list[dict[str, Any]] = field(default_factory=list)
    edges_removed: list[dict[str, Any]] = field(default_factory=list)
    edges_modified: list[dict[str, Any]] = field(default_factory=list)

    # Constraints
    constraints_added: list[dict[str, Any]] = field(default_factory=list)
    constraints_removed: list[dict[str, Any]] = field(default_factory=list)

    # Edge constraints
    edge_constraints_added: list[dict[str, Any]] = field(default_factory=list)
    edge_constraints_removed: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    hash_before: str = ""
    hash_after: str = ""
    hashes_match: bool = False

    @property
    def has_changes(self) -> bool:
        """True if any diff category is non-empty."""
        return bool(
            self.nodes_added
            or self.nodes_removed
            or self.nodes_modified
            or self.edges_added
            or self.edges_removed
            or self.edges_modified
            or self.constraints_added
            or self.constraints_removed
            or self.edge_constraints_added
            or self.edge_constraints_removed
        )

    @property
    def summary(self) -> dict[str, int]:
        """Counts for each diff category."""
        return {
            "nodes_added": len(self.nodes_added),
            "nodes_removed": len(self.nodes_removed),
            "nodes_modified": len(self.nodes_modified),
            "edges_added": len(self.edges_added),
            "edges_removed": len(self.edges_removed),
            "edges_modified": len(self.edges_modified),
            "constraints_added": len(self.constraints_added),
            "constraints_removed": len(self.constraints_removed),
            "edge_constraints_added": len(self.edge_constraints_added),
            "edge_constraints_removed": len(self.edge_constraints_removed),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "has_changes": self.has_changes,
            "summary": self.summary,
            "hash_before": self.hash_before,
            "hash_after": self.hash_after,
            "hashes_match": self.hashes_match,
            "nodes_added": self.nodes_added,
            "nodes_removed": self.nodes_removed,
            "nodes_modified": self.nodes_modified,
            "edges_added": self.edges_added,
            "edges_removed": self.edges_removed,
            "edges_modified": self.edges_modified,
            "constraints_added": self.constraints_added,
            "constraints_removed": self.constraints_removed,
            "edge_constraints_added": self.edge_constraints_added,
            "edge_constraints_removed": self.edge_constraints_removed,
        }


def diff_scenarios(
    before: dict[str, Any],
    after: dict[str, Any],
) -> DiffResult:
    """Compute a structured diff between two scenario.json snapshots.

    Args:
        before: Parsed scenario.json from the earlier collection.
        after: Parsed scenario.json from the later collection.

    Returns:
        DiffResult with all changes categorized.
    """
    result = DiffResult()

    # Hash comparison
    meta_before = before.get("metadata", {})
    meta_after = after.get("metadata", {})
    result.hash_before = meta_before.get("canonical_hash", "")
    result.hash_after = meta_after.get("canonical_hash", "")
    result.hashes_match = result.hash_before == result.hash_after and result.hash_before != ""

    # Nodes
    _diff_by_id(
        before.get("nodes", []),
        after.get("nodes", []),
        id_key="node_id",
        compare_keys=["properties"],
        added_list=result.nodes_added,
        removed_list=result.nodes_removed,
        modified_list=result.nodes_modified,
    )

    # Edges
    _diff_by_id(
        before.get("edges", []),
        after.get("edges", []),
        id_key="edge_id",
        compare_keys=["features"],
        added_list=result.edges_added,
        removed_list=result.edges_removed,
        modified_list=result.edges_modified,
    )

    # Constraints
    _diff_by_id(
        before.get("constraints", []),
        after.get("constraints", []),
        id_key="constraint_id",
        compare_keys=[],  # Presence only, no modification tracking
        added_list=result.constraints_added,
        removed_list=result.constraints_removed,
        modified_list=[],  # Unused
    )

    # Edge constraints (keyed by edge_id + constraint_id)
    _diff_edge_constraints(
        before.get("edge_constraints", []),
        after.get("edge_constraints", []),
        result,
    )

    logger.info(
        "Diff: %d added, %d removed, %d modified across all categories",
        sum(v for k, v in result.summary.items() if "added" in k),
        sum(v for k, v in result.summary.items() if "removed" in k),
        sum(v for k, v in result.summary.items() if "modified" in k),
    )

    return result


def diff_scenarios_from_files(
    before_path: str,
    after_path: str,
) -> DiffResult:
    """Compute diff from file paths.

    Convenience wrapper that loads files and computes the diff.
    """
    with open(before_path) as f:
        before = json.load(f)
    with open(after_path) as f:
        after = json.load(f)
    return diff_scenarios(before, after)


def format_diff_report(result: DiffResult) -> str:
    """Format a DiffResult as a human-readable Markdown report."""
    sections: list[str] = []

    sections.append("# IAMScope Scenario Diff Report\n")

    if result.hashes_match:
        sections.append("**No changes detected** — scenario hashes match.\n")
        return "\n".join(sections)

    if not result.has_changes:
        sections.append(
            "**No structural changes detected** (hashes differ but no node/edge/constraint changes found).\n"
        )
        sections.append(f"Hash before: `{result.hash_before[:16]}...`  ")
        sections.append(f"Hash after:  `{result.hash_after[:16]}...`  ")
        return "\n".join(sections)

    sections.append(f"Hash before: `{result.hash_before[:16]}...`  ")
    sections.append(f"Hash after:  `{result.hash_after[:16]}...`  ")
    sections.append("")

    # Summary table
    sections.append("## Summary\n")
    sections.append("| Category | Added | Removed | Modified |")
    sections.append("|----------|-------|---------|----------|")
    s = result.summary
    sections.append(f"| Nodes | {s['nodes_added']} | {s['nodes_removed']} | {s['nodes_modified']} |")
    sections.append(f"| Edges | {s['edges_added']} | {s['edges_removed']} | {s['edges_modified']} |")
    sections.append(f"| Constraints | {s['constraints_added']} | {s['constraints_removed']} | — |")
    sections.append(f"| Edge Constraints | {s['edge_constraints_added']} | {s['edge_constraints_removed']} | — |")
    sections.append("")

    # Details
    if result.nodes_added:
        sections.append("## Nodes Added\n")
        for n in result.nodes_added[:20]:
            sections.append(f"- `{n.get('provider_id', n.get('node_id', '?'))}` ({n.get('node_type', '?')})")
        if len(result.nodes_added) > 20:
            sections.append(f"- ... and {len(result.nodes_added) - 20} more")
        sections.append("")

    if result.nodes_removed:
        sections.append("## Nodes Removed\n")
        for n in result.nodes_removed[:20]:
            sections.append(f"- `{n.get('provider_id', n.get('node_id', '?'))}` ({n.get('node_type', '?')})")
        if len(result.nodes_removed) > 20:
            sections.append(f"- ... and {len(result.nodes_removed) - 20} more")
        sections.append("")

    if result.edges_added:
        sections.append("## Edges Added\n")
        for e in result.edges_added[:20]:
            src = e.get("src", {}).get("provider_id", "?")
            dst = e.get("dst", {}).get("provider_id", "?")
            sections.append(f"- `{src}` → `{dst}` ({e.get('edge_type', '?')})")
        if len(result.edges_added) > 20:
            sections.append(f"- ... and {len(result.edges_added) - 20} more")
        sections.append("")

    if result.edges_removed:
        sections.append("## Edges Removed\n")
        for e in result.edges_removed[:20]:
            src = e.get("src", {}).get("provider_id", "?")
            dst = e.get("dst", {}).get("provider_id", "?")
            sections.append(f"- `{src}` → `{dst}` ({e.get('edge_type', '?')})")
        if len(result.edges_removed) > 20:
            sections.append(f"- ... and {len(result.edges_removed) - 20} more")
        sections.append("")

    if result.nodes_modified:
        sections.append("## Nodes Modified\n")
        for m in result.nodes_modified[:20]:
            sections.append(f"- `{m.get('id', '?')}`: {_summarize_changes(m)}")
        sections.append("")

    if result.edges_modified:
        sections.append("## Edges Modified\n")
        for m in result.edges_modified[:20]:
            sections.append(f"- `{m.get('id', '?')[:40]}...`: {_summarize_changes(m)}")
        sections.append("")

    return "\n".join(sections)


def _diff_by_id(
    before_items: list[dict],
    after_items: list[dict],
    id_key: str,
    compare_keys: list[str],
    added_list: list[dict],
    removed_list: list[dict],
    modified_list: list[dict],
) -> None:
    """Diff two lists of items by a unique ID key."""
    before_map = {item[id_key]: item for item in before_items if id_key in item}
    after_map = {item[id_key]: item for item in after_items if id_key in item}

    before_ids = set(before_map.keys())
    after_ids = set(after_map.keys())

    # Added
    for item_id in sorted(after_ids - before_ids):
        added_list.append(after_map[item_id])

    # Removed
    for item_id in sorted(before_ids - after_ids):
        removed_list.append(before_map[item_id])

    # Modified
    for item_id in sorted(before_ids & after_ids):
        old = before_map[item_id]
        new = after_map[item_id]
        changes = _find_changes(old, new, compare_keys)
        if changes:
            modified_list.append(
                {
                    "id": item_id,
                    "changes": changes,
                }
            )


def _diff_edge_constraints(
    before_items: list[dict],
    after_items: list[dict],
    result: DiffResult,
) -> None:
    """Diff edge constraints by composite key (edge_id, constraint_id)."""

    def _key(ec: dict) -> str:
        return f"{ec.get('edge_id', '')}|{ec.get('constraint_id', '')}"

    before_map = {_key(ec): ec for ec in before_items}
    after_map = {_key(ec): ec for ec in after_items}

    before_keys = set(before_map.keys())
    after_keys = set(after_map.keys())

    for k in sorted(after_keys - before_keys):
        result.edge_constraints_added.append(after_map[k])

    for k in sorted(before_keys - after_keys):
        result.edge_constraints_removed.append(before_map[k])


def _find_changes(
    old: dict,
    new: dict,
    compare_keys: list[str],
) -> list[dict[str, Any]]:
    """Find changes in specific keys between old and new dicts."""
    changes: list[dict[str, Any]] = []
    for key in compare_keys:
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            changes.append(
                {
                    "field": key,
                    "before": old_val,
                    "after": new_val,
                }
            )
    return changes


def _summarize_changes(mod: dict) -> str:
    """Produce a short summary of a modification entry."""
    changes = mod.get("changes", [])
    if not changes:
        return "unknown change"
    fields = [c["field"] for c in changes]
    return f"changed: {', '.join(fields)}"
