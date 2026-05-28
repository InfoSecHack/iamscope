#!/usr/bin/env python3
"""Run the first-probe ARF-RT policy comparison for the SeRIM lab.

This is a boundary adapter only: it normalizes IAMScope's scenario export into
the strict ScenarioInput shape expected by the existing ARF-RT replay adapter,
then calls ARF-RT planner/eval functions without modifying engine logic.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_RESOURCE_POLICY_DENY,
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
)
from iamscope.output.probe_overlay_json import load_probe_overlay
from iamscope.truth.probe_overlay import join_probe_overlay_to_scenario

DEFAULT_ARF_RT_REPO = Path(
    os.environ.get("IAMSCOPE_ARF_RT_REPO", str(Path.home() / "arf_rt_repro"))
)
ARF_RUNTIME_ERROR_MESSAGE = (
    "ARF wrapper requires the external ARF runtime environment. Activate "
    "its virtualenv and set PYTHONPATH to include both repos, or set "
    "IAMSCOPE_ARF_RT_REPO."
)
OBJECTIVE_ERROR_MESSAGE = (
    "Scenario has no objectives. Provide --start-role-arn and --target-role-arn "
    "with optional --max-depth, or pass an ARF-ready scenario_with_objective.json."
)
DEFAULT_INPUT_DIR = Path(
    os.environ.get(
        "IAMSCOPE_ARF_RT_INPUT_DIR",
        str(Path.home() / "arf_rt_inputs" / "serim_lab"),
    )
)
DEFAULT_START = "arn:aws:iam::737923406074:role/serim-demo/serim-DevEngineerRole"
DEFAULT_TARGET = "arn:aws:iam::377114445031:role/serim-demo/serim-ProdDBAdminRole"

SCP_SHARED_PAIRS = {
    ("serim-TerraformRole", "serim-ProdDeployRole"),
    ("serim-TerraformRole", "serim-ProdDBAdminRole"),
    ("serim-ProdReadOnlyRole", "serim-ProdDBAdminRole"),
}

TRUST_SHARED_PAIRS = {
    ("serim-JumpRole", "serim-ProdDeployRole"),
    ("serim-JumpRole", "serim-ProdReadOnlyRole"),
    ("serim-ProdDeployRole", "serim-ProdDBAdminRole"),
    ("serim-ProdReadOnlyRole", "serim-ProdDBAdminRole"),
    ("serim-TerraformRole", "serim-ProdDeployRole"),
    ("serim-TerraformRole", "serim-ProdDBAdminRole"),
}

WRAPPER_TRUTH_CONSTRAINT_TYPES = {
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_RESOURCE_POLICY_DENY,
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
}

ARF_ADMISSIBLE_CONSTRAINT_TYPES = {
    "AZURE_CA",
    "AZURE_PIM",
    "PERMISSION_BOUNDARY",
    "RESOURCE_POLICY",
    "SCP",
    "TRUST_CONDITION",
}
ARF_ADMISSIBLE_CONSTRAINT_STATUS = {"ACTIVE", "INVALIDATED"}
ARF_ADMISSIBLE_CONSTRAINT_VALIDATION_STATUS = {"ASSUMED", "UNVALIDATED", "VALIDATED"}
ARF_ADMISSIBLE_EDGE_STATUS = {"CONFIRMED", "HYPOTHESIZED", "REFUTED", "UNKNOWN_CONDITION"}
ARF_ADMISSIBLE_RELATION_TYPES = {"APPLIES_TO", "DEPENDS_ON"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _role_name(provider_id: str) -> str:
    if provider_id.endswith(":root"):
        return provider_id
    return provider_id.rstrip("/").split("/")[-1]


def _node_ref(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": node["provider"],
        "node_type": node["node_type"],
        "provider_id": node["provider_id"],
        "region": node.get("region", "-"),
    }


def _edge_ref(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_type": edge["edge_type"],
        "src": _node_ref(edge["src"]),
        "dst": _node_ref(edge["dst"]),
        "region": edge.get("region", "-"),
    }


def _constraint_ref(constraint: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": constraint["provider"],
        "constraint_type": constraint["constraint_type"],
        "scope_type": constraint["scope_type"],
        "scope_id": constraint["scope_id"],
        "region": constraint.get("region", "-"),
        "properties": constraint.get("properties") or {},
    }


def build_truth_index(
    raw: dict[str, Any],
    *,
    probe_overlay_path: Path | None = None,
    findings_path: Path | None = None,
) -> dict[str, Any]:
    """Index optional IAMScope truth artifacts for wrapper-visible labels.

    This adapter deliberately does not mutate ARF-RT planner inputs. It gives
    the wrapper/reporting layer a stable way to say whether a candidate edge is
    only declared, live-validated, confounded, or governed by correctness
    constraints already modeled by IAMScope.
    """
    constraints_by_id = {c.get("constraint_id"): c for c in raw.get("constraints", []) if c.get("constraint_id")}
    constraints_by_edge: dict[str, list[dict[str, Any]]] = {}
    for edge_constraint in raw.get("edge_constraints", []):
        edge_id = edge_constraint.get("edge_id")
        constraint = constraints_by_id.get(edge_constraint.get("constraint_id"))
        if not edge_id or not constraint:
            continue
        constraints_by_edge.setdefault(str(edge_id), []).append(
            {
                "constraint_id": constraint.get("constraint_id"),
                "constraint_type": constraint.get("constraint_type"),
                "relation_type": edge_constraint.get("relation_type", "APPLIES_TO"),
                "properties": constraint.get("properties") or {},
            }
        )

    probe_records_by_edge: dict[str, list[dict[str, Any]]] = {}
    if probe_overlay_path is not None:
        overlay = load_probe_overlay(probe_overlay_path)
        joined = join_probe_overlay_to_scenario(raw, overlay)
        probe_records_by_edge = {
            edge_id: [record.to_dict() for record in records] for edge_id, records in joined.items()
        }

    finding_keys_by_edge: dict[str, list[dict[str, str]]] = {}
    if findings_path is not None:
        findings_doc = _load_json(findings_path)
        finding_keys_by_edge = _finding_keys_by_edge(findings_doc)

    return {
        "truth_artifacts_present": probe_overlay_path is not None or findings_path is not None,
        "probe_overlay": str(probe_overlay_path) if probe_overlay_path is not None else None,
        "findings": str(findings_path) if findings_path is not None else None,
        "probe_records_by_edge": probe_records_by_edge,
        "constraints_by_edge": constraints_by_edge,
        "finding_keys_by_edge": finding_keys_by_edge,
    }


def classify_candidate_truth(edge_id: str, truth_index: dict[str, Any]) -> dict[str, Any]:
    """Return wrapper-visible truth labels for one candidate edge."""
    records = truth_index.get("probe_records_by_edge", {}).get(edge_id, [])
    constraints = truth_index.get("constraints_by_edge", {}).get(edge_id, [])
    finding_refs = truth_index.get("finding_keys_by_edge", {}).get(edge_id, [])
    constraint_types = sorted(
        {str(constraint.get("constraint_type")) for constraint in constraints if constraint.get("constraint_type")}
    )
    probe_states = sorted({str(record.get("probe_state")) for record in records if record.get("probe_state")})

    return {
        "declared_edge": True,
        "validated_allow": any(
            record.get("probe_state") == PROBE_STATE_PROBED_CORRELATED_ALLOWED for record in records
        ),
        "validated_deny": any(record.get("probe_state") == PROBE_STATE_PROBED_CORRELATED_DENIED for record in records),
        "confounded": any(
            record.get("probe_state") == PROBE_STATE_CONFOUNDED_SKIP or bool(record.get("confounded"))
            for record in records
        ),
        "probe_disagreement": any(
            record.get("probe_state") == PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT for record in records
        ),
        "stale_drift_evidence": CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT in constraint_types,
        "permission_boundary_evidence": CONSTRAINT_TYPE_PERMISSION_BOUNDARY in constraint_types,
        "resource_policy_deny_evidence": CONSTRAINT_TYPE_RESOURCE_POLICY_DENY in constraint_types,
        "constraint_types": constraint_types,
        "probe_states": probe_states,
        "probe_ids": sorted(str(record.get("probe_id")) for record in records if record.get("probe_id")),
        "contributing_control_refs": sorted(
            {str(ref) for record in records for ref in record.get("contributing_control_refs", [])}
        ),
        "finding_refs": sorted(
            finding_refs,
            key=lambda ref: (
                ref.get("finding_key", ""),
                ref.get("pattern_id", ""),
                ref.get("verdict", ""),
            ),
        ),
    }


def _finding_keys_by_edge(findings_doc: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    by_edge: dict[str, list[dict[str, str]]] = {}
    for finding in findings_doc.get("findings", []):
        if not isinstance(finding, dict):
            continue
        finding_key = finding.get("finding_key")
        if not finding_key:
            continue
        ref = {
            "finding_key": str(finding_key),
            "finding_id": str(finding.get("finding_id", "")),
            "pattern_id": str(finding.get("pattern_id", "")),
            "verdict": str(finding.get("verdict", "")),
        }
        evidence = finding.get("evidence") or {}
        for edge_id in evidence.get("edge_refs", []):
            by_edge.setdefault(str(edge_id), []).append(ref)
    return by_edge


def prepare_scenario_for_arf(
    raw: dict[str, Any],
    *,
    start_role_arn: str | None = None,
    target_role_arn: str | None = None,
    max_depth: int = 6,
    k: int = 5,
) -> dict[str, Any]:
    """Return an ARF-ready scenario without mutating the source input."""
    if raw.get("objectives"):
        return raw
    if not start_role_arn or not target_role_arn:
        raise ValueError(OBJECTIVE_ERROR_MESSAGE)
    prepared = dict(raw)
    prepared["objectives"] = [
        {
            "objective_type": "reachability",
            "start_nodes": [start_role_arn],
            "target_nodes": [target_role_arn],
            "max_depth": max_depth,
            "k": k,
        }
    ]
    return prepared


def _objective_summary(raw: dict[str, Any]) -> dict[str, Any]:
    objective = (raw.get("objectives") or [{}])[0]
    start_nodes = objective.get("start_nodes") or [DEFAULT_START]
    target_nodes = objective.get("target_nodes") or [DEFAULT_TARGET]
    return {
        "start": start_nodes[0],
        "target": target_nodes[0],
        "objective_type": str(objective.get("objective_type", "reachability")),
        "max_depth": objective.get("max_depth", 6),
        "k": objective.get("k", 5),
    }


def normalize_for_arf_rt(raw: dict[str, Any]) -> dict[str, Any]:
    """Translate IAMScope scenario JSON to ARF-RT strict replay input."""
    node_by_id = {n.get("node_id"): n for n in raw.get("nodes", []) if n.get("node_id")}
    node_by_provider = {n["provider_id"]: n for n in raw.get("nodes", [])}
    edge_by_id = {e.get("edge_id"): e for e in raw.get("edges", []) if e.get("edge_id")}
    constraint_by_id = {c.get("constraint_id"): c for c in raw.get("constraints", []) if c.get("constraint_id")}

    def normalize_objective_ref(ref: str | dict[str, Any]) -> dict[str, Any] | str:
        if isinstance(ref, dict):
            return ref
        if ref in node_by_provider:
            return _node_ref(node_by_provider[ref])
        if ref in node_by_id:
            return _node_ref(node_by_id[ref])
        return ref

    constraints = []
    for c in raw.get("constraints", []):
        constraints.append(
            {
                "provider": c["provider"],
                "constraint_type": c["constraint_type"],
                "scope_type": c["scope_type"],
                "scope_id": c["scope_id"],
                "region": c.get("region", "-"),
                "properties": c.get("properties") or {},
                "status": c.get("status", "ACTIVE"),
                "validation_status": c.get("validation_status")
                if c.get("validation_status") in {"UNVALIDATED", "VALIDATED", "ASSUMED"}
                else "UNVALIDATED",
                "confidence_q": c.get("confidence_q", 0),
            }
        )

    edge_constraints = []
    for ec in raw.get("edge_constraints", []):
        edge = edge_by_id.get(ec.get("edge_id"))
        constraint = constraint_by_id.get(ec.get("constraint_id"))
        relation_type = _normalize_relation_type(ec.get("relation_type"))
        if edge is None or constraint is None:
            edge_constraints.append(
                {
                    "edge_ref": ec.get("edge_id"),
                    "constraint_ref": ec.get("constraint_id"),
                    "relation_type": relation_type,
                    "_iamscope_wrapper_invalid_ref": True,
                }
            )
            continue
        edge_constraints.append(
            {
                "edge_ref": _edge_ref(edge),
                "constraint_ref": _constraint_ref(constraint),
                "relation_type": relation_type,
            }
        )

    objectives = []
    for obj in raw.get("objectives", []):
        objectives.append(
            {
                "objective_type": obj.get("objective_type", "REACHABILITY").upper(),
                "start_nodes": [normalize_objective_ref(r) for r in obj.get("start_nodes", [])],
                "target_nodes": [normalize_objective_ref(r) for r in obj.get("target_nodes", [])],
                "max_depth": obj.get("max_depth", 6),
                "k": obj.get("k", 5),
            }
        )

    observations = []
    for obs in raw.get("observations", []):
        converted = dict(obs)
        if "edge_id" in converted and "edge_ref" not in converted:
            converted["edge_ref"] = _edge_ref(edge_by_id[converted.pop("edge_id")])
        observations.append(converted)

    nodes = []
    for n in raw.get("nodes", []):
        item = _node_ref(n)
        item["display_name"] = n.get("display_name", "")
        item["properties"] = n.get("properties") or {}
        nodes.append(item)

    edges = []
    for e in raw.get("edges", []):
        edges.append(
            {
                "edge_type": e["edge_type"],
                "src": _node_ref(e["src"]),
                "dst": _node_ref(e["dst"]),
                "region": e.get("region", "-"),
                "features": e.get("features") or {},
                "alpha_i": e.get("alpha_i", 1),
                "beta_i": e.get("beta_i", 1),
                "status": e.get("status", "HYPOTHESIZED"),
                "frozen": e.get("frozen", False),
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "constraints": constraints,
        "edge_constraints": edge_constraints,
        "objectives": objectives,
        "observations": observations,
        "metadata": raw.get("metadata") or {},
    }


def preflight_arf_edge_constraints(scenario: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prune normalized links against the ARF SQLite-admissible ingest set."""
    all_edge_keys = {_edge_compat_key(edge) for edge in scenario.get("edges", [])}
    admissible_edge_keys = {
        _edge_compat_key(edge) for edge in scenario.get("edges", []) if _is_arf_admissible_edge(edge)
    }
    all_constraint_keys = {_constraint_compat_key(c) for c in scenario.get("constraints", [])}
    admissible_constraints = [c for c in scenario.get("constraints", []) if _is_arf_admissible_constraint(c)]
    admissible_constraint_keys = {_constraint_compat_key(c) for c in admissible_constraints}
    kept = []
    dropped_missing_edge = 0
    dropped_missing_constraint = 0
    dropped_unsupported_edge_type = 0
    dropped_unsupported_constraint_type = 0
    dropped_invalid_ref = 0

    for edge_constraint in scenario.get("edge_constraints", []):
        if edge_constraint.get("_iamscope_wrapper_invalid_ref"):
            dropped_invalid_ref += 1
            continue
        edge_key = _edge_compat_key(edge_constraint.get("edge_ref"))
        constraint_key = _constraint_compat_key(edge_constraint.get("constraint_ref"))
        missing_edge = edge_key not in all_edge_keys
        missing_constraint = constraint_key not in all_constraint_keys
        unsupported_edge = edge_key in all_edge_keys and edge_key not in admissible_edge_keys
        unsupported_constraint = (
            constraint_key in all_constraint_keys and constraint_key not in admissible_constraint_keys
        )
        if missing_edge or missing_constraint or unsupported_edge or unsupported_constraint:
            if missing_edge:
                dropped_missing_edge += 1
            if missing_constraint:
                dropped_missing_constraint += 1
            if unsupported_edge:
                dropped_unsupported_edge_type += 1
            if unsupported_constraint:
                dropped_unsupported_constraint_type += 1
            continue
        edge_constraint = dict(edge_constraint)
        edge_constraint["relation_type"] = _normalize_relation_type(edge_constraint.get("relation_type"))
        kept.append(edge_constraint)

    cleaned = dict(scenario)
    cleaned["constraints"] = admissible_constraints
    cleaned["edge_constraints"] = kept
    diagnostics = {
        "edge_constraints_input": len(scenario.get("edge_constraints", [])),
        "edge_constraints_kept": len(kept),
        "edge_constraints_dropped": len(scenario.get("edge_constraints", [])) - len(kept),
        "dropped_invalid_ref": dropped_invalid_ref,
        "dropped_missing_edge": dropped_missing_edge,
        "dropped_missing_constraint": dropped_missing_constraint,
        "dropped_unsupported_edge_type": dropped_unsupported_edge_type,
        "dropped_unsupported_constraint_type": dropped_unsupported_constraint_type,
        "constraints_input": len(scenario.get("constraints", [])),
        "constraints_kept": len(admissible_constraints),
        "constraints_pruned": len(scenario.get("constraints", [])) - len(admissible_constraints),
    }
    return cleaned, diagnostics


def _is_arf_admissible_edge(edge: Any) -> bool:
    if not isinstance(edge, dict):
        return False
    if not edge.get("edge_type") or not edge.get("src") or not edge.get("dst"):
        return False
    if edge.get("status", "HYPOTHESIZED") not in ARF_ADMISSIBLE_EDGE_STATUS:
        return False
    return _is_nonnegative_int(edge.get("alpha_i", 1)) and _is_nonnegative_int(edge.get("beta_i", 1))


def _is_arf_admissible_constraint(constraint: Any) -> bool:
    if not isinstance(constraint, dict):
        return False
    if constraint.get("constraint_type") not in ARF_ADMISSIBLE_CONSTRAINT_TYPES:
        return False
    if constraint.get("status", "ACTIVE") not in ARF_ADMISSIBLE_CONSTRAINT_STATUS:
        return False
    if constraint.get("validation_status", "UNVALIDATED") not in ARF_ADMISSIBLE_CONSTRAINT_VALIDATION_STATUS:
        return False
    return _is_confidence_q(constraint.get("confidence_q", 0))


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_confidence_q(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1000


def _normalize_relation_type(value: Any) -> str:
    if value in ARF_ADMISSIBLE_RELATION_TYPES:
        return str(value)
    return "APPLIES_TO"


def _edge_compat_key(edge: Any) -> tuple[Any, ...]:
    if not isinstance(edge, dict):
        return ("invalid", repr(edge))
    return (
        edge.get("edge_type"),
        _stable_ref_key(edge.get("src")),
        _stable_ref_key(edge.get("dst")),
        edge.get("region", "-"),
    )


def _constraint_compat_key(constraint: Any) -> tuple[Any, ...]:
    if not isinstance(constraint, dict):
        return ("invalid", repr(constraint))
    return (
        constraint.get("provider"),
        constraint.get("constraint_type"),
        constraint.get("scope_type"),
        constraint.get("scope_id"),
        constraint.get("region", "-"),
        _stable_json_key(constraint.get("properties") or {}),
    )


def _stable_ref_key(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((k, _stable_ref_key(v)) for k, v in value.items()))
    if isinstance(value, list):
        return tuple(_stable_ref_key(v) for v in value)
    return value


def _stable_json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _edge_identity_key(edge: Any) -> tuple[Any, ...]:
    if not isinstance(edge, dict):
        return ("invalid", repr(edge))
    src = edge.get("src")
    dst = edge.get("dst")
    src_provider = src.get("provider_id") if isinstance(src, dict) else src
    dst_provider = dst.get("provider_id") if isinstance(dst, dict) else dst
    return (
        edge.get("edge_type"),
        src_provider,
        dst_provider,
        edge.get("region", "-"),
    )


def _edge_identity_key_without_region(edge: Any) -> tuple[Any, ...]:
    if not isinstance(edge, dict):
        return ("invalid", repr(edge))
    src = edge.get("src")
    dst = edge.get("dst")
    src_provider = src.get("provider_id") if isinstance(src, dict) else src
    dst_provider = dst.get("provider_id") if isinstance(dst, dict) else dst
    return (
        edge.get("edge_type"),
        src_provider,
        dst_provider,
    )


def build_original_edge_id_index(raw: dict[str, Any]) -> tuple[dict[tuple[Any, ...], str], dict[str, int]]:
    """Index original IAMScope edge IDs by stable relation identity."""
    mapping: dict[tuple[Any, ...], str] = {}
    ambiguous: set[tuple[Any, ...]] = set()
    regionless_ambiguous: set[tuple[Any, ...]] = set()
    for edge in raw.get("edges", []):
        edge_id = edge.get("edge_id")
        if not edge_id:
            continue
        exact_key = ("exact", *_edge_identity_key(edge))
        existing = mapping.get(exact_key)
        if existing is None:
            mapping[exact_key] = str(edge_id)
        elif existing != str(edge_id):
            ambiguous.add(exact_key)

        regionless_key = ("regionless", *_edge_identity_key_without_region(edge))
        regionless_existing = mapping.get(regionless_key)
        if regionless_existing is None:
            mapping[regionless_key] = str(edge_id)
            continue
        if regionless_existing != str(edge_id):
            regionless_ambiguous.add(regionless_key)
    for key in ambiguous:
        mapping.pop(key, None)
    for key in regionless_ambiguous:
        mapping.pop(key, None)
    return mapping, {
        "input_edges": len(raw.get("edges", [])),
        "unique_mappings": len({key: value for key, value in mapping.items() if key[0] == "exact"}),
        "ambiguous_mappings": len(ambiguous),
        "regionless_unique_mappings": len(
            {key: value for key, value in mapping.items() if key[0] == "regionless"}
        ),
        "regionless_ambiguous_mappings": len(regionless_ambiguous),
    }


def resolve_original_edge_id(edge: dict[str, Any], original_edge_ids: dict[tuple[Any, ...], str]) -> str | None:
    """Map an ARF planner edge row back to the original IAMScope edge_id."""
    exact_key = ("exact", *_edge_identity_key(edge))
    exact = original_edge_ids.get(exact_key)
    if exact is not None:
        return exact
    regionless_key = ("regionless", *_edge_identity_key_without_region(edge))
    return original_edge_ids.get(regionless_key)


def _warn_about_edge_constraint_pruning(diagnostics: dict[str, Any]) -> None:
    dropped = diagnostics.get("edge_constraints_dropped", 0)
    if not dropped:
        return
    print(
        "ARF compatibility preflight dropped "
        f"{dropped} edge_constraint link(s): "
        f"invalid_ref={diagnostics.get('dropped_invalid_ref', 0)}, "
        f"missing_edge={diagnostics.get('dropped_missing_edge', 0)}, "
        f"missing_constraint={diagnostics.get('dropped_missing_constraint', 0)}, "
        f"unsupported_edge_type={diagnostics.get('dropped_unsupported_edge_type', 0)}, "
        f"unsupported_constraint_type={diagnostics.get('dropped_unsupported_constraint_type', 0)}. "
        f"Pruned {diagnostics.get('constraints_pruned', 0)} unsupported constraint(s). "
        "The source scenario file was not modified.",
        file=sys.stderr,
    )


def _edge_rows(conn: Any) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT e.edge_id, e.edge_type, e.alpha_i, e.beta_i,
               n1.provider_id AS src, n2.provider_id AS dst
        FROM edges e
        JOIN nodes n1 ON n1.node_id = e.src_node_id
        JOIN nodes n2 ON n2.node_id = e.dst_node_id
        """
    ).fetchall()
    return {r["edge_id"]: dict(r) for r in rows}


def _constraint_types_by_edge(conn: Any) -> dict[str, list[str]]:
    rows = conn.execute(
        """
        SELECT ec.edge_id, c.constraint_type
        FROM edge_constraints ec
        JOIN constraints c ON c.constraint_id = ec.constraint_id
        ORDER BY ec.edge_id, c.constraint_type
        """
    ).fetchall()
    by_edge: dict[str, list[str]] = {}
    for row in rows:
        by_edge.setdefault(row["edge_id"], []).append(row["constraint_type"])
    return by_edge


def _topk_paths(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT rank, p_worst_q8, edge_id_sequence FROM derived_topk ORDER BY rank").fetchall()
    return [
        {
            "rank": row["rank"],
            "p_worst_q8": row["p_worst_q8"],
            "edge_ids": json.loads(row["edge_id_sequence"]),
        }
        for row in rows
    ]


def _shared_families(edge: dict[str, Any], constraint_types: list[str]) -> list[str]:
    """Classify SeRIM shared-control family membership by role pair.

    The comparison summary is demo labeling, not ARF-RT inference. Use the
    hand-authored SeRIM family inventory so labels remain stable even when a
    permission/trust half lacks downstream constraint metadata.
    """
    del constraint_types
    pair = (_role_name(edge["src"]), _role_name(edge["dst"]))
    families = []
    if pair in SCP_SHARED_PAIRS:
        families.append("SCP")
    if pair in TRUST_SHARED_PAIRS:
        families.append("TRUST_CONDITION")
    return families


def _informed_path_count(
    chosen_edge_id: str,
    paths: list[dict[str, Any]],
    correlation: dict[str, Any],
) -> int:
    chosen_group = correlation.get("edge_groups", {}).get(chosen_edge_id, {}).get("p_worst_sig")
    count = 0
    for path in paths:
        edge_ids = path["edge_ids"]
        if chosen_edge_id in edge_ids:
            count += 1
            continue
        if chosen_group and any(
            correlation.get("edge_groups", {}).get(eid, {}).get("p_worst_sig") == chosen_group for eid in edge_ids
        ):
            count += 1
    return count


def _format_path(path: dict[str, Any], edges: dict[str, dict[str, Any]]) -> list[str]:
    return [
        f"{_role_name(edges[eid]['src'])} -> {_role_name(edges[eid]['dst'])} [{edges[eid]['edge_type']}]"
        for eid in path["edge_ids"]
    ]


def _truth_label(truth: dict[str, Any]) -> str:
    labels = []
    if truth.get("validated_deny"):
        labels.append("validated_deny")
    if truth.get("confounded"):
        labels.append("confounded")
    if truth.get("probe_disagreement"):
        labels.append("probe_disagreement")
    if truth.get("validated_allow"):
        labels.append("validated_allow")
    if truth.get("stale_drift_evidence"):
        labels.append("stale_drift")
    if truth.get("permission_boundary_evidence"):
        labels.append("permission_boundary")
    if truth.get("resource_policy_deny_evidence"):
        labels.append("resource_policy_deny")
    return ", ".join(labels) or "declared_only"


def _write_markdown(summary: dict[str, Any], path: Path) -> None:
    truth_enabled = "truth_artifacts" in summary
    lines = [
        "# SeRIM ARF-RT First-Probe Comparison",
        "",
        f"Input: `{summary['inputs']['scenario']}`",
        f"Objective: `{summary['objective']['start']}` -> `{summary['objective']['target']}`",
        f"Baseline entropy: `{summary['baseline_entropy']:.6f}`",
        "",
    ]
    if truth_enabled:
        lines.extend(
            [
                "Truth artifacts were loaded for wrapper reporting only; ARF-RT planner inputs are unchanged.",
                "",
                "| Policy | First Probe | Shared Family | Truth Label | Paths Informed | Expected H After |",
                "|---|---|---:|---:|---:|---:|",
            ]
        )
    else:
        lines.extend(
            [
                "| Policy | First Probe | Shared Family | Paths Informed | Expected H After |",
                "|---|---|---:|---:|---:|",
            ]
        )
    for policy, row in summary["policies"].items():
        edge = row["first_probe"]
        families = ", ".join(row["shared_control_families"]) or "none"
        if truth_enabled:
            lines.append(
                f"| {policy} | `{edge['src_role']} -> {edge['dst_role']} ({edge['edge_type']})` "
                f"| {families} | {_truth_label(row.get('truth', {}))} | "
                f"{row['candidate_paths_informed']} | {row['entropy']['expected_after']:.6f} |"
            )
        else:
            lines.append(
                f"| {policy} | `{edge['src_role']} -> {edge['dst_role']} ({edge['edge_type']})` "
                f"| {families} | {row['candidate_paths_informed']} | "
                f"{row['entropy']['expected_after']:.6f} |"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--binding-metadata", type=Path)
    parser.add_argument("--probe-overlay", type=Path)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--start-role-arn")
    parser.add_argument("--target-role-arn")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--arf-rt-repo", type=Path, default=DEFAULT_ARF_RT_REPO)
    parser.add_argument("--random-seed", type=int, default=42)
    args = parser.parse_args()

    scenario_path = args.scenario or args.input_dir / "scenario_with_objective.json"
    raw = _load_json(scenario_path)
    try:
        arf_ready_raw = prepare_scenario_for_arf(
            raw,
            start_role_arn=args.start_role_arn,
            target_role_arn=args.target_role_arn,
            max_depth=args.max_depth,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    truth_index = build_truth_index(
        arf_ready_raw,
        probe_overlay_path=args.probe_overlay,
        findings_path=args.findings,
    )
    emit_truth = bool(truth_index["truth_artifacts_present"])
    normalized = normalize_for_arf_rt(arf_ready_raw)
    normalized, edge_constraint_preflight = preflight_arf_edge_constraints(normalized)
    _warn_about_edge_constraint_pruning(edge_constraint_preflight)
    objective = _objective_summary(arf_ready_raw)

    sys.path.insert(0, str(args.arf_rt_repo))
    try:
        from arf_rt.cli import run_full_pipeline
        from arf_rt.engine.correlation import compute_correlation
        from arf_rt.engine.eval import choose_candidate
        from arf_rt.engine.planner import plan_probes
    except ImportError as exc:
        print(ARF_RUNTIME_ERROR_MESSAGE, file=sys.stderr)
        print(f"Import error: {exc}", file=sys.stderr)
        return 2

    output_dir = args.output_dir or args.input_dir / "arf_rt_comparison"
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / "serim_scenario_arf_compat.json"
    normalized_path.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")

    conn, warnings = run_full_pipeline(str(normalized_path))
    correlation = compute_correlation(conn)
    plan = plan_probes(conn, correlation, signal_q=95)
    candidates = plan["candidates"]
    rng = random.Random(args.random_seed)
    edges = _edge_rows(conn)
    constraint_types = _constraint_types_by_edge(conn)
    paths = _topk_paths(conn)
    original_edge_ids, edge_id_mapping = build_original_edge_id_index(arf_ready_raw)

    policies: dict[str, Any] = {}
    for policy in ["eig", "uncertainty", "centrality", "random"]:
        chosen = choose_candidate(policy, candidates, rng, conn=conn)
        edge = edges[chosen["edge_id"]]
        families = _shared_families(edge, constraint_types.get(chosen["edge_id"], []))
        original_edge_id = resolve_original_edge_id(edge, original_edge_ids)
        truth_edge_id = original_edge_id or chosen["edge_id"]
        p_allow = chosen["p_edge"]
        h_allow = chosen["h_allow"]
        h_deny = chosen["h_deny"]
        expected_after = p_allow * h_allow + (1.0 - p_allow) * h_deny
        policy_row = {
            "first_probe": {
                "edge_id": truth_edge_id,
                "arf_edge_id": chosen["edge_id"],
                "iamscope_edge_id": original_edge_id,
                "edge_type": edge["edge_type"],
                "src": edge["src"],
                "dst": edge["dst"],
                "src_role": _role_name(edge["src"]),
                "dst_role": _role_name(edge["dst"]),
                "constraint_types": constraint_types.get(chosen["edge_id"], []),
            },
            "shared_control_families": families,
            "on_shared_control_family": bool(families),
            "candidate_paths_informed": _informed_path_count(chosen["edge_id"], paths, correlation),
            "entropy": {
                "before": plan["baseline_entropy"],
                "after_allow": h_allow,
                "after_deny": h_deny,
                "expected_after": expected_after,
                "expected_information_gain": chosen["eig"],
            },
            "p_allow": p_allow,
            "reasons": chosen.get("reasons", []),
        }
        if emit_truth:
            policy_row["truth"] = classify_candidate_truth(truth_edge_id, truth_index)
        policies[policy] = policy_row

    inputs = {
        "scenario": str(scenario_path),
        "normalized_scenario": str(normalized_path),
    }
    ingest_warnings = list(warnings)
    if args.binding_metadata:
        if args.binding_metadata.is_file():
            inputs["binding_metadata"] = str(args.binding_metadata)
        else:
            ingest_warnings.append(
                f"binding_metadata input was supplied but is not a readable file: {args.binding_metadata}"
            )
    if args.findings:
        inputs["findings"] = str(args.findings)
    if args.probe_overlay:
        inputs["probe_overlay"] = str(args.probe_overlay)
    summary = {
        "inputs": inputs,
        "objective": objective,
        "random_seed": args.random_seed,
        "edge_constraint_preflight": edge_constraint_preflight,
        "ingest_warnings": ingest_warnings,
        "baseline_entropy": plan["baseline_entropy"],
        "planner_stats": plan["stats"],
        "edge_id_mapping": edge_id_mapping,
        "topk_paths": [
            {
                "rank": path["rank"],
                "p_worst_q8": path["p_worst_q8"],
                "edges": _format_path(path, edges),
            }
            for path in paths
        ],
        "policies": policies,
    }
    if emit_truth:
        summary["truth_artifacts"] = {
            "probe_overlay": truth_index["probe_overlay"],
            "findings": truth_index["findings"],
            "probe_edges": len(truth_index["probe_records_by_edge"]),
            "finding_edge_refs": len(truth_index["finding_keys_by_edge"]),
        }

    json_path = output_dir / "serim_arf_rt_first_probe_summary.json"
    md_path = output_dir / "serim_arf_rt_first_probe_summary.md"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    _write_markdown(summary, md_path)

    print(
        json.dumps(
            {
                "json_summary": str(json_path),
                "markdown_summary": str(md_path),
                "normalized_scenario": str(normalized_path),
                "policies": {
                    p: {
                        "edge": row["first_probe"]["edge_id"],
                        "src_role": row["first_probe"]["src_role"],
                        "dst_role": row["first_probe"]["dst_role"],
                        "shared_control_families": row["shared_control_families"],
                        "candidate_paths_informed": row["candidate_paths_informed"],
                        "entropy_before": row["entropy"]["before"],
                        "entropy_expected_after": row["entropy"]["expected_after"],
                        **({"truth": row["truth"]} if "truth" in row else {}),
                    }
                    for p, row in policies.items()
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
