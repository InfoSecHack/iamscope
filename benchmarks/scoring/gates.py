from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.common import resolve_path


def _dedupe_defects(defects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for defect in defects:
        key = (str(defect.get("defect_class")), str(defect.get("message", defect.get("assertion_id", ""))))
        if key in seen:
            continue
        seen.add(key)
        unique.append(defect)
    return unique


def collect_artifact_defects(case_manifest: dict[str, Any], run_manifest: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    defects: list[dict[str, Any]] = []
    artifacts = run_manifest.get("artifacts", {})
    for artifact_key in case_manifest.get("artifacts_required", []):
        raw_path = artifacts.get(artifact_key)
        if not isinstance(raw_path, str):
            defects.append({
                "defect_class": "artifact_insufficient",
                "authority": run_manifest.get("authority", "manual"),
                "confidence": run_manifest.get("confidence", "medium"),
                "message": f"missing artifact path for {artifact_key}",
            })
            continue
        if not resolve_path(repo_root, raw_path).exists():
            defects.append({
                "defect_class": "artifact_insufficient",
                "authority": run_manifest.get("authority", "manual"),
                "confidence": run_manifest.get("confidence", "medium"),
                "message": f"artifact path does not exist for {artifact_key}: {raw_path}",
            })
    required_validation = case_manifest.get("scoring_expectations", {}).get("required_scenario_validation")
    actual_validation = run_manifest.get("artifact_status", {}).get("scenario_validation")
    if required_validation == "pass" and actual_validation != "pass":
        defects.append({
            "defect_class": "artifact_insufficient",
            "authority": run_manifest.get("authority", "manual"),
            "confidence": run_manifest.get("confidence", "medium"),
            "message": f"scenario validation did not pass: {actual_validation}",
        })
    return defects


def evaluate_gates(case_manifest: dict[str, Any], run_manifest: dict[str, Any], score_result: dict[str, Any], gate_manifest: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    artifact_defects = collect_artifact_defects(case_manifest, run_manifest, repo_root)
    all_defects = _dedupe_defects([*artifact_defects, *score_result.get("defects", [])])
    defect_classes = {str(defect.get("defect_class")) for defect in all_defects}
    gate_results: list[dict[str, Any]] = []
    promotion_blocked = False
    for gate in gate_manifest.get("gates", []):
        blocks_on = set(gate.get("blocks_on", []))
        triggered_by = sorted(blocks_on & defect_classes)
        blocked = bool(triggered_by) and gate.get("severity") == "block"
        if blocked:
            promotion_blocked = True
        gate_results.append({
            "gate_id": gate.get("gate_id"),
            "status": "block" if blocked else "pass",
            "triggered_by": triggered_by,
            "description": gate.get("description"),
        })
    human_review_required = bool(all_defects) or bool(case_manifest.get("unknowns_remaining"))
    return {
        "defects": all_defects,
        "gate_results": gate_results,
        "promotion_blocked": promotion_blocked,
        "artifact_sufficient": not any(defect.get("defect_class") == "artifact_insufficient" for defect in all_defects),
        "human_review_required": human_review_required,
    }
