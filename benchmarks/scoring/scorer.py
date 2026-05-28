from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.common import load_json, resolve_path


def _resolve_context_value(assertion: dict[str, Any], run_manifest: dict[str, Any], key_name: str) -> str | None:
    context_key = assertion.get(key_name)
    if context_key is None:
        return None
    context = run_manifest.get("context", {})
    value = context.get(str(context_key))
    if isinstance(value, str):
        return value
    return None


def _matching_findings(assertion: dict[str, Any], findings_doc: dict[str, Any], run_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    source_provider_id = _resolve_context_value(assertion, run_manifest, "source_provider_id_from_context")
    target_provider_id = _resolve_context_value(assertion, run_manifest, "target_provider_id_from_context")
    matches: list[dict[str, Any]] = []
    for finding in findings_doc.get("findings", []):
        if finding.get("pattern_id") != assertion.get("pattern_id"):
            continue
        if finding.get("verdict") != assertion.get("verdict"):
            continue
        if source_provider_id is not None and finding.get("source", {}).get("provider_id") != source_provider_id:
            continue
        if target_provider_id is not None and finding.get("target", {}).get("provider_id") != target_provider_id:
            continue
        matches.append(finding)
    return matches


def _matching_scenario_edges(assertion: dict[str, Any], scenario_doc: dict[str, Any], run_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    source_provider_id = _resolve_context_value(assertion, run_manifest, "source_provider_id_from_context")
    target_provider_id = _resolve_context_value(assertion, run_manifest, "target_provider_id_from_context")
    matches: list[dict[str, Any]] = []
    for edge in scenario_doc.get("edges", []):
        if edge.get("edge_type") != assertion.get("edge_type"):
            continue
        if source_provider_id is not None and edge.get("src", {}).get("provider_id") != source_provider_id:
            continue
        if target_provider_id is not None and edge.get("dst", {}).get("provider_id") != target_provider_id:
            continue
        if not _edge_features_match(assertion, edge):
            continue
        matches.append(edge)
    return matches


def _matching_scenario_nodes(assertion: dict[str, Any], scenario_doc: dict[str, Any], run_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    provider_id = _resolve_context_value(assertion, run_manifest, "provider_id_from_context")
    matches: list[dict[str, Any]] = []
    for node in scenario_doc.get("nodes", []):
        if node.get("node_type") != assertion.get("node_type"):
            continue
        if provider_id is not None and node.get("provider_id") != provider_id:
            continue
        matches.append(node)
    return matches


def _edge_features_match(assertion: dict[str, Any], edge: dict[str, Any]) -> bool:
    features = edge.get("features", {})
    if not isinstance(features, dict):
        features = {}

    expected_feature_values = assertion.get("feature_equals")
    if isinstance(expected_feature_values, dict):
        for key, expected_value in expected_feature_values.items():
            if features.get(str(key)) != expected_value:
                return False

    expected_has_conditions = assertion.get("feature_has_conditions")
    if expected_has_conditions is not None and bool(features.get("has_conditions", False)) != bool(expected_has_conditions):
        return False

    expected_is_wildcard_resource = assertion.get("feature_is_wildcard_resource")
    if expected_is_wildcard_resource is not None and bool(features.get("is_wildcard_resource", False)) != bool(
        expected_is_wildcard_resource
    ):
        return False

    condition_key = assertion.get("feature_condition_key_contains")
    if condition_key is not None:
        raw_conditions = features.get("raw_conditions", {})
        if not _condition_key_present(raw_conditions, str(condition_key)):
            return False

    condition_value = assertion.get("feature_condition_value_contains")
    if condition_value is not None:
        raw_conditions = features.get("raw_conditions", {})
        if str(condition_value) not in str(raw_conditions):
            return False

    return True


def _condition_key_present(raw_conditions: Any, needle: str) -> bool:
    if not isinstance(raw_conditions, dict):
        return False
    for operator_body in raw_conditions.values():
        if isinstance(operator_body, dict):
            if any(needle in str(key) for key in operator_body):
                return True
        elif needle in str(operator_body):
            return True
    return needle in str(raw_conditions)


def _constraint_matches(assertion: dict[str, Any], constraint: dict[str, Any]) -> bool:
    if constraint.get("constraint_type") != assertion.get("constraint_type"):
        return False
    needle = assertion.get("condition_key_contains")
    if needle is None:
        return True
    text = str(needle)
    properties = constraint.get("properties", {})
    condition_keys = properties.get("condition_keys", [])
    if any(text in str(value) for value in condition_keys):
        return True
    return text in str(properties)


def _matching_scenario_constraints(assertion: dict[str, Any], scenario_doc: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for constraint in scenario_doc.get("constraints", []):
        if _constraint_matches(assertion, constraint):
            matches.append(constraint)
    return matches


def _matching_scenario_edge_constraints(
    assertion: dict[str, Any], scenario_doc: dict[str, Any], run_manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    matching_edges = _matching_scenario_edges(assertion, scenario_doc, run_manifest)
    matching_constraints = _matching_scenario_constraints(assertion, scenario_doc)
    matching_edge_ids = {edge.get("edge_id") for edge in matching_edges if isinstance(edge.get("edge_id"), str)}
    matching_constraint_ids = {
        constraint.get("constraint_id")
        for constraint in matching_constraints
        if isinstance(constraint.get("constraint_id"), str)
    }
    matches: list[dict[str, Any]] = []
    for binding in scenario_doc.get("edge_constraints", []):
        if binding.get("edge_id") in matching_edge_ids and binding.get("constraint_id") in matching_constraint_ids:
            matches.append(binding)
    return matches


def _compare_count(actual: int, op: str, expected: int) -> bool:
    if op == "eq":
        return actual == expected
    if op == "gte":
        return actual >= expected
    raise ValueError(f"unsupported op: {op}")


def _score_assertion(
    assertion: dict[str, Any],
    findings_doc: dict[str, Any],
    scenario_doc: dict[str, Any],
    run_manifest: dict[str, Any],
) -> dict[str, Any]:
    assertion_type = str(assertion["type"])
    actual_value = 0
    if assertion_type == "finding_count":
        matches = _matching_findings(assertion, findings_doc, run_manifest)
        actual_value = len(matches)
    elif assertion_type == "blocker_present":
        matches = _matching_findings(assertion, findings_doc, run_manifest)
        for finding in matches:
            for blocker in finding.get("blockers_observed", []):
                if blocker.get("kind") != assertion.get("kind"):
                    continue
                if assertion.get("require_string_constraint_id") and not isinstance(blocker.get("constraint_id"), str):
                    continue
                if assertion.get("require_string_edge_id") and not isinstance(blocker.get("edge_id"), str):
                    continue
                actual_value += 1
    elif assertion_type == "check_state_present":
        matches = _matching_findings(assertion, findings_doc, run_manifest)
        for finding in matches:
            for check in finding.get("required_checks", []):
                if check.get("name") == assertion.get("check_name") and check.get("state") == assertion.get("check_state"):
                    actual_value += 1
    elif assertion_type == "scenario_edge_count":
        matches = _matching_scenario_edges(assertion, scenario_doc, run_manifest)
        actual_value = len(matches)
    elif assertion_type == "scenario_node_count":
        matches = _matching_scenario_nodes(assertion, scenario_doc, run_manifest)
        actual_value = len(matches)
    elif assertion_type == "scenario_constraint_count":
        matches = _matching_scenario_constraints(assertion, scenario_doc)
        actual_value = len(matches)
    elif assertion_type == "scenario_edge_constraint_count":
        matches = _matching_scenario_edge_constraints(assertion, scenario_doc, run_manifest)
        actual_value = len(matches)
    else:
        raise ValueError(f"unsupported assertion type: {assertion_type}")

    expected_value = int(assertion["expected_value"])
    passed = _compare_count(actual_value, str(assertion["op"]), expected_value)
    result: dict[str, Any] = {
        "assertion_id": assertion["assertion_id"],
        "type": assertion_type,
        "actual_value": actual_value,
        "expected_value": expected_value,
        "op": assertion["op"],
        "passed": passed,
    }
    if not passed:
        result["defect"] = {
            "assertion_id": assertion["assertion_id"],
            "defect_class": assertion["defect_class_on_fail"],
            "authority": assertion["authority"],
            "confidence": assertion["confidence"],
            "message": f"assertion {assertion['assertion_id']} failed: expected {assertion['op']} {expected_value}, got {actual_value}",
        }
    return result


def score_case(case_manifest: dict[str, Any], run_manifest: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    findings_path = resolve_path(repo_root, str(run_manifest["artifacts"]["findings_json"]))
    scenario_path = resolve_path(repo_root, str(run_manifest["artifacts"]["scenario_json"]))
    findings_doc = load_json(findings_path)
    scenario_doc = load_json(scenario_path)
    assertion_results: list[dict[str, Any]] = []
    defects: list[dict[str, Any]] = []
    for assertion in case_manifest.get("semantic_assertions", []):
        result = _score_assertion(assertion, findings_doc, scenario_doc, run_manifest)
        assertion_results.append(result)
        defect = result.get("defect")
        if isinstance(defect, dict):
            defects.append(defect)
    return {
        "case_id": case_manifest["case_id"],
        "run_id": run_manifest["run_id"],
        "passed": len(defects) == 0,
        "assertion_results": assertion_results,
        "defects": defects,
    }
