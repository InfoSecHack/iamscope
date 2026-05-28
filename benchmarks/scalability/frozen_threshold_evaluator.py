from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json
from benchmarks.scalability.frozen_corpus_baseline_compare import REPORT_TYPE as FROZEN_COMPARISON_REPORT_TYPE
from benchmarks.scalability.threshold_config import load_threshold_config

REPORT_TYPE = "frozen_corpus_threshold_evaluation"
SCHEMA_VERSION = "0.1"
RESULT_CLASSIFICATIONS = {
    "satisfied",
    "breached",
    "unavailable",
    "not_applicable",
    "malformed_threshold",
}
EVIDENCE_BOUNDARY = (
    "Offline report-only frozen-corpus threshold evaluation; this does not create new live AWS evidence, prove "
    "real-world scalability, prove production readiness, or expand IAMScope semantic correctness claims."
)


def build_threshold_evaluation_from_paths(
    threshold_config_path: str | Path,
    comparison_path: str | Path,
) -> dict[str, Any]:
    config = load_threshold_config(threshold_config_path)
    comparison = _load_existing_json(Path(comparison_path), label="comparison")
    return build_threshold_evaluation(
        config,
        comparison,
        threshold_config_path=threshold_config_path,
        comparison_path=comparison_path,
    )


def build_threshold_evaluation(
    config: dict[str, Any],
    comparison: dict[str, Any],
    *,
    threshold_config_path: str | Path,
    comparison_path: str | Path,
) -> dict[str, Any]:
    _validate_frozen_comparison_report(comparison)
    if config.get("report_type") != FROZEN_COMPARISON_REPORT_TYPE:
        raise ValueError(
            "threshold config report_type must be "
            f"{FROZEN_COMPARISON_REPORT_TYPE!r} for frozen-corpus threshold evaluation"
        )

    cases = _case_comparisons_by_id(comparison)
    threshold_results = [
        _evaluate_threshold(entry, cases=cases, comparison=comparison)
        for entry in config.get("thresholds", [])
    ]

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "offline_only": True,
        "report_only": True,
        "thresholds_used": True,
        "live_aws_used": False,
        "threshold_config_path": str(threshold_config_path),
        "comparison_path": str(comparison_path),
        "evaluation_mode": config["mode"],
        "input_report_type": FROZEN_COMPARISON_REPORT_TYPE,
        "threshold_result_count": len(threshold_results),
        "threshold_results": threshold_results,
        "caveats": [
            "offline_only: evaluates already-rendered frozen-corpus comparison JSON reports",
            "report_only: threshold evaluation emits per-threshold classifications only",
            "no_ci_gating: this report does not fail builds or gate releases",
            "no_pass_fail: this report does not grade, rank, or pass/fail benchmark behavior",
            "no_aggregate_scoring: no aggregate benchmark score is emitted",
            "no_new_live_aws_evidence: this report does not collect from AWS",
            "no_raw_artifact_comparison: raw live artifacts and Terraform artifacts are out of scope",
            "unavailable_missing_not_collected_are_not_zero",
            "does_not_prove_real_world_scalability_or_correctness",
        ],
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }


def write_evaluation(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope Frozen-Corpus Threshold Evaluation",
        "",
        "Offline-only threshold evaluation for frozen-corpus baseline comparison JSON reports.",
        "",
        "Report-only threshold evaluation; no CI gating is applied.",
        "",
        "No pass/fail behavior is emitted.",
        "",
        "No composite score is emitted.",
        "",
        "No new live AWS evidence is created. This report evaluates already-rendered offline comparison reports only.",
        "",
        "This report does not prove real-world scalability or correctness, live AWS correctness, "
        "production readiness, broad IAMScope correctness, or arbitrary enterprise graph correctness.",
        "",
        "## Inputs",
        "",
        f"- Threshold config path: `{report['threshold_config_path']}`.",
        f"- Comparison report path: `{report['comparison_path']}`.",
        f"- Evaluation mode: `{report['evaluation_mode']}`.",
        f"- Offline only: `{str(report['offline_only']).lower()}`.",
        f"- Report only: `{str(report['report_only']).lower()}`.",
        f"- Thresholds used: `{str(report['thresholds_used']).lower()}`.",
        f"- Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        "",
        "## Threshold Results",
        "",
        "| Target | Metric/Field | Comparison | Classification | Observed | Expected/Limit | Caveat |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["threshold_results"]:
        lines.append(
            "| {target} | {metric} | {comparison} | {classification} | {observed} | {expected} | {caveat} |".format(
                target=_markdown_value(_target_label(item)),
                metric=_markdown_value(item.get("metric")),
                comparison=_markdown_value(item.get("comparison_type")),
                classification=_markdown_value(item.get("result_classification")),
                observed=_markdown_value(item.get("observed_value")),
                expected=_markdown_value(item.get("expected_or_limit_value")),
                caveat=_markdown_value(item.get("caveat")),
            )
        )

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- Offline-only: evaluates already-rendered frozen-corpus comparison JSON reports.",
            "- Report-only: threshold evaluation emits per-threshold classifications only.",
            "- No CI gating: this report does not fail builds or gate releases.",
            "- No pass/fail: classifications are review signals, not benchmark pass/fail outcomes.",
            "- No composite score: thresholds remain separate per metric or case field.",
            "- No new live AWS evidence is created.",
            "- No raw artifact comparison: raw live artifacts and Terraform artifacts are out of scope.",
            "- Unavailable, missing, and not_collected values are not treated as zero.",
            "- Does not prove real-world scalability or correctness.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: str | Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def _evaluate_threshold(
    entry: dict[str, Any],
    *,
    cases: dict[str, dict[str, Any] | str],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    target_type = entry["target_type"]
    if target_type == "batch":
        metric = _batch_metric_for_entry(entry, comparison=comparison)
        return _evaluate_metric_threshold(entry, metric)
    if target_type == "case":
        metric = _case_metric_for_entry(entry, cases=cases)
        return _evaluate_metric_threshold(entry, metric)
    return _base_result(
        entry,
        "not_applicable",
        reason="target_type_not_supported_for_frozen_corpus_threshold_evaluation",
    )


def _evaluate_metric_threshold(entry: dict[str, Any], metric: dict[str, Any] | str | None) -> dict[str, Any]:
    if metric is None:
        return _base_result(entry, "not_applicable", reason="target_or_metric_missing")
    if isinstance(metric, str):
        return _base_result(entry, "malformed_threshold", reason=metric)

    comparison_type = entry["comparison_type"]
    if comparison_type == "max_absolute_delta":
        return _evaluate_max_absolute_delta(entry, metric)
    if comparison_type == "max_relative_delta":
        return _evaluate_max_relative_delta(entry, metric)
    if comparison_type == "equals":
        return _evaluate_equals(entry, metric)
    if comparison_type == "changed_or_unchanged":
        return _evaluate_changed_or_unchanged(entry, metric)
    if comparison_type == "must_be_available":
        return _evaluate_must_be_available(entry, metric)
    if comparison_type == "may_be_unavailable":
        return _evaluate_may_be_unavailable(entry, metric)
    return _base_result(entry, "malformed_threshold", reason="unsupported_comparison_type")


def _evaluate_max_absolute_delta(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    delta = _numeric_delta(metric)
    if delta is None:
        return _metric_result(entry, metric, "unavailable", reason="numeric_delta_unavailable")
    limit = entry["delta_limit"]
    classification = "satisfied" if abs(delta) <= limit else "breached"
    return _metric_result(
        entry,
        metric,
        classification,
        observed_value=delta,
        expected_or_limit_value=limit,
        reason="absolute_delta_within_limit" if classification == "satisfied" else "absolute_delta_exceeds_limit",
    )


def _evaluate_max_relative_delta(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    baseline = metric.get("baseline_value")
    current = metric.get("current_value")
    if not _available_number(baseline) or not _available_number(current):
        return _metric_result(entry, metric, "unavailable", reason="relative_delta_unavailable")
    if baseline == 0:
        if current == 0:
            relative_delta = 0
        else:
            return _metric_result(entry, metric, "unavailable", reason="relative_delta_requires_nonzero_baseline")
    else:
        relative_delta = abs((current - baseline) / baseline)
    limit = entry["delta_limit"]
    classification = "satisfied" if relative_delta <= limit else "breached"
    return _metric_result(
        entry,
        metric,
        classification,
        observed_value=relative_delta,
        expected_or_limit_value=limit,
        reason="relative_delta_within_limit" if classification == "satisfied" else "relative_delta_exceeds_limit",
    )


def _evaluate_equals(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    observed = _observed_value_for_equals(entry, metric)
    if _is_unavailable_value(observed):
        return _metric_result(entry, metric, "unavailable", observed_value=observed, reason="observed_value_unavailable")
    expected = entry["expected"]
    classification = "satisfied" if observed == expected else "breached"
    return _metric_result(
        entry,
        metric,
        classification,
        observed_value=observed,
        expected_or_limit_value=expected,
        reason="observed_value_matches_expected" if classification == "satisfied" else "observed_value_differs",
    )


def _evaluate_changed_or_unchanged(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    observed = metric.get("classification")
    expected = entry["expected"]
    if observed == "unavailable":
        return _metric_result(entry, metric, "unavailable", observed_value=observed, reason="metric_unavailable")
    classification = "satisfied" if observed == expected else "breached"
    return _metric_result(
        entry,
        metric,
        classification,
        observed_value=observed,
        expected_or_limit_value=expected,
        reason="classification_matches_expected" if classification == "satisfied" else "classification_differs",
    )


def _evaluate_must_be_available(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    if _metric_is_unavailable(metric):
        return _metric_result(entry, metric, "unavailable", reason="metric_unavailable")
    return _metric_result(entry, metric, "satisfied", reason="metric_available")


def _evaluate_may_be_unavailable(entry: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    reason = "metric_unavailable_but_allowed" if _metric_is_unavailable(metric) else "metric_available"
    return _metric_result(entry, metric, "satisfied", reason=reason)


def _batch_metric_for_entry(entry: dict[str, Any], *, comparison: dict[str, Any]) -> dict[str, Any] | str | None:
    if _explicit_target_name(entry) is None:
        return "selector_not_supported_for_minimal_frozen_corpus_evaluator"
    metric = entry["metric"]
    for collection_name in ("batch_summary_comparisons", "metadata_comparisons"):
        result = _comparison_item_by_name(comparison.get(collection_name, []), metric)
        if result is not None:
            return result
    unavailable = _unavailable_metric_by_name(comparison.get("unavailable_metric_comparisons", []), metric)
    if unavailable is not None:
        return unavailable
    if metric == "caveats":
        caveat_comparison = comparison.get("caveat_comparison")
        if isinstance(caveat_comparison, dict):
            return {
                **caveat_comparison,
                "metric": "caveats",
                "current_value": caveat_comparison.get("current_count"),
                "baseline_value": caveat_comparison.get("baseline_count"),
                "delta": _count_delta(caveat_comparison),
            }
    return None


def _case_metric_for_entry(
    entry: dict[str, Any],
    *,
    cases: dict[str, dict[str, Any] | str],
) -> dict[str, Any] | str | None:
    target_name = _explicit_target_name(entry)
    if target_name is None:
        return "selector_not_supported_for_minimal_frozen_corpus_evaluator"
    case = cases.get(target_name)
    if case is None:
        return None
    if isinstance(case, str):
        return case
    metric = entry["metric"]
    if metric in {"presence", "classification"}:
        return {
            "metric": metric,
            "classification": case.get("classification", "unavailable"),
            "baseline_value": "unavailable_with_reason:not_reported_for_case_presence",
            "current_value": case.get(metric, "unavailable_with_reason:missing"),
            "reason": "case_presence_classification",
        }
    field_comparisons = [
        item for item in case.get("field_comparisons", []) if item.get("field") == metric or item.get("metric") == metric
    ]
    if len(field_comparisons) > 1:
        return "duplicate_case_field_comparison"
    if field_comparisons:
        item = dict(field_comparisons[0])
        item["metric"] = metric
        return item
    return None


def _case_comparisons_by_id(comparison: dict[str, Any]) -> dict[str, dict[str, Any] | str]:
    cases: dict[str, dict[str, Any] | str] = {}
    duplicate_case_ids: set[str] = set()
    for case in comparison.get("case_comparisons", []):
        case_id = case.get("case_id") if isinstance(case, dict) else None
        if not isinstance(case_id, str):
            continue
        if case_id in cases:
            duplicate_case_ids.add(case_id)
        cases[case_id] = case
    for case_id in duplicate_case_ids:
        cases[case_id] = "duplicate_target_name"
    return cases


def _comparison_item_by_name(items: Any, metric: str) -> dict[str, Any] | None:
    if not isinstance(items, list):
        return None
    matches = [
        item for item in items if isinstance(item, dict) and (item.get("metric") == metric or item.get("field") == metric)
    ]
    if len(matches) != 1:
        return None
    item = dict(matches[0])
    item["metric"] = metric
    return item


def _unavailable_metric_by_name(items: Any, metric: str) -> dict[str, Any] | None:
    if not isinstance(items, list):
        return None
    matches = [item for item in items if isinstance(item, dict) and item.get("metric") == metric]
    if len(matches) != 1:
        return None
    item = dict(matches[0])
    return {
        "metric": metric,
        "classification": "unavailable",
        "baseline_value": item.get("baseline_reason", "unavailable_with_reason:missing"),
        "current_value": item.get("current_reason", "unavailable_with_reason:missing"),
        "reason": item.get("reason", "unavailable_metric_metadata_comparison"),
        "comparison_classification": item.get("classification", "unavailable"),
    }


def _validate_frozen_comparison_report(comparison: dict[str, Any]) -> None:
    if comparison.get("report_type") != FROZEN_COMPARISON_REPORT_TYPE:
        raise ValueError(
            "comparison report_type must be "
            f"{FROZEN_COMPARISON_REPORT_TYPE!r}; got {comparison.get('report_type')!r}"
        )
    if not isinstance(comparison.get("case_comparisons"), list):
        raise ValueError("comparison report is missing case_comparisons list")


def _load_existing_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} input path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"{label} input path is not a file: {path}")
    return load_json(path)


def _base_result(
    entry: dict[str, Any],
    result_classification: str,
    *,
    reason: str,
    observed_value: Any = None,
    expected_or_limit_value: Any = None,
) -> dict[str, Any]:
    return {
        "target_type": entry.get("target_type"),
        "target_name": _explicit_target_name(entry) or "unavailable_with_reason:selector_not_resolved",
        "metric": entry.get("metric"),
        "comparison_type": entry.get("comparison_type"),
        "result_classification": _validated_result_classification(result_classification),
        "observed_value": _report_value(observed_value),
        "expected_or_limit_value": _report_value(expected_or_limit_value),
        "rationale": entry.get("rationale"),
        "caveat": entry.get("caveat"),
        "reason": reason,
    }


def _metric_result(
    entry: dict[str, Any],
    metric: dict[str, Any],
    result_classification: str,
    *,
    reason: str,
    observed_value: Any = None,
    expected_or_limit_value: Any = None,
) -> dict[str, Any]:
    if observed_value is None:
        observed_value = _default_observed_value(metric)
    if expected_or_limit_value is None:
        expected_or_limit_value = entry.get("expected", entry.get("delta_limit"))
    result = _base_result(
        entry,
        result_classification,
        reason=reason,
        observed_value=observed_value,
        expected_or_limit_value=expected_or_limit_value,
    )
    result["comparison_classification"] = metric.get(
        "comparison_classification",
        metric.get("classification", "unavailable"),
    )
    result["baseline_value"] = _report_value(metric.get("baseline_value"))
    result["current_value"] = _report_value(metric.get("current_value"))
    if "delta" in metric:
        result["delta"] = _report_value(metric.get("delta"))
    if metric.get("reason"):
        result["comparison_reason"] = metric["reason"]
    return result


def _numeric_delta(metric: dict[str, Any]) -> int | float | None:
    delta = metric.get("delta")
    if _available_number(delta):
        return delta
    baseline = metric.get("baseline_value")
    current = metric.get("current_value")
    if _available_number(baseline) and _available_number(current):
        return current - baseline
    return None


def _observed_value_for_equals(entry: dict[str, Any], metric: dict[str, Any]) -> Any:
    expected = entry.get("expected")
    if expected in {"changed", "unchanged", "unavailable"}:
        return metric.get("classification", "unavailable")
    return _default_observed_value(metric)


def _default_observed_value(metric: dict[str, Any]) -> Any:
    if metric.get("classification") == "unavailable":
        return metric.get("current_value", "unavailable")
    return metric.get("current_value", metric.get("classification", "unavailable"))


def _metric_is_unavailable(metric: dict[str, Any]) -> bool:
    return (
        metric.get("classification") == "unavailable"
        or _is_unavailable_value(metric.get("baseline_value"))
        or _is_unavailable_value(metric.get("current_value"))
    )


def _is_unavailable_value(value: Any) -> bool:
    return (
        value is None
        or value == "missing"
        or value == "unavailable"
        or value == "not_collected"
        or (isinstance(value, str) and value.startswith("unavailable_with_reason"))
    )


def _available_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _count_delta(item: dict[str, Any]) -> int | None:
    baseline = item.get("baseline_count")
    current = item.get("current_count")
    if isinstance(baseline, int) and isinstance(current, int):
        return current - baseline
    return None


def _explicit_target_name(entry: dict[str, Any]) -> str | None:
    target_name = entry.get("target_name")
    if isinstance(target_name, str) and target_name.strip():
        return target_name
    selector = entry.get("selector")
    if isinstance(selector, str) and selector.strip():
        return selector
    if isinstance(selector, dict):
        allowed_selector_keys = ("target_name", "case_id", "batch_name")
        resolved = [selector[key] for key in allowed_selector_keys if isinstance(selector.get(key), str)]
        if len(resolved) == 1 and resolved[0].strip():
            return resolved[0]
    return None


def _validated_result_classification(value: str) -> str:
    if value not in RESULT_CLASSIFICATIONS:
        raise ValueError(f"unsupported threshold result classification: {value!r}")
    return value


def _report_value(value: Any) -> Any:
    return "unavailable_with_reason:missing" if value is None else value


def _target_label(item: dict[str, Any]) -> str:
    return f"{item.get('target_type')}:{item.get('target_name')}"


def _markdown_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value).replace("|", "\\|")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate explicit thresholds against a frozen-corpus comparison JSON report."
    )
    parser.add_argument("--threshold-config", required=True, type=Path, help="Threshold config JSON file.")
    parser.add_argument("--comparison", required=True, type=Path, help="Frozen-corpus comparison JSON report.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON evaluation.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown evaluation.")
    args = parser.parse_args(argv)

    try:
        report = build_threshold_evaluation_from_paths(args.threshold_config, args.comparison)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_evaluation(report, args.json_out)
        print(f"frozen_corpus_threshold_evaluation_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"frozen_corpus_threshold_evaluation_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
