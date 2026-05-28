from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json
from benchmarks.scalability.baseline_compare import REPORT_TYPE as SYNTHETIC_COMPARISON_REPORT_TYPE
from benchmarks.scalability.threshold_config import (
    RUNTIME_METRICS,
    load_threshold_config,
)

REPORT_TYPE = "synthetic_threshold_evaluation"
SCHEMA_VERSION = "0.1"
RESULT_CLASSIFICATIONS = {
    "satisfied",
    "breached",
    "unavailable",
    "not_applicable",
    "malformed_threshold",
}
EVIDENCE_BOUNDARY = (
    "Report-only synthetic threshold evaluation; this does not prove real-world scalability, production readiness, "
    "live AWS behavior, broad IAMScope correctness, arbitrary enterprise graph correctness, or runtime correctness."
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
    _validate_synthetic_comparison_report(comparison)
    if config.get("report_type") != SYNTHETIC_COMPARISON_REPORT_TYPE:
        raise ValueError(
            "threshold config report_type must be "
            f"{SYNTHETIC_COMPARISON_REPORT_TYPE!r} for synthetic threshold evaluation"
        )

    fixtures = _fixture_comparisons_by_name(comparison)
    threshold_results = [
        _evaluate_threshold(entry, fixtures=fixtures, comparison=comparison)
        for entry in config.get("thresholds", [])
    ]

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "report_only": True,
        "thresholds_used": True,
        "threshold_config_path": str(threshold_config_path),
        "comparison_path": str(comparison_path),
        "evaluation_mode": config["mode"],
        "input_report_type": SYNTHETIC_COMPARISON_REPORT_TYPE,
        "threshold_result_count": len(threshold_results),
        "threshold_results": threshold_results,
        "caveats": [
            "report_only: threshold evaluation emits per-threshold classifications only",
            "no_ci_gating: this report does not fail builds or gate releases",
            "no_pass_fail: this report does not grade, rank, or pass/fail benchmark behavior",
            "no_aggregate_scoring: no aggregate benchmark score is emitted",
            "synthetic_scalability_comparison_json_only: frozen-corpus threshold execution is out of scope",
            "runtime_metrics_are_machine_sensitive: wall-clock and artifact-load thresholds require context",
            "unavailable_missing_not_collected_are_not_zero",
            "does_not_prove_real_world_scalability_or_correctness",
        ],
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }


def write_evaluation(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope Synthetic Threshold Evaluation",
        "",
        "Report-only threshold evaluation for synthetic scalability comparison JSON reports.",
        "",
        "No CI gating is applied.",
        "",
        "No pass/fail behavior is emitted.",
        "",
        "No composite score is emitted.",
        "",
        "This report does not prove real-world scalability or correctness, live AWS correctness, "
        "production readiness, broad IAMScope correctness, or arbitrary enterprise graph correctness.",
        "",
        "## Inputs",
        "",
        f"- Threshold config path: `{report['threshold_config_path']}`.",
        f"- Comparison report path: `{report['comparison_path']}`.",
        f"- Evaluation mode: `{report['evaluation_mode']}`.",
        f"- Report only: `{str(report['report_only']).lower()}`.",
        f"- Thresholds used: `{str(report['thresholds_used']).lower()}`.",
        "",
        "## Threshold Results",
        "",
        "| Target | Metric | Comparison | Classification | Observed | Expected/Limit | Caveat |",
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
            "- Report-only: threshold evaluation emits per-threshold classifications only.",
            "- No CI gating: this report does not fail builds or gate releases.",
            "- No pass/fail: classifications are review signals, not benchmark pass/fail outcomes.",
            "- No composite score: thresholds remain separate per metric and target.",
            "- Synthetic scalability comparison JSON only: frozen-corpus threshold execution is intentionally out of scope.",
            "- Runtime metric breaches are performance signals, not correctness failures.",
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
    fixtures: dict[str, dict[str, Any] | str],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    target_type = entry["target_type"]
    if target_type == "fixture":
        metric = _fixture_metric_for_entry(entry, fixtures=fixtures)
        return _evaluate_metric_threshold(entry, metric)
    if target_type == "batch":
        metric = _batch_metric_for_entry(entry, comparison=comparison)
        return _evaluate_metric_threshold(entry, metric)
    return _base_result(
        entry,
        "not_applicable",
        reason="target_type_not_supported_for_synthetic_threshold_evaluation",
    )


def _evaluate_metric_threshold(entry: dict[str, Any], metric: dict[str, Any] | None) -> dict[str, Any]:
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


def _fixture_metric_for_entry(
    entry: dict[str, Any],
    *,
    fixtures: dict[str, dict[str, Any] | str],
) -> dict[str, Any] | str | None:
    target_name = _explicit_target_name(entry)
    if target_name is None:
        return "selector_not_supported_for_minimal_synthetic_evaluator"
    fixture = fixtures.get(target_name)
    if fixture is None:
        return None
    if isinstance(fixture, str):
        return fixture
    metrics = [item for item in fixture.get("metric_comparisons", []) if item.get("metric") == entry["metric"]]
    if len(metrics) > 1:
        return "duplicate_metric_comparison"
    return metrics[0] if metrics else None


def _batch_metric_for_entry(entry: dict[str, Any], *, comparison: dict[str, Any]) -> dict[str, Any] | str | None:
    if _explicit_target_name(entry) is None:
        return "selector_not_supported_for_minimal_synthetic_evaluator"
    metric = entry["metric"]
    if metric not in comparison:
        return None
    value = comparison[metric]
    if not _available_number(value):
        return {
            "metric": metric,
            "classification": "unavailable",
            "baseline_value": "unavailable_with_reason:batch_baseline_not_reported",
            "current_value": value,
            "reason": "batch_metric_not_numeric",
        }
    return {
        "metric": metric,
        "classification": "unchanged",
        "baseline_value": value,
        "current_value": value,
        "delta": 0,
    }


def _fixture_comparisons_by_name(comparison: dict[str, Any]) -> dict[str, dict[str, Any] | str]:
    fixtures: dict[str, dict[str, Any] | str] = {}
    duplicate_names: set[str] = set()
    for fixture in comparison.get("fixture_comparisons", []):
        name = fixture.get("fixture_name") if isinstance(fixture, dict) else None
        if not isinstance(name, str):
            continue
        if name in fixtures:
            duplicate_names.add(name)
        fixtures[name] = fixture
    for name in duplicate_names:
        fixtures[name] = "duplicate_target_name"
    return fixtures


def _validate_synthetic_comparison_report(comparison: dict[str, Any]) -> None:
    if comparison.get("report_type") != SYNTHETIC_COMPARISON_REPORT_TYPE:
        raise ValueError(
            "comparison report_type must be "
            f"{SYNTHETIC_COMPARISON_REPORT_TYPE!r}; got {comparison.get('report_type')!r}"
        )
    if not isinstance(comparison.get("fixture_comparisons"), list):
        raise ValueError("comparison report is missing fixture_comparisons list")


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
    result["comparison_classification"] = metric.get("classification", "unavailable")
    result["baseline_value"] = _report_value(metric.get("baseline_value"))
    result["current_value"] = _report_value(metric.get("current_value"))
    if "delta" in metric:
        result["delta"] = _report_value(metric.get("delta"))
    if entry.get("metric") in RUNTIME_METRICS:
        result["runtime_caveat"] = entry.get("runtime_context_note") or entry.get("caveat")
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


def _explicit_target_name(entry: dict[str, Any]) -> str | None:
    target_name = entry.get("target_name")
    if isinstance(target_name, str) and target_name.strip():
        return target_name
    selector = entry.get("selector")
    if isinstance(selector, str) and selector.strip():
        return selector
    if isinstance(selector, dict):
        allowed_selector_keys = ("target_name", "fixture_name", "case_id", "batch_name")
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
        description="Evaluate explicit thresholds against a synthetic scalability comparison JSON report."
    )
    parser.add_argument("--threshold-config", required=True, type=Path, help="Threshold config JSON file.")
    parser.add_argument("--comparison", required=True, type=Path, help="Synthetic scalability comparison JSON report.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON evaluation.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown evaluation.")
    args = parser.parse_args(argv)

    try:
        report = build_threshold_evaluation_from_paths(args.threshold_config, args.comparison)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_evaluation(report, args.json_out)
        print(f"synthetic_threshold_evaluation_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"synthetic_threshold_evaluation_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
