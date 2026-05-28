from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json

REPORT_TYPE = "synthetic_scalability_baseline_comparison"
SCHEMA_VERSION = "0.1"
SYNTHETIC_REPORT_TYPE = "synthetic_scalability_benchmark"
EVIDENCE_BOUNDARY = (
    "Report-only synthetic scalability baseline comparison; this does not prove real-world scalability, "
    "production readiness, live AWS behavior, broad IAMScope correctness, or arbitrary enterprise graph correctness."
)
NUMERIC_METRICS = (
    "wall_clock_runtime_ms",
    "candidate_paths_considered",
    "constraint_evaluations",
    "artifact_load_time_ms",
)
VALUE_METRICS = (
    "failure_mode_classification",
)
DIGEST_METRICS = (
    "deterministic_output_stability.fixture_digest",
    "deterministic_output_stability.stable_metric_digest",
)
UNAVAILABLE_SCHEMA_METRICS = (
    "paths_validated",
    "paths_rejected",
    "peak_memory_bytes",
    "report_generation_time_ms",
)


def build_comparison(
    baseline_report: dict[str, Any],
    current_report: dict[str, Any],
    *,
    baseline_path: str | Path,
    current_path: str | Path,
) -> dict[str, Any]:
    _validate_synthetic_report(baseline_report, label="baseline")
    _validate_synthetic_report(current_report, label="current")

    baseline_fixtures = _fixtures_by_name(baseline_report)
    current_fixtures = _fixtures_by_name(current_report)
    fixture_names = sorted(set(baseline_fixtures) | set(current_fixtures))
    comparisons = [
        _compare_fixture(name, baseline=baseline_fixtures.get(name), current=current_fixtures.get(name))
        for name in fixture_names
    ]

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "baseline_path": str(baseline_path),
        "current_path": str(current_path),
        "input_report_type": SYNTHETIC_REPORT_TYPE,
        "report_only": True,
        "thresholds_used": False,
        "fixture_count": len(comparisons),
        "fixture_comparisons": comparisons,
        "caveats": [
            "report_only: comparison emits deltas and classifications only",
            "no_thresholds: no threshold gating is applied",
            "no_pass_fail: this report does not grade, rank, or gate changes",
            "no_frozen_corpus_comparison: inputs must be synthetic scalability JSON reports",
            "runtime_noise: wall-clock and artifact-load timings depend on local machine context",
            "unavailable_metrics_are_not_zero: not_collected and missing metrics are classified unavailable",
            "does_not_prove_real_world_scalability_or_correctness",
        ],
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }


def build_comparison_from_paths(baseline_path: str | Path, current_path: str | Path) -> dict[str, Any]:
    baseline = _load_existing_json(Path(baseline_path), label="baseline")
    current = _load_existing_json(Path(current_path), label="current")
    return build_comparison(
        baseline,
        current,
        baseline_path=baseline_path,
        current_path=current_path,
    )


def write_comparison(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope Synthetic Scalability Baseline Comparison",
        "",
        "Report-only comparison of synthetic scalability JSON reports.",
        "",
        "No thresholds are applied by default.",
        "",
        "No composite score is emitted. This report does not grade, rank, or gate changes.",
        "",
        "This report does not prove real-world scalability or correctness, live AWS correctness, "
        "production readiness, broad IAMScope correctness, or arbitrary enterprise graph correctness.",
        "",
        "## Inputs",
        "",
        f"- Baseline path: `{report['baseline_path']}`.",
        f"- Current path: `{report['current_path']}`.",
        f"- Report only: `{str(report['report_only']).lower()}`.",
        f"- Thresholds used: `{str(report['thresholds_used']).lower()}`.",
        "",
        "## Per-Fixture Comparison",
        "",
        "| Fixture | Classification | Metric | Baseline | Current | Delta |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for fixture in report["fixture_comparisons"]:
        for metric in fixture["metric_comparisons"]:
            lines.append(
                "| {fixture_name} | {classification} | {metric} | {baseline} | {current} | {delta} |".format(
                    fixture_name=fixture["fixture_name"],
                    classification=metric["classification"],
                    metric=metric["metric"],
                    baseline=_markdown_value(metric.get("baseline_value")),
                    current=_markdown_value(metric.get("current_value")),
                    delta=_markdown_value(metric.get("delta")),
                )
            )

    unavailable = [
        (fixture["fixture_name"], metric)
        for fixture in report["fixture_comparisons"]
        for metric in fixture["metric_comparisons"]
        if metric["classification"] == "unavailable"
    ]
    if unavailable:
        lines.extend(
            [
                "",
                "## Unavailable Metrics",
                "",
                "| Fixture | Metric | Reason |",
                "| --- | --- | --- |",
            ]
        )
        for fixture_name, metric in unavailable:
            lines.append(f"| {fixture_name} | {metric['metric']} | {metric.get('reason', 'unavailable')} |")

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- Report-only: this comparison emits deltas and classifications only.",
            "- No thresholds: no threshold gating is applied.",
            "- No pass/fail: this is not a grade, ranking, or release gate.",
            "- No composite score: metrics remain separate per fixture and per metric.",
            "- Synthetic scalability JSON only: frozen-corpus comparison is intentionally out of scope for this slice.",
            "- Runtime values such as `wall_clock_runtime_ms` and `artifact_load_time_ms` are machine-sensitive.",
            "- Unavailable metrics are not treated as zero.",
            "- Does not prove real-world scalability or correctness.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: str | Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def _validate_synthetic_report(report: dict[str, Any], *, label: str) -> None:
    if report.get("report_type") != SYNTHETIC_REPORT_TYPE:
        raise ValueError(
            f"{label} report_type must be {SYNTHETIC_REPORT_TYPE!r}; got {report.get('report_type')!r}"
        )
    fixtures = report.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError(f"{label} report is missing fixtures list")


def _load_existing_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} input path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"{label} input path is not a file: {path}")
    return load_json(path)


def _fixtures_by_name(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fixtures: dict[str, dict[str, Any]] = {}
    for fixture in report.get("fixtures", []):
        if isinstance(fixture, dict) and fixture.get("fixture_name") is not None:
            fixtures[str(fixture["fixture_name"])] = fixture
    return fixtures


def _compare_fixture(
    fixture_name: str,
    *,
    baseline: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> dict[str, Any]:
    if baseline is None or current is None:
        return {
            "fixture_name": fixture_name,
            "classification": "unavailable",
            "reason": "fixture_missing_from_baseline_or_current",
            "metric_comparisons": [
                _unavailable_metric(metric, reason="fixture_missing_from_baseline_or_current")
                for metric in (*NUMERIC_METRICS, *UNAVAILABLE_SCHEMA_METRICS, *VALUE_METRICS, *DIGEST_METRICS)
            ],
        }

    metric_comparisons = [
        *(_compare_numeric_metric(metric, baseline=baseline, current=current) for metric in NUMERIC_METRICS),
        *(_compare_value_metric(metric, baseline=baseline, current=current) for metric in UNAVAILABLE_SCHEMA_METRICS),
        *(_compare_value_metric(metric, baseline=baseline, current=current) for metric in VALUE_METRICS),
        *(_compare_digest_metric(metric, baseline=baseline, current=current) for metric in DIGEST_METRICS),
    ]
    classification = "changed" if any(item["classification"] == "changed" for item in metric_comparisons) else "unchanged"
    return {
        "fixture_name": fixture_name,
        "fixture_class": str(current.get("fixture_class") or baseline.get("fixture_class") or "unavailable"),
        "classification": classification,
        "metric_comparisons": metric_comparisons,
    }


def _compare_numeric_metric(metric: str, *, baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_value = baseline.get("metrics", {}).get(metric)
    current_value = current.get("metrics", {}).get(metric)
    if not _is_available_number(baseline_value) or not _is_available_number(current_value):
        return _unavailable_metric(
            metric,
            baseline_value=baseline_value,
            current_value=current_value,
            reason="metric_missing_or_not_collected",
        )
    delta = current_value - baseline_value
    classification = "unchanged" if delta == 0 else "changed"
    return {
        "metric": metric,
        "classification": classification,
        "baseline_value": baseline_value,
        "current_value": current_value,
        "delta": delta,
        "caveat": "runtime_metric_machine_sensitive" if metric in {"wall_clock_runtime_ms", "artifact_load_time_ms"} else "",
    }


def _compare_value_metric(metric: str, *, baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_value = baseline.get("metrics", {}).get(metric)
    current_value = current.get("metrics", {}).get(metric)
    if _is_unavailable(baseline_value) or _is_unavailable(current_value):
        return _unavailable_metric(
            metric,
            baseline_value=baseline_value,
            current_value=current_value,
            reason="metric_missing_or_not_collected",
        )
    classification = "unchanged" if baseline_value == current_value else "changed"
    return {
        "metric": metric,
        "classification": classification,
        "baseline_value": baseline_value,
        "current_value": current_value,
    }


def _compare_digest_metric(metric: str, *, baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_value = _nested_metric_value(baseline, metric)
    current_value = _nested_metric_value(current, metric)
    if _is_unavailable(baseline_value) or _is_unavailable(current_value):
        return _unavailable_metric(
            metric,
            baseline_value=baseline_value,
            current_value=current_value,
            reason="metric_missing_or_not_collected",
        )
    classification = "unchanged" if baseline_value == current_value else "changed"
    return {
        "metric": metric,
        "classification": classification,
        "baseline_value": baseline_value,
        "current_value": current_value,
    }


def _nested_metric_value(fixture: dict[str, Any], metric: str) -> Any:
    value: Any = fixture.get("metrics", {})
    for part in metric.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _unavailable_metric(
    metric: str,
    *,
    reason: str,
    baseline_value: Any = None,
    current_value: Any = None,
) -> dict[str, Any]:
    return {
        "metric": metric,
        "classification": "unavailable",
        "baseline_value": _unavailable_value(baseline_value),
        "current_value": _unavailable_value(current_value),
        "reason": reason,
    }


def _is_available_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_unavailable(value: Any) -> bool:
    return value is None or value == "not_collected" or (
        isinstance(value, str) and value.startswith("unavailable_with_reason")
    )


def _unavailable_value(value: Any) -> Any:
    return "unavailable_with_reason:missing" if value is None else value


def _markdown_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two synthetic scalability JSON reports.")
    parser.add_argument("--baseline", required=True, type=Path, help="Baseline synthetic scalability JSON report.")
    parser.add_argument("--current", required=True, type=Path, help="Current synthetic scalability JSON report.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON comparison.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown comparison.")
    args = parser.parse_args(argv)

    try:
        report = build_comparison_from_paths(args.baseline, args.current)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_comparison(report, args.json_out)
        print(f"scalability_baseline_comparison_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"scalability_baseline_comparison_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
