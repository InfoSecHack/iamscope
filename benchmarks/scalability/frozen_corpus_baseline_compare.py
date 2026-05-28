from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json

REPORT_TYPE = "frozen_corpus_baseline_comparison"
SCHEMA_VERSION = "0.1"
FROZEN_CORPUS_REPORT_TYPE = "frozen_corpus_batch_report"
EVIDENCE_BOUNDARY = (
    "Offline frozen-corpus baseline comparison only; this does not create new live AWS evidence, "
    "prove real-world scalability, prove production readiness, or expand IAMScope semantic correctness claims."
)
BATCH_SUMMARY_KEYS = (
    "cases",
    "total_cases_evaluated",
    "passes",
    "failures",
    "artifact_insufficient_count",
    "blocked_promotions",
    "human_review_required_count",
)
CASE_COMPARISON_FIELDS = (
    "run_id",
    "family",
    "benchmark_date",
    "environment",
    "authority",
    "confidence",
    "scenario_validation",
    "score_passed",
    "artifact_sufficient",
    "promotion_blocked",
    "human_review_required",
    "assertion_count",
    "assertion_passed_count",
    "defect_count",
    "defect_classes",
)


def build_comparison(
    baseline_report: dict[str, Any],
    current_report: dict[str, Any],
    *,
    baseline_path: str | Path,
    current_path: str | Path,
) -> dict[str, Any]:
    _validate_frozen_corpus_report(baseline_report, label="baseline")
    _validate_frozen_corpus_report(current_report, label="current")

    baseline_cases = _cases_by_id(baseline_report)
    current_cases = _cases_by_id(current_report)
    case_ids = sorted(set(baseline_cases) | set(current_cases))
    case_comparisons = [
        _compare_case(case_id, baseline=baseline_cases.get(case_id), current=current_cases.get(case_id))
        for case_id in case_ids
    ]

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "baseline_path": str(baseline_path),
        "current_path": str(current_path),
        "input_report_type": FROZEN_CORPUS_REPORT_TYPE,
        "report_only": True,
        "thresholds_used": False,
        "live_aws_used": False,
        "metadata_comparisons": _metadata_comparisons(baseline_report, current_report),
        "batch_summary_comparisons": _batch_summary_comparisons(baseline_report, current_report),
        "case_comparisons": case_comparisons,
        "case_presence_summary": _case_presence_summary(case_comparisons),
        "unavailable_metric_comparisons": _unavailable_metric_comparisons(baseline_report, current_report),
        "caveat_comparison": _compare_list_field("caveats", baseline_report, current_report),
        "caveats": [
            "offline_only: compares already-rendered frozen-corpus batch JSON reports",
            "report_only: comparison emits deltas and classifications only",
            "no_thresholds: no threshold gating is applied",
            "no_pass_fail: this report does not grade, rank, or gate changes",
            "no_raw_artifacts: raw live artifacts, Terraform artifacts, and collect directories are out of scope",
            "no_new_live_aws_evidence: comparison does not collect from AWS or require cloud credentials",
            "unavailable_metrics_are_not_zero: missing and not_collected metrics are classified unavailable",
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
        "# IAMScope Frozen Corpus Baseline Comparison",
        "",
        "Offline-only comparison of frozen-corpus batch JSON reports.",
        "",
        "Report-only: this comparison emits deltas and classifications only.",
        "",
        "No thresholds are applied by default.",
        "",
        "No composite score is emitted. This report does not grade, rank, or gate changes.",
        "",
        "No new live AWS evidence is created. This report compares already-rendered offline reports only.",
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
        f"- Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        "",
        "## Batch Summary Comparison",
        "",
        "| Metric | Classification | Baseline | Current | Delta |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for item in report["batch_summary_comparisons"]:
        lines.append(
            "| {metric} | {classification} | {baseline} | {current} | {delta} |".format(
                metric=item["metric"],
                classification=item["classification"],
                baseline=_markdown_value(item.get("baseline_value")),
                current=_markdown_value(item.get("current_value")),
                delta=_markdown_value(item.get("delta")),
            )
        )

    lines.extend(
        [
            "",
            "## Per-Case Comparison",
            "",
            "| Case ID | Presence | Classification | Changed fields |",
            "| --- | --- | --- | --- |",
        ]
    )
    for item in report["case_comparisons"]:
        lines.append(
            "| {case_id} | {presence} | {classification} | {changed_fields} |".format(
                case_id=item["case_id"],
                presence=item["presence"],
                classification=item["classification"],
                changed_fields=", ".join(item["changed_fields"]) if item["changed_fields"] else "",
            )
        )

    presence = report["case_presence_summary"]
    lines.extend(
        [
            "",
            "## Added / Removed / Matched Cases",
            "",
            f"- Added: `{', '.join(presence['added']) if presence['added'] else 'none'}`.",
            f"- Removed: `{', '.join(presence['removed']) if presence['removed'] else 'none'}`.",
            f"- Matched: `{presence['matched_count']}`.",
        ]
    )

    unavailable = report["unavailable_metric_comparisons"]
    if unavailable:
        lines.extend(
            [
                "",
                "## Unavailable Metrics",
                "",
                "| Metric | Classification | Reason |",
                "| --- | --- | --- |",
            ]
        )
        for item in unavailable:
            lines.append(f"| {item['metric']} | {item['classification']} | {item['reason']} |")

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- Offline-only: compares already-rendered frozen-corpus batch JSON reports.",
            "- Report-only: no threshold gating is applied.",
            "- No thresholds: thresholds are not used by default.",
            "- No pass/fail: this is not a release gate.",
            "- No composite score: metrics and case deltas remain separate.",
            "- No raw artifact comparison: raw live artifacts, Terraform artifacts, and collect directories are out of scope.",
            "- No new live AWS evidence is created.",
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


def _validate_frozen_corpus_report(report: dict[str, Any], *, label: str) -> None:
    if report.get("report_type") != FROZEN_CORPUS_REPORT_TYPE:
        raise ValueError(
            f"{label} report_type must be {FROZEN_CORPUS_REPORT_TYPE!r}; got {report.get('report_type')!r}"
        )
    if not isinstance(report.get("cases"), list):
        raise ValueError(f"{label} report is missing cases list")


def _load_existing_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} input path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"{label} input path is not a file: {path}")
    return load_json(path)


def _metadata_comparisons(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _compare_value("report_type", baseline.get("report_type"), current.get("report_type")),
        _compare_value("offline_only", baseline.get("offline_only"), current.get("offline_only")),
        _compare_value("live_aws_used", baseline.get("live_aws_used"), current.get("live_aws_used")),
        _compare_value("snapshot_path", baseline.get("snapshot_path"), current.get("snapshot_path")),
    ]


def _batch_summary_comparisons(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    baseline_summary = baseline.get("batch_summary", {})
    current_summary = current.get("batch_summary", {})
    return [_compare_numeric(key, baseline_summary.get(key), current_summary.get(key)) for key in BATCH_SUMMARY_KEYS]


def _cases_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for case in report.get("cases", []):
        if isinstance(case, dict) and case.get("case_id") is not None:
            cases[str(case["case_id"])] = case
    return cases


def _compare_case(case_id: str, *, baseline: dict[str, Any] | None, current: dict[str, Any] | None) -> dict[str, Any]:
    if baseline is None:
        return {
            "case_id": case_id,
            "presence": "added",
            "classification": "added",
            "field_comparisons": [],
            "changed_fields": [],
        }
    if current is None:
        return {
            "case_id": case_id,
            "presence": "removed",
            "classification": "removed",
            "field_comparisons": [],
            "changed_fields": [],
        }

    field_comparisons = [
        _compare_value(field, baseline.get(field), current.get(field)) for field in CASE_COMPARISON_FIELDS
    ]
    changed_fields = [item["field"] for item in field_comparisons if item["classification"] == "changed"]
    unavailable_fields = [item["field"] for item in field_comparisons if item["classification"] == "unavailable"]
    classification = "changed" if changed_fields else "unchanged"
    if not changed_fields and unavailable_fields and len(unavailable_fields) == len(field_comparisons):
        classification = "unavailable"
    return {
        "case_id": case_id,
        "presence": "matched",
        "classification": classification,
        "field_comparisons": field_comparisons,
        "changed_fields": changed_fields,
    }


def _case_presence_summary(case_comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    added = sorted(item["case_id"] for item in case_comparisons if item["presence"] == "added")
    removed = sorted(item["case_id"] for item in case_comparisons if item["presence"] == "removed")
    matched = sorted(item["case_id"] for item in case_comparisons if item["presence"] == "matched")
    return {
        "added": added,
        "removed": removed,
        "matched_count": len(matched),
    }


def _unavailable_metric_comparisons(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    baseline_metrics = _unavailable_metric_map(baseline)
    current_metrics = _unavailable_metric_map(current)
    metrics = sorted(set(baseline_metrics) | set(current_metrics))
    comparisons = []
    for metric in metrics:
        baseline_reason = baseline_metrics.get(metric)
        current_reason = current_metrics.get(metric)
        comparisons.append(
            {
                "metric": metric,
                "classification": "unchanged" if baseline_reason == current_reason else "changed",
                "baseline_reason": baseline_reason or "unavailable_with_reason:missing",
                "current_reason": current_reason or "unavailable_with_reason:missing",
                "reason": "unavailable_metric_metadata_comparison",
            }
        )
    return comparisons


def _unavailable_metric_map(report: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in report.get("unavailable_metrics", []):
        if isinstance(item, dict) and item.get("metric") is not None:
            result[str(item["metric"])] = str(item.get("reason", "unavailable_with_reason:reason_missing"))
    return result


def _compare_list_field(field: str, baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_value = baseline.get(field)
    current_value = current.get(field)
    if not isinstance(baseline_value, list) or not isinstance(current_value, list):
        return _unavailable_comparison(field, baseline_value, current_value)
    return {
        "field": field,
        "classification": "unchanged" if baseline_value == current_value else "changed",
        "baseline_count": len(baseline_value),
        "current_count": len(current_value),
        "added": sorted(str(item) for item in set(current_value) - set(baseline_value)),
        "removed": sorted(str(item) for item in set(baseline_value) - set(current_value)),
    }


def _compare_numeric(field: str, baseline_value: Any, current_value: Any) -> dict[str, Any]:
    if not _is_available_number(baseline_value) or not _is_available_number(current_value):
        return _unavailable_comparison(field, baseline_value, current_value)
    delta = current_value - baseline_value
    return {
        "metric": field,
        "classification": "unchanged" if delta == 0 else "changed",
        "baseline_value": baseline_value,
        "current_value": current_value,
        "delta": delta,
    }


def _compare_value(field: str, baseline_value: Any, current_value: Any) -> dict[str, Any]:
    if _is_unavailable(baseline_value) or _is_unavailable(current_value):
        return _unavailable_comparison(field, baseline_value, current_value)
    return {
        "field": field,
        "classification": "unchanged" if baseline_value == current_value else "changed",
        "baseline_value": baseline_value,
        "current_value": current_value,
    }


def _unavailable_comparison(field: str, baseline_value: Any, current_value: Any) -> dict[str, Any]:
    return {
        "field": field,
        "metric": field,
        "classification": "unavailable",
        "baseline_value": _unavailable_value(baseline_value),
        "current_value": _unavailable_value(current_value),
        "reason": "field_missing_or_unavailable",
    }


def _is_available_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_unavailable(value: Any) -> bool:
    return (
        value is None
        or value == "not_collected"
        or (isinstance(value, str) and value.startswith("unavailable_with_reason"))
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
    parser = argparse.ArgumentParser(description="Compare two frozen-corpus batch JSON reports.")
    parser.add_argument("--baseline", required=True, type=Path, help="Baseline frozen-corpus batch JSON report.")
    parser.add_argument("--current", required=True, type=Path, help="Current frozen-corpus batch JSON report.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON comparison.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown comparison.")
    args = parser.parse_args(argv)

    try:
        report = build_comparison_from_paths(args.baseline, args.current)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_comparison(report, args.json_out)
        print(f"frozen_corpus_baseline_comparison_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"frozen_corpus_baseline_comparison_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
