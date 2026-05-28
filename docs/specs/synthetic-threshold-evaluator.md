# Synthetic Threshold Evaluator

## Purpose

Add a minimal report-only threshold evaluator for synthetic scalability comparison JSON reports.

The evaluator applies already-validated threshold configs to synthetic scalability baseline comparison reports and emits JSON and Markdown summaries. It is a review aid only.

## Scope

- Synthetic scalability comparison JSON reports only.
- Threshold configs validated by `benchmarks/scalability/threshold_config.py`.
- Report-only or advisory output.
- Per-threshold classifications: `satisfied`, `breached`, `unavailable`, `not_applicable`, and `malformed_threshold`.
- No frozen-corpus threshold execution.
- No CI gating, pass/fail behavior, composite score, scoring changes, fixture changes, or live AWS behavior.

## Output

The evaluator writes only to caller-provided JSON and Markdown paths, or prints JSON to stdout when no output path is supplied. Unavailable, missing, and `not_collected` values remain distinct from zero. Runtime metrics preserve machine/context caveats and are not correctness evidence.
