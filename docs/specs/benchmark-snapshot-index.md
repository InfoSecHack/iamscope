# Benchmark Snapshot Index

## Scope
- Add one tiny generator that scans repo-local frozen benchmark snapshots and produces `benchmarks/snapshots/INDEX.md`.
- The index is reviewer-facing only.
- It must not change scoring, gates, IAMScope logic, or introduce any composite score.

## Inputs
- `--snapshots-dir`
- `--out`

## Behavior
- For each snapshot directory, read `corpus/corpus_summary.json` and `corpus/promotion_decision.json` if present.
- Render snapshot-level summary fields:
  - snapshot id
  - corpus decision
  - total cases evaluated
  - passes / failures
  - blocked promotions
  - artifact insufficient count
  - human review required count
  - included case IDs / run IDs
  - directly proven
  - still unknown
  - path to `README.md`
  - path to `corpus/corpus_report.md`
- If a snapshot is malformed, report it explicitly in the index instead of silently skipping it.
- If no snapshots exist, render an empty-state index.