# Env05 Stability Snapshot: 2026-04-28T21:01:17Z

This directory preserves repo-local summary evidence for a three-run live
stability probe of the existing Env05 benchmark case.

## What Was Tested

- Stability probe case: `env05`
- Benchmark case ID: `env05_permission_boundary_blocked_chain`
- Runner: `scripts/run_env05_first_benchmark.sh`
- Requested runs: `3`

Env05 covers the permission-boundary blocked assume-role/admin chain benchmark
case. The probe repeated the existing Env05 runner and evaluated each run
against the case's semantic assertions.

## What Passed

- Completed run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`
- All runs semantically stable: `true`

## Snapshot Artifacts

- Summary JSON: `benchmarks/stability-snapshots/env05-20260428T210117Z/stability_summary.json`
- Stability report: `benchmarks/stability-snapshots/env05-20260428T210117Z/stability_report.md`
- Runs JSONL: `benchmarks/stability-snapshots/env05-20260428T210117Z/stability_runs.jsonl`

## What Not To Conclude

- This snapshot is not a composite benchmark score.
- This snapshot does not prove broad IAMScope stability or production readiness.
- This snapshot does not add a new benchmark case or change Env05 semantics.
- This snapshot does not include raw live AWS archives, Terraform state,
  provider caches, `scenario.json`, `findings.json`, `binding_metadata.json`,
  collect directories, or run logs.
