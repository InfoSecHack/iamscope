# Env21 Stability Snapshot: 2026-05-06T18:48:37Z

This directory preserves repo-local summary evidence for a three-run live
stability probe of the existing Env21 benchmark case.

## What Was Tested

- Stability probe case: `env21`
- Benchmark case ID: `env21_ecs_passedtoservice_scoped_away_nonvalidated`
- Runner: `scripts/run_env21_ecs_passedtoservice_scoped_away_benchmark.sh`
- Requested runs: `3`

Env21 covers the ECS PassRole `iam:PassedToService` scoped-away benchmark case.
The probe repeated the existing Env21 runner and evaluated each run against the
case's semantic assertions.

## What Passed

- Completed run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`
- All runs semantically stable: `true`

## Snapshot Artifacts

- Summary JSON: `benchmarks/stability-snapshots/env21-20260506T184837Z/stability_summary.json`
- Stability report: `benchmarks/stability-snapshots/env21-20260506T184837Z/stability_report.md`
- Runs JSONL: `benchmarks/stability-snapshots/env21-20260506T184837Z/stability_runs.jsonl`

## What Not To Conclude

- This snapshot is not a composite benchmark score.
- This snapshot does not prove broad IAMScope stability or production readiness.
- This snapshot does not add a new benchmark case or change Env21 semantics.
- This snapshot does not include raw live AWS archives, Terraform state,
  provider caches, `scenario.json`, `findings.json`, `binding_metadata.json`,
  collect directories, or run logs.
