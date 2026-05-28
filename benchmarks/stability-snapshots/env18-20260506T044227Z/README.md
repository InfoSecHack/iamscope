# Env18 Stability Snapshot: 2026-05-06T04:42:27Z

This directory preserves repo-local summary evidence for a three-run live
stability probe of the existing Env18 benchmark case.

## What Was Tested

- Stability probe case: `env18`
- Benchmark case ID: `env18_lambda_passrole_validated`
- Runner: `scripts/run_env18_lambda_passrole_benchmark.sh`
- Requested runs: `3`

Env18 covers the validated Lambda PassRole benchmark case. The probe repeated
the existing Env18 runner and evaluated each run against the case's semantic
assertions.

## What Passed

- Completed run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`
- All runs semantically stable: `true`

## Snapshot Artifacts

- Summary JSON: `benchmarks/stability-snapshots/env18-20260506T044227Z/stability_summary.json`
- Stability report: `benchmarks/stability-snapshots/env18-20260506T044227Z/stability_report.md`
- Runs JSONL: `benchmarks/stability-snapshots/env18-20260506T044227Z/stability_runs.jsonl`

## What Not To Conclude

- This snapshot is not a composite benchmark score.
- This snapshot does not prove broad IAMScope stability or production readiness.
- This snapshot does not add a new benchmark case or change Env18 semantics.
- This snapshot does not include raw live AWS archives, Terraform state,
  provider caches, `scenario.json`, `findings.json`, `binding_metadata.json`,
  collect directories, or run logs.
