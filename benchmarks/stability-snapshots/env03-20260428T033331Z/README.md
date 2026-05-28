# Env03 Stability Snapshot: 2026-04-28T03:33:31Z

This directory preserves repo-local summary evidence for a three-run live
stability probe of the existing Env03 benchmark case.

## What Was Tested

- Stability probe case: `env03`
- Benchmark case ID: `env03_identity_deny_group_escalation`
- Runner: `scripts/run_env03_second_benchmark.sh`
- Requested runs: `3`

Env03 covers the identity-policy explicit-deny blocked-path benchmark case. The
probe repeated the existing Env03 runner and evaluated each run against the
case's semantic assertions.

## What Passed

- Completed run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`
- All runs semantically stable: `true`

## Snapshot Artifacts

- Summary JSON: `benchmarks/stability-snapshots/env03-20260428T033331Z/stability_summary.json`
- Stability report: `benchmarks/stability-snapshots/env03-20260428T033331Z/stability_report.md`
- Runs JSONL: `benchmarks/stability-snapshots/env03-20260428T033331Z/stability_runs.jsonl`

## What Not To Conclude

- This snapshot is not a composite benchmark score.
- This snapshot does not prove broad IAMScope stability or production readiness.
- This snapshot does not add a new benchmark case or change Env03 semantics.
- This snapshot does not include raw live AWS archives, Terraform state,
  provider caches, `scenario.json`, `findings.json`, or `binding_metadata.json`
  run artifacts.
