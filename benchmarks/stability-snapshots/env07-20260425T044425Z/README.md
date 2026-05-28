# Env07 Stability Snapshot: 20260425T044425Z

## What Was Tested
- Case: `env07`
- Case ID: `env07_validated_non_admin_reachability`
- Probe shape: 3 repeated live benchmark runs using the existing Env07 runner.
- Target signal: non-admin AssumeRole structure remains present and does not produce a false admin reachability claim.

## Result
- Requested runs: `3`
- Completed run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`
- All runs semantically stable: `true`

## Copied Artifacts
- `stability_summary.json`
- `stability_report.md`
- `stability_runs.jsonl`

## Evidence Boundary
- This proves only that Env07's target semantics were stable across these three live runs.
- It does not prove broad IAMScope stability.
- It does not prove stability for admin-positive cases, deny/boundary cases, trust-condition cases, or SCP/Organizations cases.
- It does not copy raw benchmark archives, Terraform state, provider caches, or live AWS artifact directories.
