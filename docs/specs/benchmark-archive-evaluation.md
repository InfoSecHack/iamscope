# Benchmark Archive Evaluation

## Scope
- Add one tiny Phase 0 end-to-end command that consumes a completed benchmark archive.
- The command runs: ingest -> validate -> score -> gates -> render report.
- It must not change IAMScope logic or broaden Phase 0 scoring.

## Inputs
- `--case-id`
- `--archive-dir`
- `--out-dir`

## Outputs
- `run_manifest.json`
- `scorer_result.json`
- `gate_result.json`
- `report.md`

## Exit behavior
- Exit `0` only when scoring passes and promotion is not blocked.
- Exit nonzero when semantic assertions fail, artifact sufficiency fails, or any Phase 0 gate blocks promotion.
- Required archive ingestion failures still fail immediately with a clear error.

## Supported Phase 0 cases
- `env03_identity_deny_group_escalation`
- `env05_permission_boundary_blocked_chain`
- `env06_validated_admin_reachability`