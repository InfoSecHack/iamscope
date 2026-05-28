# Benchmark Phase 0 Materialization

## Scope
- Add one tiny helper that materializes explicit Env03 / Env05 / Env06 / Env07 / Env08 / Env09 / Env10 / Env11 / Env12 / Env13 / Env14 / Env15 / Env16 archives into repo-local Phase 0 evaluation outputs.
- Then run the existing corpus summarizer over the chosen run output root.
- Do not change scoring, gates, or IAMScope logic.

## Inputs
- `--env03-archive`
- `--env05-archive`
- `--env06-archive`
- `--env07-archive`
- `--env08-archive`
- `--env09-archive`
- `--env10-archive`
- `--env11-archive`
- `--env12-archive`
- `--env13-archive`
- `--env14-archive`
- `--env15-archive`
- `--env16-archive`
- `--out-root`
- `--corpus-out`

## Behavior
- Each supplied archive is evaluated into:
  - `benchmarks/runs/env03-<run_id>/`
  - `benchmarks/runs/env05-<run_id>/`
  - `benchmarks/runs/env06-<run_id>/`
  - `benchmarks/runs/env07-<run_id>/`
  - `benchmarks/runs/env08-<run_id>/`
  - `benchmarks/runs/env09-<run_id>/`
  - `benchmarks/runs/env10-<run_id>/`
  - `benchmarks/runs/env11-<run_id>/`
  - `benchmarks/runs/env12-<run_id>/`
  - `benchmarks/runs/env13-<run_id>/`
  - `benchmarks/runs/env14-<run_id>/`
  - `benchmarks/runs/env15-<run_id>/`
  - `benchmarks/runs/env16-<run_id>/`
- Omitted archives are reported clearly and do not fail the command.
- The helper exits nonzero if any evaluation fails.
- After successful evaluations, it runs the existing corpus summarizer over `--out-root`.
- The helper exits nonzero if corpus promotion is blocked.
- `hold_review` remains a successful completion state.
