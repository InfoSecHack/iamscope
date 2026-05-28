# Benchmark Phase 0 Freeze Snapshot

## Scope
- Add one tiny helper that copies selected evaluated Phase 0 outputs into a stable repo-local snapshot.
- Copy only allowlisted benchmark evaluation outputs.
- Do not copy Terraform state, provider caches, temp archives, or arbitrary files.

## Inputs
- `--runs-dir`
- `--corpus-dir`
- `--snapshot-id`
- `--out-root`

## Snapshot layout
- `benchmarks/snapshots/<snapshot-id>/README.md`
- `benchmarks/snapshots/<snapshot-id>/runs/<run-dir>/`
  - `run_manifest.json`
  - `scorer_result.json`
  - `gate_result.json`
  - `report.md` if present
- `benchmarks/snapshots/<snapshot-id>/corpus/`
  - `corpus_summary.json`
  - `promotion_decision.json`
  - `corpus_report.md`

## Safety rules
- Fail if required corpus files are missing.
- Fail if no evaluated run directories are found.
- Warn, but do not fail, if a run directory lacks `report.md`.
- Fail if any snapshot output contains Terraform state, `.terraform`, or provider directories/binaries.