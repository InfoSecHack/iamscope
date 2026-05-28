# Benchmark Mutation Pair Report

## Purpose

The mutation-pair report summarizes expected vs observed deltas for the known Phase 0 benchmark mutation pairs in a frozen snapshot. It is review evidence, not a scoring layer.

The current canonical input is `benchmarks/snapshots/phase0-20260429-env21/`, which contains 18 evaluated benchmark cases.

## Scope

The report covers these bounded pairs:

- Env03 -> Env16: identity Deny removed.
- Env05 -> Env09: permission boundary removed.
- Env08 -> Env10: trust condition removed.
- Env14 -> Env15: permission condition removed.
- Env13 -> Env17: SCP removed.
- Env18 -> Env19: Lambda PassRole with `iam:PassedToService` scoped away.
- Env20 -> Env21: ECS PassRole with `iam:PassedToService` scoped away.

## Inputs

The generator reads only frozen evaluated snapshot artifacts:

- `run_manifest.json`
- `scorer_result.json`
- `gate_result.json`

It does not read raw live AWS archives, Terraform state, provider caches, `collect/` directories, `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.

## Outputs

The canonical report files are:

- `benchmarks/pair-reports/phase0-20260429-env21-mutation-pairs.json`
- `benchmarks/pair-reports/phase0-20260429-env21-mutation-pairs.md`

For each pair, the JSON report emits:

- `pair_id`
- `control_family`
- `control_present_case_id`
- `control_removed_or_mutated_case_id`
- `expected_control_present_verdict`
- `expected_mutation_verdict`
- `observed_control_present_summary`
- `observed_mutation_summary`
- `pair_delta_passed`
- `evidence_boundary`

If either case is missing from the snapshot, the pair is marked incomplete and the missing case IDs are listed.

## Non-Goals

- No composite score is emitted.
- No benchmark scoring semantics are changed.
- No broad IAMScope correctness or production-readiness claim is made.
- No raw benchmark artifacts are copied.

## Regeneration

```bash
bash scripts/render_benchmark_pair_report.sh
```
