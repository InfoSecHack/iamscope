# Controlled STS Run #1 Pre-Live Plan

## Scope

This document records the pre-live plan for Controlled STS Validation Run #1 and the dry-run-only validation/simulation results for the single selected Env06 STS path.

This slice is pre-live planning and validation only. It does not run live AWS, call STS AssumeRole, run `live_probe`, execute a runtime probe, run Terraform, create or modify AWS resources, inspect raw AWS artifacts, copy raw artifacts, commit `/tmp` outputs, change IAMScope logic, change benchmark logic, add pass/fail benchmark labels, add composite scoring, or claim production readiness, broad IAMScope correctness, or broad runtime exploitability.

## Selected Run Metadata

- `validation_run_id`: `controlled-sts-run-001-env06-admin-reachability-assume-role`
- Environment label: `acceptance/env06_ar_validated_admin`
- Case ID: `env06_validated_admin_reachability`
- Benchmark run ID: `iamscope-benchmark-env06-20260425T003000Z`
- Exact account ID: `516525145310`
- Exact source principal ARN: `arn:aws:iam::516525145310:user/iamscope-test/env06-alice`
- Exact target role ARN: `arn:aws:iam::516525145310:role/iamscope-test/env06-admin`
- Predicted behavior: `assumed`
- Expected outcome: `assumed`
- Planned action: `sts:AssumeRole`
- Planned AWS profile label in probe plan: `iamscope-test`
- Planned session name prefix: `iamscope-run001`
- Planned duration seconds: `900`

## Evidence Sources

Committed sanitized evidence used for this pre-live plan:

- `docs/specs/controlled-sts-run-001-path-id-strategy.md`
- `benchmarks/cases/env06_validated_admin_reachability.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/run_manifest.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/scorer_result.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/report.md`

The committed sanitized evidence confirms an Env06 positive admin-reachability claim for the selected source/target pair at the benchmark case and scorer level. This pre-live slice does not inspect raw `/tmp` benchmark archives or raw `findings.json` artifacts.

## Identifier Strategy

- IAMScope-native `finding_id`: unavailable in committed sanitized evidence.
- IAMScope-native `path_id`: unavailable in committed sanitized evidence.
- Validation-layer ID: `controlled-sts-run-001-env06-admin-reachability-assume-role`.
- Derivation: `controlled-sts-run-001` + `env06` + `admin-reachability` + `assume-role`.

The validation-layer ID is only a controlled validation run/probe identifier. It is not an IAMScope-native `finding_id` or `path_id` and must not be presented as one.

## Probe Plan And Output Paths

All generated pre-live artifacts are under `/tmp` and are not committed:

- Probe plan: `/tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-plan.json`
- Validation JSON: `/tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-validation.json`
- Validation Markdown: `/tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-validation.md`
- Simulation JSON: `/tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-simulation.json`
- Simulation Markdown: `/tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-simulation.md`

The `/tmp` plan contains exactly one probe with the resolved account, source principal, target role, expected outcome, bounded duration, evidence boundary, safety notes, and future live-mode operator confirmation phrase.

## Pre-Live Validation Result

Command run:

```bash
bash scripts/validate_sts_probe_plan.sh \
  --plan /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-plan.json \
  --json-out /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-validation.json \
  --markdown-out /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-validation.md
```

Result summary:

- Report type: `sts_probe_plan_validation`
- Probe count: `1`
- Validation classification: `valid`
- Reason: `plan satisfies dry-run safety validation`
- Live AWS used: `false`
- AWS calls made: `false`

## Simulation Result

Command run:

```bash
bash scripts/run_sts_probe_executor.sh \
  --mode simulate \
  --plan /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-plan.json \
  --json-out /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-simulation.json \
  --markdown-out /tmp/iamscope-controlled-sts-validation-run-001/controlled-sts-run-001-simulation.md
```

Result summary:

- Report type: `sts_probe_executor_simulation`
- Mode: `simulate`
- Execution classification: `simulated_not_executed`
- Reasons:
  - `probe plan satisfies dry-run validation`
  - `live STS execution is intentionally not implemented in this skeleton`
- Live AWS used: `false`
- AWS calls made: `false`
- STS AssumeRole called: `false`
- Credentials obtained: `false`

## Live Approval Status

- Live approval status: not approved.
- Ready to request explicit live approval: yes.
- Ready to execute live without a separate approval step: no.

Any future live slice must show the selected source principal, target role, expected behavior, output paths, abort conditions, and confirmation phrase again before calling STS.

## Abort Conditions

Abort any future live execution if any of these are true:

- The operator has not explicitly approved live execution for this exact single probe.
- The source principal ARN, target role ARN, or expected account ID differs from this document.
- The probe plan contains more than one probe.
- `duration_seconds` exceeds `900`.
- The validation-layer ID is represented as an IAMScope-native `finding_id` or `path_id`.
- The selected path is changed from Env06 without a new pre-live plan.
- Output paths are not under `/tmp/iamscope-controlled-sts-validation-run-001/` or another explicitly reviewed temporary location.
- The future command would perform downstream AWS actions after STS AssumeRole.
- The future command would commit raw artifacts, credentials, raw AWS logs, Terraform state, or `/tmp` outputs.
- Dry-run plan validation is not `valid` immediately before any future live execution request.

## Evidence Boundary

This pre-live slice proves only that the selected Env06 source/target metadata can be represented as a single dry-run STS probe plan, that the plan satisfies the current dry-run safety validator, and that the simulate-mode executor produces no-call output for that plan.

It does not add runtime STS evidence, corroborate or refute the selected IAMScope prediction, inspect raw benchmark artifacts, or validate any production resource.

## Non-Claims

This pre-live plan does not claim:

- A live AWS call occurred.
- STS AssumeRole was called.
- `live_probe` was executed.
- Runtime exploitability was proven.
- Downstream authorization was proven.
- Any new finding was corroborated or refuted.
- IAMScope-native `finding_id` or `path_id` was recovered.
- The validation-layer ID is an IAMScope-native identifier.
- IAMScope is production-ready.
- IAMScope is broadly correct.
- Resource-policy Deny support exists.
- Real-world scalability was shown.
