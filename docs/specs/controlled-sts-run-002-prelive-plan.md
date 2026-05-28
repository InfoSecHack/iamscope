# Controlled STS Run #2 Pre-Live Plan

## Scope

This document records the pre-live plan for Controlled STS Validation Run #2 and the dry-run-only validation/simulation results for the selected `iamscope-admin` denied STS path.

This slice is pre-live planning and validation only. It does not run live AWS, call STS AssumeRole, run `live_probe`, execute a runtime probe, run Terraform, create or modify AWS resources, inspect raw AWS artifacts, copy raw artifacts, commit `/tmp` outputs, change IAMScope logic, change benchmark logic, add pass/fail benchmark labels, add composite scoring, or claim production readiness, broad IAMScope correctness, or broad runtime exploitability.

## Selected Run Metadata

- `validation_run_id`: `controlled-sts-run-002-iam-admin-arf-rt-devrole-denied`
- Environment label: `controlled-sts-denied-proof-summary`
- Source profile: `iamscope-admin`
- Exact account ID: `516525145310`
- Exact source principal ARN: `arn:aws:iam::516525145310:user/iamscope-admin`
- Exact target role ARN: `arn:aws:iam::516525145310:role/arf-rt-DevRole`
- Predicted behavior: `denied`
- Expected outcome: `denied`
- Planned action: `sts:AssumeRole`
- Planned session name prefix: `iamscope-run002`
- Planned duration seconds: `900`

## Evidence Sources

Committed sanitized evidence used for this pre-live plan:

- `docs/specs/controlled-sts-live-profile-path-selection.md`
- `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`
- `docs/archive/BENCHMARK_RUNTIME_STS_SINGLE_CASE_PROOF_PROTOCOL.md`
- `benchmarks/runtime/controlled_sts_validation_report_generator.py`
- `benchmarks/runtime/controlled_sts_validation_report_bundle.py`

The merged live-profile path selection slice selected this candidate because the source principal matches the current `iamscope-admin` profile identity from prior discovery, the target role exists by safe read-only IAM lookup, and committed sanitized evidence records the expected/observed denied outcome for this single-case proof.

## Identifier Strategy

- IAMScope-native `finding_id`: unavailable in committed sanitized evidence.
- IAMScope-native `path_id`: unavailable in committed sanitized evidence.
- Existing sanitized proof/report path ID: `runtime-sts-denied-single-case-proof`.
- Validation-layer ID: `controlled-sts-run-002-iam-admin-arf-rt-devrole-denied`.

The validation-layer ID is only a controlled validation run/probe identifier. It is not an IAMScope-native `finding_id` or `path_id` and must not be presented as one.

The existing sanitized proof/report path ID is also not claimed as an IAMScope-native finding/path identifier.

## Probe Plan And Output Paths

All generated pre-live artifacts are under `/tmp` and are not committed:

- Probe plan: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-plan.json`
- Validation JSON: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-validation.json`
- Validation Markdown: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-validation.md`
- Simulation JSON: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-simulation.json`
- Simulation Markdown: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-simulation.md`

The `/tmp` plan contains exactly one probe with the resolved source profile, account, source principal, target role, expected denied outcome, bounded duration, evidence boundary, safety notes, and future live-mode operator confirmation phrase.

## Pre-Live Validation Result

Command run:

```bash
bash scripts/validate_sts_probe_plan.sh \
  --plan /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-plan.json \
  --json-out /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-validation.json \
  --markdown-out /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-validation.md
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
  --plan /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-plan.json \
  --json-out /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-simulation.json \
  --markdown-out /tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-simulation.md
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
- The `iamscope-admin` profile no longer resolves to `arn:aws:iam::516525145310:user/iamscope-admin`.
- The target role ARN differs from `arn:aws:iam::516525145310:role/arf-rt-DevRole`.
- The target role cannot be read by safe IAM lookup immediately before live planning or execution.
- The probe plan contains more than one probe.
- `duration_seconds` exceeds `900`.
- The expected outcome changes from `denied` without a new pre-live plan.
- The validation-layer ID is represented as an IAMScope-native `finding_id` or `path_id`.
- Output paths are not under `/tmp/iamscope-controlled-sts-validation-run-002/` or another explicitly reviewed temporary location.
- The future command would perform downstream AWS actions after STS AssumeRole.
- The future command would commit raw artifacts, credentials, raw AWS logs, Terraform state, or `/tmp` outputs.
- Dry-run plan validation is not `valid` immediately before any future live execution request.

## Evidence Boundary

This pre-live slice proves only that the selected `iamscope-admin` denied STS candidate can be represented as a single dry-run STS probe plan, that the plan satisfies the current dry-run safety validator, and that the simulate-mode executor produces no-call output for that plan.

It does not add runtime STS evidence, corroborate or refute the selected prediction, inspect raw artifacts, mutate IAM, or validate any production resource.

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
- The sanitized proof/report path ID is an IAMScope-native identifier.
- IAMScope is production-ready.
- IAMScope is broadly correct.
- Broad runtime exploitability was shown.