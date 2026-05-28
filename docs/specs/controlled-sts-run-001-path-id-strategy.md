# Controlled STS Run #1 Path Identifier Strategy

## Purpose

This planning slice resolves how Controlled STS Validation Run #1 should identify the selected IAMScope-predicted STS path without inventing a missing IAMScope-native `finding_id` or `path_id`.

This slice is documentation only. It does not run live AWS, call STS AssumeRole, run `live_probe`, run Terraform, inspect raw AWS artifacts, copy raw artifacts, commit `/tmp` outputs, change IAMScope logic, change benchmark logic, add pass/fail benchmark labels, add composite scoring, or claim production readiness, broad IAMScope correctness, or broad runtime exploitability.

## Resolved Sanitized Env06 Metadata

Committed sanitized benchmark evidence identifies the selected controlled environment and source/target pair:

- Environment label: `acceptance/env06_ar_validated_admin`
- Case ID: `env06_validated_admin_reachability`
- Run ID: `iamscope-benchmark-env06-20260425T003000Z`
- Account ID: `516525145310`
- Source principal ARN: `arn:aws:iam::516525145310:user/iamscope-test/env06-alice`
- Target role ARN: `arn:aws:iam::516525145310:role/iamscope-test/env06-admin`
- Predicted action: `sts:AssumeRole`
- Predicted behavior: `assumed`

Source evidence documents:

- `benchmarks/cases/env06_validated_admin_reachability.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/run_manifest.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/scorer_result.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env06-20260425T003000Z/report.md`

The sanitized evidence confirms this is the positive admin-reachability benchmark path at the case/scorer level: `admin_reachability.validated >= 1`, with zero blocked or inconclusive admin-reachability findings for the selected source and target.

## Identifier Gap

No exact IAMScope-native `finding_id` or `path_id` for this Env06 selected path is present in the committed sanitized evidence inspected for this slice.

The frozen `run_manifest.json` preserves the source/target context and points to raw archive paths under `/tmp`, including `findings.json`, but this slice does not inspect raw `/tmp` artifacts or copy them into the repository.

The controlled STS validation report schema currently requires `finding_reference.finding_id` or `finding_reference.path_id`. Therefore, a controlled STS validation report cannot honestly be created from the committed sanitized Env06 evidence alone without either finding a native identifier or adding a new sanitized evidence export that includes it.

## Option Assessment

### A. Use an existing stable finding_id/path_id

- Evidence integrity: strong if found in committed sanitized evidence.
- Reproducibility: strong.
- Synthetic/native confusion risk: low.
- Schema compatibility: compatible.
- Boundary preservation: strong.
- Result: not selected because no native Env06 `finding_id` or `path_id` was found in committed sanitized evidence.

### B. Use a deterministic synthetic validation_id only

- Evidence integrity: acceptable for naming the controlled validation run, but not for identifying an IAMScope-native path.
- Reproducibility: strong if derived from environment/source/target/action.
- Synthetic/native confusion risk: high if reused as `finding_id` or `path_id`.
- Schema compatibility: not sufficient today because the validator requires `finding_reference.finding_id` or `finding_reference.path_id`.
- Boundary preservation: only safe if the synthetic identifier is clearly labeled as a controlled validation ID and the missing native path ID remains unavailable.
- Result: not selected for Run #1 report creation because it would either fail the current schema or risk disguising a generated ID as an IAMScope-native finding/path ID.

### C. Require a new sanitized evidence export containing the native identifier

- Evidence integrity: strong if the export is sanitized, repo-reviewable, and tied to the existing Env06 source/target/action.
- Reproducibility: strong if the export records the selected native `finding_id` or `path_id`, source document, run ID, account, source ARN, target ARN, and predicted action.
- Synthetic/native confusion risk: low.
- Schema compatibility: compatible with the current controlled STS validation report schema.
- Boundary preservation: strong if no raw AWS artifacts, raw `/tmp` outputs, credentials, Terraform state, or unsanitized findings are committed.
- Result: selected strategy.

### D. Abort Controlled STS Run #1 until an exact identifier is available

- Evidence integrity: strongest defensive posture.
- Reproducibility: no run proceeds.
- Synthetic/native confusion risk: none.
- Schema compatibility: no report is created.
- Boundary preservation: strong.
- Result: retained as the abort condition if the selected sanitized export cannot be produced or reviewed.

## Selected Strategy

Use option C.

Controlled STS Run #1 must wait for a new sanitized Env06 selected-path identifier export that includes an exact IAMScope-native `finding_id` or `path_id` for the selected positive admin-reachability STS path.

The export must be sanitized and reviewable. It must not include raw AWS artifacts, raw `/tmp` proof outputs, raw collection directories, credentials, Terraform state, provider caches, or broad benchmark outputs. It should contain only the minimum metadata needed to bind the future controlled STS validation report to the selected IAMScope-native path.

Until that export exists, Run #1 is not ready for a pre-live plan or live execution.

## Identifier Fields To Use

Future controlled STS validation artifacts should use these fields:

- `validation_id`: `controlled-sts-run-001-env06-admin-reachability-assume-role`
- `environment_label`: `acceptance/env06_ar_validated_admin`
- `finding_reference.source_principal_arn`: `arn:aws:iam::516525145310:user/iamscope-test/env06-alice`
- `finding_reference.target_role_arn`: `arn:aws:iam::516525145310:role/iamscope-test/env06-admin`
- `finding_reference.expected_account_id`: `516525145310`
- `finding_reference.reasoner_or_finding_type`: `admin_reachability`
- `predicted_behavior.predicted_action`: `sts:AssumeRole`
- `predicted_behavior.predicted_outcome`: `assumed`
- `finding_reference.finding_id` or `finding_reference.path_id`: unavailable in committed sanitized evidence; must come from the new sanitized selected-path export.

`validation_id` is a controlled validation run identifier only. It is not an IAMScope-native `finding_id` or `path_id` and must not be presented as one.

## Naming Convention

Use deterministic controlled validation IDs shaped as:

`controlled-sts-run-<number>-<environment>-<claim>-<action>`

For Run #1:

`controlled-sts-run-001-env06-admin-reachability-assume-role`

Use native IAMScope identifiers only in `finding_reference.finding_id` or `finding_reference.path_id`, and only when they are present in sanitized committed evidence or a reviewed sanitized export.

## Non-Claims

This strategy does not claim:

- A live AWS call occurred.
- An STS AssumeRole call occurred.
- Runtime exploitability was proven.
- A controlled validation report was created.
- Any new finding was corroborated or refuted.
- Env06 is broadly representative.
- IAMScope is production-ready.
- IAMScope is broadly correct.
- Downstream authorization was proven.
- Resource-policy Deny support exists.
- Finding-level reachability was verified beyond the missing identifier strategy.
- Real-world scalability was shown.

## Abort Conditions

Abort pre-live planning and live execution if any of these are true:

- No sanitized native `finding_id` or `path_id` export exists for the selected Env06 path.
- The export has multiple matching Env06 findings/paths and does not mark one as primary.
- The export source ARN, target ARN, account ID, predicted action, or predicted outcome differs from the resolved Env06 metadata in this document.
- The export relies on raw `/tmp` artifacts, raw AWS logs, credentials, Terraform state, or unreviewed collection directories.
- The controlled STS validation report schema cannot represent the selected identifier without weakening its current one-finding/path boundary.
- A proposed synthetic identifier is presented as an IAMScope-native `finding_id` or `path_id`.

## Readiness

`ready_for_prelive_plan`: no.

Reason: the selected Env06 source/target/action is resolved, but the native IAMScope `finding_id` or `path_id` needed by the controlled STS validation report schema remains unavailable in committed sanitized evidence.

## Recommended Next Slice

Create Controlled STS Run #1 pre-live plan using the resolved identifier strategy and run dry-run validation/simulation only.

The pre-live plan must not authorize live execution, STS calls, Terraform, raw artifact ingestion, `/tmp` output commits, or presentation of a validation-layer ID as an IAMScope-native `finding_id` or `path_id`.

