# Controlled PassRole Run #1 Pre-Live Static Validation Plan

## Purpose

Create a pre-live/static validation plan for Controlled PassRole Run #1 using the isolated test-only setup values, then validate only a controlled PassRole validation report.

This slice is pre-live/static report validation only. It does not run live AWS, call `iam:PassRole`, launch Lambda or any service, create or modify AWS resources, run Terraform, inspect raw AWS artifacts, copy raw artifacts, change generator or validator logic, or change IAMScope behavior.

## Validation Run Summary

- Validation run ID: `controlled-passrole-run-001-lambda-static-allowed`.
- Environment label: `controlled-passrole-run-001-test-only-static`.
- AWS profile name for future setup reference: `iamscope-passrole-positive-source`.
- Expected account ID: `<redacted-aws-account-id>`.
- Source principal ARN: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- Target role ARN: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Predicted action: `iam:PassRole`.
- Predicted behavior: `allowed`.
- Expected static outcome: `allowed`.
- Evidence method: `static_policy_trust_corroboration`.
- `iam_passrole_called`: `false`.
- `service_launch_attempted`: `false`.
- `downstream_actions_performed`: `false`.
- Session/report prefix: `iamscope-passrole-run001`.

## Generated Report and Validation Paths

- Generated report path: `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-report.json`.
- Validation JSON path: `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-validation.json`.
- Validation Markdown path: `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-validation.md`.

The `/tmp` report is not committed. The existing built-in PassRole report generator was not used for the exact Run #1 report because it emits built-in placeholder sanitized static cases rather than the explicit Run #1 account, source principal, target role, and service principal values. The exact-value report was created under `/tmp` only and validated with the existing PassRole report validator.

## Static Evidence Representation

The generated report represents the provided test-only setup metadata as one controlled PassRole validation report:

- The source-side static summary states that the selected test-only source has `iam:PassRole` scoped to the selected target role.
- The target-side static summary states that the selected target role trust allows exactly `lambda.amazonaws.com`.
- The report records no live AWS usage, no AWS calls, no `iam:PassRole` call, no service launch, and no downstream actions.
- The report uses `validation_layer_id` because no IAMScope-native finding ID or path ID exists for this test-only setup metadata.

## Validation Result

The report validator result is valid for schema and safety boundaries:

- Validator command: `bash scripts/validate_controlled_passrole_validation_report.sh --report /tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-report.json`.
- Validator result: `valid=true`.
- Outcome classification in report: `corroborated`.
- Observed static outcome in report: `allowed`.
- `iam_passrole_called=false`.
- `service_launch_attempted=false`.
- `downstream_actions_performed=false`.

This is report-shape and static-summary validation only, not active PassRole validation.

## Readiness for Live or Active Validation

Readiness for live/active validation: no.

Reasons:

- No active validation protocol has been approved for PassRole Run #1.
- No live AWS call was made in this slice.
- No `iam:PassRole` call was made in this slice.
- No Lambda or other service launch was attempted.
- The report proves only representability and schema/safety validation of the provided static setup metadata.

## Abort Conditions

Abort any live or active validation if any condition is true:

- The source profile does not resolve to `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- The target role ARN differs from `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- The target role trust does not allow exactly the selected service principal.
- The source permission is broader than `iam:PassRole` on the selected target role.
- The setup requires production accounts, production profiles, broad wildcards, or downstream service launch.
- Any credentials, raw AWS logs, raw `/tmp` outputs, Terraform state/cache/provider artifacts, or generated outputs would be committed.
- A separate active validation protocol has not been reviewed and approved.

## Evidence Boundary

This pre-live/static validation proves only that the test-only PassRole setup metadata can be represented as a controlled PassRole validation report and pass schema/safety validation.

It does not prove `iam:PassRole` execution, Lambda service behavior, downstream authorization, or runtime exploitability.

## Non-Claims

This slice does not claim:

- Live PassRole validation.
- `iam:PassRole` execution.
- Lambda creation, invocation, or service launch.
- AWS resource creation or modification.
- Downstream authorization proof.
- Production readiness.
- Broad runtime exploitability.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.
- All findings verified.
- Composite score or pass/fail benchmark label.

## Teardown Reminder

Before any future active setup or validation, confirm teardown expectations:

- Delete or disable source access keys if temporary keys are created in a separately approved setup.
- Remove the test-only source principal if temporary.
- Remove the test-only target role if temporary.
- Remove the local profile if temporary.
- Record only safe sanitized teardown summaries.
- Do not commit raw logs, credentials, `/tmp` outputs, or generated reports by default.

## Recommended Next Slice

Recommend exactly one next slice: document Controlled PassRole Run #1 static validation checkpoint, then decide whether to stop or separately design an active non-destructive PassRole validation method.

That next slice should be docs/checkpoint or docs/decision only. It must not authorize immediate live PassRole execution, service launch, AWS resource creation, Terraform apply, downstream AWS actions, CI gating, composite scoring, or multiple active-validation paths at once.