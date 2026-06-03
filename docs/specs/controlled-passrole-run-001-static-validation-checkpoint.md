# Controlled PassRole Run #1 Static Validation Checkpoint

## Purpose

Record the sanitized static validation result for Controlled PassRole Run #1.

This is a docs/checkpoint slice only. It does not run live AWS, call `iam:PassRole`, call STS, launch Lambda or any service, create or modify AWS resources, generate new reports, commit `/tmp` outputs, or change IAMScope behavior.

## Run Summary

- Validation run ID: `controlled-passrole-run-001-lambda-static-allowed`.
- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- Target role: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Predicted action: `iam:PassRole`.
- Predicted outcome: `allowed`.
- Evidence method: `static_policy_trust_corroboration`.
- Observed static outcome: `allowed`.
- Outcome classification: `corroborated`.
- `iam_passrole_called=false`.
- `service_launch_attempted=false`.
- `downstream_actions_performed=false`.

## Evidence Source

The following `/tmp` outputs were inspected for this checkpoint and were not committed:

- `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-report.json`.
- `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-validation.json`.
- `/tmp/iamscope-controlled-passrole-run-001/controlled-passrole-run-001-validation.md`.

The checkpoint records only a sanitized summary. It does not paste raw `/tmp` JSON or Markdown into the repository.

## Evidence Boundary

This checkpoint proves only that the test-only PassRole setup metadata can be represented as a controlled PassRole validation report and pass schema/safety validation.

It does not prove `iam:PassRole` execution, Lambda service behavior, downstream service execution, downstream authorization, or runtime exploitability.

## Non-Claims

This checkpoint does not claim:

- `iam:PassRole` execution.
- Service launch.
- Downstream service execution.
- Production readiness.
- Broad runtime exploitability.
- Broad IAMScope correctness.
- Downstream authorization proof.
- Real-world scalability.
- All findings verified.
- Arbitrary enterprise graph correctness.
- Generic resource-policy Deny support.
- Finding-level reachability.

## Artifact Safety

Artifact safety status:

- No credentials emitted.
- No raw credentials committed.
- No `/tmp` outputs committed.
- No raw AWS logs committed.
- No Terraform state committed.
- No composite score.
- No pass/fail label.
- No generated reports committed by default.

## Relationship to Future Active Validation

Active validation is not approved by this checkpoint.

Any future active check requires a separate protocol and explicit approval. No service launch is allowed by default, and this checkpoint does not authorize live PassRole execution, Lambda creation, downstream AWS actions, or resource mutation.

## Teardown Status

Test-only IAM resources remain in place after this checkpoint.

Teardown should happen after deciding whether to stop controlled PassRole validation for this phase or separately design an active non-destructive PassRole validation method.

## Recommended Next Slice

Recommend exactly one next slice: decide whether to teardown the test-only PassRole setup or design active non-destructive PassRole validation.

That next slice should be a docs/decision slice. It must not recommend immediate live PassRole, service launch, Terraform, production testing, CI gates, composite scoring, or multiple slices at once.