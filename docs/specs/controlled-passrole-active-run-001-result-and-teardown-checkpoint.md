# Controlled PassRole Active Run #1 Result and Teardown Checkpoint

## Purpose

Record the sanitized result and teardown for active controlled PassRole-to-Lambda Run #1.

This is a docs/checkpoint slice only. It does not run live AWS, call `iam:PassRole`, call Lambda APIs, call STS, launch or invoke Lambda, create or modify AWS resources, generate new reports, commit `/tmp` outputs, commit raw AWS artifacts, or change IAMScope behavior.

## Run Summary

- Validation run ID: `controlled-passrole-active-run-001-lambda-createfunction`.
- Source principal: `arn:aws:iam::516525145310:user/iamscope-passrole-active-source`.
- Target role: `arn:aws:iam::516525145310:role/iamscope-passrole-active-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Function name: `iamscope-passrole-active-run001`.
- Region: `us-east-1`.
- Runtime: `python3.12`.
- Handler: `lambda_function.handler`.
- Expected behavior: `allowed`.
- Observed behavior: `CreateFunction` accepted the selected target role for the selected Lambda function.
- `GetFunctionConfiguration`: succeeded.
- `DeleteFunction`: succeeded with status code `204`.
- Post-delete `GetFunction`: returned `ResourceNotFoundException`, confirming the function was missing after cleanup.
- Outcome classification: `corroborated`.

## What Happened

- A Lambda function named `iamscope-passrole-active-run001` was created as a test-only validation artifact.
- The function was not invoked.
- The function was deleted immediately after the active result was observed.
- Cleanup was verified by a post-delete `GetFunction` result showing `ResourceNotFoundException`.
- No triggers, function URL, event source mappings, aliases, versions, or downstream actions were created or used.
- Output remained under `/tmp` and is not committed in this checkpoint.

## Evidence Boundary

This checkpoint proves only that one test-only source principal could perform one service-mediated Lambda `CreateFunction` operation using one test-only target role trusted by `lambda.amazonaws.com` under explicit controlled conditions, and that the test function was deleted afterward.

It does not prove Lambda invocation behavior, downstream authorization, production readiness, broad runtime exploitability, broad IAMScope correctness, arbitrary enterprise graph correctness, real-world scalability, or all findings verified.

## What This Does Not Prove

This checkpoint does not prove:

- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Downstream Lambda execution.
- Lambda invocation behavior.
- Downstream authorization.
- Arbitrary enterprise graph correctness.
- All findings verified.
- Real-world scalability.
- Resource-policy Deny support.
- Finding-level reachability.
- Composite scoring or pass/fail benchmark status.

## Artifact Safety

- No raw credentials committed.
- No `/tmp` outputs committed.
- No raw AWS logs committed.
- No Terraform state committed.
- No generated bundle committed.
- No Lambda ZIP committed.
- No composite score.
- No pass/fail label.
- Only sanitized summary fields are recorded in this checkpoint.

## Teardown Summary

Observed teardown verification:

- `aws lambda get-function` for `iamscope-passrole-active-run001` returned `ResourceNotFoundException`; the function is missing.
- `aws iam get-user` for `iamscope-passrole-active-source` returned `NoSuchEntity`; the source user is missing.
- `aws iam get-role` for `iamscope-passrole-active-target-role` returned `NoSuchEntity`; the target role is missing.
- `aws sts get-caller-identity` for profile `iamscope-passrole-active-source` returned `InvalidClientTokenId`; the temporary local profile is no longer usable.
- Temporary access key status: invalidated or removed, as indicated by the unusable profile and missing source user.
- Test resources are no longer present or usable based on the observed teardown verification.

## Relationship to Previous Evidence

- This result is stronger than static PassRole report validation because it observed service-mediated AWS behavior for one controlled Lambda `CreateFunction` operation.
- This remains one controlled test-only result and is not broad PassRole correctness.
- This complements the earlier controlled STS validation work but does not replace broader validation, benchmark, or reasoning limitations.
- Static PassRole report validation remains useful for schema/safety representation; this checkpoint records an active service-mediated result under narrower live conditions.

## Non-Claims

This checkpoint does not claim:

- Production readiness.
- Broad exploitability.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Downstream Lambda execution.
- Lambda invocation behavior.
- Downstream authorization proof.
- Real-world scalability.
- All findings verified.
- Composite benchmark scoring.
- Pass/fail benchmark labeling.

## Recommended Next Slice

Recommend exactly one next slice: update supported/unsupported evidence matrix with active PassRole-to-Lambda result.

That next slice should be docs-only unless separately scoped otherwise. It must not recommend another live PassRole run immediately, service invocation, broader live validation, production testing, CI gates, composite scoring, or multiple slices at once.