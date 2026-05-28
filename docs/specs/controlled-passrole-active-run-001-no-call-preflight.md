# Controlled PassRole Active Run #1 No-Call Preflight

## Purpose

Collect and record no-call preflight status for one future active PassRole-to-Lambda validation run.

This is a docs/preflight slice only. It does not call `iam:PassRole`, call Lambda APIs, call STS except the permitted source-profile identity check, invoke Lambda, create Lambda, create or modify AWS resources, run Terraform, commit `/tmp` outputs, or authorize live validation.

## Run Identity

- Validation run ID: `controlled-passrole-active-run-001-lambda-createfunction`.
- Expected account ID: `516525145310`.
- Confirmed region: `us-east-1`, from local AWS config for profile `iamscope-passrole-positive-source`.
- Source profile: `iamscope-passrole-positive-source`.
- Planned source principal ARN: `arn:aws:iam::516525145310:user/iamscope-passrole-positive-source`.
- Target role ARN: `arn:aws:iam::516525145310:role/iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Function name: `iamscope-passrole-active-run001`.
- Expected outcome for later active validation: `allowed`.
- Planned active operations if later approved: `lambda:CreateFunction`, `lambda:GetFunction` or `lambda:GetFunctionConfiguration`, and `lambda:DeleteFunction`.
- Invocation, triggers, function URL, event source mappings, aliases, versions, and downstream actions: not planned and not allowed in this slice.

## Read-Only Checks Performed

Only no-call/read-only checks were performed:

- Local profile region lookup for `iamscope-passrole-positive-source`: returned `us-east-1`.
- `aws sts get-caller-identity --profile iamscope-passrole-positive-source`: returned `InvalidClientTokenId`; the profile did not resolve to the expected source principal.
- `aws iam get-user --profile iamscope-admin --user-name iamscope-passrole-positive-source`: returned `NoSuchEntity`; the source user was not found by this read-only check.
- `aws iam get-role --profile iamscope-admin --role-name iamscope-passrole-target-role`: returned `NoSuchEntity`; the target role was not found by this read-only check.

No Lambda API, `iam:PassRole`, STS `AssumeRole`, resource creation, or resource modification call was made.

## Source Identity Check Result

- Expected source principal: `arn:aws:iam::516525145310:user/iamscope-passrole-positive-source`.
- Observed source profile status: unusable; `get-caller-identity` returned `InvalidClientTokenId`.
- Readiness implication: source profile identity is not confirmed and is a blocker for live approval.

## Source Policy Summary

Source policy readiness is not confirmed:

- Source user lookup returned `NoSuchEntity`.
- No source inline or attached policy was confirmed.
- `iam:PassRole` scoped to `arn:aws:iam::516525145310:role/iamscope-passrole-target-role` with `iam:PassedToService=lambda.amazonaws.com` was not confirmed.
- Lambda `CreateFunction`, `GetFunction`, `GetFunctionConfiguration`, and `DeleteFunction` permissions scoped to the single test function were not confirmed.
- Absence of `lambda:InvokeFunction`, trigger creation, function URL creation, event source mapping permissions, broad admin permissions, broad role wildcards, and unrelated service permissions was not confirmed.

## Target Trust Summary

Target role readiness is not confirmed:

- Target role lookup returned `NoSuchEntity`.
- Trust policy for `lambda.amazonaws.com` only was not confirmed.
- Absence of wildcard principal, account-root trust, production principal trust, and unrelated service principals was not confirmed.

## Target Role Permission Posture

Target role permission posture is not confirmed:

- The role was not found by the read-only `get-role` check.
- Empty, inert, or minimal target permissions were not confirmed.
- Attached and inline role policy posture was not inspected because the target role was missing.

## Function Package Preflight

A minimal no-op ZIP was generated under `/tmp` only:

- ZIP path: `/tmp/iamscope-active-passrole-run-001/iamscope-passrole-active-run001.zip`.
- Source file in ZIP: `index.py`.
- Handler shape: `index.handler`.
- Behavior: static no-op response.
- Secrets: none.
- Dependencies: none.
- Repository commit status: not committed and must not be committed by default.

The ZIP package preflight does not create a Lambda function, call a Lambda API, invoke code, create logs, or prove service behavior.

## Call and Resource Boundary

- Lambda API calls made: no.
- `iam:PassRole` called: no.
- STS `AssumeRole` called: no.
- Lambda invocation: no.
- Triggers, function URL, event source mappings: no.
- AWS resources created or modified: no.
- Terraform run: no.
- `/tmp` ZIP or outputs committed: no.

## Missing Blockers

`ready_for_live_approval`: no.

Blockers:

- Source profile does not currently resolve to the expected source principal; it returned `InvalidClientTokenId`.
- Source user `iamscope-passrole-positive-source` was not found.
- Target role `iamscope-passrole-target-role` was not found.
- Source `iam:PassRole` permission with `iam:PassedToService=lambda.amazonaws.com` was not confirmed.
- Source Lambda create/read/delete permissions scoped to the one function were not confirmed.
- Absence of source invoke/trigger/function URL/event source mapping permissions was not confirmed.
- Target role trust for exactly `lambda.amazonaws.com` was not confirmed.
- Target role empty or inert/minimal permission posture was not confirmed.
- Function name availability remains unchecked because Lambda APIs are forbidden in this slice.
- Cleanup ownership cannot be fully confirmed while source user and target role are missing.

## Abort Conditions

Abort before any active action if any of these remains true:

- Live approval is absent.
- Source profile identity does not resolve to the expected source ARN.
- Source user is missing or mismatched.
- Source permissions are missing, too broad, or include invocation, trigger, function URL, event source mapping, broad admin, broad role wildcard, or unrelated service permissions.
- `iam:PassRole` is not scoped to exactly the target role with `iam:PassedToService=lambda.amazonaws.com`.
- Target role is missing, mismatched, or trusts anything other than `lambda.amazonaws.com`.
- Target role has meaningful downstream data-plane permissions that would broaden the claim.
- Function name availability remains unchecked or the name is in use by an unrelated function.
- No-op ZIP cannot be generated safely under `/tmp`.
- Cleanup ownership for function, CloudWatch log group if created, source keys/user/policies, target role/policies, local profile, and `/tmp` files is unclear.
- Any raw credential, raw AWS log, Terraform state, generated ZIP, or `/tmp` output would be committed.

## Cleanup Ownership

If a later active slice is separately approved, cleanup ownership must be confirmed before action:

- Delete function `iamscope-passrole-active-run001` immediately if created.
- Verify function missing only if Lambda read calls are explicitly approved in that later slice.
- Delete the CloudWatch log group only if one appears for this test function.
- Delete or disable temporary source access keys if they exist.
- Remove source user inline and attached policies.
- Delete the test-only source user if created for validation.
- Remove target role inline and attached policies.
- Delete the test-only target role if created for validation.
- Remove the local profile if created for validation.
- Remove generated `/tmp` ZIP, plan, result, and cleanup files after any approved sanitized checkpoint.
- Do not delete unrelated Lambda functions, log groups, IAM users, roles, policies, profiles, or files.

## Evidence Boundary

This preflight proves only that IAMScope can record the planned active PassRole-to-Lambda setup values, perform permitted no-call/read-only checks, identify current setup blockers, and create a minimal no-op ZIP under `/tmp` without committing it.

It does not prove `iam:PassRole` execution, Lambda `CreateFunction` behavior, Lambda invocation behavior, downstream authorization, production readiness, broad exploitability, broad IAMScope correctness, real-world scalability, or all findings verified.

## Non-Claims

This preflight does not claim:

- Live validation has run.
- `iam:PassRole` has been called.
- Lambda `CreateFunction`, `GetFunction`, `GetFunctionConfiguration`, or `DeleteFunction` has been called.
- Lambda has been created, launched, or invoked.
- Triggers, function URLs, or event source mappings exist.
- AWS resources have been created or modified.
- Source and target setup is currently ready.
- Production readiness.
- Broad runtime exploitability.
- Broad IAMScope correctness.
- Downstream authorization proof.
- Real-world scalability.
- All findings verified.
- Composite scoring or pass/fail benchmark status.

## Recommended Next Slice

Recommend exactly one next slice: resolve active PassRole preflight blockers.

That next slice must not call `iam:PassRole`, call Lambda `CreateFunction`, invoke Lambda, create production resources, commit `/tmp` outputs, add CI gates, add composite scoring, or authorize live validation without separate explicit approval.