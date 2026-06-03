# Controlled PassRole Active Run #1 Pre-Live Plan

## Purpose

Define the pre-live plan for one future active PassRole-to-Lambda `CreateFunction` / `DeleteFunction` validation using the test-only setup metadata.

This is a pre-live planning slice only. It does not run live AWS, call `iam:PassRole`, call Lambda APIs, call STS, create or modify resources, generate a Lambda ZIP, commit `/tmp` outputs, or change IAMScope behavior.

## Plan Status

- Validation run ID: `controlled-passrole-active-run-001-lambda-createfunction`.
- Live approval status: not approved.
- `ready_for_live_approval`: no.
- Reason: exact planned values are known from prior docs, but this slice does not run identity checks, IAM lookups, Lambda lookups, or setup verification. Region and current resource existence still require a later no-call/static preflight or explicitly approved setup confirmation.

## Planned Test-Only Values

- Account ID: `<redacted-aws-account-id>`, from prior test-only setup metadata.
- Source profile: `iamscope-passrole-positive-source`.
- Source principal ARN: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- Target role ARN: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Function name: `iamscope-passrole-active-run001`.
- Region: required before live approval; suggested only as a placeholder until confirmed: `<controlled-test-region>`.
- Expected outcome: `allowed`.
- Active evidence method: `lambda_createfunction_non_invoked_cleanup`.

## Planned Active Operations

If a later slice explicitly approves active validation, the planned operation sequence is:

1. `lambda:CreateFunction` for exactly `iamscope-passrole-active-run001`.
2. `lambda:GetFunction` or `lambda:GetFunctionConfiguration` for exactly `iamscope-passrole-active-run001`.
3. `lambda:DeleteFunction` for exactly `iamscope-passrole-active-run001`.

No invocation is part of the plan. No triggers, function URLs, event source mappings, aliases, versions, permissions, or downstream actions are part of the plan.

## Minimal No-Op ZIP Package Plan

No ZIP package is generated in this slice.

If a later no-call preflight package slice is approved, the ZIP must be created under `/tmp/iamscope-active-passrole-run-001/` only and contain minimal no-op code:

- File: `index.py`.
- Handler: `index.handler`.
- Behavior: return a static JSON-compatible object.
- Secrets: none.
- Environment variables: none.
- Dependencies: none.
- Invocation: not allowed.

## Required Source Permissions

The source principal must have only the permissions needed for this active path:

- `iam:PassRole` on `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role` with `iam:PassedToService=lambda.amazonaws.com`.
- `lambda:CreateFunction` on the single test function ARN if AWS supports that scope for `CreateFunction`; otherwise the later setup checklist must document the narrowest supported create scope.
- `lambda:GetFunction` on the single test function ARN.
- `lambda:GetFunctionConfiguration` on the single test function ARN.
- `lambda:DeleteFunction` on the single test function ARN.

The source must not have `lambda:InvokeFunction`, trigger creation, function URL creation, event source mapping creation, broad admin permissions, broad role wildcards, or unrelated service permissions for this validation.

## Target Role Trust Requirements

The target role trust must be scoped to exactly the selected service principal:

- Trusted service principal: `lambda.amazonaws.com`.
- No wildcard principal.
- No account-root trust.
- No production principal trust.
- No unrelated service principals.

The target role permissions should be empty or inert/minimal. This validation is service-mediated PassRole evidence through Lambda create acceptance, not downstream Lambda execution evidence.

## Required `/tmp` Paths

Future approved preflight or active outputs must use `/tmp/iamscope-active-passrole-run-001/` only:

- Function ZIP path if later generated: `/tmp/iamscope-active-passrole-run-001/iamscope-passrole-active-run001.zip`.
- Active plan path if later generated: `/tmp/iamscope-active-passrole-run-001/controlled-passrole-active-run-001-plan.json`.
- Live result JSON path if later approved: `/tmp/iamscope-active-passrole-run-001/controlled-passrole-active-run-001-result.json`.
- Live result Markdown path if later approved: `/tmp/iamscope-active-passrole-run-001/controlled-passrole-active-run-001-result.md`.
- Cleanup summary path if later approved: `/tmp/iamscope-active-passrole-run-001/controlled-passrole-active-run-001-cleanup-summary.json`.

No `/tmp` output may be committed by default.

## Pre-Live Static Checks Only

This slice performs only static/doc checks:

- Reads protocol/checklist docs.
- Defines planned values and required missing confirmations.
- Does not run identity checks.
- Does not run IAM lookups.
- Does not run Lambda lookups.
- Does not generate a Lambda ZIP.
- Does not call AWS.

## Values Requiring Confirmation

Before live approval, a later slice must collect or confirm:

- Controlled test region.
- Source profile resolves to `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- Source user exists and has only the required scoped permissions.
- Target role exists.
- Target role trust is scoped to `lambda.amazonaws.com` only.
- Target role permission posture is empty or inert/minimal.
- Function name `iamscope-passrole-active-run001` does not already exist, or the existing function is a known test artifact safe to clean up.
- Cleanup ownership for function, log group if created, source keys/user/policies, target role/policies, local profile, and `/tmp` files.

## Abort Conditions

Abort before any live action if any condition is true:

- Live approval is absent.
- Region is not explicitly confirmed as a controlled test region.
- Source profile identity is unconfirmed or mismatched.
- Source permissions are missing, too broad, or include invocation/trigger/function URL/event source mapping capability.
- `iam:PassRole` is not constrained to the target role and `iam:PassedToService=lambda.amazonaws.com`.
- Target role is missing, mismatched, or trusts anything beyond `lambda.amazonaws.com`.
- Target role has meaningful downstream data-plane permissions that would broaden the claim.
- Function name is already in use by an unrelated resource.
- A no-op ZIP package cannot be generated safely under `/tmp`.
- Any raw credential, raw AWS log, Terraform state, generated ZIP, or `/tmp` output would be committed.
- Cleanup cannot be attempted safely.

## Classification Rules

- `corroborated`: `CreateFunction` succeeds for the selected function and role, no invocation occurs, and cleanup succeeds or the function is verified absent.
- `denied`: a sanitized access-denied result is attributable to `iam:PassRole`, `lambda:CreateFunction`, or related caller permission.
- `configuration_error`: failure is attributable to package, runtime, handler, role propagation, naming collision, region, quota, malformed request, or setup issue rather than the PassRole authorization question.
- `environment_mismatch`: source, target role, account, trust, region, or service principal does not match the approved test-only setup.
- `inconclusive`: evidence is insufficient to distinguish authorization behavior from setup or environment behavior.
- `probe_harness_issue`: preflight or active harness fails before usable evidence exists.
- `tool_bug_candidate`: only after environment and configuration mismatch are ruled out.
- `model_limitation`: result depends on behavior intentionally outside IAMScope's modeled scope.

Avoid `pass`, `fail`, `vulnerable`, `exploited`, `production_ready`, and composite score language.

## Cleanup Plan

A later approved active validation must clean up:

- Delete function `iamscope-passrole-active-run001` immediately after recording sanitized result.
- Verify function missing with `GetFunction` or `GetFunctionConfiguration` if read permissions are available.
- Delete the CloudWatch log group only if one appears for this test function.
- Delete or disable temporary source access keys if they exist.
- Remove inline and attached policies from the test-only source user.
- Delete the test-only source user if it was created for validation.
- Remove inline and attached policies from the test-only target role.
- Delete the test-only target role if it was created for validation.
- Remove the local profile if it was created for validation.
- Remove generated `/tmp` ZIP, plan, result, and cleanup files after any approved sanitized checkpoint.

Do not delete unrelated Lambda functions, log groups, IAM users, roles, policies, profiles, or files.

## Evidence Boundary

This pre-live plan proves only that IAMScope has a bounded active validation plan for one test-only source, one test-only target role, and one Lambda `CreateFunction` attempt without invocation.

It does not prove active PassRole execution, Lambda behavior, downstream authorization, production readiness, broad exploitability, broad IAMScope correctness, real-world scalability, or all findings verified.

## Non-Claims

This plan does not claim:

- Active validation has run.
- `iam:PassRole` has been called.
- Lambda `CreateFunction`, `GetFunction`, `GetFunctionConfiguration`, or `DeleteFunction` has been called.
- Lambda has been launched or invoked.
- AWS resources have been created or modified.
- Production readiness.
- Broad runtime exploitability.
- Broad IAMScope correctness.
- Downstream authorization proof.
- Real-world scalability.
- All findings verified.
- Composite scoring or pass/fail benchmark status.

## Recommended Next Slice

Recommend exactly one next slice: collect/confirm exact active PassRole setup values and create no-call preflight package/checklist, or perform manual setup if values/resources do not exist.

That next slice must not call `iam:PassRole`, call Lambda `CreateFunction`, launch or invoke services, create production resources, commit `/tmp` outputs, add CI gates, add composite scoring, or authorize live validation without explicit approval.