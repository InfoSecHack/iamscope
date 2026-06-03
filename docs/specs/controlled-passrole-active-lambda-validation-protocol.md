# Controlled PassRole Active Lambda Validation Protocol

## Purpose

Define the exact active validation procedure for one test-only PassRole-to-Lambda case using `lambda:CreateFunction` as the bounded service API path.

This is a docs/design slice only. It does not run AWS commands, call `iam:PassRole`, create Lambda functions, create or modify AWS resources, generate reports, or perform active validation.

## Validation Question

Can one explicitly test-only source principal create one minimal Lambda function by passing one explicitly test-only target role to `lambda.amazonaws.com`, under controlled conditions, and then immediately clean up without invocation or downstream actions?

The expected active result for this protocol is `allowed` only if Lambda accepts the `CreateFunction` request using the selected role and the function can be deleted during cleanup.

## Selected Test-Only Case

- Validation run ID: `controlled-passrole-run-001-lambda-createfunction-active`.
- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
- Source local profile: `iamscope-passrole-positive-source`.
- Target role: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Expected account ID: `<redacted-aws-account-id>`.
- Predicted action: `iam:PassRole`.
- Predicted outcome: `allowed`.
- Active evidence method: `lambda_createfunction_non_invoked_cleanup`.
- Function/report prefix: `iamscope-passrole-run001`.

## Required Source Permissions

The source principal must have only the permissions needed for the active validation path:

- `iam:PassRole` on exactly `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`, constrained with `iam:PassedToService=lambda.amazonaws.com`.
- `lambda:CreateFunction` on exactly the selected test function ARN pattern if AWS supports that resource scope for the selected call context; if service semantics require broader create scope, the future setup checklist must document the narrowest supported alternative and why.
- `lambda:GetFunction` on exactly the selected test function ARN pattern.
- `lambda:GetFunctionConfiguration` on exactly the selected test function ARN pattern.
- `lambda:DeleteFunction` on exactly the selected test function ARN pattern.
- Optional `iam:GetRole` on the selected target role for pre-flight trust inspection if separately approved.

The source should not have admin permissions, wildcard Lambda resource scope beyond a documented AWS API limitation for `CreateFunction`, broad role scope, `lambda:InvokeFunction`, event source permissions, function URL permissions, trigger management permissions, log read/write permissions beyond what AWS implicitly performs for the service, or unrelated service permissions.

## Required Target Role Trust

The target role trust policy must allow exactly the selected service principal:

- Trusted service principal: `lambda.amazonaws.com`.
- No wildcard principal.
- No account-root trust.
- No production principal trust.
- No unrelated service principals.

The target role permissions should be empty or inert/minimal. The active validation checks service acceptance of the role during function creation, not downstream execution capability.

## Does the Source Need Lambda Permissions?

Yes. Active `CreateFunction` validation requires the source principal to be authorized for the Lambda API call in addition to `iam:PassRole`.

Minimum future active permissions are:

- `iam:PassRole` for the selected target role with `iam:PassedToService=lambda.amazonaws.com`.
- `lambda:CreateFunction` for the selected test function if AWS supports that scope, otherwise the narrowest documented create scope.
- `lambda:GetFunction` for the selected test function.
- `lambda:GetFunctionConfiguration` for the selected test function.
- `lambda:DeleteFunction` for immediate cleanup.

`lambda:InvokeFunction` is not required and must not be granted for this protocol.

## Setup Checklist Gate

Before any pre-live plan or active validation slice, a separate active PassRole-to-Lambda setup checklist must document all of these items:

- Source user/profile creation or selection for `iamscope-passrole-positive-source`.
- Target role creation or selection for `iamscope-passrole-target-role`.
- Target role trust scoped to exactly `lambda.amazonaws.com`.
- Source permission policy with `iam:PassRole` on the target role and `iam:PassedToService=lambda.amazonaws.com`.
- Source Lambda permissions: `lambda:CreateFunction`, `lambda:GetFunction`, `lambda:GetFunctionConfiguration`, and `lambda:DeleteFunction` scoped to the single test function ARN wherever AWS supports that scope.
- Explicit denial of `lambda:InvokeFunction`, trigger creation, function URL creation, event source mapping creation, broad admin permissions, and broad role/resource wildcards.
- Minimal no-op ZIP package generation under `/tmp` only.
- Local profile handling without committing credentials or raw logs.
- Cleanup ownership for the Lambda function, CloudWatch log group if one appears, source access keys, source user, source policies, target role policies, target role, local profile, and generated `/tmp` files.
- Abort conditions before any live action.

This protocol does not itself satisfy the setup checklist gate. The next slice must create that checklist before a pre-live active plan is allowed.

## Exact Minimal Lambda Function Shape

The future active validation should create exactly one temporary Lambda function with this shape:

- Function name: `iamscope-passrole-run001-createfunction-active`.
- Runtime: `python3.12` unless the future pre-live plan selects another currently supported runtime.
- Handler: `index.handler`.
- Role: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-passrole-target-role`.
- Code package: a minimal ZIP created under `/tmp/iamscope-controlled-passrole-run-001-active/` only.
- Minimal code content: an `index.py` handler returning a static JSON-compatible object.
- Timeout: `3` seconds.
- Memory size: `128` MB.
- Publish: `false`.
- Package type: `Zip`.
- Architectures: omit unless the pre-live plan needs an explicit default.
- Environment variables: none.
- Secrets: none.
- Layers: none.
- VPC config: none.
- Dead-letter config: none.
- File system config: none.
- Tracing config: disabled or omitted.
- Tags: omit unless separately approved.

The function must not be invoked. No event source mapping, trigger, function URL, permission, alias, version publish, secret, or downstream action is part of this protocol.

## Future Active Procedure

A separately approved active validation slice may follow this procedure:

1. Confirm explicit approval for active validation.
2. Confirm source profile identity matches `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-passrole-positive-source`.
3. Confirm target role exists and trust is scoped to `lambda.amazonaws.com`.
4. Confirm the source has only the required scoped permissions.
5. Build the minimal Lambda ZIP under `/tmp/iamscope-controlled-passrole-run-001-active/`.
6. Call `lambda:CreateFunction` exactly once for the selected function shape.
7. Record only sanitized outcome metadata under `/tmp`.
8. Do not invoke the function.
9. Immediately call `lambda:DeleteFunction` for cleanup if the function was created.
10. Verify cleanup with `lambda:GetFunction` or `lambda:GetFunctionConfiguration` if those read permissions are included.
11. Emit a sanitized active validation summary under `/tmp` only.

## Output Paths

Future active validation outputs must remain under `/tmp/iamscope-controlled-passrole-run-001-active/`:

- Plan: `/tmp/iamscope-controlled-passrole-run-001-active/controlled-passrole-run-001-active-plan.json`.
- Minimal code ZIP: `/tmp/iamscope-controlled-passrole-run-001-active/lambda-function.zip`.
- Sanitized result JSON: `/tmp/iamscope-controlled-passrole-run-001-active/controlled-passrole-run-001-active-result.json`.
- Sanitized result Markdown: `/tmp/iamscope-controlled-passrole-run-001-active/controlled-passrole-run-001-active-result.md`.
- Cleanup summary: `/tmp/iamscope-controlled-passrole-run-001-active/controlled-passrole-run-001-cleanup-summary.json`.

No `/tmp` output is committed by default.

## Abort Conditions

Abort before any active call if any condition is true:

- Explicit active-validation approval is absent.
- Source profile identity does not match the selected source principal.
- Target role ARN does not match the selected target role.
- Target role trust is missing, broader than expected, or does not trust `lambda.amazonaws.com`.
- Source permission lacks scoped `iam:PassRole` on the selected target role.
- Source permission lacks scoped `lambda:CreateFunction` or `lambda:DeleteFunction` for the selected function.
- Source permission includes broad admin permissions, broad wildcard role/resource scope, or `lambda:InvokeFunction` for this test.
- Account is production or not explicitly controlled/test-only.
- Any raw credential, raw AWS log, Terraform state, or `/tmp` output would be committed.
- A pre-existing function with the selected name exists and is not known to be this test artifact.
- Cleanup cannot be attempted safely.

## Expected Allowed Result

Classify the active result as `corroborated` only if all are true:

- `CreateFunction` succeeds for the selected function shape.
- The accepted role ARN is the selected target role.
- No invocation occurs.
- Cleanup with `DeleteFunction` succeeds or the function is verified absent afterward.
- No raw credentials, raw logs, generated ZIP, or `/tmp` outputs are committed.

## Outcome Classification

- `corroborated`: predicted `allowed` and `CreateFunction` succeeds with the selected role, followed by cleanup.
- `denied`: `CreateFunction` returns a sanitized access-denied style result attributable to missing `iam:PassRole`, `lambda:CreateFunction`, or related caller permission.
- `configuration_error`: `CreateFunction` fails due to function packaging, runtime, handler, role propagation delay, region, naming collision, quota, malformed request, or cleanup-related setup issue rather than the PassRole authorization question.
- `environment_mismatch`: selected source, target role, account, trust, or service principal does not match the approved test-only setup.
- `inconclusive`: evidence is insufficient to distinguish authorization from setup/configuration behavior.
- `probe_harness_issue`: the active probe script or operator procedure failed before producing usable evidence.
- `tool_bug_candidate`: only if IAMScope predicted metadata conflicts with a clean controlled result after environment/configuration mismatch is ruled out.
- `model_limitation`: if the result depends on an IAM/Lambda behavior intentionally outside the modeled scope.

Avoid labels such as `pass`, `fail`, `vulnerable`, `exploited`, or `production_ready`.

## Artifact Safety Rules

- No credentials, tokens, access keys, or credential-shaped values in committed files, prompts, logs, JSON, or Markdown.
- No raw AWS logs committed.
- No `/tmp` outputs committed.
- No Lambda ZIP committed.
- No Terraform state/cache/provider artifacts.
- No generated active reports committed by default.
- Sanitized summaries only if later reviewed.
- No composite score.
- No pass/fail label.

## Teardown Plan

If the future active validation creates any test artifact, teardown must cover the full setup lifecycle:

- Delete `iamscope-passrole-run001-createfunction-active` immediately after recording the sanitized result.
- Verify the function is missing using `lambda:GetFunction` or `lambda:GetFunctionConfiguration` if read permissions are included.
- Delete the CloudWatch log group for the test function only if one appears; do not create one intentionally and do not delete unrelated log groups.
- Delete or disable temporary source access keys.
- Remove inline and attached policies from the test-only source user.
- Delete the test-only source user if it was created for this validation.
- Remove inline and attached policies from the test-only target role.
- Delete the test-only target role if it was created for this validation.
- Remove the local profile if it was created for this validation.
- Remove generated `/tmp` files, including the ZIP package, active result summaries, and cleanup summaries, after any approved sanitized checkpoint is recorded.
- If any deletion fails, record a sanitized cleanup-needed status under `/tmp` and stop.
- Do not retry broad cleanup against wildcard names.
- Do not delete unrelated Lambda functions, IAM identities, roles, policies, profiles, log groups, or files.
- Commit only a later sanitized checkpoint, not raw cleanup output.

## Evidence Boundary

This active protocol, if later executed, would prove only whether one test-only source principal could create one minimal Lambda function by passing one selected role to `lambda.amazonaws.com` under explicit controlled conditions, without invocation and with immediate cleanup.

It would not prove production readiness, broad runtime exploitability, downstream authorization, arbitrary IAMScope correctness, all findings verified, resource-policy Deny support, finding-level reachability, or real-world scalability.

## Non-Claims

This design does not claim:

- Active validation has run.
- `iam:PassRole` has been executed.
- Lambda creation has occurred.
- Lambda invocation or downstream service execution.
- Production readiness.
- Broad exploitability.
- Broad IAMScope correctness.
- Downstream authorization proof.
- Real-world scalability.
- All findings verified.
- Composite scoring or pass/fail benchmark status.

## Recommended Next Slice

Recommend exactly one next slice: create active PassRole-to-Lambda setup checklist.

That next slice must be docs/checklist only. It must not execute `iam:PassRole`, call Lambda `CreateFunction`, create resources, launch services, run Terraform, commit `/tmp` outputs, add CI gates, add composite scoring, or authorize active validation without separate approval.