# Controlled PassRole-to-Lambda Denied Live Validation Design

## Purpose

Design one narrow denied controlled live validation case for the
PassRole-to-Lambda evidence program.

This is a design checkpoint only. It does not run live AWS, Terraform,
AWS CLI, STS, Lambda APIs, or `iam:PassRole`.

## Why Denied Case Is Needed

The existing controlled live result documents one allowed case:
`lambda:CreateFunction` accepted the selected Lambda execution role, the
function was created, the function was not invoked, and cleanup was verified.

A denied case adds the opposite service-mediated control point:
`lambda:CreateFunction` is attempted by a test source principal that can call
Lambda create APIs but cannot pass the selected execution role. The purpose is
to check that the live service rejects the selected operation when
`source_has_passrole_to_target` is absent or failed.

This improves the evidence boundary without claiming broad IAMScope
correctness, broad PassRole correctness, exploitability, or production
readiness.

## Candidate Denied Condition

Selected denied condition:

- The test source principal has permission to attempt `lambda:CreateFunction`
  for the controlled test function name prefix.
- The same test source principal lacks `iam:PassRole` permission to the
  selected Lambda execution role.
- The selected Lambda execution role trusts `lambda.amazonaws.com`.
- No Lambda invocation is attempted.
- No triggers, function URLs, event source mappings, aliases, versions, or
  downstream actions are created or tested.

Expected AWS behavior:

- `lambda:CreateFunction` returns an access-denied style error.
- The sanitized result records `observed_aws_result: "access_denied"`.
- The sanitized result records `function_created: false`.
- The sanitized result records `cleanup_status: "not_needed"`.

## Proposed Terraform/Resource Model

The implementation slice should extend the existing controlled
PassRole-to-Lambda Terraform fixture rather than create a broad new live
environment.

Proposed resources:

- Keep the existing account guard:
  - explicit `aws_profile`
  - explicit `expected_account_id`
  - AWS provider configured with the explicit profile
  - `aws_caller_identity` account precondition before resource creation
- Keep the test-only Lambda execution role that trusts
  `lambda.amazonaws.com`.
- Add one test-only denied source role named with the
  `iamscope-live-passrole-lambda-test-` prefix.
- Attach the minimum policy needed for the denied source role to attempt
  `lambda:CreateFunction` for the controlled function prefix.
- Do not attach an `iam:PassRole` allow for the selected execution role to the
  denied source role.
- Prefer no explicit `iam:PassRole` Deny in the first denied case, so the live
  condition represents missing PassRole allow rather than an explicit deny
  suppression case.
- Tag every taggable resource with the existing controlled validation tags and
  the `iamscope-live-passrole-lambda-test-` prefix.

Credential model:

- Do not create or commit long-lived credentials.
- Prefer a denied source role that trusts the operator principal from the
  authorized test account.
- The trust can use `data.aws_caller_identity.current.arn` by default, with an
  optional explicit `denied_source_trusted_principal_arn` variable if the
  operator needs to authorize a different test principal.
- The future live runner can use the operator's existing profile to assume the
  denied source role and then attempt `lambda:CreateFunction` with temporary
  credentials.

This is implementation-ready without long-lived credentials, provided the next
slice keeps the assume-role trust restricted to the authorized test account and
preserves the account guard.

## Proposed Live Runner Behavior

The denied live runner should be a small extension or sibling of the existing
guarded live harness.

Required behavior:

- Require the same explicit live AWS acknowledgement used by the allowed
  harness.
- Require `AWS_PROFILE`, `AWS_REGION`, and
  `IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID`.
- Verify the caller account before any Lambda operation.
- Resolve the denied source role ARN and selected execution role ARN from
  Terraform outputs or explicit arguments.
- Assume the denied source role using temporary credentials only.
- Attempt exactly one `lambda:CreateFunction` with the selected execution role.
- Classify access-denied style Lambda errors as `access_denied`.
- Record `function_created: false` and `cleanup_status: "not_needed"` when the
  denied attempt creates no function.
- If a function is unexpectedly created, delete it, verify
  `deleted_not_found_verified`, write sanitized `result.json`, and fail closed
  if cleanup is not verified.
- Write all live output under `/tmp` or a caller-provided path outside the repo.
- Never invoke the Lambda function.
- Never create triggers, function URLs, event source mappings, aliases,
  versions, or downstream actions.

The runner should write sanitized result JSON only. Raw account IDs, raw role
ARNs, Terraform state, provider cache, plans, and raw live artifacts must not be
committed.

## Proposed Local IAMScope Fixture/Finding Expectation

The exact local IAMScope behavior must be derived from the existing local
reasoner behavior, not invented.

Current `PassRoleLambdaReasoner` behavior:

- It enumerates source/target candidates when the source has
  `lambda:CreateFunction` and the target role trusts Lambda.
- During candidate evaluation, missing `iam:PassRole` to the target role causes
  an early exit before a finding is emitted.
- Therefore, the expected local behavior for this denied case is currently
  `no_selected_passrole_lambda_finding_emitted`, not a fabricated `blocked`
  finding.

Proposed local fixture:

- Start from the existing sanitized selected-finding fixture.
- Remove the `iam:PassRole_permission` edge from the denied source principal to
  the selected execution role.
- Keep the `lambda:CreateFunction_permission` edge.
- Keep the Lambda service trust edge on the selected execution role.
- Assert that no selected `passrole_lambda` finding is emitted for that
  source/target pair, because `source_has_passrole_to_target` has no witness.

Binding expectation:

- Compare the live `access_denied` result to the absence of a selected local
  validated PassRole-to-Lambda finding for the same source/target shape.
- Do not label the local result as `blocked` unless the existing reasoner
  actually emits a blocked finding in the future.
- Do not add a new reasoner mode in this slice.

## Safety Guardrails

- No live AWS in this design task.
- No Terraform apply or destroy in this design task.
- No AWS CLI in this design task.
- No STS calls in this design task.
- No Lambda API calls in this design task.
- No `iam:PassRole` calls in this design task.
- No new reasoners.
- No benchmark semantic changes.
- No raw account IDs or raw role ARNs committed.
- No raw `/tmp` live outputs committed.
- No Terraform state, provider cache, plan files, lock files, or output JSON
  committed.
- All future live resources must use the
  `iamscope-live-passrole-lambda-test-` prefix.
- All future generated live outputs must go under `/tmp` or a caller-provided
  path outside the repo.

## Expected Observed AWS Result

Expected sanitized live result shape:

```json
{
  "attempted_action": "lambda:CreateFunction",
  "observed_aws_result": "access_denied",
  "function_created": false,
  "cleanup_status": "not_needed",
  "lambda_invoke_function_called": false,
  "triggers_created": false,
  "function_url_created": false,
  "event_source_mappings_created": false,
  "aliases_or_versions_created": false,
  "downstream_actions_tested": false,
  "live_aws_used": true
}
```

This expected result is a design target only until a later explicitly
authorized live run records sanitized evidence.

## Cleanup Behavior

Expected denied cleanup behavior:

- If `lambda:CreateFunction` fails with `access_denied`, no function should be
  created.
- The sanitized result should record `function_created: false`.
- The sanitized result should record `cleanup_status: "not_needed"`.
- Terraform-managed IAM resources must be destroyed after the authorized live
  run.

Fail-closed behavior:

- If a function is unexpectedly created, the runner must attempt deletion.
- The runner must verify deletion with a not-found check.
- The runner must write sanitized `result.json`.
- The runner must exit nonzero if a created function cleanup status is anything
  other than `deleted_not_found_verified`.

## Evidence Boundaries

This design proposes one future controlled denied live validation case. It does
not prove active AWS behavior by itself.

If implemented and run later under explicit authorization, the evidence would
cover only one controlled test account, one controlled source role, one
controlled Lambda execution role, one region, one function-name prefix, and one
`lambda:CreateFunction` attempt.

The proposed comparison is narrow:

- observed live AWS denial for service-mediated Lambda `CreateFunction`
- no local selected validated PassRole-to-Lambda finding because
  `source_has_passrole_to_target` lacks a witness

It would not establish correctness for other principals, roles, accounts,
regions, findings, IAM conditions, permission boundaries, SCPs, resource policy
Deny, or generic Deny handling.

## Non-Claims

This design does not claim:

- Broad IAMScope correctness.
- Broad PassRole correctness.
- Exploitability proof.
- Downstream authorization proof.
- Lambda invocation behavior.
- Production readiness.
- Correctness for other principals, roles, accounts, regions, or findings.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Composite benchmark score.
- Pass/fail benchmark label.

## Exact Next Slice

Recommended next slice: implement denied PassRole-to-Lambda live harness.

That slice should add the minimal Terraform and runner changes needed for this
one denied case, with local tests only and no live AWS in CI.
