# Controlled PassRole-to-Lambda Denied Live Binding #1 Checkpoint

## Purpose

Bind the sanitized denied controlled PassRole-to-Lambda live result to the
corresponding local IAMScope no-selected-finding expectation.

This is a local fixture/test/docs checkpoint slice only. It does not run live
AWS, run Terraform, call AWS CLI, call STS, call Lambda APIs, call
`iam:PassRole`, create or modify AWS resources, commit raw live artifacts,
change IAMScope reasoners, change benchmark semantics, or change public
release/version state.

## Source Evidence

Live result source:

- `docs/specs/controlled-passrole-lambda-denied-live-result-001-checkpoint.md`
- Validation mode: `denied_missing_passrole`
- Attempted action: `lambda:CreateFunction`
- Expected observed AWS result: `access_denied`
- Observed AWS result: `access_denied`
- Error category: `AccessDeniedException`
- Function created: `false`
- Cleanup status: `not_needed`
- Lambda function was not invoked.
- No triggers, function URLs, event source mappings, aliases, versions, or
  downstream actions were created or tested.
- Terraform-managed resources were destroyed.
- Account id redacted.
- Role ARNs redacted.
- Raw live result JSON not committed.

Local fixture source:

- `tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/`
- Local fixture uses synthetic account `000000000000`.
- Source role is synthetic/redacted.
- Lambda execution role is synthetic/redacted.
- Source has `lambda:CreateFunction`.
- Source lacks `iam:PassRole` to the selected execution role.
- Execution role trusts `lambda.amazonaws.com`.
- No live AWS was used by the local fixture.

## Local Denied IAMScope Expectation

The local denied fixture reconstructs a `FactGraph` and runs the existing
`PassRoleLambdaReasoner`.

Expected local IAMScope behavior:

- The reasoner emits no selected validated `passrole_lambda` finding for the
  corresponding source/target shape.
- The missing required evidence is `source_has_passrole_to_target`.
- The fixture still contains `lambda:CreateFunction_permission`.
- The fixture intentionally omits `iam:PassRole_permission` from the denied
  source role to the selected Lambda execution role.
- The fixture contains Lambda service trust for the selected execution role.

This expectation is derived from existing local reasoner behavior. It is not a
new reasoner mode and does not change IAMScope semantics.

## Observed Denied Live AWS Result

The sanitized denied live result was:

```json
{
  "validation_mode": "denied_missing_passrole",
  "attempted_action": "lambda:CreateFunction",
  "expected_observed_aws_result": "access_denied",
  "observed_aws_result": "access_denied",
  "error_category": "AccessDeniedException",
  "function_created": false,
  "cleanup_status": "not_needed",
  "lambda_invoke_function_called": false,
  "live_aws_used": true
}
```

The function was not invoked.

No function was created, so cleanup was not needed.

Terraform resources were destroyed after the controlled live run.

## Comparison Result

Comparison result:

`matched_for_selected_missing_passrole_denial_behavior`

Allowed claim:

For one controlled missing-PassRole case, AWS denied `lambda:CreateFunction`,
and the existing local IAMScope PassRole reasoner emitted no selected validated
`passrole_lambda` finding for the corresponding source/target shape.

Required caveat:

This is a narrow match for missing `iam:PassRole` evidence in one controlled
service-mediated Lambda `CreateFunction` case.

## Evidence Boundaries

Live AWS was used only in the previously documented controlled run.

This PR does not run live AWS.

This checkpoint compares one sanitized live denial summary to one local
synthetic no-selected-finding fixture.

The live result came from one controlled test account and one controlled
fixture. The local fixture uses synthetic account `000000000000`.

Account id redacted.

Role ARNs redacted.

Raw live result JSON not committed.

This checkpoint does not establish correctness for other principals, roles,
accounts, regions, findings, IAM conditions, permission boundaries, SCPs,
resource-policy Deny, or generic Deny handling.

## Non-Claims

This checkpoint does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Broad PassRole correctness.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Broad runtime exploitability.
- Exploitability proof.
- Downstream authorization proof.
- Lambda invocation behavior.
- That any trigger, function URL, event source mapping, alias, version, or
  downstream action was created or tested.
- Correctness for other principals, roles, accounts, regions, or findings.
- Composite benchmark score.
- Pass/fail benchmark label.

## Current Reviewer Entry Point

Recommended reviewer entry point: docs/case-studies/passrole-lambda-controlled-live-validation.md
