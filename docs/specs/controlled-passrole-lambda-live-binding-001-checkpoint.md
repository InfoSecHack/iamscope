# Controlled PassRole-to-Lambda Live Binding #1 Checkpoint

## Purpose

Record the sanitized comparison between one selected local IAMScope PassRole-to-Lambda finding and one observed controlled live AWS result.

This is a docs/checkpoint slice only. It does not run live AWS, run Terraform, call AWS CLI, call STS, call Lambda APIs, call `iam:PassRole`, change the live runner, change reasoner logic, change benchmark semantics, commit raw `/tmp` live output, commit raw AWS account ids, or commit raw role ARNs.

## Source Evidence

Sanitized live AWS result checkpoint:

- `docs/specs/controlled-passrole-lambda-live-result-001-checkpoint.md`

Binding gap checkpoint that this checkpoint closes narrowly:

- `docs/specs/controlled-passrole-lambda-live-binding-gap-001-checkpoint.md`

Selected local IAMScope finding fixture:

- `tests/fixtures/live_binding/passrole_lambda_selected_finding/scenario.json`
- `tests/fixtures/live_binding/passrole_lambda_selected_finding/expected_finding.json`
- `tests/fixtures/live_binding/passrole_lambda_selected_finding/README.md`

The selected local fixture uses synthetic account `000000000000`. The live account id is redacted. The live role ARN is redacted. The raw live result JSON is not committed.

## Selected Local IAMScope Finding

- `finding_id`: `dc284c673334e54974e229c9ac006684b3e928d0d03936f857fe93068dc74dc8`
- `pattern_id`: `passrole_lambda`
- `expected_verdict`: `validated`
- `severity`: `high`
- Classification: `selected_local_createfunction_passrole_finding`
- Source principal: synthetic/redacted fixture principal under account `000000000000`
- Target role: synthetic/redacted fixture role under account `000000000000`
- Generation method: local existing `PassRoleLambdaReasoner`

The selected local path represents service-mediated Lambda `CreateFunction` plus `iam:PassRole` plus Lambda trust only. It does not include an admin-equivalent execution-role edge.

## Observed Live AWS Result

The sanitized live result was:

```json
{
  "attempted_action": "lambda:CreateFunction",
  "observed_aws_result": "create_function_succeeded",
  "function_created": true,
  "cleanup_status": "deleted_not_found_verified",
  "lambda_invoke_function_called": false,
  "live_aws_used": true
}
```

Additional observed boundaries:

- The function was not invoked.
- No triggers, function URLs, event source mappings, aliases, versions, or downstream actions were created or tested.
- Cleanup was verified.
- Terraform resources were destroyed.
- Account id redacted.
- Role ARN redacted.
- Raw live result JSON not committed.

Live AWS was used only in the previously documented controlled run. This PR does not run live AWS.

## Comparison Result

Comparison result: `matched_for_selected_service_mediated_createfunction_behavior`

Allowed claim:

> For one selected controlled PassRole-to-Lambda case, the selected local IAMScope `validated` PassRole finding matched the observed AWS `lambda:CreateFunction` result.

Required caveat:

> This is a narrow match for service-mediated Lambda `CreateFunction` plus `iam:PassRole` plus Lambda trust only.

The selected local finding expected the Lambda PassRole path to be `validated` for the sanitized fixture. The live run observed that Lambda `CreateFunction` accepted the selected execution role under the controlled test conditions, created the function, and then verified cleanup.

## Evidence Boundaries

This checkpoint binds only:

- One selected local IAMScope `passrole_lambda` finding.
- One observed controlled live AWS `lambda:CreateFunction` result.
- One controlled service-mediated CreateFunction behavior.

This checkpoint does not bind or validate Lambda invocation, downstream authorization, execution-role permissions, admin-equivalent role behavior, other principals, other roles, other accounts, other regions, other IAMScope findings, or broader PassRole behavior.

The selected local fixture is sanitized and synthetic. The observed live result is recorded only through sanitized checkpoint fields. No raw `/tmp` live result, Terraform state/cache/provider/plan/output file, raw account id, or raw role ARN is committed.

## Non-Claims

This checkpoint does not claim:

- Lambda invocation behavior.
- Downstream authorization.
- Admin-equivalent execution role behavior.
- Exploitability proof.
- Production readiness.
- Broad IAMScope correctness.
- Broad PassRole correctness.
- Correctness for other principals, roles, accounts, regions, or findings.
- Composite benchmark score.
- Pass/fail benchmark label.

## Current Reviewer Entry Point

Recommended reviewer entry point: docs/case-studies/passrole-lambda-controlled-live-validation.md
