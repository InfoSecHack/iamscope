# PassRole-to-Lambda Controlled Live Validation

## What this case study shows

IAMScope now has one two-sided controlled PassRole-to-Lambda validation pair: a
selected local validated finding matched live AWS `CreateFunction` success,
while a corresponding missing-PassRole case produced live AWS `access_denied`
and no selected validated local `passrole_lambda` finding.

This is two controlled cases, not broad IAMScope correctness.

The useful reviewer takeaway is narrow: IAMScope's local PassRole-to-Lambda
reasoning has one controlled allowed-side match and one controlled denied-side
match against sanitized live AWS observations for Lambda `CreateFunction`.

## What was tested

Both controlled runs used the same service-mediated behavior boundary:

- Lambda `CreateFunction` was the attempted AWS action.
- The Lambda execution role trusted `lambda.amazonaws.com`.
- Lambda was not invoked in either case.
- No triggers, function URLs, event source mappings, aliases, versions, or
  downstream actions were created or tested.
- Live AWS was used only in the previously documented controlled runs.
- This PR does not run live AWS.
- Account IDs are redacted in checkpoints.
- Role ARNs are redacted in checkpoints.
- Raw live result JSON is not committed.

The allowed case tested a selected source that could perform
`lambda:CreateFunction` and pass the selected Lambda execution role.

The denied case tested a corresponding source/target shape where the source
could attempt `lambda:CreateFunction` but lacked `iam:PassRole` to the selected
Lambda execution role.

## Allowed-side result

Allowed comparison result:

`matched_for_selected_service_mediated_createfunction_behavior`

Local IAMScope behavior:

- The selected local fixture under
  `tests/fixtures/live_binding/passrole_lambda_selected_finding/` emitted one
  `validated` `passrole_lambda` finding from the existing
  `PassRoleLambdaReasoner`.
- The selected finding represented only service-mediated Lambda
  `CreateFunction` plus `iam:PassRole` plus Lambda trust.
- The local fixture did not represent Lambda invocation, downstream
  authorization, admin-equivalent execution-role behavior, exploitability, or
  production readiness.

Observed live AWS behavior:

- Lambda `CreateFunction` succeeded.
- A function was created.
- The function was not invoked.
- Cleanup was verified by deleting the function and confirming it was not
  found.

Allowed claim:

For one selected controlled PassRole-to-Lambda case, the selected local IAMScope
`validated` PassRole finding matched the observed AWS `lambda:CreateFunction`
result.

## Denied-side result

Denied comparison result:

`matched_for_selected_missing_passrole_denial_behavior`

Local IAMScope behavior:

- The denied local fixture under
  `tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/`
  includes `lambda:CreateFunction_permission`.
- It intentionally omits `iam:PassRole_permission` from the denied source to
  the selected Lambda execution role.
- The selected execution role still trusts `lambda.amazonaws.com`.
- The existing local `PassRoleLambdaReasoner` emitted no selected validated
  `passrole_lambda` finding because `source_has_passrole_to_target` had no
  witness.

Observed live AWS behavior:

- Lambda `CreateFunction` returned `access_denied`.
- The sanitized error category was `AccessDeniedException`.
- No function was created.
- Cleanup was not needed.
- The function was not invoked.

Denied claim:

For one controlled missing-PassRole case, AWS denied `lambda:CreateFunction`,
and the existing local IAMScope PassRole reasoner emitted no selected validated
`passrole_lambda` finding for the corresponding source/target shape.

## How to inspect the evidence

Start with the binding checkpoints:

- [`docs/specs/controlled-passrole-lambda-live-binding-001-checkpoint.md`](../specs/controlled-passrole-lambda-live-binding-001-checkpoint.md)
- [`docs/specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md`](../specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md)

Then inspect the local fixtures:

- [`tests/fixtures/live_binding/passrole_lambda_selected_finding/`](../../tests/fixtures/live_binding/passrole_lambda_selected_finding/)
- [`tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/`](../../tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/)

Optional raw-result checkpoint summaries:

- [`docs/specs/controlled-passrole-lambda-live-result-001-checkpoint.md`](../specs/controlled-passrole-lambda-live-result-001-checkpoint.md)
- [`docs/specs/controlled-passrole-lambda-denied-live-result-001-checkpoint.md`](../specs/controlled-passrole-lambda-denied-live-result-001-checkpoint.md)

These documents contain sanitized summaries only. They do not include raw
`/tmp` result JSON, real account IDs, or real role ARNs.

## Claim boundaries

This case study may claim:

- one selected local `validated` PassRole-to-Lambda finding matched live AWS
  `CreateFunction` success for one controlled allowed case;
- one missing-PassRole local source/target shape emitted no selected validated
  `passrole_lambda` finding and matched live AWS `access_denied` for one
  controlled denied case;
- allowed-side cleanup was verified after function creation;
- denied-side cleanup was `not_needed` because no function was created;
- Lambda was not invoked in either case;
- no triggers, function URLs, event source mappings, aliases, versions, or
  downstream actions were created or tested.

This is not broad IAMScope correctness evidence.

This is not exploitability evidence.

## What this does not prove

This case study does not prove:

- production readiness;
- broad IAMScope correctness;
- broad PassRole correctness;
- generic Deny correctness;
- resource-policy Deny support;
- SCP Deny support;
- broad runtime exploitability;
- exploitability proof;
- downstream authorization proof;
- Lambda invocation behavior;
- correctness for other principals, roles, accounts, regions, or findings;
- composite benchmark score;
- pass/fail benchmark label.

## Next validation slice

Recommended next slice: add one boundary-condition PassRole live validation case.

That slice should remain one controlled case and should not broaden the evidence
claim beyond the specific live behavior it observes.
