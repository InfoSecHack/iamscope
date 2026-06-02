# Controlled PassRole-to-Lambda Live Binding Gap #1 Checkpoint

## Purpose

Record the current binding status for the sanitized controlled live PassRole-to-Lambda result.

The live AWS behavior was observed successfully, but the repository does not yet bind that observation to a generated IAMScope finding/path.

This is a local docs/checkpoint slice only. It does not run live AWS, run Terraform, call STS, call Lambda APIs, call `iam:PassRole`, invoke Lambda, create or modify AWS resources, commit raw `/tmp` live output, change reasoner logic, change benchmark semantics, or broaden public claims.

## Source Evidence

Primary sanitized source:

- `docs/specs/controlled-passrole-lambda-live-result-001-checkpoint.md`

The checkpoint records:

- Attempted action: `lambda:CreateFunction`.
- Observed AWS result: `create_function_succeeded`.
- `function_created`: `true`.
- `cleanup_status`: `deleted_not_found_verified`.
- Function was not invoked.
- Terraform destroy completed with `4 destroyed`.
- Account id: redacted.
- Role ARN: redacted.
- Raw `/tmp/iamscope-live-passrole-lambda-validation/result.json` intentionally not committed.

The raw live result had:

- `expected_iamscope_verdict`: `null`.
- `source_principal_arn`: `null`.

## Artifact Search Summary

The repository was inspected for an existing generated or replayable IAMScope finding/path matching the controlled live fixture.

Search targets included:

- Existing docs/checkpoints for controlled PassRole-to-Lambda validation.
- Committed acceptance findings.
- Demo fixtures under `tests/fixtures/demo/`.
- Live harness tests and Terraform fixture metadata.
- PassRole report/report-validation references.

Closest related artifacts found:

- `acceptance/env18_lambda_passrole_validated/expected_findings.json`: committed benchmark expected findings for a Lambda PassRole scenario, not the redacted live fixture.
- `tests/fixtures/demo/path_overcounting_shared_uncertainty/findings.json`: synthetic teaching fixture findings, not the redacted live fixture.
- `tests/live/aws/passrole_lambda_validation/`: guarded live harness and tests, not generated IAMScope finding output for the manual live run.

No committed artifact was found that both:

- Represents a generated/replayable IAMScope `passrole_lambda` finding for the exact controlled live fixture.
- Carries the selected source principal, target role, expected IAMScope verdict/path, and finding id needed to compare prediction to observation.

## Selected IAMScope Artifact / Finding / Path

No selected generated IAMScope finding/path is bound in this checkpoint.

The live result is not yet bound to an IAMScope finding id, path id, expected verdict, or replayed local scenario output.

## Observed Live AWS Result

Sanitized observed result:

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

Cleanup summary:

```text
Destroy complete. Resources: 4 destroyed.
```

## Comparison Result

Comparison result: not yet bound.

Because no suitable generated/replayable IAMScope finding/path is currently committed for the exact live fixture, this checkpoint does not claim a prediction-vs-observation match.

Allowed current claim:

> The live AWS behavior was observed successfully, but the repository does not yet bind that observation to a generated IAMScope finding/path.

Not claimed here:

> IAMScope predicted this selected path and AWS agreed.

## Evidence Boundaries

This checkpoint preserves the existing live-result boundary:

- One controlled test account.
- One controlled fixture.
- One service-mediated Lambda `CreateFunction` observation.
- Account id redacted.
- Role ARN redacted.
- Raw live result JSON intentionally not committed.
- Terraform state, provider cache, lock file, plan files, output JSON, and raw live artifacts intentionally not committed.

The result remains evidence of observed service-mediated AWS behavior only until a selected IAMScope finding/path is generated or selected locally and compared.

## Non-Claims

This checkpoint does not claim:

- Broad IAMScope correctness.
- Broad PassRole correctness.
- Exploitability proof.
- Downstream authorization proof.
- Lambda invocation behavior.
- Production readiness.
- A claim about other principals, roles, accounts, regions, or findings.
- A prediction-vs-observation match.
- Composite benchmark score.
- Pass/fail benchmark label.

## Next Validation Slice

Recommended next slice: generate selected IAMScope PassRole finding for live binding.

That next slice should generate or select a local IAMScope `passrole_lambda` finding/path for the controlled live fixture, using sanitized/redacted fixture material, then compare that selected expected verdict/path to the observed AWS `lambda:CreateFunction` result without broadening claims.
