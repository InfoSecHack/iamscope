# Controlled PassRole-to-Lambda Live Result #1 Checkpoint

## Purpose

Record the sanitized live result for one controlled PassRole-to-Lambda validation run.

This is a docs/checkpoint slice only. It does not run live AWS, run Terraform, call STS, call Lambda APIs, call `iam:PassRole`, create or modify AWS resources, commit `/tmp` outputs, commit raw live artifacts, change IAMScope behavior, change benchmark semantics, or change public release/version state.

## Preconditions

- The guarded live harness from `tests/live/aws/passrole_lambda_validation/` was run manually.
- The run occurred in an explicitly authorized test AWS account.
- The operator used an explicit AWS profile, region, expected account id, and live-run acknowledgement.
- The live harness verified STS caller identity before attempting Lambda `CreateFunction`.
- The test account id is redacted in this checkpoint.
- The Lambda execution role ARN is redacted in this checkpoint.
- Raw live result JSON is intentionally not committed.
- Terraform state, provider cache, lock file, plan files, output JSON, and raw live artifacts are intentionally not committed.

## Commands Run

Commands are shown with placeholders and redacted values. They are not default reviewer commands and are not run in CI.

```bash
cd tests/live/aws/passrole_lambda_validation/terraform
terraform init
terraform plan \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<redacted-12-digit-test-account-id>'
terraform apply \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<redacted-12-digit-test-account-id>'
terraform output -json > /tmp/iamscope-live-passrole-lambda-validation/terraform-outputs.json
```

```bash
export IAMSCOPE_LIVE_AWS_ACK=I_UNDERSTAND_THIS_CREATES_AND_DELETES_TEST_AWS_RESOURCES
export AWS_PROFILE=<test-profile>
export AWS_REGION=<region>
export IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID=<redacted-12-digit-test-account-id>

python tests/live/aws/passrole_lambda_validation/run_live_validation.py \
  --terraform-outputs /tmp/iamscope-live-passrole-lambda-validation/terraform-outputs.json \
  --out /tmp/iamscope-live-passrole-lambda-validation
```

```bash
cd tests/live/aws/passrole_lambda_validation/terraform
terraform destroy \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<redacted-12-digit-test-account-id>'
```

## Observed Sanitized Result

The sanitized observed result was:

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

Additional sanitized safety fields:

- `triggers_created`: `false`
- `function_url_created`: `false`
- `event_source_mappings_created`: `false`
- `aliases_or_versions_created`: `false`
- `downstream_actions_tested`: `false`
- Account id: redacted.
- Role ARN: redacted.

The function was not invoked.

## Cleanup Result

The Lambda function was deleted and not-found cleanup was verified by the harness.

Terraform-managed resources were destroyed after the live validation window.

```text
Destroy complete. Resources: 4 destroyed.
```

The git working tree was clean after cleanup. No generated live artifacts were committed.

## Evidence Boundaries

This result is from one controlled test account and one controlled fixture.

This validates one service-mediated PassRole-to-Lambda behavior: Lambda `CreateFunction` accepted the selected redacted execution role under the explicit test conditions.

This checkpoint records only sanitized summary fields. The raw `/tmp/iamscope-live-passrole-lambda-validation/result.json` file is intentionally not committed.

## Non-Claims

This checkpoint does not claim:

- Production readiness.
- Not broad IAMScope correctness.
- Broad PassRole correctness.
- Broad runtime exploitability.
- Not exploitability proof.
- Downstream authorization proof.
- Lambda invocation behavior.
- That any trigger, function URL, event source mapping, alias, version, or downstream action was created or tested.
- That any other principal, role, account, region, or IAMScope finding would have the same result.
- Composite benchmark scoring.
- Pass/fail benchmark labeling.

## Next Validation Slice

Recommended next slice: bind live PassRole result to selected IAMScope finding.

That next slice should compare a selected IAMScope expected verdict/path to the observed AWS result without broadening claims.
