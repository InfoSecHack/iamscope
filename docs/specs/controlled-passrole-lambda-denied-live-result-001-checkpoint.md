# Controlled PassRole-to-Lambda Denied Live Result #1 Checkpoint

## Purpose

Record the sanitized live result for one controlled PassRole-to-Lambda
missing-PassRole validation run.

This is a docs/checkpoint slice only. It does not run live AWS, run Terraform,
call STS, call Lambda APIs, call `iam:PassRole`, create or modify AWS
resources, commit `/tmp` outputs, commit raw live artifacts, change IAMScope
behavior, change benchmark semantics, or change public release/version state.

## Preconditions

- The guarded denied live harness from
  `tests/live/aws/passrole_lambda_validation/` was run manually.
- The run occurred in an explicitly authorized test AWS account.
- The operator used an explicit AWS profile, region, expected account id, and
  live-run acknowledgement.
- The live harness verified STS caller identity before attempting Lambda
  `CreateFunction`.
- The denied mode assumed a test-only denied source role with temporary
  credentials.
- The test account id is redacted in this checkpoint.
- The Lambda execution role ARN is redacted in this checkpoint.
- The denied source role ARN is redacted in this checkpoint.
- Raw live result JSON is intentionally not committed.
- Terraform state, provider cache, lock file, plan files, output JSON, and raw
  live artifacts are intentionally not committed.

## Commands Run

Commands are shown with placeholders and redacted values. They are not default
reviewer commands and are not run in CI.

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
terraform output -json > /tmp/iamscope-live-passrole-lambda-validation-denied/terraform-outputs.json
```

If the denied source role needed an explicit trusted principal override, the
Terraform commands used the same placeholder-only pattern:

```bash
terraform plan \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<redacted-12-digit-test-account-id>' \
  -var 'denied_source_trusted_principal_arn=<redacted-operator-principal-arn>'
terraform apply \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<redacted-12-digit-test-account-id>' \
  -var 'denied_source_trusted_principal_arn=<redacted-operator-principal-arn>'
```

```bash
export IAMSCOPE_LIVE_AWS_ACK=I_UNDERSTAND_THIS_CREATES_AND_DELETES_TEST_AWS_RESOURCES
export AWS_PROFILE=<test-profile>
export AWS_REGION=<region>
export IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID=<redacted-12-digit-test-account-id>

python tests/live/aws/passrole_lambda_validation/run_live_validation.py \
  --mode denied_missing_passrole \
  --terraform-outputs /tmp/iamscope-live-passrole-lambda-validation-denied/terraform-outputs.json \
  --out /tmp/iamscope-live-passrole-lambda-validation-denied
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

Additional sanitized safety fields:

- `triggers_created`: `false`
- `function_url_created`: `false`
- `event_source_mappings_created`: `false`
- `aliases_or_versions_created`: `false`
- `downstream_actions_tested`: `false`
- Account id: redacted.
- Lambda execution role ARN: redacted.
- Denied source role ARN: redacted.

The function was not invoked.

## Cleanup Result

No Lambda function was created, so `cleanup_status` was `not_needed`.

Terraform-managed resources were destroyed after the live validation window.

```text
Destroy complete. Resources: 7 destroyed.
```

The git working tree was clean after cleanup. No generated live artifacts were
committed.

## Evidence Boundaries

This result is from one controlled test account and one controlled fixture.

This validates one service-mediated missing-PassRole denial behavior: Lambda
`CreateFunction` rejected the selected redacted execution role when the denied
source role lacked `iam:PassRole` to that role under the explicit test
conditions.

This does not prove broad IAMScope correctness.

This does not prove broad PassRole correctness.

This does not prove exploitability.

This does not prove downstream authorization.

This is not broad IAMScope correctness evidence.

This is not exploitability evidence.

This checkpoint records only sanitized summary fields. The raw
`/tmp/iamscope-live-passrole-lambda-validation-denied/result.json` file is
intentionally not committed.

## Non-Claims

This checkpoint does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Broad PassRole correctness.
- Broad runtime exploitability.
- Exploitability proof.
- Downstream authorization proof.
- Lambda invocation behavior.
- That any trigger, function URL, event source mapping, alias, version, or
  downstream action was created or tested.
- That any other principal, role, account, region, or IAMScope finding would
  have the same result.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Composite benchmark scoring.
- Pass/fail benchmark labeling.

## Current Reviewer Entry Point

Recommended reviewer entry point: docs/case-studies/passrole-lambda-controlled-live-validation.md
