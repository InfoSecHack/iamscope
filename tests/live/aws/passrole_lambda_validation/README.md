# Controlled live PassRole-to-Lambda validation harness

This optional harness validates one selected IAMScope PassRole-to-Lambda path against observed AWS behavior in an explicitly authorized test AWS account.

This is advanced, opt-in, and local operator driven. It does not run in CI.

## Boundary

- Creates and deletes test AWS resources only.
- Requires an explicitly scoped AWS profile, region, account id, and acknowledgement.
- Calls STS `GetCallerIdentity` only to verify the expected account before any Lambda operation.
- Tests service-mediated PassRole behavior through Lambda `CreateFunction`.
- Does not call `iam:PassRole` as a standalone API because `iam:PassRole` is a permission, not an API operation.
- Does not invoke the Lambda function.
- Does not create triggers, aliases, versions, event source mappings, function URLs, or downstream actions.
- Does not prove production readiness, broad IAMScope correctness, broad PassRole correctness, exploitability, or downstream authorization.

## Test resources

The Terraform fixture defines one test-only Lambda execution role trusted by Lambda:

- `aws_iam_role.lambda_execution`
- `aws_iam_policy.lambda_basic_logs`
- `aws_iam_role_policy_attachment.lambda_basic_logs`

Resource names use the `iamscope-live-passrole-lambda-test-` prefix. Taggable resources use:

- `Project=IAMScope`
- `Purpose=ControlledLiveValidation`
- `Owner=TestOnly`

Terraform state, provider cache, plans, and variable files are ignored and must not be committed.

## Manual setup

Use a dedicated test AWS account and a scoped profile. Terraform is configured with the explicit profile and verifies the caller account id before creating IAM resources. Review the plan before applying.

```bash
cd tests/live/aws/passrole_lambda_validation/terraform
terraform init
terraform plan \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<12-digit-test-account-id>'
terraform apply \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<12-digit-test-account-id>'
terraform output -json > /tmp/iamscope-live-passrole-lambda-validation/terraform-outputs.json
```

The profile used for the live validation runner must be the selected source principal for the IAMScope path. It must have, or intentionally lack, only the permissions needed for the selected controlled case, including Lambda `CreateFunction` and service-mediated PassRole to the test execution role.

## Run the validation

```bash
export IAMSCOPE_LIVE_AWS_ACK=I_UNDERSTAND_THIS_CREATES_AND_DELETES_TEST_AWS_RESOURCES
export AWS_PROFILE=<test-profile>
export AWS_REGION=<region>
export IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID=<12-digit-test-account-id>

python tests/live/aws/passrole_lambda_validation/run_live_validation.py \
  --terraform-outputs /tmp/iamscope-live-passrole-lambda-validation/terraform-outputs.json \
  --out /tmp/iamscope-live-passrole-lambda-validation
```

The runner writes a sanitized result to:

```text
/tmp/iamscope-live-passrole-lambda-validation/result.json
```

Observed result values are:

- `create_function_succeeded`
- `access_denied`
- `other_error`

## Cleanup

The runner attempts to delete the test Lambda function and verifies not-found cleanup when creation succeeds. It does not destroy Terraform-managed IAM resources.

Destroy Terraform-managed test resources after the validation window:

```bash
cd tests/live/aws/passrole_lambda_validation/terraform
terraform destroy \
  -var 'aws_profile=<test-profile>' \
  -var 'aws_region=<region>' \
  -var 'expected_account_id=<12-digit-test-account-id>'
```

If cleanup fails, inspect only sanitized AWS error categories from the runner result first, then clean up the named test-only function and role manually in the dedicated test account.
