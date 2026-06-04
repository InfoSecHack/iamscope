# IAMScope Prod-Like Accuracy Sandbox Terraform Source

This directory contains Terraform source for a future dedicated IAMScope
prod-like accuracy sandbox. This PR only adds source files. It does not run
Terraform, does not call AWS, and does not create AWS resources.

## Boundary

- Terraform source only.
- Do not run in production.
- Dedicated sandbox account only.
- No Terraform apply in this PR.
- No AWS resources are created by this PR.
- Future command examples below are examples only. Do not run until Phase 4 approval.

## Required Variables

- `aws_profile`: explicit AWS profile for the future sandbox operator.
- `aws_region`: explicit AWS region.
- `expected_account_id`: expected dedicated sandbox AWS account ID.
- `resource_prefix`: defaults to `iamscope-prodlike-v1-`.
- `live_ack`: must equal `I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX`.

## Account Guard

The Terraform source uses `data "aws_caller_identity" "current"` and a
Terraform-native `terraform_data` guard. Future Terraform evaluation must fail
unless:

- the caller account matches `expected_account_id`;
- `live_ack` matches the required acknowledgement;
- `resource_prefix` begins with `iamscope-prodlike-v1-`.

## Future Commands, Do Not Run Until Phase 4 Approval

```bash
terraform init
terraform plan \
  -var 'aws_profile=<sandbox-profile>' \
  -var 'aws_region=<sandbox-region>' \
  -var 'expected_account_id=<redacted-sandbox-account-id>' \
  -var 'live_ack=I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX'
terraform apply <reviewed-plan-file>
```

Do not run these commands until the Terraform source has its own review and
Phase 4 is explicitly approved.

## Cleanup Expectations For Future Phase 4

Future Phase 4 must include:

- `terraform destroy` instructions;
- cleanup verification that created IAM users, roles, policies, and attachments are gone;
- sanitized cleanup proof only;
- no orphaned IAM resources.

## Artifact Hygiene

Do not commit:

- `.terraform/`
- `.terraform.lock.hcl`
- `terraform.tfstate`
- `terraform.tfstate.backup`
- `*.tfplan`
- `terraform-outputs.json`
- `result.json`
- `*.log`
- raw account IDs
- raw IAM ARNs
- secrets

## Non-Claims

- not broad IAMScope correctness
- not production readiness
- not real production AWS
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- not resource-policy Deny support except unsupported/static-only row labeling
- not SCP Deny support beyond selected benchmark behavior
- no composite benchmark score
- no pass/fail benchmark label
