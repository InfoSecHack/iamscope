# Prod-Like AWS Sandbox Lifecycle 001 Checkpoint

## Purpose

Document the sanitized lifecycle result from one controlled prod-like IAM
sandbox Terraform apply/destroy run in a dedicated IAMScope sandbox account.

This checkpoint records only the Terraform lifecycle and cleanup result. It
does not claim IAMScope accuracy or oracle comparison.

## Scope

- Prod-like IAM sandbox Terraform source under
  tests/live/aws/prod_like_accuracy_sandbox/terraform/.
- Controlled live run executed from /tmp, not from the repository tree.
- IAM-only sandbox resources created by Terraform.
- Sanitized lifecycle summary only.

No raw logs, Terraform state, lock files, plan files, output JSON, raw AWS
outputs, raw account IDs, or raw IAM ARNs are committed.

## Preconditions

- Run was performed in an explicitly authorized dedicated IAMScope sandbox
  account.
- Terraform source had account/profile/prefix acknowledgement guards.
- Terraform plan previously showed IAM-only resources.
- Raw run artifacts stayed under /tmp.
- The repository working tree was clean after the run.

## Sanitized Observed Result

    Terraform plan: IAM-only sandbox resources.
    Apply complete! Resources: 39 added, 0 changed, 0 destroyed.
    Destroy complete! Resources: 39 destroyed.

Sanitized lifecycle result:

    {
      "terraform_plan_scope": "iam_only_sandbox_resources",
      "terraform_apply_result": "39_added_0_changed_0_destroyed",
      "terraform_destroy_result": "39_destroyed",
      "raw_account_id_committed": false,
      "raw_iam_arn_committed": false,
      "raw_terraform_artifacts_committed": false,
      "raw_aws_outputs_committed": false
    }

## Cleanup Verification

Prefix cleanup checks for iamscope-prodlike-v1- returned no remaining IAM users, no remaining IAM roles, and no remaining local policies.

The cleanup verification covered:

- no remaining IAM users with the sandbox prefix;
- no remaining IAM roles with the sandbox prefix;
- no remaining local policies with the sandbox prefix.

The observed Terraform destroy summary was:

    Destroy complete. Resources: 39 destroyed.

## Artifact Hygiene

Raw artifacts remained under /tmp and were not committed:

- raw apply logs;
- raw destroy logs;
- Terraform state;
- Terraform lock file;
- Terraform plan file;
- Terraform output JSON;
- raw AWS outputs.

Post-run repository artifact scan was clean, and git status --short was clean
after the run.

## Supported Claim

For one controlled prod-like IAM sandbox lifecycle run, Terraform created 39 IAM-only sandbox resources and Terraform destroy removed 39 resources, with prefix cleanup checks returning no remaining IAM users, roles, or local policies.

## Non-Claims

- not IAMScope accuracy
- not oracle comparison
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

## Exact Next Slice

Recommended next slice: collect sanitized IAMScope findings from a freshly applied prod-like sandbox.
