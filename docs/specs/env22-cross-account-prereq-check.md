# Env22 Cross-Account Prerequisite Check

## Purpose

`scripts/check_env22_cross_account_prereqs.sh` is a read-only preflight for the Env22/Env23 cross-account trust benchmark family. It verifies that the required profiles, accounts, Organizations visibility, local tooling, and IAM read readiness are present before any Terraform build or live benchmark run is attempted.

The script is intentionally a prerequisite gate only. It does not create IAM resources, run `terraform apply`, attach SCPs, run IAMScope collection, or copy benchmark artifacts.

## Required Inputs

The preflight accepts flags or equivalent environment variables:

- `--management-profile` or `MANAGEMENT_PROFILE`
- `--caller-profile` or `CALLER_PROFILE`
- `--target-profile` or `TARGET_PROFILE`
- `--caller-account-id` or `CALLER_ACCOUNT_ID`
- `--target-account-id` or `TARGET_ACCOUNT_ID`
- `--region` or `AWS_REGION`

Example:

```bash
bash scripts/check_env22_cross_account_prereqs.sh \
  --management-profile "$MANAGEMENT_PROFILE" \
  --caller-profile "$CALLER_PROFILE" \
  --target-profile "$TARGET_PROFILE" \
  --caller-account-id "$CALLER_ACCOUNT_ID" \
  --target-account-id "$TARGET_ACCOUNT_ID" \
  --region "$AWS_REGION"
```

## Read-Only Checks

The script checks:

- required CLIs exist: `aws`, `terraform`, and `python` or `python3`;
- all three AWS profiles can call `sts get-caller-identity`;
- caller and target account IDs are well-formed 12-digit IDs;
- caller and target account IDs differ;
- `CALLER_PROFILE` resolves to `CALLER_ACCOUNT_ID`;
- `TARGET_PROFILE` resolves to `TARGET_ACCOUNT_ID`;
- `MANAGEMENT_PROFILE` can call `organizations describe-organization`;
- `MANAGEMENT_PROFILE` can call `organizations list-accounts`;
- caller and target accounts are visible and `ACTIVE` in Organizations;
- `CALLER_PROFILE` can call `iam get-account-summary`;
- `TARGET_PROFILE` can call `iam get-account-summary`;
- a region is explicitly provided.

The IAM checks are intentionally read-only. They prove basic IAM API visibility and profile/account wiring before a build pass. They do not prove that Terraform can create every future Env22/Env23 resource; creation remains a later build-time responsibility.

## Output Contract

The script prints profile names, expected account IDs, resolved account IDs, STS caller ARNs, Organization ID, and boolean readiness facts. It must not print secrets, session tokens, access keys, Terraform plans, raw benchmark artifacts, or policy documents.

If every prerequisite passes, it prints:

```text
Env22 cross-account benchmark readiness: SAFE_TO_BUILD
```

If any prerequisite is missing, it prints:

```text
Env22 cross-account benchmark readiness: NOT_READY
```

and lists each missing prerequisite explicitly.

## Safety Boundary

This preflight is safe to run before Env22 exists because it performs only read-only AWS calls:

- `sts get-caller-identity`
- `organizations describe-organization`
- `organizations list-accounts`
- `iam get-account-summary`

It does not validate the future collection role assumption after Terraform creates the role. The Env22 build runner must still perform a post-apply collection-role assume preflight in both the caller and target accounts before running IAMScope collection.

## Validation

Local validation for this slice:

- `bash -n scripts/check_env22_cross_account_prereqs.sh`
- `bash scripts/check_env22_cross_account_prereqs.sh --help`
- `./scripts/check.sh`
- `./scripts/test_fast.sh`
