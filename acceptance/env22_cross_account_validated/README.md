# Env22: Validated Cross-Account AssumeRole

Env22 is a bounded live AWS benchmark for one positive cross-account AssumeRole path.

The caller account contains `env22-alice`, an IAM user with an inline policy allowing `sts:AssumeRole` on the target account role `env22-cross-account-admin`. The target account role trusts that exact caller principal and has `AdministratorAccess`.

This environment is intentionally IAM-only:

- no SCPs are created or attached;
- no Organizations resources are mutated;
- no access keys are created for `env22-alice`;
- no production identities should be referenced;
- collection roles named `env22-iamscope-reader` are created in both accounts for IAMScope collection.

## Required Environment

Run the read-only preflight first:

```bash
bash scripts/check_env22_cross_account_prereqs.sh \
  --management-profile "$MANAGEMENT_PROFILE" \
  --caller-profile "$CALLER_PROFILE" \
  --target-profile "$TARGET_PROFILE" \
  --caller-account-id "$CALLER_ACCOUNT_ID" \
  --target-account-id "$TARGET_ACCOUNT_ID" \
  --region "$AWS_REGION"
```

Proceed only when the preflight prints `SAFE_TO_BUILD`.

The benchmark runner requires:

```bash
export MANAGEMENT_PROFILE=iamscope-admin
export CALLER_PROFILE=serim-dev-admin
export TARGET_PROFILE=serim-prod-admin
export CALLER_ACCOUNT_ID=377114445031
export TARGET_ACCOUNT_ID=737923406074
export AWS_REGION=us-east-1
export CONFIRM_ENV22_CROSS_ACCOUNT_MUTATION=YES
```

## Run

From the repository root:

```bash
bash scripts/run_env22_cross_account_benchmark.sh
```

The runner copies this acceptance environment into a temporary work directory, applies Terraform, collects IAMScope output through the management profile, runs semantic assertions, archives the output, and destroys Terraform-managed resources on exit.

## Expected Truth

Env22 should produce:

- scenario validation `PASS`;
- one `sts:AssumeRole_permission` edge from `env22-alice` to `env22-cross-account-admin`;
- one `sts:AssumeRole_trust` edge from `env22-alice` to `env22-cross-account-admin`;
- at least one `admin_reachability` finding with verdict `validated`;
- zero `blocked` or `inconclusive` `admin_reachability` findings for that target path;
- at least one validated `cross_account_trust` finding for that target path;
- no blockers on the validated target finding.

This proves only the narrow Env22 two-account AssumeRole fixture. It does not prove broad cross-account trust correctness, production readiness, or runtime credential exploitation.
