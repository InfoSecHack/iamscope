# Env23: Cross-Account Trust Scoped-Away Mutation

Env23 is the negative mutation pair for Env22.

Env22 validates a cross-account AssumeRole/admin path when the caller has `sts:AssumeRole` permission and the target role trusts that exact caller. Env23 preserves the same two-account IAM shape, but the target role trusts a decoy caller principal instead of `env23-alice`.

This environment is intentionally IAM-only:

- no SCPs are created or attached;
- no Organizations resources are mutated;
- no access keys are created for `env23-alice` or `env23-decoy`;
- no production identities should be referenced;
- collection roles named `env23-iamscope-reader` are created in both accounts for IAMScope collection.

## Required Environment

Run the read-only Env22/Env23 preflight first:

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
export CONFIRM_ENV23_CROSS_ACCOUNT_MUTATION=YES
```

## Run

From the repository root:

```bash
bash scripts/run_env23_cross_account_trust_scoped_away_benchmark.sh
```

The runner copies this acceptance environment into a temporary work directory, applies Terraform, collects IAMScope output through the management profile, runs semantic assertions, archives the output, and destroys Terraform-managed resources on exit.

## Expected Truth

Env23 should produce:

- scenario validation `PASS`;
- one `sts:AssumeRole_permission` edge from `env23-alice` to `env23-cross-account-admin`;
- zero `sts:AssumeRole_trust` edges from `env23-alice` to `env23-cross-account-admin`;
- at least one `sts:AssumeRole_trust` edge from `env23-decoy` to `env23-cross-account-admin`;
- zero validated `admin_reachability` findings for the `env23-alice` target path;
- zero validated `cross_account_trust` findings for the `env23-alice` target path.

The benchmark should not call the path `blocked` unless IAMScope emits supported blocked evidence. The honest target is non-validated because trust does not authorize the caller.

This proves only the narrow Env23 trust-scoped-away mutation. It does not prove broad cross-account trust correctness, production readiness, or runtime credential exploitation.
