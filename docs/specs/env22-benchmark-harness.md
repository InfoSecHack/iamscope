# Env22 Benchmark Harness

Env22 is the validated cross-account AssumeRole benchmark for the cross-account trust family.

It is intentionally narrow:

- two dedicated non-production AWS member accounts;
- caller account IAM user `env22-alice`;
- target account role `env22-cross-account-admin`;
- caller identity policy allows `sts:AssumeRole` to that target role;
- target role trust allows the exact caller test principal;
- target role has `AdministratorAccess`;
- collection roles named `env22-iamscope-reader` are created in both accounts;
- no SCPs, Organizations mutations, access keys, Lambda resources, ECS resources, or production identities.

## Prerequisites

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

The benchmark must only be run after this prints `SAFE_TO_BUILD`.

Expected approved setup for the first live run:

```bash
export MANAGEMENT_PROFILE=iamscope-admin
export CALLER_PROFILE=serim-dev-admin
export TARGET_PROFILE=serim-prod-admin
export CALLER_ACCOUNT_ID=<redacted-aws-account-id>
export TARGET_ACCOUNT_ID=<redacted-aws-account-id>
export AWS_REGION=us-east-1
export CONFIRM_ENV22_CROSS_ACCOUNT_MUTATION=YES
```

The runner refuses to run unless `CONFIRM_ENV22_CROSS_ACCOUNT_MUTATION=YES` is set and the caller and target account IDs differ.

## Harness Flow

`scripts/run_env22_cross_account_benchmark.sh`:

1. Copies `acceptance/env22_cross_account_validated/` into a temporary work directory.
2. Removes any copied Terraform cache/state files.
3. Runs the acceptance `run.sh` with `PROJECT_ROOT_OVERRIDE` and `OUTPUT_DIR`.
4. Runs `iamscope validate` on the collected scenario.
5. Checks the Env22 semantic contract with `jq`.
6. Saves the benchmark archive under `/tmp/iamscope-benchmark-env22-<run_id>`.

The acceptance `run.sh`:

1. Verifies required environment variables and CLIs.
2. Runs the Env22 read-only preflight.
3. Applies Terraform in the caller and target accounts.
4. Verifies the management profile can assume collection roles in both accounts.
5. Runs IAMScope collection across exactly the caller and target accounts.
6. Destroys Terraform-managed resources on exit through a trap.

## Semantic Contract

Env22 expects:

- scenario validation `PASS`;
- `sts:AssumeRole_permission` edge from Alice to the target admin role;
- `sts:AssumeRole_trust` edge from Alice to the target admin role;
- trust edge feature `cross_account=true`;
- no condition evidence on the target permission/trust path;
- `admin_reachability.validated >= 1`;
- `admin_reachability.blocked == 0`;
- `admin_reachability.inconclusive == 0`;
- no blockers on the validated admin target finding;
- `cross_account_trust.validated >= 1`;
- `cross_account_trust.blocked == 0`;
- `cross_account_trust.inconclusive == 0`.

## Evidence Boundary

If Env22 passes, it proves that IAMScope can collect and validate one controlled two-account same-organization AssumeRole admin path. It does not prove broad cross-account trust correctness, all principal-matching shapes, runtime credential exploitation, or production readiness.
