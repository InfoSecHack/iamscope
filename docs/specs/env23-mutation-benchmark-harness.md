# Env23 Mutation Benchmark Harness

Env23 is the negative mutation pair for Env22.

Env22 proves one narrow positive cross-account AssumeRole path:

- caller account `env22-alice`;
- target account `env22-cross-account-admin`;
- caller-side `sts:AssumeRole` permission;
- target-side exact trust for Alice;
- target role has `AdministratorAccess`;
- `admin_reachability` and `cross_account_trust` validate.

Env23 preserves the same account/profile setup and target-path shape but scopes target trust away from the real caller:

- caller account `env23-alice` has `sts:AssumeRole` permission to the target admin role;
- caller account `env23-decoy` exists only as the trusted principal;
- target account role `env23-cross-account-admin` trusts `env23-decoy`, not `env23-alice`;
- target role has `AdministratorAccess`.

## Safety

The harness uses the same non-production account/profile prerequisites as Env22:

- `MANAGEMENT_PROFILE=iamscope-admin`
- `CALLER_PROFILE=serim-dev-admin`
- `TARGET_PROFILE=serim-prod-admin`
- `CALLER_ACCOUNT_ID=377114445031`
- `TARGET_ACCOUNT_ID=737923406074`
- `AWS_REGION=us-east-1`

The runner refuses to run unless `CONFIRM_ENV23_CROSS_ACCOUNT_MUTATION=YES` is set and the caller and target account IDs differ. It runs the existing read-only cross-account preflight before Terraform mutation, creates no SCPs, performs no Organizations mutation, and destroys Terraform-managed IAM resources on exit.

## Expected Evidence

Expected scenario evidence:

- one unconditioned `sts:AssumeRole_permission` edge from `env23-alice` to `env23-cross-account-admin`;
- zero `sts:AssumeRole_trust` edges from `env23-alice` to `env23-cross-account-admin`;
- at least one unconditioned cross-account `sts:AssumeRole_trust` edge from `env23-decoy` to `env23-cross-account-admin`.

Expected finding behavior:

- `admin_reachability.validated == 0` for `env23-alice` -> `env23-cross-account-admin`;
- `cross_account_trust.validated == 0` for `env23-alice` -> `env23-cross-account-admin`.

Current reasoner behavior may produce no target finding, `precondition_only`, or `inconclusive` for the Alice target path. That is acceptable for this benchmark. A validated finding for Alice is not acceptable.

## What This Proves

If Env23 passes, IAMScope did not validate the target cross-account admin path when the caller-side permission existed but target trust was scoped to another principal.

## What This Does Not Prove

Env23 does not prove broad cross-account trust correctness, all external-principal shapes, all trust condition behavior, all Organizations/SCP interactions, production readiness, or runtime credential exploitability.

## Live Command

```bash
export MANAGEMENT_PROFILE=iamscope-admin
export CALLER_PROFILE=serim-dev-admin
export TARGET_PROFILE=serim-prod-admin
export CALLER_ACCOUNT_ID=377114445031
export TARGET_ACCOUNT_ID=737923406074
export AWS_REGION=us-east-1
export CONFIRM_ENV23_CROSS_ACCOUNT_MUTATION=YES

bash scripts/run_env23_cross_account_trust_scoped_away_benchmark.sh
```
