# Env17 - Env13 SCP-Removed Mutation

Env17 is the positive mutation pair for Env13.

Env13 uses the same IAM target shape plus a complete Organizations SCP Deny to block admin reachability. Env17 keeps the target IAM shape but creates no SCP and requires no Organizations mutation, so IAMScope should validate the admin path.

## Fixture Shape

- `env17-alice` is an IAM user under `/iamscope-test/`.
- `env17-alice` has an identity policy allowing `sts:AssumeRole` on `env17-admin`.
- `env17-admin` trusts `env17-alice`.
- `env17-admin` has `AdministratorAccess`.
- No SCP is created or attached by this environment.

## Expected Result

- Scenario validation passes.
- The `env17-alice -> env17-admin` permission edge exists.
- The `env17-alice -> env17-admin` trust edge exists.
- `admin_reachability.validated >= 1`.
- `admin_reachability.blocked == 0`.
- `admin_reachability.inconclusive == 0`.
- The validated target finding has no blockers.

## Live Run

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env17_scp_removed_mutation.sh
```

## Boundary

This benchmark proves only that the Env13 target IAM path validates when the Env13 SCP blocker is absent. It does not prove broader SCP correctness, inherited SCP behavior, OU/root SCP behavior, or production readiness.
