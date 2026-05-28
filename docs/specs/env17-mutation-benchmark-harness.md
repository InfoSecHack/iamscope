# Env17 Mutation Benchmark Harness

## Purpose
Env17 is the positive mutation pair for Env13. Env13 proves the target `alice -> admin` AssumeRole path is blocked when a complete SCP Deny applies. Env17 preserves the same IAM/trust/admin target shape and removes the SCP entirely, so IAMScope should validate admin reachability.

## Ground Truth
- `env17-alice` has IAM permission to call `sts:AssumeRole` on `env17-admin`.
- `env17-admin` trusts `env17-alice`.
- `env17-admin` has `AdministratorAccess`.
- No Env17 SCP is created or attached.
- Organizations and management-account collection are not required.

Expected target result:
- scenario validation PASS;
- permission and trust edges exist for `env17-alice -> env17-admin`;
- the target trust edge is not bound to an SCP constraint;
- `admin_reachability.validated >= 1`;
- `admin_reachability.blocked == 0`;
- `admin_reachability.inconclusive == 0`;
- the validated target finding has no blockers.

## Safety Contract
- This harness creates only IAM resources.
- It does not create, attach, detach, or delete SCPs.
- It does not require AWS Organizations permissions.
- It does not require management/member profile separation.
- Terraform destroy runs through a shell trap.

## Live Command
Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env17_scp_removed_mutation.sh
```

## Machine Scoring
The case manifest is `benchmarks/cases/env17_scp_removed_validated_admin.json`.

The current scorer can represent Env17 with existing assertions:
- `scenario_edge_count`;
- `scenario_edge_constraint_count`;
- `finding_count`;
- `blocker_present`.

The shell harness additionally checks that validated target findings have no blockers of any kind.
