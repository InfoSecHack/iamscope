# Env13 Benchmark Harness

## Purpose
Env13 tests complete SCP blocking for a live Organizations benchmark path. It is the complete-blocking counterpart to Env12, which intentionally remains partial/inconclusive for resource-scoped SCP evidence.

## Ground Truth
- `env13-alice` has IAM permission to call `sts:AssumeRole` on `env13-admin`.
- `env13-admin` trusts `env13-alice`.
- `env13-admin` has `AdministratorAccess`.
- An Env13-specific SCP attached to the member account denies `sts:AssumeRole` with `Resource: "*"`.
- The SCP has an `ArnNotLike aws:PrincipalArn` carveout for the management collection caller.
- Collection-role assumption must work before and after SCP attachment.

Expected target result:
- scenario validation PASS;
- `accounts_collected >= 1`;
- permission and trust edges exist for `env13-alice -> env13-admin`;
- SCP constraint and trust-edge binding exist;
- `binding_metadata.scp_complete_blocking >= 1`;
- `admin_reachability.blocked >= 1`;
- `admin_reachability.validated == 0`;
- `admin_reachability.inconclusive == 0`;
- `assume_role_chain.validated == 0`.

## Safety Contract
- Requires explicit `MANAGEMENT_PROFILE`, `MEMBER_PROFILE`, and `AWS_REGION`.
- Requires `CONFIRM_ENV13_SCP_MUTATION=YES`.
- Creates no AWS accounts and closes no AWS accounts.
- Creates one Env13-specific SCP and attaches it directly to the member account.
- Cleanup always attempts SCP detach/delete before Terraform destroy.
- If post-SCP attachment collection-role preflight fails, IAMScope collection is not run.

## SCP Shape
```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": ["<management collection caller ARN/patterns>"]
    }
  }
}
```

This shape is chosen because IAMScope currently parses `Action` plus wildcard `Resource` plus recognized `ArnNotLike aws:PrincipalArn` exception as complete. The Env13 target principal does not match the exception, so the target trust edge should bind as complete blocking.

## Live Command
```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
MANAGEMENT_PROFILE=iamscope-admin \
MEMBER_PROFILE=serim-dev-admin \
AWS_REGION=us-east-1 \
CONFIRM_ENV13_SCP_MUTATION=YES \
bash scripts/run_env13_complete_scp_blocked_benchmark.sh
```

Do not run live AWS unless explicitly requested.

## Machine Scoring
The case manifest is `<local-iam-scope-repo>/benchmarks/cases/env13_complete_scp_blocked_assumerole.json`.

The current scorer can represent Env13 with existing assertions:
- `scenario_edge_count`
- `scenario_constraint_count`
- `scenario_edge_constraint_count`
- `finding_count`
- `blocker_present`

No new benchmark framework behavior is required.
