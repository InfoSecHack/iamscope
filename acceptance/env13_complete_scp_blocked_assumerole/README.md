# Env13: Complete SCP-Blocked AssumeRole Admin Path

Env13 is the complete-blocking counterpart to Env12.

It creates a minimal IAM fixture in an existing dedicated member account:

- `env13-alice`
- `env13-admin`
- `env13-alice` can call `sts:AssumeRole` on `env13-admin`
- `env13-admin` trusts `env13-alice`
- `env13-admin` has `AdministratorAccess`
- `env13-iamscope-reader` lets IAMScope collect the member account from the management account

The runner then creates and attaches one Env13-specific SCP to the member account:

```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": [
        "<management collection caller ARN/patterns>"
      ]
    }
  }
}
```

Ground truth: the IAM path is structurally allowed, but effective Organizations policy blocks the critical `sts:AssumeRole` action for the benchmark principal. IAMScope should emit blocked admin reachability for `env13-alice -> env13-admin`, not validated or inconclusive.

The SCP uses `Resource: "*"` so IAMScope's current SCP parser can classify it as complete. Collection safety is preserved by an `aws:PrincipalArn` carveout for the management collection caller plus mandatory pre- and post-SCP attachment collection-role assume preflights.

## Required Profiles

Do not rely on default AWS credentials. Set all of these explicitly:

```bash
export MANAGEMENT_PROFILE=iamscope-admin
export MEMBER_PROFILE=serim-dev-admin
export AWS_REGION=us-east-1
export CONFIRM_ENV13_SCP_MUTATION=YES
```

`MANAGEMENT_PROFILE` must be the Organizations management account profile. `MEMBER_PROFILE` must be an admin-capable profile in the dedicated member test account.

## Safety Boundary

- Does not create or close AWS accounts.
- Creates one Env13-specific SCP per run.
- Attaches that SCP directly to the member account only.
- Cleanup detaches/deletes the SCP before destroying Terraform IAM resources.
- If the run fails after SCP attachment, the cleanup trap still attempts detach/delete.
- Before any SCP is created, the run verifies management can assume Terraform's exact `collection_role_arn`.
- After SCP attachment, the run verifies management can still assume `collection_role_arn`; if this fails, IAMScope collection is not run.

Run through the repo-level wrapper:

```bash
bash scripts/run_env13_complete_scp_blocked_benchmark.sh
```
