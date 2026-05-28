# Env12: SCP-Blocked AssumeRole Admin Path

Env12 is the first live SCP / AWS Organizations benchmark.

It creates a minimal IAM fixture in an existing dedicated member account:

- `env12-alice`
- `env12-admin`
- `env12-alice` can call `sts:AssumeRole` on `env12-admin`
- `env12-admin` trusts `env12-alice`
- `env12-admin` has `AdministratorAccess`
- `env12-iamscope-reader` lets IAMScope collect the member account from the management account

The collection role is created under `/iamscope-test/`. The run script derives IAMScope's `--role-name` value from Terraform's `collection_role_arn`, so collection uses `iamscope-test/env12-iamscope-reader` rather than the unqualified role name.

The runner then creates and attaches one Env12-specific SCP to the member account:

```json
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::<member-account-id>:role/iamscope-test/env12-admin"
}
```

Ground truth: the IAM path is structurally allowed, but effective Organizations policy blocks the critical `sts:AssumeRole` action. IAMScope must not emit validated admin reachability for `env12-alice -> env12-admin`.

The SCP is intentionally resource-scoped to `env12-admin` so it does not block the management account from assuming `env12-iamscope-reader` for collection.

## Required Profiles

Do not rely on default AWS credentials. Set all of these explicitly:

```bash
export MANAGEMENT_PROFILE=iamscope-admin
export MEMBER_PROFILE=serim-dev-admin
export AWS_REGION=us-east-1
export CONFIRM_ENV12_SCP_MUTATION=YES
```

`MANAGEMENT_PROFILE` must be the Organizations management account profile. `MEMBER_PROFILE` must be an admin-capable profile in the dedicated member test account.

## Safety Boundary

- Does not create or close AWS accounts.
- Creates one Env12-specific SCP per run.
- Attaches that SCP directly to the member account only.
- Cleanup detaches/deletes the SCP before destroying Terraform IAM resources.
- If the run fails after SCP attachment, the cleanup trap still attempts detach/delete.
- Before any SCP is created, the run script verifies that the management profile can assume Terraform's exact `collection_role_arn`. If this preflight fails, no SCP is created or attached.

Run through the repo-level wrapper:

```bash
bash scripts/run_env12_scp_blocked_benchmark.sh
```
