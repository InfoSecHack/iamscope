# Env12 SCP-Blocked Benchmark Harness

## Purpose

Env12 is the first live AWS Organizations/SCP benchmark. It tests whether IAMScope avoids validated admin reachability when an IAM-allowed AssumeRole path is blocked by an SCP attached to the member account.

## Live Command

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
MANAGEMENT_PROFILE=iamscope-admin \
MEMBER_PROFILE=serim-dev-admin \
AWS_REGION=us-east-1 \
CONFIRM_ENV12_SCP_MUTATION=YES \
bash scripts/run_env12_scp_blocked_benchmark.sh
```

The harness refuses to run without explicit profiles, region, and confirmation.

## AWS Shape

Existing accounts only:

- management account: `516525145310`
- member account: `377114445031`
- organization: `o-ubf697v0et`

Member IAM fixture:

- `env12-alice`
- `env12-admin`
- `env12-alice` can call `sts:AssumeRole` on `env12-admin`
- `env12-admin` trusts `env12-alice`
- `env12-admin` has `AdministratorAccess`
- `env12-iamscope-reader` lets IAMScope collect the member account from the management account

The collection role lives at `/iamscope-test/env12-iamscope-reader`. The harness derives the IAMScope `--role-name` value from Terraform's exact `collection_role_arn`, so IAMScope assumes `arn:aws:iam::<member>:role/iamscope-test/env12-iamscope-reader` instead of the unqualified `arn:aws:iam::<member>:role/env12-iamscope-reader`.

Organizations mutation:

- creates one SCP named `env12-deny-env12-admin-assumerole-<RUN_ID>`
- attaches it directly to the member account
- SCP policy denies `sts:AssumeRole` only on `arn:aws:iam::<member>:role/iamscope-test/env12-admin`
- SCP policy intentionally does not deny `arn:aws:iam::<member>:role/iamscope-test/env12-iamscope-reader`, so IAMScope collection can still assume the reader role

## Expected Truth Contract

Required artifacts:

- `collect/scenario.json`
- `collect/binding_metadata.json`
- `collect/findings.json`
- `scenario_validate.txt`
- `run.log`

Expected scenario evidence:

- `sts:AssumeRole_permission` edge from `env12-alice` to `env12-admin`
- `sts:AssumeRole_trust` edge from `env12-alice` to `env12-admin`
- top-level `SCP` constraint whose `deny_actions` include `sts:AssumeRole`
- SCP constraint `resource_patterns` should contain the exact `env12-admin` role ARN, not `*`
- `edge_constraints` binding the SCP constraint to the trust edge
- `binding_metadata.json` may mark the binding as partial because IAMScope currently downgrades non-wildcard SCP resources. That is acceptable for Env12; the target truth assertion is that IAMScope does not emit validated admin reachability through the SCP-scoped target path.

Expected finding semantics:

- `admin_reachability.validated == 0` for `env12-alice -> env12-admin`
- `assume_role_chain.validated == 0` for the target path if emitted
- blocked or inconclusive findings are acceptable only when supported by current reasoner evidence
- extra non-target findings are noise unless they contradict the Env12 target semantics

## Cleanup Contract

`acceptance/env12_scp_blocked_assumerole/run.sh` installs a cleanup trap that:

1. detaches the Env12 SCP from the member account if attached;
2. deletes the Env12 SCP if created;
3. removes the temporary SCP content file;
4. destroys the member IAM Terraform fixture.

If apply fails before SCP creation, cleanup still attempts Terraform destroy. If collection fails after SCP attachment, cleanup still detaches/deletes the SCP before destroying IAM resources.

Before SCP creation, the harness runs:

```bash
aws sts assume-role \
  --profile "$MANAGEMENT_PROFILE" \
  --role-arn "$COLLECTION_ROLE_ARN" \
  --role-session-name env12-preflight-collection
```

If this preflight fails, the harness fails fast, creates no SCP, and destroys the member IAM fixture.

## Safety Boundary

Env12 does not:

- create or close AWS accounts
- attach an SCP to the organization root
- attach an SCP to a shared OU
- modify unrelated SCPs
- use default AWS credentials silently
- weaken scenario validation or suppress findings

## Machine Scoring

Env12 is machine-scoreable with existing benchmark assertion types:

- `scenario_edge_count`
- `scenario_constraint_count`
- `scenario_edge_constraint_count`
- `finding_count`

The case manifest is `benchmarks/cases/env12_scp_blocked_assumerole.json`.
