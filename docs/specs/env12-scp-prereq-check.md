# Env12 SCP Prerequisite Check

## Purpose

`scripts/check_env12_scp_prereqs.sh` is a read-only safety preflight for the Env12 SCP benchmark. It answers one question:

> Do the supplied AWS profiles/account setup provide enough non-mutating evidence to start building Env12 safely?

It does not create IAM resources, create Organizations accounts, create SCPs, attach SCPs, detach SCPs, or delete anything.

## Command

```bash
scripts/check_env12_scp_prereqs.sh \
  --management-profile iamscope-org-management \
  --member-profile iamscope-env12-member-admin \
  --region us-east-1
```

## Read-Only Checks

The preflight requires:

- `aws`, `terraform`, and `python` or `python3` on `PATH`
- management profile resolves with `aws sts get-caller-identity`
- member profile resolves with `aws sts get-caller-identity`
- management profile can call `organizations describe-organization`
- management profile can call `organizations list-accounts`
- member account ID is visible in the organization account list
- management profile can call `organizations list-policies --filter SERVICE_CONTROL_POLICY`
- member profile can call `iam get-account-summary`
- member account ID is different from the management account ID

## Output Contract

The script prints:

- management profile
- member profile
- region
- management account ID
- member account ID
- organization ID, when readable
- whether the member account is visible in Organizations
- whether SCP policy listing is readable
- whether member IAM read access is present
- final readiness: `SAFE_TO_BUILD` or `NOT_READY`
- exact missing prerequisites when not ready

## Exit Contract

- Exit `0`: all preflight checks passed and Env12 is `SAFE_TO_BUILD`.
- Exit nonzero: Env12 is `NOT_READY`, or arguments are invalid.

`SAFE_TO_BUILD` means the next build pass can safely create the Env12 Terraform/harness for a dedicated member account. It does not prove that future mutating Terraform calls will succeed, and it does not prove IAMScope SCP benchmark correctness.

## Safety Boundary

The preflight intentionally does not test mutating permissions such as:

- `organizations create-policy`
- `organizations attach-policy`
- `organizations detach-policy`
- `organizations delete-policy`
- IAM user/role/policy creation in the member account

Those calls are reserved for the reviewed Env12 benchmark build/run, with explicit dedicated-account confirmation.
