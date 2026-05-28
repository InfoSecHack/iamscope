# Env11 - Broad Trust With Unsatisfied Condition

Env11 is a negative-control benchmark for broad-looking trust.

## Ground Truth

- `env11-alice` can call `sts:AssumeRole` on `env11-broad-conditioned-admin`
- `env11-broad-conditioned-admin` has `AdministratorAccess`
- the role trust allows the same-account root principal
- the role trust also requires `aws:MultiFactorAuthPresent=true`
- this benchmark does not create or use an MFA-backed Alice session

## Expected IAMScope Behavior

- `scenario.json` validates successfully
- a permission edge exists for `alice -> broad-conditioned-admin`
- a trust edge exists to `broad-conditioned-admin`
- a `TRUST_CONDITION` constraint exists with `aws:MultiFactorAuthPresent`
- that trust edge is bound to the `TRUST_CONDITION`
- `admin_reachability.validated == 0` for `alice -> broad-conditioned-admin`

An inconclusive target finding is acceptable and useful, but the core benchmark contract is no false validated admin reachability.

## What This Does Not Prove

- It does not prove runtime MFA validation.
- It does not prove broad trust handling for every condition shape.
- It does not prove broad trust without conditions should validate.
