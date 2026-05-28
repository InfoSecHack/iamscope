# Env10 - Env08 mutation with trust condition removed

Env10 is the mutation pair for Env08.

## Relationship To Env08

- Base case: `acceptance/env08_trust_condition_blocked_admin`
- Mutation: remove only `Bool: {"aws:MultiFactorAuthPresent": "true"}` from the target role trust policy
- Preserved shape: `alice -> admin`

## Ground Truth

- `env10-alice` can call `sts:AssumeRole` on `env10-admin`
- `env10-admin` trusts `env10-alice`
- `env10-admin` has `AdministratorAccess`
- No MFA trust condition gates the path

## Expected IAMScope Behavior

- `scenario.json` validates successfully
- `admin_reachability.validated >= 1` for `alice -> admin`
- `admin_reachability.blocked == 0` for `alice -> admin`
- `admin_reachability.inconclusive == 0` for `alice -> admin`
- no `TRUST_CONDITION` constraint is bound to the target trust edge

## What This Does Not Prove

- It does not yet machine-score pairwise delta behavior against Env08.
- It does not prove broader trust-condition mutation coverage.
- It does not prove every condition-free trust policy shape validates.
