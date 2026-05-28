# Env15 Mutation Benchmark Harness

## Purpose

Env15 is the positive mutation pair for Env14's permission-side MFA condition
guardrail. Env14 keeps a clean trust/admin target shape but guards Alice's
identity-policy `sts:AssumeRole` Allow with
`aws:MultiFactorAuthPresent=true`, so IAMScope must not emit validated admin
reachability without runtime MFA proof.

Env15 removes only that permission-side condition. The trust relationship and
admin-equivalent target remain clean.

## Mutation Design

Env14:

- `env14-alice` can assume `env14-admin` only through an identity-policy Allow
  with `Bool: {"aws:MultiFactorAuthPresent": "true"}`
- `env14-admin` cleanly trusts `env14-alice`
- expected result: no validated admin reachability, with an inconclusive admin
  path acceptable and expected

Env15:

- `env15-alice` has the same `sts:AssumeRole` Allow to `env15-admin`, but with
  no condition block
- `env15-admin` cleanly trusts `env15-alice`
- expected result: validated admin reachability, with zero blocked or
  inconclusive admin findings for the same path

## Expected Truth

Expected IAMScope behavior:

- scenario validation passes
- `sts:AssumeRole_permission` edge exists from `env15-alice` to `env15-admin`
- the permission edge has no `aws:MultiFactorAuthPresent` condition evidence
- `sts:AssumeRole_trust` edge exists from `env15-alice` to `env15-admin`
- `admin_reachability.validated >= 1`
- `admin_reachability.blocked == 0`
- `admin_reachability.inconclusive == 0`
- the live shell harness rejects validated findings with blockers

## Evidence Boundary

Passing Env15 proves only this narrow Env14/Env15 mutation delta. It does not
prove broad IAM condition-language evaluation, runtime MFA behavior,
cross-account behavior, or generic identity-policy mutation coverage.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
bash scripts/run_env15_permission_condition_removed_mutation.sh
```
