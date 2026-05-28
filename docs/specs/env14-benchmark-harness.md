# Env14 Benchmark Harness

## Purpose

Env14 covers a permission-side condition on an otherwise direct AssumeRole path
to an admin-equivalent role.

The benchmark guards against a false validated admin claim when IAMScope sees:

- a clean trust policy from `env14-admin` to `env14-alice`
- an admin-equivalent target role
- an identity-policy `sts:AssumeRole` Allow from `env14-alice` to
  `env14-admin`
- a runtime-dependent permission-side condition on that Allow

## Chosen Condition

Env14 uses:

```json
{"Bool": {"aws:MultiFactorAuthPresent": "true"}}
```

This condition is deterministic to express, already preserved by the
permission-policy parser as `raw_conditions`, and already causes IAMScope's
reasoner fact graph to treat the permission edge as an UNKNOWN witness rather
than a clean PASS witness. IAMScope does not prove runtime MFA context from
static collection, so validated admin reachability would overclaim.

## Expected Truth

The target role is admin-equivalent and cleanly trusts Alice, but Alice's
identity-policy permission to assume the role is condition guarded. Without
runtime evidence that `aws:MultiFactorAuthPresent=true`, the path must not be
reported as validated admin reachability.

Expected IAMScope behavior:

- scenario validation passes
- `sts:AssumeRole_permission` edge exists from `env14-alice` to `env14-admin`
- the permission edge carries `has_conditions=true` and
  `raw_conditions` containing `aws:MultiFactorAuthPresent`
- `sts:AssumeRole_trust` edge exists from `env14-alice` to `env14-admin`
- `admin_reachability.validated == 0`
- `admin_reachability.inconclusive >= 1`

## Evidence Boundary

Passing Env14 proves only this narrow permission-condition guardrail. It does
not prove broad IAM condition-language evaluation, runtime MFA satisfaction,
cross-account behavior, or condition handling for other reasoners.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
bash scripts/run_env14_permission_condition_benchmark.sh
```
