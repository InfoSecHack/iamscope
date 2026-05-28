# Env14: Permission-Condition Guarded Admin AssumeRole

Env14 is a single-account live AWS benchmark for a permission-side condition on
an otherwise direct admin AssumeRole path.

## Shape

- `env14-alice` has an identity policy allowing `sts:AssumeRole` to
  `env14-admin`.
- That identity-policy Allow is guarded by
  `Bool: {"aws:MultiFactorAuthPresent": "true"}`.
- `env14-admin` has a clean trust policy for `env14-alice`.
- `env14-admin` has `AdministratorAccess`.

## Truth Boundary

The trust side is clean and the target role is admin-equivalent, but IAMScope
does not prove the runtime MFA condition on Alice's identity-policy Allow.
Therefore IAMScope must not emit validated admin reachability for the
`env14-alice -> env14-admin` path.

Passing this benchmark proves only this narrow permission-condition guardrail.
It does not prove broad IAM condition-language evaluation or runtime MFA
satisfaction.

## Run

Do not run live AWS unless explicitly requested.

```bash
bash acceptance/env14_permission_condition_blocked_admin/run.sh
```
