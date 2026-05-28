# Env15: Env14 Permission Condition Removed

Env15 is the positive mutation pair for Env14.

Env14 gives `env14-alice` an identity-policy Allow for `sts:AssumeRole` to an
admin role, but guards that Allow with `aws:MultiFactorAuthPresent=true`.
IAMScope should not validate admin reachability there because static
collection does not prove runtime MFA context.

Env15 keeps the same single-account shape:

- `env15-alice` has an identity-policy Allow for `sts:AssumeRole` to
  `env15-admin`
- `env15-admin` cleanly trusts `env15-alice`
- `env15-admin` has `AdministratorAccess`
- the Env14 permission-side MFA condition is removed

Expected IAMScope behavior:

- scenario validation passes
- the `sts:AssumeRole_permission` edge exists from `env15-alice` to
  `env15-admin`
- that permission edge has no condition evidence for
  `aws:MultiFactorAuthPresent`
- the `sts:AssumeRole_trust` edge exists from `env15-alice` to `env15-admin`
- `admin_reachability.validated >= 1`
- `admin_reachability.blocked == 0`
- `admin_reachability.inconclusive == 0`
- the validated finding has no blockers

This benchmark proves only the narrow Env14/Env15 mutation delta. It does not
prove broader condition-language evaluation, runtime MFA behavior, or generic
identity-policy mutation coverage.

Do not run live AWS unless explicitly requested:

```bash
bash scripts/run_env15_permission_condition_removed_mutation.sh
```
