# Env26 Multi-Hop Chain Validated

Env26 is a controlled same-account 3-hop `sts:AssumeRole` benchmark:

```text
env26-alice -> env26-hop1 -> env26-hop2 -> env26-admin
```

The fixture creates exact, unconditioned permission and trust evidence for each
hop. The final `env26-admin` role has `AdministratorAccess`, making the target
admin-equivalent.

## Resources

- IAM user `env26-alice`
- IAM role `env26-hop1`
- IAM role `env26-hop2`
- IAM role `env26-admin`
- Exact inline AssumeRole policies for the three hops
- Exact trust policies for the three hops
- `AdministratorAccess` attached only to `env26-admin`

The fixture does not create SCPs, permission boundaries, Deny statements,
conditions, Organizations mutations, compute resources, or production
identities.

## Expected Result

- Scenario validation passes.
- Three `sts:AssumeRole_permission` edges exist.
- Three `sts:AssumeRole_trust` edges exist.
- `assume_role_chain` validates the Alice-to-admin 3-hop path.
- `admin_reachability` validates Alice reaching the final admin role.
- Target findings are not blocked, inconclusive, or validated with blockers.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env26_multihop_chain_benchmark.sh
```
