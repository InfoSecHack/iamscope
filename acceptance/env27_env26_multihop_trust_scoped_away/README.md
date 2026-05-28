# Env27 Multi-Hop Trust Scoped Away

Env27 is the negative/non-validated mutation pair for Env26's controlled
same-account 3-hop `sts:AssumeRole` chain.

```text
env27-alice -> env27-hop1 -> env27-hop2 -> env27-admin
```

Env27 preserves the first-hop permission/trust, the hop1-to-hop2 permission,
and the downstream hop2-to-admin permission/trust shape. The mutation is that
`env27-hop2` trusts `env27-decoy`, not `env27-hop1`, so Alice's middle hop must
not validate.

## Resources

- IAM user `env27-alice`
- IAM user `env27-decoy`
- IAM role `env27-hop1`
- IAM role `env27-hop2`
- IAM role `env27-admin`
- Exact inline AssumeRole policy from Alice to hop1
- Exact trust policy from hop1 to Alice
- Exact inline AssumeRole policy from hop1 to hop2
- Exact trust policy from hop2 to decoy, not hop1
- Exact inline AssumeRole policy from hop2 to admin
- Exact trust policy from admin to hop2
- `AdministratorAccess` attached only to `env27-admin`

The fixture does not create SCPs, permission boundaries, Deny statements,
conditions, Organizations mutations, compute resources, or production
identities.

## Expected Result

- Scenario validation passes.
- First-hop permission and trust edges exist.
- The hop1-to-hop2 permission edge exists.
- The matching hop1-to-hop2 trust edge is absent.
- The decoy-to-hop2 trust edge exists.
- Downstream hop2-to-admin permission and trust edges exist.
- No validated `assume_role_chain` is emitted for Alice to admin.
- No validated `admin_reachability` is emitted for Alice to admin.

This case does not call the result blocked unless IAMScope emits explicit
blocker evidence. The honest target is non-validated because the middle trust
does not authorize hop1.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env27_multihop_trust_scoped_away_benchmark.sh
```
