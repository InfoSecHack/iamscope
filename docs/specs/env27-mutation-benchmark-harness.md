# Env27 Mutation Benchmark Harness

Env27 implements the trust-scoped-away mutation pair for Env26's positive
same-account 3-hop AssumeRole chain.

## Fixture

- Single-account IAM-only fixture.
- IAM users `env27-alice` and `env27-decoy` under `/iamscope-test/`.
- IAM roles `env27-hop1`, `env27-hop2`, and `env27-admin` under
  `/iamscope-test/`.
- Exact, unconditioned `sts:AssumeRole` permission from Alice to hop1.
- Exact, unconditioned trust from hop1 to Alice.
- Exact, unconditioned `sts:AssumeRole` permission from hop1 to hop2.
- Mutated middle trust: hop2 trusts decoy, not hop1.
- Exact, unconditioned `sts:AssumeRole` permission from hop2 to admin.
- Exact, unconditioned trust from admin to hop2.
- `AdministratorAccess` attached to `env27-admin`.

The fixture does not create SCPs, Organizations mutations, permission
boundaries, Deny statements, conditions, compute resources, or production
identities.

## Expected Machine-Scored Evidence

The case manifest asserts:

- `IAMUser` nodes exist for `env27-alice` and `env27-decoy`.
- `IAMRole` nodes exist for `env27-hop1`, `env27-hop2`, and `env27-admin`.
- The first-hop `sts:AssumeRole_permission` and `sts:AssumeRole_trust` edges
  exist.
- The hop1-to-hop2 `sts:AssumeRole_permission` edge exists.
- The matching hop1-to-hop2 `sts:AssumeRole_trust` edge is absent.
- The decoy-to-hop2 `sts:AssumeRole_trust` edge exists.
- The downstream hop2-to-admin permission and trust edges exist.
- No validated `assume_role_chain` finding is emitted for Alice to admin.
- No validated `admin_reachability` finding is emitted for Alice to admin.

Env27 does not require a blocked finding. The honest target is non-validated
because the middle trust does not authorize hop1. If current reasoner semantics
emit no finding or an inconclusive finding, the benchmark remains honest as long
as the Alice-to-admin target path is not validated.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env27_multihop_trust_scoped_away_benchmark.sh
```

## Boundary

Env27 proves one bounded same-account 3-hop trust-scoped-away mutation. It does
not prove arbitrary enterprise graph correctness, deeper-chain behavior,
cross-account multi-hop behavior, SCP behavior, permission-boundary behavior,
identity Deny behavior, condition evaluation, runtime exploitability, or
production readiness.
