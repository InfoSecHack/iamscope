# Env26 Benchmark Harness

Env26 implements the positive same-account 3-hop AssumeRole chain benchmark
from `docs/specs/env26-multihop-chain-benchmark-design.md`.

## Fixture

- Single-account IAM-only fixture.
- IAM user `env26-alice` under `/iamscope-test/`.
- IAM roles `env26-hop1`, `env26-hop2`, and `env26-admin` under
  `/iamscope-test/`.
- Exact, unconditioned `sts:AssumeRole` permission from Alice to hop1.
- Exact, unconditioned trust from hop1 to Alice.
- Exact, unconditioned `sts:AssumeRole` permission from hop1 to hop2.
- Exact, unconditioned trust from hop2 to hop1.
- Exact, unconditioned `sts:AssumeRole` permission from hop2 to admin.
- Exact, unconditioned trust from admin to hop2.
- `AdministratorAccess` attached to `env26-admin`.

The fixture does not create SCPs, Organizations mutations, permission
boundaries, Deny statements, conditions, compute resources, or production
identities.

## Expected Machine-Scored Evidence

The case manifest asserts:

- `IAMUser` node exists for `env26-alice`.
- `IAMRole` nodes exist for `env26-hop1`, `env26-hop2`, and `env26-admin`.
- All three exact `sts:AssumeRole_permission` edges exist.
- All three exact `sts:AssumeRole_trust` edges exist.
- `assume_role_chain` emits a validated Alice-to-admin finding.
- `admin_reachability` emits a validated Alice-to-admin finding.
- The target findings are not blocked or inconclusive.
- Validated target findings have no known blockers.

Intermediate roles may also produce findings because they have outgoing
`sts:AssumeRole` permissions. Env26 scores only the Alice-to-admin target path.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env26_multihop_chain_benchmark.sh
```

## Boundary

Env26 proves one bounded same-account 3-hop chain. It does not prove arbitrary
enterprise graph correctness, chains deeper than the current depth cap,
cross-account multi-hop behavior, SCP behavior, permission-boundary behavior,
identity Deny behavior, condition evaluation, runtime exploitability, or
production readiness.
