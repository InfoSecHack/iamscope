# Env26 Multi-Hop Chain Benchmark Design

## Purpose And Scope

Env26 starts the long multi-hop AssumeRole benchmark family. The purpose is to
prove, with a small controlled fixture, that IAMScope can compose more than one
intermediate `sts:AssumeRole` hop into a validated admin path without
overclaiming arbitrary enterprise graph correctness.

This is a design-only slice. It does not build Terraform, run live AWS, change
IAMScope logic, add benchmark artifacts, or add a composite score.

## Why Long-Chain Coverage Matters

Existing benchmark families cover single-hop or short composed shapes:

- same-account and cross-account admin reachability
- SCP, boundary, identity Deny, trust condition, permission condition, and
  PassRole mutation pairs
- scenario-edge-level resource-policy Allow evidence

Large IAM graphs often hide privilege escalation in chains where every
individual hop looks ordinary. A 3-hop chain tests whether IAMScope can preserve
the path composition:

```text
env26-alice -> env26-hop1 -> env26-hop2 -> env26-admin
```

The family should also prove the opposite direction: when a middle hop is not
authorized, IAMScope must not validate the final admin path.

## Current Reasoner Support Summary

Current reasoner support is sufficient for a same-account 3-hop benchmark:

- `iamscope/reasoner/assume_role_chain.py` walks `sts:AssumeRole` chains by
  BFS and has `_MAX_DEPTH = 4`.
- `assume_role_chain` emits findings only for chains of length 2 or more, so a
  3-hop path is inside its intended contract.
- `assume_role_chain` already has unit coverage for a validated 3-hop chain and
  a 4-hop depth boundary.
- `iamscope/reasoner/admin_reachability.py` also uses `_MAX_DEPTH = 4` and has
  unit coverage for Alice reaching admin through a 3-hop chain.
- `iamscope/reasoner/chain_walking.py` requires both an
  `sts:AssumeRole_permission` edge and an admitting `sts:AssumeRole_trust`
  edge at every hop.
- If a trust edge is missing or scoped to the wrong principal, the walker skips
  that hop. The honest current contract for that mutation is no target
  validated finding, not a blocked finding.

No reasoner changes should be required for the positive Env26 fixture if live
collection produces exact permission, trust, and admin-equivalence evidence.

## Env26 Fixture Shape

Env26 should be a same-account IAM-only fixture:

- IAM user: `env26-alice`
- Role 1: `env26-hop1`
- Role 2: `env26-hop2`
- Final role: `env26-admin`

Identity and role policies:

- `env26-alice` has an identity policy allowing `sts:AssumeRole` on
  `env26-hop1`.
- `env26-hop1` has an inline or attached policy allowing `sts:AssumeRole` on
  `env26-hop2`.
- `env26-hop2` has an inline or attached policy allowing `sts:AssumeRole` on
  `env26-admin`.
- `env26-admin` has `AdministratorAccess` attached.

Trust policies:

- `env26-hop1` trusts the exact `env26-alice` ARN.
- `env26-hop2` trusts the exact `env26-hop1` role ARN.
- `env26-admin` trusts the exact `env26-hop2` role ARN.

The fixture should not add SCPs, permission boundaries, identity Deny
statements, trust conditions, permission conditions, wildcard trust principals,
or production identities.

Same-account is the recommended first design because it isolates path
composition from Organizations/SCP, cross-account collection, and management
profile variables. Cross-account multi-hop chains should be a later family only
after this same-account truth is frozen.

## Env27 Mutation Shape

Env27 should be the negative/non-validated mutation pair for Env26. It should
preserve the chain shape and break the middle trust:

- IAM user: `env27-alice`
- Role 1: `env27-hop1`
- Role 2: `env27-hop2`
- Final role: `env27-admin`
- Decoy principal: `env27-decoy`

Policies remain intentionally close to Env26:

- `env27-alice` can call `sts:AssumeRole` on `env27-hop1`.
- `env27-hop1` can call `sts:AssumeRole` on `env27-hop2`.
- `env27-hop2` can call `sts:AssumeRole` on `env27-admin`.
- `env27-admin` has `AdministratorAccess`.

Trust policies differ at the middle hop:

- `env27-hop1` trusts exact `env27-alice`.
- `env27-hop2` trusts exact `env27-decoy`, not `env27-hop1`.
- `env27-admin` trusts exact `env27-hop2`.

Expected truth: IAMScope should observe that the decoy trust exists while the
matching `env27-hop1 -> env27-hop2` trust edge is absent. The path from
`env27-alice` to `env27-admin` must not validate. Do not call this blocked
unless a future reasoner emits a supported blocker; under current semantics it
is a non-validated missing-precondition mutation.

This mutation is preferred over identity Deny, SCP, boundary, or condition
mutations because the current walker contract can express it cleanly without
turning Env27 into another control-family benchmark.

## Expected Collected Nodes And Edges

Env26 expected nodes:

- `IAMUser` node for `env26-alice`
- `IAMRole` nodes for `env26-hop1`, `env26-hop2`, and `env26-admin`

Env26 expected edges:

- `sts:AssumeRole_permission`: `env26-alice -> env26-hop1`
- `sts:AssumeRole_trust`: `env26-alice -> env26-hop1`
- `sts:AssumeRole_permission`: `env26-hop1 -> env26-hop2`
- `sts:AssumeRole_trust`: `env26-hop1 -> env26-hop2`
- `sts:AssumeRole_permission`: `env26-hop2 -> env26-admin`
- `sts:AssumeRole_trust`: `env26-hop2 -> env26-admin`
- admin-equivalence permission evidence for `env26-admin`

Env27 expected nodes:

- `IAMUser` node for `env27-alice`
- `IAMRole` nodes for `env27-hop1`, `env27-hop2`, `env27-admin`, and
  `env27-decoy`

Env27 expected edges:

- `sts:AssumeRole_permission`: `env27-alice -> env27-hop1`
- `sts:AssumeRole_trust`: `env27-alice -> env27-hop1`
- `sts:AssumeRole_permission`: `env27-hop1 -> env27-hop2`
- no matching `sts:AssumeRole_trust`: `env27-hop1 -> env27-hop2`
- `sts:AssumeRole_trust`: `env27-decoy -> env27-hop2`
- `sts:AssumeRole_permission`: `env27-hop2 -> env27-admin`
- `sts:AssumeRole_trust`: `env27-hop2 -> env27-admin`
- admin-equivalence permission evidence for `env27-admin`

All intended path edges should be exact, unconditioned, non-wildcard, and
non-hyperedge.

## Expected Findings And Reasoner Output

Env26 expected result:

- scenario validation passes.
- `assume_role_chain.validated >= 1` for `env26-alice -> env26-admin`.
- The Alice finding includes a 3-hop chain.
- `assume_role_chain.blocked == 0` for the target path.
- `assume_role_chain.inconclusive == 0` for the target path.
- The validated chain has no blockers.
- `admin_reachability.validated >= 1` for `env26-alice`.
- `admin_reachability.blocked == 0`.
- `admin_reachability.inconclusive == 0`.
- The validated admin reachability finding has no blockers.

The reasoners may also emit subchain findings for intermediate roles because
`env26-hop1` and `env26-hop2` have outgoing `sts:AssumeRole` permissions. The
benchmark should score the target Alice-to-admin path rather than assuming only
one finding exists globally.

Env27 expected result:

- scenario validation passes.
- permission evidence exists through the middle hop.
- decoy trust evidence exists for `env27-decoy -> env27-hop2`.
- matching trust evidence for `env27-hop1 -> env27-hop2` is absent.
- `assume_role_chain.validated == 0` for `env27-alice -> env27-admin`.
- `admin_reachability.validated == 0` for `env27-alice -> env27-admin`.
- Acceptable current result: no target finding.
- Unacceptable result: validated Alice-to-admin chain or validated Alice admin
  reachability.

## Semantic Assertions

Env26 case manifest should assert:

- scenario node count for `env26-alice` equals 1.
- scenario node count for `env26-hop1`, `env26-hop2`, and `env26-admin` equals
  1 each.
- scenario edge count for each of the three permission edges equals 1.
- scenario edge count for each of the three trust edges equals 1.
- admin-equivalence evidence for `env26-admin` exists.
- finding count for `assume_role_chain` with `validated >= 1` for the
  Alice-to-admin target.
- finding count for `assume_role_chain` with `blocked == 0` and
  `inconclusive == 0` for the target path.
- finding count for `admin_reachability` with `validated >= 1` for
  `env26-alice`.
- validated target findings have no blockers.

Env27 case manifest should assert:

- scenario node count for `env27-alice`, `env27-hop1`, `env27-hop2`,
  `env27-admin`, and `env27-decoy`.
- permission edge count for `env27-hop1 -> env27-hop2` equals 1.
- matching trust edge count for `env27-hop1 -> env27-hop2` equals 0.
- decoy trust edge count for `env27-decoy -> env27-hop2` equals 1.
- `assume_role_chain.validated == 0` for `env27-alice -> env27-admin`.
- `admin_reachability.validated == 0` for `env27-alice -> env27-admin`.
- no blocker assertion unless the current reasoner emits a supported blocked
  finding, which is not expected for this mutation.

If current benchmark assertion support cannot filter the chain findings tightly
enough by source and target, add only the smallest structural/finding assertion
extension consistent with existing `scenario_edge_count` and
`finding_count` patterns.

## Materializer And Case Manifest Needs

Env26/Env27 should follow existing benchmark patterns:

- Add acceptance environments only in build slices:
  - `acceptance/env26_multihop_chain_validated/`
  - `acceptance/env27_env26_middle_trust_scoped_away/`
- Add runner scripts only in build slices:
  - `scripts/run_env26_multihop_chain_benchmark.sh`
  - `scripts/run_env27_multihop_middle_trust_scoped_away_benchmark.sh`
- Add case manifests:
  - `benchmarks/cases/env26_multihop_chain_validated_admin.json`
  - `benchmarks/cases/env27_multihop_middle_trust_scoped_away_nonvalidated.json`
- Add materializer support only if small and consistent with existing Env18+
  patterns.
- Add focused tests if scorer, ingest, or materializer support changes.

The first build should not broaden the benchmark framework beyond the minimum
needed to score a source/target chain and a decoy trust edge.

## Live AWS Risk And Cost Notes

Env26/Env27 are low-cost IAM-only benchmarks:

- no compute resources
- no S3 buckets or data-plane objects
- no Lambda functions
- no ECS tasks or clusters
- no Organizations mutation
- no SCP creation or attachment

Primary live risks:

- IAM eventual consistency can briefly hide a new policy or trust update.
- Terraform destroy must detach `AdministratorAccess` from the final admin role.
- Role trust policy updates must target only benchmark-named roles.
- The role chain briefly creates an admin-equivalent role, so the fixture must
  use explicit benchmark names, non-production accounts, and immediate cleanup.

Use the same safety posture as prior live IAM benchmarks: explicit confirmation
environment variable, unique names, Terraform destroy trap, and no production
identities.

## Cleanup Risks

Cleanup must remove:

- `env26-alice` / `env27-alice`
- `env27-decoy`
- hop roles
- final admin roles
- inline policies
- attached managed policies, including `AdministratorAccess`

The most important cleanup failure is a leftover admin-equivalent final role.
The runner should print the exact role ARNs it created and run Terraform destroy
on exit. If destroy fails, the runner should report the remaining resource names
clearly.

## What This Proves

Env26 proves, for one small live AWS fixture, that IAMScope can compose a clean
same-account 3-hop AssumeRole path to an admin-equivalent role and emit validated
chain/admin reachability evidence.

Env27 proves, for the paired mutation, that a missing/scoped-away middle trust
precondition prevents the Alice-to-admin path from validating while preserving
evidence that the decoy trust was observed.

Together, the pair proves bounded long-chain path composition and a precise
middle-hop trust mutation.

## What This Does Not Prove

This family does not prove:

- arbitrary enterprise graph correctness
- chains deeper than the current depth cap of 4
- cross-account multi-hop correctness
- Organizations or SCP behavior
- permission boundary behavior
- identity Deny behavior
- condition evaluation on chain hops
- runtime exploitability
- production readiness
- large-account performance or scalability

## Exact Next Build Prompt

```text
Work from current origin/main in a fresh branch.

Mission:
Build Env26 from docs/specs/env26-multihop-chain-benchmark-design.md.

Goal:
Create the validated same-account 3-hop AssumeRole chain benchmark.

Do not change IAMScope reasoner logic unless the benchmark exposes a real bug.
Do not create SCPs.
Do not mutate Organizations.
Do not use production identities.
Do not run live AWS unless explicitly asked.

Expected fixture:
- single-account IAM-only setup
- env26-alice IAM user
- env26-hop1 role
- env26-hop2 role
- env26-admin role with AdministratorAccess
- Alice can sts:AssumeRole env26-hop1
- env26-hop1 trusts exact Alice ARN
- env26-hop1 can sts:AssumeRole env26-hop2
- env26-hop2 trusts exact env26-hop1 role ARN
- env26-hop2 can sts:AssumeRole env26-admin
- env26-admin trusts exact env26-hop2 role ARN
- no SCPs, permission boundaries, identity Deny, trust conditions, permission
  conditions, or wildcard trust principals

Expected Env26 behavior:
- scenario validation PASS
- three exact permission edges exist
- three exact trust edges exist
- admin-equivalent target role evidence exists
- assume_role_chain.validated >= 1 for env26-alice -> env26-admin
- assume_role_chain.blocked == 0
- assume_role_chain.inconclusive == 0
- admin_reachability.validated >= 1 for env26-alice
- admin_reachability.blocked == 0
- admin_reachability.inconclusive == 0
- validated target findings have no blockers

Required files:
- acceptance/env26_multihop_chain_validated/
  - main.tf
  - run.sh
  - README.md
  - expected_findings.json
- scripts/run_env26_multihop_chain_benchmark.sh
- docs/specs/env26-benchmark-harness.md
- benchmarks/cases/env26_multihop_chain_validated_admin.json
- ingest/materializer support if small and consistent
- focused tests if manifest/ingest/materializer changes

Verification:
- bash -n new scripts
- terraform fmt -check if Terraform added
- targeted benchmark tests if manifest/ingest/materializer changes
- ./scripts/check.sh
- ./scripts/test_fast.sh
- no live AWS

Final summary:
- exact fixture resources
- scenario-edge and finding assertions
- whether Env26 is machine-scoreable
- changed files
- validation results
- exact live command
- whether ready for PR
```
