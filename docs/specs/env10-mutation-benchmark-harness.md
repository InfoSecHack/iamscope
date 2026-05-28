# Env10 Mutation Benchmark Harness

## Goal

- Add the second mutation-pair benchmark as an independently machine-scoreable case.
- Keep the mutation narrow: remove only the Env08 MFA trust condition.

## Mutation Design

- Base case: `acceptance/env08_trust_condition_blocked_admin`
- Mutated case: `acceptance/env10_env08_trust_condition_removed`
- Preserved shape: `alice -> admin`
- Intended semantic delta:
  - Env08: trust condition evidence exists and admin reachability is not validated
  - Env10: trust condition evidence is absent from the path and admin reachability validates

## Harness Contract

- The wrapper uses the same temp-copy pattern as Env08/Env09.
- Required benchmark pass conditions:
  - scenario validation PASS
  - `sts:AssumeRole_permission` edge exists for `alice -> admin`
  - `sts:AssumeRole_trust` edge exists for `alice -> admin`
  - `TRUST_CONDITION` evidence for `aws:MultiFactorAuthPresent` is not bound to that trust edge
  - `admin_reachability.validated >= 1`
  - `admin_reachability.blocked == 0`
  - `admin_reachability.inconclusive == 0`

## Out Of Scope

- No pairwise mutation scorer in this pass.
- No reasoner changes.
- No broader mutation framework.
