# Env09 Mutation Benchmark Harness

## Goal
- Add the first mutation-pair benchmark as an independently machine-scoreable case.
- Keep the mutation narrow: remove only the Env05 permission boundary from the intermediate devops role.

## Mutation Design
- Base case: `acceptance/env05_ar1_blocked_chain`
- Mutated case: `acceptance/env09_env05_boundary_removed`
- Preserved shape: `alice -> devops -> admin`
- Intended semantic delta:
  - Env05: blocked chain and no validated admin reachability
  - Env09: validated admin reachability and no blocked/inconclusive admin reachability

## Harness Contract
- The wrapper uses the same temp-copy pattern as Env05/Env06.
- Required benchmark pass conditions:
  - scenario validation PASS
  - `admin_reachability.validated >= 1`
  - `admin_reachability.blocked == 0`
  - `admin_reachability.inconclusive == 0`
  - validated admin findings have zero blockers
- `assume_role_chain` counts are logged for visibility but not required for pass/fail.

## Out Of Scope
- No pairwise mutation scorer in this pass.
- No reasoner changes.
- No broader mutation framework.
