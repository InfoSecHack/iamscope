# Env08 Benchmark Harness

## Goal

Add a small controlled AWS benchmark for conditioned trust to test whether IAMScope avoids overclaiming admin reachability when the trust relationship exists structurally but carries an unsatisfied trust-policy condition.

## Chosen Condition Shape

- Trust policy condition: `Bool: {"aws:MultiFactorAuthPresent": "true"}`
- Reason: the parser already surfaces MFA trust conditions explicitly, the binder already exports them as `TRUST_CONDITION`, and the benchmark user does not have an MFA-backed session in this setup.

## Current Repo-Grounded Contract

- Conditioned trust is definitely exported structurally as:
  - a `sts:AssumeRole_trust` edge with `raw_conditions`
  - a top-level `TRUST_CONDITION` constraint
  - an `edge_constraints` binding from the trust edge to that constraint
- Existing reasoner tests do not prove how `admin_reachability` consumes `TRUST_CONDITION` today.
- Therefore this harness asserts the structural trust-condition evidence and treats any validated admin claim as a benchmark-failing overclaim.

## Out Of Scope

- No reasoner logic changes in this benchmark setup pass.
- No new scorer extension yet for machine-scoring top-level constraint evidence.
