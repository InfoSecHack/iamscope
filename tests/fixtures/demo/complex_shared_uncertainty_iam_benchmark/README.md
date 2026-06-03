# Complex Shared Uncertainty IAM Benchmark Fixture

Fixture id: `complex_shared_uncertainty_iam_benchmark_001`

This is a local-only synthetic fixture and frozen synthetic oracle for a future
IAMScope demo/benchmark slice. It uses only synthetic account `000000000000`
and does not contain live AWS evidence.

## Fixture Files

- `scenario.json`
- `binding_metadata.json`
- `findings.json`
- `naive_candidates.json`
- `expected_uncertainty_groups.json`

## Oracle Counts

- naive candidate rows: `42`
- findings/verdict rows: `18`
- `validated`: `4`
- `blocked`: `5`
- `precondition_only`: `3`
- `inconclusive`: `6`

## Shared Uncertainty Groups

- `shared_passrole_target_resource_scope_unknown`: `3`
- `shared_cross_account_trust_condition_unknown`: `2`
- `shared_boundary_or_session_policy_context_missing`: `1`

## Boundary

The fixture is manually authored as `frozen_synthetic_oracle` with
`source_tool: static_fixture_authoring`. It was not generated or replayed by
IAMScope reasoners, makes `0` AWS calls, and uses no live AWS.

## Non-Claims

- no live AWS
- no broad IAMScope correctness
- no broad PassRole correctness
- no generic Deny correctness
- no resource-policy Deny support
- no SCP Deny support beyond selected synthetic fixture behavior
- no exploitability proof
- no downstream authorization proof
- no Lambda invocation behavior
- no production readiness
- no correctness for real AWS environments
- no correctness for other principals, roles, accounts, regions, conditions, permission boundaries, SCPs, resource policies, or findings
- no composite benchmark score
- no pass/fail benchmark label
