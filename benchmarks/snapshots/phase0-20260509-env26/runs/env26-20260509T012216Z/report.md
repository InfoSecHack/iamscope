# Benchmark Dry Run: env26_multihop_chain_validated_admin

- Run ID: `iamscope-benchmark-env26-20260509T012216Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env26 three-hop permission/trust chain exists structurally.
- The exact Env26 Alice-to-admin path is emitted as validated assume_role_chain.
- The exact Env26 Alice-to-admin path is emitted as validated admin_reachability.
- The exact Env26 Alice-to-admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- IAMScope's same-account AssumeRole chain composition is coherent on one controlled live AWS 3-hop positive path.

## Only Implied
- Broader multi-hop chain correctness remains only implied.

## Still Unknown
- Env27 should test the scoped-away middle-trust mutation.
- Cross-account multi-hop chains remain outside this case.
- Longer chains and conditioned middle-hop controls remain outside this case.

## Defects
- None

## Gate Results
- `artifact_sufficient`: `pass` (triggered_by=none)
- `false_admin_claim`: `pass` (triggered_by=none)
- `dishonest_degradation`: `pass` (triggered_by=none)
- `semantic_mismatch`: `pass` (triggered_by=none)

## Artifact Sufficiency
- Required scenario validation: `pass`
- Observed scenario validation: `pass`
