# Benchmark Dry Run: env27_multihop_trust_scoped_away_nonvalidated

- Run ID: `iamscope-benchmark-env27-20260509T212354Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The Env27 first-hop permission/trust structure exists.
- The Env27 hop1-to-hop2 permission edge exists.
- The Env27 hop1-to-hop2 matching trust edge is absent.
- The Env27 decoy-to-hop2 trust edge exists.
- The Env27 downstream hop2-to-admin structure exists.
- The exact Env27 Alice-to-admin path is not emitted as validated assume_role_chain.
- The exact Env27 Alice-to-admin path is not emitted as validated admin_reachability.

## Strongly Supported
- IAMScope's same-account AssumeRole chain composition does not validate one controlled live AWS 3-hop path when the middle trust is scoped away.

## Only Implied
- Broader multi-hop mutation correctness remains only implied.

## Still Unknown
- Longer chains remain outside this case.
- Cross-account multi-hop chains remain outside this case.
- Conditioned middle-hop controls remain outside this case.

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
