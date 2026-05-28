# Benchmark Dry Run: env08_trust_condition_blocked_admin

- Run ID: `iamscope-benchmark-env08-20260425T002835Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env08 alice->conditioned-admin permission edge exists structurally.
- The exact Env08 alice->conditioned-admin trust edge exists structurally.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- The exact Env08 alice->conditioned-admin path is not falsely emitted as validated admin reachability.

## Strongly Supported
- IAMScope can demote or hold uncertain a trust-conditioned admin path instead of overclaiming it as validated.

## Only Implied
- Broader trust-condition coverage remains only implied.

## Still Unknown
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.

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
