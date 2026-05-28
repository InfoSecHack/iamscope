# Benchmark Dry Run: env11_broad_trust_condition_blocked_admin

- Run ID: `iamscope-benchmark-env11-20260425T020442Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env11 alice->broad-conditioned-admin permission edge exists structurally.
- The Env11 target role has broad-looking trust structure.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- The exact Env11 alice->broad-conditioned-admin path is not falsely emitted as validated admin reachability.

## Strongly Supported
- IAMScope can avoid shortcutting broad-looking conditioned trust into validated admin reachability.

## Only Implied
- Broader broad-trust condition coverage remains only implied.

## Still Unknown
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.

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
