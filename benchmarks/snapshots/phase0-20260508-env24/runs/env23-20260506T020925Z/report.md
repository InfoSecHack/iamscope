# Benchmark Dry Run: env23_cross_account_trust_scoped_away_nonvalidated

- Run ID: `iamscope-benchmark-env23-20260506T020925Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env23 cross-account permission edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.

## Strongly Supported
- IAMScope's same-organization cross-account trust reasoning does not validate one controlled trust-scoped-away live AWS mutation.

## Only Implied
- Broader cross-account trust mutation correctness remains only implied.

## Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Longer cross-account chains remain outside this case.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.

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
