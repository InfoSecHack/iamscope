# Benchmark Dry Run: env22_cross_account_validated_admin

- Run ID: `iamscope-benchmark-env22-20260505T210729Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- IAMScope's same-organization cross-account trust reasoning is coherent on one controlled live AWS positive path.

## Only Implied
- Broader cross-account trust correctness remains only implied.

## Still Unknown
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
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
