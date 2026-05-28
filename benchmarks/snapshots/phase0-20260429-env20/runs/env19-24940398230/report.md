# Benchmark Dry Run: env19_passedtoservice_scoped_away_nonvalidated

- Run ID: `iamscope-benchmark-env19-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.

## Strongly Supported
- IAMScope distinguishes the Env18 positive Lambda PassRole path from the Env19 PassedToService-scoped-away mutation.

## Only Implied
- Broader PassRole condition handling remains only implied.

## Still Unknown
- How unsupported iam:PassedToService operators behave remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- Whether broader PassRole mutation families behave the same way remains unknown here.

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
