# Benchmark Dry Run: env18_lambda_passrole_validated

- Run ID: `iamscope-benchmark-env18-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.

## Strongly Supported
- IAMScope's Lambda PassRole reasoner behaves coherently on one controlled live AWS positive path.

## Only Implied
- Broader PassRole correctness remains only implied.

## Still Unknown
- How every iam:PassedToService condition shape behaves remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- Whether broader PassRole families validate the same way remains unknown here.

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
