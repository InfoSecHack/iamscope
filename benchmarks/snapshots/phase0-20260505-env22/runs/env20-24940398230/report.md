# Benchmark Dry Run: env20_ecs_passrole_validated

- Run ID: `iamscope-benchmark-env20-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.

## Strongly Supported
- IAMScope's ECS PassRole reasoner behaves coherently on one controlled live AWS positive path.

## Only Implied
- Broader PassRole correctness remains only implied.

## Still Unknown
- How every iam:PassedToService condition shape behaves remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
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
