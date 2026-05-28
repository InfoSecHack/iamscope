# Benchmark Dry Run: env21_ecs_passedtoservice_scoped_away_nonvalidated

- Run ID: `iamscope-benchmark-env21-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.

## Strongly Supported
- IAMScope distinguishes the Env20 positive ECS PassRole path from the Env21 PassedToService-scoped-away mutation.

## Only Implied
- Broader ECS PassRole condition handling remains only implied.

## Still Unknown
- How unsupported iam:PassedToService operators behave remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
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
