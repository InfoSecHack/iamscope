# Env21 ECS PassedToService Mutation Benchmark Harness

## Purpose
Env21 is the negative mutation pair for Env20. Env20 validates one controlled ECS
PassRole path. Env21 preserves that IAM shape but scopes `iam:PassRole` to
`ec2.amazonaws.com`, so ECS PassRole escalation must not validate.

## Ground Truth
- `env21-alice` has `ecs:RegisterTaskDefinition` permission on the precise
  future task-definition ARN `env21-passrole-probe:1`.
- `env21-alice` has `ecs:RunTask` permission on the same precise future
  task-definition ARN.
- `env21-alice` has `iam:PassRole` permission on `env21-ecs-admin-task`.
- That PassRole statement has `StringEquals: {"iam:PassedToService":
  "ec2.amazonaws.com"}`.
- `env21-ecs-admin-task` trusts `ecs-tasks.amazonaws.com`.
- `env21-ecs-admin-task` has `AdministratorAccess`.
- No ECS cluster, task definition, task, service, or container image is created.

Expected target result:
- scenario validation PASS;
- ECS RegisterTaskDefinition permission edge exists for `env21-alice`;
- ECS RunTask permission edge exists for `env21-alice`;
- PassRole permission edge exists for `env21-alice -> env21-ecs-admin-task`;
- PassRole condition evidence preserves `iam:PassedToService =
  ec2.amazonaws.com`;
- ECS task service trust edge exists for `ecs-tasks.amazonaws.com ->
  env21-ecs-admin-task`;
- `passrole_ecs.validated == 0`;
- `passrole_ecs.precondition_only >= 1`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passed_to_service` blocker/check evidence is present.

## Honesty Boundary
Do not call Env21 blocked unless the reasoner emits `blocked`. Under current
`passrole_ecs` semantics, the truthful expected state is non-validated /
precondition-only because the PassRole permission exists but is scoped away from
ECS.

If live collection does not preserve the `iam:PassedToService` condition on the
PassRole edge, stop and redesign rather than weakening the benchmark.

## Safety Contract
- This harness creates only IAM resources.
- It does not create an ECS cluster, task definition, task, service, container
  image, ECR repository, CloudWatch log group, or networking.
- It does not require AWS Organizations permissions.
- Terraform destroy runs through a shell trap.

## Live Command
Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env21_ecs_passedtoservice_scoped_away_benchmark.sh
```

## Machine Scoring
The case manifest is
`benchmarks/cases/env21_ecs_passedtoservice_scoped_away_nonvalidated.json`.

It uses existing assertion types:
- `scenario_edge_count`;
- `finding_count`;
- `blocker_present`;
- `check_state_present`.

The shell harness additionally checks exact ECS task service trust, clean ECS
action witnesses, PassRole condition evidence, precondition-only severity, and
the `passed_to_service` blocker/check failure.
