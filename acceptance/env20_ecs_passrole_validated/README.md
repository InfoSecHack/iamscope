# Env20: ECS PassRole Validated

Env20 is the positive ECS PassRole benchmark. It creates a small
single-account IAM-only fixture where `env20-alice` has the permissions that
the current `passrole_ecs` reasoner requires:

- `ecs:RegisterTaskDefinition` on a precise future task-definition ARN.
- `ecs:RunTask` on the same precise future task-definition ARN.
- `iam:PassRole` on `env20-ecs-admin-task`.
- `env20-ecs-admin-task` trusts `ecs-tasks.amazonaws.com`.
- `env20-ecs-admin-task` has `AdministratorAccess`.

No ECS cluster, task definition, task, service, container image, or networking
resource is created. The benchmark proves only static IAM evidence collection
and reasoning for this controlled path.

Expected result:

- scenario validation PASS;
- ECS RegisterTaskDefinition edge exists and is clean;
- ECS RunTask edge exists and is clean;
- PassRole edge exists from Alice to the target role;
- ECS task-role trust exists;
- `passrole_ecs.validated >= 1`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passrole_ecs.precondition_only == 0`;
- the validated target finding has no blockers.

Do not run live AWS unless explicitly requested.
