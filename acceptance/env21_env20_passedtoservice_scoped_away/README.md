# Env21: ECS PassRole PassedToService Scoped Away

Env21 is the negative mutation pair for Env20. It keeps the same ECS PassRole
shape:

- `env21-alice` has `ecs:RegisterTaskDefinition` on a precise future
  task-definition ARN.
- `env21-alice` has `ecs:RunTask` on the same precise future task-definition
  ARN.
- `env21-alice` has `iam:PassRole` on `env21-ecs-admin-task`.
- `env21-ecs-admin-task` trusts `ecs-tasks.amazonaws.com`.
- `env21-ecs-admin-task` has `AdministratorAccess`.

The mutation is that the `iam:PassRole` statement includes
`StringEquals: {"iam:PassedToService": "ec2.amazonaws.com"}`. That scopes the
PassRole permission away from ECS tasks, so IAMScope must not validate ECS
PassRole escalation through this path.

No ECS cluster, task definition, task, service, container image, or networking
resource is created. The benchmark proves only static IAM evidence collection
and reasoning for this controlled mutation.

Expected result:

- scenario validation PASS;
- ECS RegisterTaskDefinition edge exists and is clean;
- ECS RunTask edge exists and is clean;
- PassRole edge exists from Alice to the target role;
- PassRole edge preserves `iam:PassedToService = ec2.amazonaws.com`;
- ECS task-role trust exists;
- `passrole_ecs.validated == 0`;
- `passrole_ecs.precondition_only >= 1`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passed_to_service` blocker/check evidence is present.

Do not run live AWS unless explicitly requested.
