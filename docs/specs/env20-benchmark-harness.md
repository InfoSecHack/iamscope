# Env20 ECS PassRole Benchmark Harness

## Purpose
Env20 is the first ECS PassRole benchmark family case. It proves one narrow,
controlled ECS PassRole escalation path when the collector emits all evidence
required by `passrole_ecs`.

## Ground Truth
- `env20-alice` has `ecs:RegisterTaskDefinition` permission on the precise
  future task-definition ARN `env20-passrole-probe:1`.
- `env20-alice` has `ecs:RunTask` permission on the same precise future
  task-definition ARN.
- `env20-alice` has `iam:PassRole` permission on `env20-ecs-admin-task`.
- `env20-ecs-admin-task` trusts `ecs-tasks.amazonaws.com`.
- `env20-ecs-admin-task` has `AdministratorAccess`.
- No ECS cluster, task definition, task, service, or container image is created.

Expected target result:
- scenario validation PASS;
- ECS RegisterTaskDefinition permission edge exists for `env20-alice`;
- ECS RunTask permission edge exists for `env20-alice`;
- PassRole permission edge exists for `env20-alice -> env20-ecs-admin-task`;
- ECS task service trust edge exists for `ecs-tasks.amazonaws.com -> env20-ecs-admin-task`;
- `passrole_ecs.validated >= 1`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passrole_ecs.precondition_only == 0`;
- the validated target finding has severity `critical`;
- the validated target finding has no blockers.

## Guardrail
The positive Env20 claim is only truthful if the ECS action witnesses are clean,
non-wildcard, and unconditioned. If live collection yields wildcard or hyperedge
ECS action evidence, stop and redesign Env20 instead of weakening the semantic
assertions or claiming validation.

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
bash scripts/run_env20_ecs_passrole_benchmark.sh
```

## Machine Scoring
The case manifest is `benchmarks/cases/env20_ecs_passrole_validated.json`.

The current scorer represents Env20 with existing assertion families plus the
same edge-feature matching style already used for conditions:
- `scenario_edge_count`;
- `finding_count`;
- `check_state_present`.

The shell harness additionally checks exact ECS task service trust, critical
severity, no blockers on the validated target finding, and clean non-wildcard
ECS action witnesses.

## Evidence Boundary
Env20 proves only one controlled ECS PassRole positive path. It does not prove
live ECS task execution exploitability, wildcard PassRole expansion correctness,
every `iam:PassedToService` condition shape, behavior under SCPs or permission
boundaries, cross-account PassRole, or production readiness.
