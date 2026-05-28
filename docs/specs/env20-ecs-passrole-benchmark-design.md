# Env20 ECS PassRole Benchmark Design

## Purpose

Env20 should add the first ECS PassRole benchmark family, complementing the existing Lambda PassRole pair:

- Env18 validates a Lambda PassRole path when `lambda:CreateFunction`, `iam:PassRole`, Lambda service trust, and an admin-equivalent target role all align.
- Env19 keeps the same Lambda shape but scopes `iam:PassedToService` away from Lambda, producing a non-validated precondition-only result.

Env20 should prove the analogous positive ECS PassRole path for one bounded live AWS fixture. Env21 should be the paired negative mutation that preserves the same IAM shape but scopes `iam:PassedToService` away from ECS.

This is benchmark expansion only. It should not change IAMScope reasoner logic, broaden the benchmark framework, run ECS workloads, or copy raw benchmark artifacts into the repository.

## Why ECS After Lambda

ECS is the natural next PassRole family because IAMScope already has a `passrole_ecs` reasoner and unit fixtures for the relevant truth states. ECS is also a major real-world PassRole escalation path, but it is slightly wider than Lambda because the current reasoner requires two service-side permissions:

- `ecs:RegisterTaskDefinition`
- `ecs:RunTask`

That makes ECS a good second family after the simpler Lambda benchmark is already live, frozen, and paired with a `PassedToService` negative mutation.

## Current Reasoner Contract

The current `passrole_ecs` reasoner requires:

- a source IAM user or role;
- an IAM role target that trusts `ecs-tasks.amazonaws.com`;
- source permission for both `ecs:RegisterTaskDefinition` and `ecs:RunTask`;
- source permission for `iam:PassRole` to the target role;
- no complete SCP blocker for either ECS action or `iam:PassRole`;
- no complete permission-boundary blocker for either ECS action or `iam:PassRole`;
- `iam:PassedToService` absent or scoped to `ecs-tasks.amazonaws.com` through a supported operator;
- admin-equivalent target role evidence for critical severity.

Important current behavior:

- Missing either ECS action is an early exit and produces no finding.
- Missing target ECS task trust is not a validated path; target-first enumeration may produce no finding.
- A wildcard or hyperedge PassRole witness produces `inconclusive`, not `validated`.
- `iam:PassedToService = ec2.amazonaws.com` on the PassRole statement produces `precondition_only` with a `passed_to_service` blocker.
- Validated findings carry a `session_policy` assumption because session policies are not visible at collection time.

## Smallest Live AWS Fixture Shape

Prefer a single-account IAM-only fixture. Do not create an ECS cluster, task definition, service, task, container image, log group, or networking resources.

Env20 IAM shape:

- IAM user `env20-alice` under `/iamscope-test/`.
- IAM role `env20-ecs-admin-task` under `/iamscope-test/`.
- `env20-ecs-admin-task` trust policy allows `ecs-tasks.amazonaws.com`.
- `env20-ecs-admin-task` has `AdministratorAccess`.
- `env20-alice` has `ecs:RegisterTaskDefinition` on a precise future task-definition ARN such as `arn:aws:ecs:${region}:${account_id}:task-definition/env20-passrole-probe:1`.
- `env20-alice` has `ecs:RunTask` on the same precise future task-definition ARN.
- `env20-alice` has `iam:PassRole` on `env20-ecs-admin-task`.

The positive benchmark depends on the ECS action witnesses being clean, non-wildcard, and non-conditioned. Current `FactGraph.has_action` treats wildcard-resource witnesses as `UNKNOWN`, so a wildcard-only ECS permission would not honestly validate Env20.

Build-time guardrail:

- Verify that AWS accepts the precise task-definition resource pattern and that IAMScope emits non-wildcard `ecs:RegisterTaskDefinition_permission` and `ecs:RunTask_permission` edges.
- If AWS requires `Resource: "*"` for either required ECS action, pause and redesign. Do not fake the benchmark by using an IAM role ARN as the ECS action resource, because that would not truthfully grant the ECS action on the intended task-definition surface.

## Required ECS Action Permissions

Env20 should grant exactly the service-side permissions the reasoner requires:

- `ecs:RegisterTaskDefinition`
- `ecs:RunTask`

Both should be represented as source permission edges from `env20-alice`. The shell harness should assert both edges exist and have `has_conditions == false` and `is_wildcard_resource == false`.

No ECS API should be invoked to register or run a task. The benchmark proves IAMScope's static IAM reasoning for this controlled path, not runtime task execution.

## Target Role Trust Shape

The target role trust policy should be minimal:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "ecs-tasks.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}
```

Do not include additional service principals, conditions, cross-account principals, or wildcard trust. Env20 should test ECS PassRole, not trust-condition handling.

## Expected Collected Nodes And Edges

Expected `scenario.json` should include:

- IAMUser node for `env20-alice`.
- IAMRole node for `env20-ecs-admin-task`.
- AWSService node for `ecs-tasks.amazonaws.com`.
- A non-wildcard `ecs:RegisterTaskDefinition_permission` edge from `env20-alice`.
- A non-wildcard `ecs:RunTask_permission` edge from `env20-alice`.
- A non-wildcard `iam:PassRole_permission` edge from `env20-alice` to `env20-ecs-admin-task`.
- A `sts:AssumeRole_trust` edge from `ecs-tasks.amazonaws.com` to `env20-ecs-admin-task`.
- Admin-equivalent permission evidence for `env20-ecs-admin-task` from `AdministratorAccess`.

Expected absent or zero evidence:

- no target-path SCP blocker;
- no target-path permission-boundary blocker;
- no identity-Deny blocker;
- no wildcard or hyperedge witness for `iam:PassRole`;
- no wildcard or hyperedge witness for either ECS action used by the finding;
- no ECS runtime resources.

## Expected Env20 Findings

Expected target finding:

- `pattern_id == "passrole_ecs"`;
- source provider ID is `env20-alice`;
- target provider ID is `env20-ecs-admin-task`;
- `verdict == "validated"`;
- `severity == "critical"`;
- `blockers_observed == []`;
- a `session_policy` assumption may be present.

Expected counts:

- `passrole_ecs.validated >= 1`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passrole_ecs.precondition_only == 0`;
- validated finding has no blockers.

## Semantic Assertions

Use existing benchmark assertion types where possible:

- `scenario_edge_count` for `ecs:RegisterTaskDefinition_permission`, source `env20-alice`, `gte 1`.
- `scenario_edge_count` for `ecs:RunTask_permission`, source `env20-alice`, `gte 1`.
- `scenario_edge_count` for `iam:PassRole_permission`, source `env20-alice`, target `env20-ecs-admin-task`, `gte 1`.
- `scenario_edge_count` for `sts:AssumeRole_trust`, target `env20-ecs-admin-task`, `gte 1`.
- `finding_count` for `passrole_ecs.validated`, source `env20-alice`, target `env20-ecs-admin-task`, `gte 1`.
- `finding_count` for `passrole_ecs.blocked`, same source/target, `eq 0`.
- `finding_count` for `passrole_ecs.inconclusive`, same source/target, `eq 0`.
- `finding_count` for `passrole_ecs.precondition_only`, same source/target, `eq 0`.
- `check_state_present` for `source_has_ecs_create_and_run_permissions == pass` on the validated finding.
- `check_state_present` for `source_has_passrole_to_target == pass` on the validated finding.
- `check_state_present` for `target_trusts_ecs_tasks_service == pass` on the validated finding.
- `check_state_present` for `passrole_condition_scoped_to_ecs_or_absent == pass` on the validated finding.

The shell harness should additionally assert:

- both ECS action edges are non-wildcard and unconditioned;
- the ECS trust edge source is `ecs-tasks.amazonaws.com`;
- the target finding has severity `critical`;
- the target finding has no blockers.

## Proposed Env20 / Env21 Pair

Recommended pair:

- Env20: validated ECS PassRole escalation.
- Env21: same fixture shape, but the `iam:PassRole` statement has `StringEquals: {"iam:PassedToService": "ec2.amazonaws.com"}`.

Env21 expected behavior:

- scenario validation PASS;
- `ecs:RegisterTaskDefinition_permission` edge exists;
- `ecs:RunTask_permission` edge exists;
- `iam:PassRole_permission` edge exists and preserves the EC2 `iam:PassedToService` condition evidence;
- ECS task trust edge exists;
- `passrole_ecs.validated == 0`;
- `passrole_ecs.blocked == 0`;
- `passrole_ecs.inconclusive == 0`;
- `passrole_ecs.precondition_only >= 1`;
- `passed_to_service` blocker is present;
- `passrole_condition_scoped_to_ecs_or_absent` check fails.

Do not call Env21 blocked unless the reasoner emits `blocked`. Under current reasoner semantics, the honest expectation is precondition-only/non-validated.

## Materializer And Case Manifest Needs

Recommended case IDs:

- `env20_ecs_passrole_validated`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated`

Recommended build files for Env20:

- `acceptance/env20_ecs_passrole_validated/main.tf`
- `acceptance/env20_ecs_passrole_validated/run.sh`
- `acceptance/env20_ecs_passrole_validated/README.md`
- `acceptance/env20_ecs_passrole_validated/expected_findings.json`
- `scripts/run_env20_ecs_passrole_benchmark.sh`
- `docs/specs/env20-benchmark-harness.md`
- `benchmarks/cases/env20_ecs_passrole_validated.json`

Recommended later files for Env21:

- `acceptance/env21_env20_passedtoservice_scoped_away/main.tf`
- `acceptance/env21_env20_passedtoservice_scoped_away/run.sh`
- `acceptance/env21_env20_passedtoservice_scoped_away/README.md`
- `acceptance/env21_env20_passedtoservice_scoped_away/expected_findings.json`
- `scripts/run_env21_ecs_passedtoservice_scoped_away_benchmark.sh`
- `docs/specs/env21-mutation-benchmark-harness.md`
- `benchmarks/cases/env21_ecs_passedtoservice_scoped_away_nonvalidated.json`

Recommended materializer support:

- add optional `--env20-archive` and `--env21-archive`;
- map Env20 to `env20_ecs_passrole_validated`;
- map Env21 to `env21_ecs_passedtoservice_scoped_away_nonvalidated`;
- output directory patterns `env20-<run_id>` and `env21-<run_id>`;
- omitted Env20/Env21 archives behave like other optional environments.

Recommended ingest context labels:

- `source_label: alice_arn`;
- `target_label: ecs_admin_role_arn`;
- optional `task_definition_label: ecs_task_definition_arn` if the harness prints it for structural assertions.

## Live AWS Risk And Cost Notes

Expected cost is zero or near-zero because the fixture should create only IAM resources. It should not create an ECS cluster, task definition, task, service, container image, ECR repository, CloudWatch log group, or VPC resources.

Risk is lower than SCP benchmarks because no Organizations setup is required. Primary risks:

- IAM eventual consistency;
- accidental stale `env20-*` or `env21-*` IAM resources after a failed run;
- exact ECS task-definition resource scoping may not behave as expected in AWS or in IAMScope's collector;
- accidentally falling back to wildcard ECS permissions, which would make a validated positive claim dishonest under current reasoner semantics.

## Cleanup Risks

The runner should follow the Env18/Env19 temp-copy pattern:

- copy the acceptance environment to a temporary directory;
- remove `.terraform`, state files, and provider caches from the temp copy before execution;
- trap `terraform destroy`;
- fail hard if `scenario.json` or `findings.json` is missing;
- run scenario validation before semantic assertions;
- print `alice_arn`, `ecs_admin_role_arn`, `ecs_task_definition_arn`, and account ID in `run.log`.

Do not copy raw live archives, Terraform state, provider caches, collect directories, `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log` into the repository.

## What This Proves

If Env20 passes, it directly proves:

- IAMScope collects the exact ECS RegisterTaskDefinition permission edge for the Env20 source.
- IAMScope collects the exact ECS RunTask permission edge for the Env20 source.
- IAMScope collects the exact PassRole permission edge from the Env20 source to the ECS task role.
- IAMScope collects ECS task service trust on the target role.
- IAMScope recognizes the target role as admin-equivalent.
- IAMScope emits a validated, critical `passrole_ecs` finding for this path.
- IAMScope does not emit blocked, inconclusive, or precondition-only findings for the same target path.

If Env21 later passes, it directly proves:

- IAMScope preserves `iam:PassedToService` condition evidence on the ECS PassRole path.
- IAMScope does not validate the same ECS PassRole path when `iam:PassedToService` is scoped away from ECS.
- IAMScope emits the scoped-away path as precondition-only with `passed_to_service` blocker/check evidence.

## What This Does Not Prove

Env20/Env21 do not prove:

- broad PassRole correctness;
- live ECS task execution exploitability;
- runtime container behavior;
- ECS cluster or networking correctness;
- wildcard or hyperedge PassRole correctness;
- every `iam:PassedToService` condition shape;
- behavior under SCPs, permission boundaries, or identity-policy Deny blockers;
- cross-account PassRole behavior;
- production readiness.

## Exact Next Build Prompt

Build Env20 as the validated ECS PassRole benchmark. Create `acceptance/env20_ecs_passrole_validated/` with `main.tf`, `run.sh`, `README.md`, and `expected_findings.json`; create `scripts/run_env20_ecs_passrole_benchmark.sh`; create `docs/specs/env20-benchmark-harness.md`; create `benchmarks/cases/env20_ecs_passrole_validated.json`; and add optional `--env20-archive` materializer/ingest support if it follows existing Env14-Env19 patterns. Use a single-account IAM-only fixture: `env20-alice`, `env20-ecs-admin-task`, exact `ecs:RegisterTaskDefinition` and `ecs:RunTask` permissions on a precise task-definition ARN pattern, exact `iam:PassRole` permission on the target role, ECS task service trust on the target role, and `AdministratorAccess` on the target role. Do not create an ECS cluster, task definition, service, task, container image, or networking resources. Before claiming Env20 as validated, verify the ECS action edges are clean, non-wildcard, and unconditioned; if AWS or IAMScope forces wildcard-only ECS action evidence, stop and redesign rather than weakening the truth contract. Do not run live AWS unless explicitly asked. Expected result: scenario validation PASS, ECS RegisterTaskDefinition edge present, ECS RunTask edge present, PassRole edge present, ECS task trust edge present, `passrole_ecs.validated >= 1`, blocked/inconclusive/precondition-only `0`, severity `critical`, and no blockers on the validated target finding.
