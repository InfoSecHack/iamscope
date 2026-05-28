# Env18 Lambda PassRole Benchmark Harness

## Purpose
Env18 is the first PassRole benchmark family case. It proves one narrow,
controlled Lambda PassRole escalation path when the collector emits all
evidence required by `passrole_lambda`.

## Ground Truth
- `env18-alice` has `lambda:CreateFunction` permission on the precise future
  Lambda function ARN `env18-passrole-probe`.
- `env18-alice` has `iam:PassRole` permission on `env18-lambda-admin-exec`.
- `env18-lambda-admin-exec` trusts `lambda.amazonaws.com`.
- `env18-lambda-admin-exec` has `AdministratorAccess`.
- No Lambda function is created or invoked.

Expected target result:
- scenario validation PASS;
- Lambda CreateFunction permission edge exists for `env18-alice`;
- PassRole permission edge exists for `env18-alice -> env18-lambda-admin-exec`;
- Lambda service trust edge exists for `lambda.amazonaws.com -> env18-lambda-admin-exec`;
- `passrole_lambda.validated >= 1`;
- `passrole_lambda.blocked == 0`;
- `passrole_lambda.inconclusive == 0`;
- `passrole_lambda.precondition_only == 0`;
- the validated target finding has severity `critical`;
- the validated target finding has no blockers.

## Safety Contract
- This harness creates only IAM resources.
- It does not create a Lambda function, package code, invoke Lambda, create log
  groups, or provision networking.
- It does not require AWS Organizations permissions.
- Terraform destroy runs through a shell trap.

## Live Command
Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env18_lambda_passrole_benchmark.sh
```

## Machine Scoring
The case manifest is `benchmarks/cases/env18_lambda_passrole_validated.json`.

The current scorer can represent Env18 with existing assertions:
- `scenario_edge_count`;
- `finding_count`;
- `check_state_present`.

The shell harness additionally checks exact Lambda service trust, critical
severity, and no blockers on the validated target finding.

## Evidence Boundary
Env18 proves only one controlled Lambda PassRole positive path. It does not
prove ECS PassRole behavior, wildcard PassRole expansion correctness, every
`iam:PassedToService` condition shape, Lambda runtime exploitability,
cross-account PassRole, or production readiness.
