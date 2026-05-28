# Env19 PassedToService Scoped-Away Mutation Benchmark Harness

## Purpose
Env19 is the negative mutation pair for Env18. Env18 proves a validated Lambda
PassRole path. Env19 preserves the same Lambda CreateFunction, PassRole,
Lambda-trust, and admin-equivalent target shape, but scopes the PassRole
permission away from Lambda using `iam:PassedToService = ec2.amazonaws.com`.

## Ground Truth
- `env19-alice` has `lambda:CreateFunction` permission on the precise future
  Lambda function ARN `env19-passrole-probe`.
- `env19-alice` has `iam:PassRole` permission on `env19-lambda-admin-exec`.
- The PassRole statement has `StringEquals:
  {"iam:PassedToService": "ec2.amazonaws.com"}`.
- `env19-lambda-admin-exec` trusts `lambda.amazonaws.com`.
- `env19-lambda-admin-exec` has `AdministratorAccess`.
- No Lambda function is created or invoked.

Expected target result:
- scenario validation PASS;
- Lambda CreateFunction permission edge exists for `env19-alice`;
- PassRole permission edge exists for `env19-alice -> env19-lambda-admin-exec`;
- the PassRole edge carries `iam:PassedToService = ec2.amazonaws.com` condition evidence;
- Lambda service trust edge exists for `lambda.amazonaws.com -> env19-lambda-admin-exec`;
- `passrole_lambda.validated == 0`;
- current reasoner behavior emits `passrole_lambda.precondition_only >= 1`;
- the precondition-only target finding includes a `passed_to_service` blocker.

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
bash scripts/run_env19_passedtoservice_scoped_away_benchmark.sh
```

## Machine Scoring
The case manifest is
`benchmarks/cases/env19_passedtoservice_scoped_away_nonvalidated.json`.

The current scorer can represent Env19 with existing assertions:
- `scenario_edge_count`;
- `finding_count`;
- `check_state_present`;
- `blocker_present`.

The shell harness additionally checks the exact `iam:PassedToService` value,
precondition-only severity, and the failed PassRole condition check.

## Evidence Boundary
Env19 proves only that this Env18-shaped Lambda PassRole path does not validate
when `iam:PassRole` is scoped to EC2 instead of Lambda. It does not prove all
PassRole condition handling, ECS PassRole behavior, cross-account PassRole, or
production readiness.
