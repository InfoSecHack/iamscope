# Env18 - Lambda PassRole Validated Benchmark

Env18 is the first PassRole benchmark family case. It is a single-account,
IAM-only fixture for the Lambda PassRole escalation reasoner.

## Fixture Shape

- `env18-alice` is an IAM user under `/iamscope-test/`.
- `env18-alice` can call `lambda:CreateFunction` on the precise future
  function ARN `env18-passrole-probe`.
- `env18-alice` can call `iam:PassRole` on `env18-lambda-admin-exec`.
- `env18-lambda-admin-exec` trusts `lambda.amazonaws.com`.
- `env18-lambda-admin-exec` has `AdministratorAccess`.
- No Lambda function is created.

## Expected Result

- Scenario validation passes.
- The `lambda:CreateFunction_permission` edge exists for `env18-alice`.
- The `iam:PassRole_permission` edge exists from `env18-alice` to
  `env18-lambda-admin-exec`.
- The `sts:AssumeRole_trust` edge exists from `lambda.amazonaws.com` to
  `env18-lambda-admin-exec`.
- `passrole_lambda.validated >= 1`.
- `passrole_lambda.blocked == 0`.
- `passrole_lambda.inconclusive == 0`.
- `passrole_lambda.precondition_only == 0`.
- The validated target finding has no blockers.

## Live Run

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env18_lambda_passrole_benchmark.sh
```

## Boundary

This benchmark proves only one controlled Lambda PassRole positive path. It
does not prove ECS PassRole behavior, wildcard PassRole expansion correctness,
cross-account PassRole, Lambda runtime exploitability, or production readiness.
