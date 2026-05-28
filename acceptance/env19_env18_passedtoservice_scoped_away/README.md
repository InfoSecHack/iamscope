# Env19 - Env18 PassedToService Scoped-Away Mutation

Env19 is the negative mutation pair for Env18.

Env18 validates a Lambda PassRole path where Alice can create a Lambda function,
pass a Lambda-trusted admin execution role, and the target role has
`AdministratorAccess`. Env19 preserves that IAM/trust/admin shape, but scopes
Alice's `iam:PassRole` permission to `ec2.amazonaws.com` with
`iam:PassedToService`, so IAMScope must not validate the path as a Lambda
PassRole escalation.

## Fixture Shape

- `env19-alice` is an IAM user under `/iamscope-test/`.
- `env19-alice` can call `lambda:CreateFunction` on the precise future function
  ARN `env19-passrole-probe`.
- `env19-alice` can call `iam:PassRole` on `env19-lambda-admin-exec`, but only
  with `StringEquals: {"iam:PassedToService": "ec2.amazonaws.com"}`.
- `env19-lambda-admin-exec` trusts `lambda.amazonaws.com`.
- `env19-lambda-admin-exec` has `AdministratorAccess`.
- No Lambda function is created.

## Expected Result

- Scenario validation passes.
- The `lambda:CreateFunction_permission` edge exists for `env19-alice`.
- The `iam:PassRole_permission` edge exists from `env19-alice` to
  `env19-lambda-admin-exec` and carries `iam:PassedToService` condition
  evidence scoped to `ec2.amazonaws.com`.
- The `sts:AssumeRole_trust` edge exists from `lambda.amazonaws.com` to
  `env19-lambda-admin-exec`.
- `passrole_lambda.validated == 0`.
- Current reasoner behavior should emit `passrole_lambda.precondition_only >= 1`
  for the target path.

## Live Run

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env19_passedtoservice_scoped_away_benchmark.sh
```

## Boundary

This benchmark proves only that the Env18 Lambda PassRole path does not validate
when `iam:PassRole` is scoped away from Lambda through `iam:PassedToService`.
It does not prove broader PassRole condition handling, ECS PassRole behavior,
cross-account PassRole, Lambda runtime exploitability, or production readiness.
