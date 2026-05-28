# Env18 PassRole Benchmark Design

## Purpose

Env18 should be the first live AWS benchmark family for IAMScope's PassRole escalation reasoners. The goal is to prove one narrow, concrete Lambda PassRole escalation path when all required evidence is present:

- the source principal can create a Lambda function;
- the source principal can pass a privileged execution role;
- the execution role trusts `lambda.amazonaws.com`;
- the execution role is admin-equivalent;
- no complete SCP, permission boundary, identity-Deny, or `iam:PassedToService` condition blocks the path.

This is benchmark expansion only. It should not change IAMScope reasoner logic, broaden the benchmark framework unnecessarily, or copy raw live artifacts into the repository.

## Chosen Service

Use Lambda for Env18.

Lambda is the smallest first PassRole family because the current `passrole_lambda` reasoner needs one service-side action, `lambda:CreateFunction`, plus `iam:PassRole` and Lambda service trust on the target role. The ECS reasoner is also implemented, but its validated path requires both `ecs:RegisterTaskDefinition` and `ecs:RunTask`, making it a better follow-on family after the simpler Lambda path is frozen.

The relevant reasoner contract is:

- `passrole_lambda` enumerates IAM users/roles that can call `lambda:CreateFunction`.
- It pairs them with roles that trust `lambda.amazonaws.com`.
- It requires `iam:PassRole` from the source principal to the target role.
- It treats wildcard or hyperedge witnesses as `UNKNOWN`, which demotes the finding to `inconclusive`.
- It treats `iam:PassedToService` as valid when absent or scoped to Lambda via supported operators.
- It emits `validated` when all checks pass, and `critical` when the target role is admin-equivalent.

## Recommended Env18/Env19 Pair

Recommended pair:

- Env18: validated Lambda PassRole escalation.
- Env19: same shape, but `iam:PassRole` is scoped away from Lambda with `iam:PassedToService = ec2.amazonaws.com`, producing a non-validated precondition-only result.

Env19 should be a negative mutation rather than a broad "blocked" claim. A permission-boundary or SCP-blocked PassRole mutation can be useful later, but the `iam:PassedToService` mutation is lower risk, single-account, and directly exercises a PassRole-specific truth condition already modeled by the reasoner.

## Env18 IAM Fixture Shape

Use a single-account IAM-only fixture:

- IAM user `env18-alice` under `/iamscope-test/`.
- IAM role `env18-lambda-admin-exec` under `/iamscope-test/`.
- `env18-lambda-admin-exec` trusts `lambda.amazonaws.com`.
- `env18-lambda-admin-exec` has `AdministratorAccess`.
- `env18-alice` has `lambda:CreateFunction` on a precise Lambda function ARN, for example `arn:aws:lambda:${region}:${account_id}:function:env18-passrole-probe`.
- `env18-alice` has `iam:PassRole` on `env18-lambda-admin-exec`.

Do not create a Lambda function for Env18. The benchmark is about whether IAMScope can prove the permission path from collected IAM state, not whether the exploit is executed live. Creating an actual function would add runtime cleanup and code-package risks without adding useful truth evidence for the current reasoner.

The precise Lambda function ARN is important. A wildcard `Resource: "*"` grant for `lambda:CreateFunction` may become an unknown witness under current `FactGraph.has_action` semantics and could turn a positive benchmark into an inconclusive one. During build, confirm AWS accepts the resource-scoped `lambda:CreateFunction` policy shape; if not, pause and redesign rather than weakening the benchmark.

Optional `iam:PassedToService` condition:

- For Env18, prefer either no condition or `StringEquals: {"iam:PassedToService": "lambda.amazonaws.com"}`.
- If included, the shell harness should assert the finding remains validated and the relevant check passes.
- The simpler first pass should use no condition unless the builder wants Env18 to explicitly prove positive `iam:PassedToService` handling.

## Expected Collected Nodes And Edges

Expected `scenario.json` should include:

- IAMUser node for `env18-alice`.
- IAMRole node for `env18-lambda-admin-exec`.
- AWSService node for `lambda.amazonaws.com`.
- `lambda:CreateFunction_permission` edge from `env18-alice` to the precise Lambda function ARN/resource node.
- `iam:PassRole_permission` edge from `env18-alice` to `env18-lambda-admin-exec`.
- `sts:AssumeRole_trust` edge from `lambda.amazonaws.com` to `env18-lambda-admin-exec`.
- Admin-equivalent permission evidence for `env18-lambda-admin-exec` from `AdministratorAccess`.

Expected absent or zero evidence:

- no target-path SCP blocker;
- no target-path permission-boundary blocker;
- no target-path identity-Deny blocker;
- no wildcard/hyperedge witness for `iam:PassRole`;
- no wildcard/hyperedge witness for the `lambda:CreateFunction` permission edge used by the finding.

## Expected Findings

Expected `findings.json` should include one target finding:

- `pattern_id == "passrole_lambda"`;
- source provider ID is `env18-alice`;
- target provider ID is `env18-lambda-admin-exec`;
- `verdict == "validated"`;
- `severity == "critical"`;
- `blockers_observed == []`;
- a session-policy assumption may be present because current reasoner behavior records that session policies are not visible at collection time.

Expected counts for the target path:

- `passrole_lambda.validated >= 1`;
- `passrole_lambda.blocked == 0`;
- `passrole_lambda.inconclusive == 0`;
- `passrole_lambda.precondition_only == 0`.

## Semantic Assertions

Use existing benchmark scorer assertions where they fit:

- `scenario_edge_count` for `lambda:CreateFunction_permission`, source `env18-alice`, `gte 1`.
- `scenario_edge_count` for `iam:PassRole_permission`, source `env18-alice`, target `env18-lambda-admin-exec`, `gte 1`.
- `scenario_edge_count` for `sts:AssumeRole_trust`, target `env18-lambda-admin-exec`, `gte 1`.
- `finding_count` for `passrole_lambda.validated`, source `env18-alice`, target `env18-lambda-admin-exec`, `gte 1`.
- `finding_count` for `passrole_lambda.blocked`, same source/target, `eq 0`.
- `finding_count` for `passrole_lambda.inconclusive`, same source/target, `eq 0`.
- `finding_count` for `passrole_lambda.precondition_only`, same source/target, `eq 0`.

The shell harness should assert the stricter live contract:

- exact Lambda service trust edge exists from `lambda.amazonaws.com` to the target role;
- the validated target finding has severity `critical`;
- the validated target finding has no blockers;
- required checks include successful `source_has_lambda_create_function`, `source_has_passrole_to_target`, and `target_trusts_lambda_service`.

If exact service-principal source matching is desired in the case manifest, add only minimal benchmark scoring support for literal provider IDs or an optional `service_provider_id` context label. Do not add a general graph query engine for Env18.

## Materializer And Case Manifest Needs

Recommended files for the build pass:

- `acceptance/env18_lambda_passrole_validated/`
- `scripts/run_env18_lambda_passrole_benchmark.sh`
- `docs/specs/env18-passrole-benchmark-harness.md`
- `benchmarks/cases/env18_lambda_passrole_validated_admin.json`

Recommended case ID:

- `env18_lambda_passrole_validated_admin`

Recommended materializer support:

- add optional `--env18-archive`;
- map Env18 to `env18_lambda_passrole_validated_admin`;
- output directory pattern `env18-<run_id>`;
- omitted Env18 behaves like other optional environment archives.

Recommended ingest context labels:

- `source_label: alice_arn`;
- `target_label: lambda_admin_role_arn`;
- optional `service_label: lambda_service_principal` only if minimal context support is added.

## Live AWS Risk And Cost Notes

Expected live AWS cost is zero or near-zero because Env18 should create only IAM resources. It should not create a Lambda function, upload code, invoke code, create log groups, or provision networking.

Risk is lower than the SCP benchmarks because Env18 does not require AWS Organizations and does not attach account-level guardrails. The main risks are:

- IAM eventual consistency;
- stale `env18-*` resources after a failed run;
- accidentally using wildcard permissions that make the reasoner correctly return `inconclusive`;
- accidentally creating live Lambda runtime artifacts.

## Cleanup Risks

The runner should:

- copy the acceptance env to a temp work directory;
- remove `.terraform`, state files, and provider caches from the temp copy before execution;
- trap `terraform destroy`;
- fail hard if `scenario.json` or `findings.json` is missing;
- run `iamscope validate` before semantic assertions;
- print `alice_arn`, `lambda_admin_role_arn`, `lambda_function_arn`, and account ID in `run.log`.

Do not copy raw live archives, Terraform state, provider caches, collect directories, `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log` into the repository.

## What This Proves

If Env18 passes, it directly proves:

- IAMScope collects the exact Lambda PassRole path for `env18-alice -> env18-lambda-admin-exec`.
- The source principal has a non-ambiguous `lambda:CreateFunction` witness.
- The source principal has a non-ambiguous `iam:PassRole` witness to the target role.
- The target role trusts Lambda.
- The target role is admin-equivalent.
- IAMScope emits a validated, critical `passrole_lambda` finding for this path.
- IAMScope does not emit blocked, inconclusive, or precondition-only findings for the same target path.

It strongly supports:

- IAMScope's Lambda PassRole reasoner behaves coherently on one controlled live AWS positive path.

## What This Does Not Prove

Env18 does not prove:

- broad PassRole correctness;
- ECS PassRole correctness;
- wildcard PassRole expansion correctness;
- every `iam:PassedToService` condition shape;
- Lambda runtime exploitability after function creation;
- behavior under SCPs, permission boundaries, or identity-policy Deny blockers;
- cross-account PassRole behavior;
- production readiness.

## Exact Build Prompt For Next Pass

Build Env18 as the first PassRole benchmark family. Create `acceptance/env18_lambda_passrole_validated/` with `main.tf`, `run.sh`, `README.md`, and `expected_findings.json`; create `scripts/run_env18_lambda_passrole_benchmark.sh`; create `docs/specs/env18-passrole-benchmark-harness.md`; create `benchmarks/cases/env18_lambda_passrole_validated_admin.json`; and add optional `--env18-archive` materializer support if it follows the existing Env14-Env17 pattern. Use a single-account IAM-only fixture: `env18-alice`, `env18-lambda-admin-exec`, precise `lambda:CreateFunction` permission on `arn:aws:lambda:${region}:${account_id}:function:env18-passrole-probe`, exact `iam:PassRole` permission on the target role, Lambda service trust on the target role, and `AdministratorAccess` on the target role. Do not create a Lambda function. Do not run live AWS unless explicitly asked. Expected result: scenario validation PASS, Lambda CreateFunction permission edge present, PassRole permission edge present, Lambda trust edge present, `passrole_lambda.validated >= 1`, blocked/inconclusive/precondition-only `0`, severity `critical`, and no blockers on the validated target finding.
