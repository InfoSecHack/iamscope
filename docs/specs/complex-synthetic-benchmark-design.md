# Complex Synthetic Benchmark Design

## Purpose

This document designs a future local-only synthetic IAMScope benchmark/demo fixture named
`complex_shared_uncertainty_iam_benchmark_001`.

The purpose is to make the public demo more representative without adding live
AWS evidence. The future fixture should test whether IAMScope can locally and
deterministically separate validated, blocked, precondition-only, and
inconclusive paths in a more complex synthetic IAM graph, while also grouping
shared uncertainty classes that affect multiple path-shaped candidates.

This is a design/spec slice only. It does not add fixture JSON, tests, runner
integration, reasoner changes, live AWS behavior, benchmark semantics, or new
evidence claims.

## Reviewer-Facing Claim Boundary

The future fixture may support one narrow reviewer-facing story:

IAMScope reduces overconfident path interpretation by separating validated,
blocked, precondition-only, and inconclusive paths, and by grouping shared
uncertainty.

The design is not broad IAMScope correctness. It is not exploitability proof.
It is not production readiness. It is not live AWS validation.

## Synthetic Graph Overview

The fixture should model a synthetic multi-principal AWS IAM graph with
overlapping PassRole and AssumeRole patterns. It should use only the synthetic
account `000000000000`.

Suggested future fixture path:

`tests/fixtures/demo/complex_shared_uncertainty_iam_benchmark/`

The graph should include:

- multiple source principals that can reach different services or roles;
- multiple target roles with different trust and constraint states;
- service principals for Lambda and ECS;
- synthetic resources that make path-shaped rows concrete without implying
  live AWS reachability;
- repeated ambiguity sources so several inconclusive findings share the same
  missing evidence class.

## Principals

The future fixture should include five source principals:

- `AnalystUser`
- `CICDRole`
- `DeveloperRole`
- `ReadOnlyAuditRole`
- `BreakGlassCandidateRole`

Each principal should have deterministic synthetic identifiers under account
`000000000000`. No real account IDs or real IAM ARNs should be committed.

## Roles and Resources

The future fixture should include six target roles:

- `LambdaExecutionAdminLikeRole`
- `LambdaExecutionScopedRole`
- `ECSExecutionAdminLikeRole`
- `CrossAccountOpsRole`
- `BoundaryConstrainedRole`
- `UnknownResourceScopeRole`

The future fixture should include two service principals:

- `lambda.amazonaws.com`
- `ecs-tasks.amazonaws.com`

Optional synthetic resources may include:

- one Lambda function resource pattern;
- one ECS task or service pattern;
- one Secrets Manager secret pattern;
- one S3 bucket pattern.

Resource identifiers should be synthetic and deterministic. Any role named
`AdminLikeRole` should be treated as a synthetic label for fixture structure,
not as downstream authorization proof or exploitability proof.

## Edge Categories

The fixture should cover these edge categories:

- PassRole-to-Lambda candidate edges.
- PassRole-to-ECS candidate edges.
- AssumeRole chain edges.
- Cross-account trust-shaped edges using only synthetic account values.
- Permission boundary blocked path evidence.
- SCP blocked path evidence scoped only to this synthetic fixture.
- Identity-Deny suppressed path evidence scoped only to this synthetic fixture.
- Missing `iam:PassRole` precondition evidence.
- Missing target trust precondition evidence.
- Shared unknown resource-scope evidence.

The fixture should not add new reasoners or benchmark semantics. If an expected
path cannot be represented with existing local IAMScope behavior, the next
implementation slice should document that gap in the oracle instead of faking a
finding.

## Expected Naive Candidate Categories

The future fixture should include roughly 35 to 60 deterministic naive
path-shaped candidate rows. A naive candidate should be any source ->
action/precondition -> target row emitted by the fixture before evaluating
blockers, preconditions, or uncertainty.

Naive candidate categories should include:

- Lambda `CreateFunction` plus `iam:PassRole` shaped rows.
- ECS task-definition/run plus `iam:PassRole` shaped rows.
- direct AssumeRole shaped rows.
- chained AssumeRole shaped rows.
- cross-account trust-shaped rows using synthetic account identifiers.
- rows blocked by permission boundary evidence.
- rows blocked by SCP-like evidence scoped only to this fixture.
- rows suppressed by selected identity-Deny evidence scoped only to this
  fixture.
- rows missing `iam:PassRole` evidence.
- rows missing target trust evidence.
- rows with unknown target resource scope.

The naive list is not IAMScope output and should not be treated as evidence of
reachability.

## Expected IAMScope Verdict Categories

The future fixture should produce roughly 15 to 25 IAMScope finding/verdict
rows. The exact count should be frozen only in the implementation slice, after
the fixture oracle is derived from existing local behavior.

Intended lower bounds:

- at least 4 validated rows;
- at least 4 blocked rows;
- at least 3 precondition-only rows;
- at least 6 inconclusive rows;
- at least 3 shared uncertainty classes.

If the implementation slice chooses exact counts, those counts should be
documented as fixture-oracle counts and pinned by local tests.

Expected verdict categories:

- `validated`: all modeled evidence required by the selected existing reasoner
  is present under the synthetic fixture rules.
- `blocked`: a selected blocker, such as permission boundary, SCP-like fixture
  evidence, or identity-Deny fixture evidence, suppresses the path.
- `precondition_only`: the row represents a missing prerequisite such as absent
  `iam:PassRole` or absent target trust and should not be promoted to validated.
- `inconclusive`: the row has path-shaped structure but depends on unresolved
  resource-scope, trust-condition, boundary, session-policy, or SCP-like
  context.

## Shared Uncertainty Classes

The fixture must include these shared uncertainty classes:

- `shared_passrole_target_resource_scope_unknown`
- `shared_cross_account_trust_condition_unknown`
- `shared_boundary_or_session_policy_context_missing`

Optional additional class:

- `shared_scp_scope_unknown`

The primary public lesson should be that several inconclusive paths can share
one missing evidence source. A reviewer should resolve the shared uncertainty
before treating the affected rows as independent validated risks.

## Exact Files To Build Next

The next implementation slice should add proposed fixture files under:

`tests/fixtures/demo/complex_shared_uncertainty_iam_benchmark/`

Proposed files:

- `scenario.json`
- `binding_metadata.json`
- `findings.json`
- `naive_candidates.json`
- `expected_uncertainty_groups.json`
- `README.md`

The fixture files should be synthetic, deterministic, sanitized, and local-only.
Generated `/tmp` outputs should not be committed.

## Local Tests To Build Next

The next implementation slice should add focused local tests that verify:

- fixture files exist;
- only synthetic account `000000000000` appears;
- no raw live IAM ARNs appear;
- no generated outputs, Terraform state/cache/provider artifacts, plan files,
  outputs JSON, or raw live artifacts are committed;
- naive candidate count is within the chosen design range or equals a frozen
  oracle count;
- finding/verdict counts match the frozen fixture oracle;
- each naive candidate maps to one IAMScope finding or one documented
  non-finding reason;
- each inconclusive finding referenced by an uncertainty group exists in
  `findings.json`;
- shared uncertainty classes include
  `shared_passrole_target_resource_scope_unknown`,
  `shared_cross_account_trust_condition_unknown`, and
  `shared_boundary_or_session_policy_context_missing`;
- no output claims live AWS validation, exploitability proof, production
  readiness, broad correctness, composite benchmark score, or pass/fail
  benchmark label.

## Demo Runner Integration Plan

After the fixture and oracle tests exist, a later slice may wire the fixture
into the local public demo review runner.

The integration should remain local-only and should:

- read the committed synthetic fixture;
- write generated outputs under `/tmp` or a caller-provided path outside the
  repository;
- summarize naive candidate counts, verdict counts, and shared uncertainty
  classes;
- preserve the existing public claim boundary;
- avoid composite scoring or pass/fail benchmark labels;
- avoid live AWS, Terraform, AWS CLI, STS, Lambda API, and `iam:PassRole` calls.

Runner integration should not be part of the next implementation slice unless a
future review explicitly narrows it to a small, report-only change.

## Evidence Boundaries

This design is for a local synthetic benchmark/demo fixture only.

The future fixture should not be described as live AWS evidence. It should not
claim replay equivalence unless a separate local replay-equivalence test proves
that equivalence using existing IAMScope machinery without reasoner or benchmark
semantic changes.

The fixture may claim only that, for this synthetic deterministic graph,
IAMScope's local outputs separate path-shaped candidates into validated,
blocked, precondition-only, and inconclusive categories under the fixture oracle.

## Non-Claims

This design and the future fixture do not claim:

- broad IAMScope correctness;
- broad PassRole correctness;
- generic Deny correctness;
- resource-policy Deny support;
- SCP Deny support beyond selected synthetic fixture behavior;
- exploitability proof;
- downstream authorization proof;
- Lambda invocation behavior;
- production readiness;
- correctness for real AWS environments;
- correctness for other principals, roles, accounts, regions, conditions,
  permission boundaries, SCPs, resource policies, or findings;
- composite benchmark score;
- pass/fail benchmark label.

Short-form review boundaries:

- not broad IAMScope correctness;
- not exploitability proof;
- no composite benchmark score;
- no pass/fail benchmark label.

## Exact Next Implementation Slice

Recommended next slice: implement complex synthetic benchmark fixture and oracle tests.
