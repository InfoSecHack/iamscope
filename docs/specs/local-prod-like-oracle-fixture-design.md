# Local Prod-Like Oracle Fixture Design

## Purpose

This document defines the local prod-like oracle fixture for IAMScope's prod-like
AWS accuracy benchmark before any fixture JSON, tests, Terraform, or live AWS
work is built.

The fixture design is intentionally bounded, deterministic, and local-only. It
freezes the oracle shape that a later fixture-file PR can implement and test.
It does not prove IAMScope accuracy yet.

## Roadmap Alignment

This is Phase 2 of
`docs/specs/prod-like-aws-accuracy-benchmark-roadmap.md`: Local Prod-Like
Oracle Fixture.

The roadmap end goal is a messy prod-like AWS sandbox with known ground truth,
where IAMScope findings are compared against an oracle and reported through a
bounded reviewer-facing accuracy report.

Later phases remain separate:

- Phase 3: Terraform sandbox design.
- Phase 4: controlled sandbox run.
- Phase 5: accuracy report.

## Fixture Identity And Future Path

- Fixture id: `prod_like_aws_accuracy_oracle_v1`.
- Future fixture path: `tests/fixtures/prod_like/aws_accuracy_oracle_v1/`.

## Local-Only Boundary

This is a local oracle design only:

- no live AWS;
- no Terraform;
- no AWS credentials;
- no production accounts;
- no raw AWS result JSON;
- no real account IDs;
- no broad correctness claim.

## Synthetic Account And Identity Model

The future fixture must use only synthetic identifiers. It must not introduce
non-`000000000000` 12-digit account IDs.

Cross-account semantics should be represented with sanitized aliases:

- `synthetic-account-a`;
- `synthetic-account-b`.

If an ARN-like value is required in fixture JSON, it must use only the synthetic
account `000000000000`, or a non-ARN alias that cannot be mistaken for a real
AWS account or principal.

## Target Fixture Shape

Freeze this v1 target shape:

- 2 synthetic account aliases maximum;
- 8 principals;
- 10 roles;
- 3 permission-boundary cases;
- 3 SCP-like/account-guardrail cases;
- 3 service-mediated paths;
- 3 AssumeRole chains;
- 3 PassRole cases;
- 2 cross-account trust-shaped cases;
- 2 explicit Deny cases;
- 3 wildcard/resource-scope uncertainty cases;
- 3 missing-precondition cases;
- 3 unsupported/static-only cases.

## Oracle Row Categories

Expected oracle categories:

- `validated`: the oracle expects IAMScope to emit a validated finding for the selected modeled evidence.
- `blocked`: the oracle expects a blocker to prevent promotion.
- `precondition_only`: the oracle expects a missing required precondition to prevent promotion.
- `inconclusive`: the oracle expects an unresolved condition, boundary, trust, SCP-like, or resource-scope uncertainty to remain explicit.
- `unsupported`: the row is intentionally outside v1 support and should remain unsupported or static-only.

Later comparison statuses:

- `matched`: IAMScope emitted the expected category for the oracle row.
- `false_positive`: IAMScope emitted a stronger category than the oracle supports.
- `false_negative`: IAMScope failed to emit an expected supported finding/category.
- `extra_finding`: IAMScope emitted a finding without a corresponding oracle row.
- `missing_finding`: an oracle row has no corresponding IAMScope finding.
- `unsupported_behavior`: the row maps to an explicitly unsupported/static-only behavior and is not counted as a false positive or false negative.

## Frozen Oracle Row Plan

This fixture design freezes exactly 24 planned oracle rows.

Category breakdown:

- `validated`: 6.
- `blocked`: 5.
- `precondition_only`: 4.
- `inconclusive`: 5.
- `unsupported`: 4.

| Oracle row id | Expected category | Pattern | Source principal alias | Target alias | Expected IAMScope behavior | Evidence required | Blocker/precondition/uncertainty reason | Current support expectation | Reviewer note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `oracle-v-001` | `validated` | PassRole-to-Lambda allowed scoped role | `principal-ci-deployer` | `role-lambda-exec-scoped` | Emit selected `passrole_lambda` validated finding | `lambda:CreateFunction`, `iam:PassRole`, Lambda trust, no selected blocker | None | `yes` | Mirrors the bounded service-mediated CreateFunction evidence shape without invoking Lambda. |
| `oracle-v-002` | `validated` | PassRole-to-ECS allowed scoped role | `principal-ecs-deployer` | `role-ecs-task-scoped` | Emit selected PassRole-to-ECS modeled finding if supported by current reasoner set | ECS task/run permission, `iam:PassRole`, ECS trust, no selected blocker | None | `partial` | Keeps ECS as modeled service-mediated behavior, not runtime execution proof. |
| `oracle-v-003` | `validated` | Direct AssumeRole allowed | `principal-helpdesk` | `role-readonly-ops` | Emit selected AssumeRole validated finding | `sts:AssumeRole` permission plus target trust | None | `yes` | Single-hop baseline. |
| `oracle-v-004` | `validated` | Two-hop AssumeRole chain allowed | `principal-build` | `role-prod-observer` | Emit selected chain finding | First-hop permission/trust and second-hop permission/trust | None | `yes` | Bounded multi-hop case. |
| `oracle-v-005` | `validated` | Cross-account trust-shaped allowed with modeled condition satisfied | `principal-audit-a` | `role-audit-b` | Emit selected cross-account trust-shaped finding if supported by current reasoner set | Source permission, target trust, modeled satisfied condition | None | `partial` | Uses `synthetic-account-a` and `synthetic-account-b` aliases only. |
| `oracle-v-006` | `validated` | Service-mediated role path with modeled trust and permission evidence | `principal-release-bot` | `role-service-mediated-target` | Emit selected service-mediated modeled finding if supported by current reasoner set | Service action permission, target role trust, service-mediated role use evidence | None | `partial` | No downstream service action or invocation claim. |
| `oracle-b-001` | `blocked` | Permission boundary blocks PassRole-to-Lambda | `principal-boundary-lambda` | `role-lambda-exec-boundary` | Emit or preserve blocked PassRole-to-Lambda result | PassRole/Lambda evidence plus boundary binding | Permission boundary blocks `iam:PassRole` or `lambda:CreateFunction` | `yes` | Boundary blocker should prevent validated promotion. |
| `oracle-b-002` | `blocked` | Permission boundary blocks AssumeRole chain continuation | `principal-boundary-chain` | `role-chain-target` | Emit or preserve blocked chain result | Chain evidence plus boundary binding on continuation edge | Permission boundary blocks second-hop action | `partial` | Tests chain continuation blocker attribution. |
| `oracle-b-003` | `blocked` | SCP-like guardrail blocks PassRole | `principal-scp-passrole` | `role-scp-passrole-target` | Emit or preserve blocked PassRole result | PassRole evidence plus SCP-like/account-guardrail binding | SCP-like guardrail blocks `iam:PassRole` | `partial` | Selected benchmark behavior only, not generic SCP Deny support. |
| `oracle-b-004` | `blocked` | Identity-Deny suppresses AssumeRole | `principal-identity-deny` | `role-denied-assume` | Emit or preserve blocked/static suppression result where supported | AssumeRole evidence plus identity-Deny evidence | Explicit identity Deny suppresses `sts:AssumeRole` | `partial` | Static/report validation only unless future phase explicitly adds runtime proof. |
| `oracle-b-005` | `blocked` | Explicit Deny blocks service-mediated permission | `principal-deny-service` | `role-service-denied` | Emit or preserve blocked service-mediated result where supported | Service permission evidence plus explicit Deny | Explicit Deny blocks service action | `partial` | No generic Deny correctness claim. |
| `oracle-p-001` | `precondition_only` | Missing `iam:PassRole` | `principal-missing-passrole` | `role-lambda-exec-missing-passrole` | Emit no selected validated PassRole finding, or emit precondition-only where supported | Lambda create/service action exists; PassRole witness absent | Missing `iam:PassRole` | `yes` | Aligns with denied controlled case expectation. |
| `oracle-p-002` | `precondition_only` | Missing target service trust | `principal-missing-trust` | `role-no-lambda-trust` | Avoid validated service-mediated finding | Source permissions exist; target trust to required service absent | Missing target service trust | `partial` | Target-first reasoners may emit no finding rather than precondition-only. |
| `oracle-p-003` | `precondition_only` | Missing `lambda:CreateFunction` or service action | `principal-missing-service-action` | `role-lambda-exec-service-action` | Avoid selected validated PassRole-to-Lambda finding | PassRole and trust exist; service action absent | Missing service action permission | `yes` | No live AWS call implied. |
| `oracle-p-004` | `precondition_only` | Missing `sts:AssumeRole` permission | `principal-missing-assume` | `role-assume-target` | Avoid selected validated AssumeRole finding | Target trust exists; source permission absent | Missing `sts:AssumeRole` permission | `yes` | Missing permission should not become a validated path. |
| `oracle-i-001` | `inconclusive` | Wildcard target resource scope unknown | `principal-wildcard-scope` | `role-wildcard-target` | Emit inconclusive or preserve uncertainty | Wildcard/resource scope evidence | Target resource scope cannot be proven specific enough | `yes` | Keeps shared uncertainty visible. |
| `oracle-i-002` | `inconclusive` | Unresolved condition key | `principal-condition-unknown` | `role-condition-target` | Emit inconclusive where supported | Permission/trust evidence with unresolved condition key | Condition key context unavailable | `partial` | Must not assume condition satisfaction. |
| `oracle-i-003` | `inconclusive` | Session policy or permission boundary context missing | `principal-session-context` | `role-session-target` | Emit inconclusive or retain assumption where supported | Path evidence plus missing session/boundary context | Runtime/session context missing | `partial` | Does not prove runtime authorization. |
| `oracle-i-004` | `inconclusive` | SCP-like scope unknown | `principal-scp-unknown` | `role-scp-unknown-target` | Emit inconclusive where supported | Path evidence plus ambiguous SCP-like scope | Account/OU guardrail scope unknown | `partial` | Selected benchmark behavior only. |
| `oracle-i-005` | `inconclusive` | Cross-account trust condition unknown | `principal-cross-condition-a` | `role-cross-condition-b` | Emit inconclusive where supported | Cross-account trust-shaped evidence plus unresolved trust condition | Trust condition context unknown | `partial` | Uses sanitized account aliases only. |
| `oracle-u-001` | `unsupported` | Generic resource-policy Deny outside v1 support | `principal-resource-deny` | `resource-policy-target` | Keep unsupported/static-only | Resource-policy Deny note | Generic resource-policy Deny outside v1 support | `no` | Not counted as false positive or false negative. |
| `oracle-u-002` | `unsupported` | Service-specific condition semantics outside v1 support | `principal-service-condition` | `role-service-condition-target` | Keep unsupported/static-only | Service-specific condition note | Condition semantics outside v1 support | `no` | Avoids overclaiming service-specific policy semantics. |
| `oracle-u-003` | `unsupported` | Downstream Lambda invocation behavior outside v1 support | `principal-lambda-invocation` | `role-lambda-runtime-target` | Keep unsupported/static-only | Invocation behavior note | Lambda invocation behavior outside v1 support | `no` | No Lambda invocation behavior claim. |
| `oracle-u-004` | `unsupported` | Broad exploitability/downstream authorization outside v1 support | `principal-exploitability` | `role-downstream-target` | Keep unsupported/static-only | Downstream authorization note | Exploitability/downstream authorization outside v1 support | `no` | Explicit non-claim row. |

## Future Fixture File Plan

The next PR should implement:

- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/README.md`
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/oracle_rows.json`
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/scenario.json`
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/binding_metadata.json`
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/expected_findings.json`
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/expected_comparison.json`

## Future Tests To Build Next

Focused tests should verify:

- all required files exist;
- fixture id is correct;
- exactly 24 oracle rows;
- category breakdown is 6 / 5 / 4 / 5 / 4;
- all row IDs are stable and unique;
- no non-synthetic 12-digit IDs;
- no non-synthetic IAM ARNs;
- no live AWS artifacts;
- no Terraform state/cache/lock/plan/output files;
- unsupported rows are not counted as false positives or false negatives;
- no composite score or pass/fail label exists;
- all rows include `evidence_required` and `reviewer_note`.

## Accuracy Comparison Method

Phase 5 should compare:

- oracle row id;
- expected category;
- emitted IAMScope category;
- match status;
- evidence used;
- blocker/precondition/uncertainty reason;
- reviewer note.

Counts by category are allowed. There must be no composite score and no
pass/fail benchmark label.

## Gates And Stop Conditions

- Do not build fixture JSON until this design is merged.
- Do not build Terraform until fixture files and tests are merged.
- Do not run live AWS until local oracle fixture is frozen.
- Do not add rows beyond 24 unless a reviewer identifies a named missing evidence category.
- Do not add a new category unless it maps to the roadmap.
- Stop this phase after design is merged and next fixture-file PR is opened.

## Evidence Boundaries And Non-Claims

- not broad IAMScope correctness;
- not production readiness;
- not real production AWS;
- not exploitability proof;
- not downstream authorization proof;
- not Lambda invocation behavior;
- not generic Deny correctness;
- not resource-policy Deny support except unsupported/static-only row labeling;
- not SCP Deny support beyond selected benchmark behavior;
- no composite benchmark score;
- no pass/fail benchmark label.

## Exact Next Implementation Slice

Recommended next slice: implement local prod-like oracle fixture files and oracle tests.
