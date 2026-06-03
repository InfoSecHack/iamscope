# Complex Synthetic Benchmark Replay-Equivalence Design

## Purpose

This document designs a bounded replay-equivalence path for the local complex
synthetic benchmark fixture:

`tests/fixtures/demo/complex_shared_uncertainty_iam_benchmark/`

The complex synthetic benchmark is currently a frozen synthetic oracle, not
generated/replayed IAMScope output. Replay-equivalence must be proven before
claiming IAMScope generated the complex benchmark findings. Unsupported or
static-only rows must remain labeled as such.

This is design-only. It does not implement replay, change fixture JSON, change
reasoners, change benchmark semantics, or add live evidence.

## Current Fixture Status

Current fixture id: `complex_shared_uncertainty_iam_benchmark_001`.

Current frozen oracle:

- naive candidates: `42`
- findings: `18`
- verdicts: `4 validated`, `5 blocked`, `3 precondition-only`, `6 inconclusive`
- uncertainty groups: `3 / 2 / 1`
- source tool: `static_fixture_authoring`
- generation mode: `frozen_synthetic_oracle`
- generated/replayed by IAMScope: `false`
- reasoners run: `[]`
- live AWS used: `false`
- AWS calls made: `0`

The fixture is intentionally local-only and static until replay-equivalence is
proven with existing local IAMScope machinery.

## Existing Replay/Generation Mechanisms Inspected

Inspected local mechanisms:

- `iamscope/reasoner/replay.py`
- `tests/test_replay_findings.py`
- `iamscope/output/scenario_json.py`
- `iamscope/reasoner/registry.py`
- existing reasoner tests for PassRole, AssumeRole, cross-account trust,
  permission boundary, SCP, identity-Deny, precondition-only, and inconclusive
  behavior

Relevant existing mechanism:

- `run_reasoners_on_frozen_artifacts(...)` can load emitted `scenario.json` and
  `binding_metadata.json` sidecars, reconstruct a `FactGraph`, run selected
  reasoner instances, optionally apply cross-reasoner demotions, and emit
  `findings.json` bytes.
- `load_frozen_fact_graph(...)` expects `scenario.json` in the emitted IAMScope
  scenario shape and `binding_metadata.json` as an edge-constraint binding
  sidecar list.
- Existing tests show replay for a frozen AssumeRole chain and optional probe
  overlay mutation.

Current gap:

- The complex synthetic fixture uses descriptive demo/oracle JSON, not a fully
  emitted IAMScope scenario plus edge-constraint binding sidecar.
- Exact replay-equivalence is not yet proven for the complex synthetic
  benchmark.

## Pattern-By-Pattern Replay Feasibility Table

| pattern/category | existing reasoner/tooling candidate | replayable now? | expected comparison target | gap/risk | recommended next action |
| --- | --- | --- | --- | --- | --- |
| `passrole_lambda` | `PassRoleLambdaReasoner` through `run_reasoners_on_frozen_artifacts` | partial | generated PassRole-to-Lambda findings versus frozen `passrole_lambda` rows | Fixture edge shape may not match emitted `FactGraph` edge features needed by the reasoner; frozen oracle includes static-only precondition/inconclusive rows. | Build a probe that converts only replay-compatible PassRole-to-Lambda rows or reports why conversion is unavailable. |
| `passrole_ecs` | `PassRoleEcsReasoner` through `run_reasoners_on_frozen_artifacts` | partial | generated PassRole-to-ECS findings versus frozen `passrole_ecs` rows | Same scenario/binding shape risk as Lambda; ECS task/run semantics may require precise edge features. | Test replay-compatible ECS rows separately from static-only rows. |
| `assume_role_chain` | `AssumeRoleChainReasoner` through existing replay machinery | partial | generated AssumeRole-chain findings versus frozen `assume_role_chain` rows | Existing replay tests cover a generated chain fixture, but the complex fixture's scenario is not currently in emitted replay format. | Use a minimal complex-fixture conversion probe or keep rows static until emitted format exists. |
| `cross_account_trust` | `CrossAccountTrustReasoner` through registry/replay | partial | generated cross-account findings versus frozen `cross_account_trust` rows | Synthetic same-account placeholder values may not satisfy cross-account classification unless fixture encodes synthetic cross-account attributes without real account IDs. | Probe whether existing reasoner emits expected rows from sanitized synthetic cross-account metadata. |
| permission boundary blocked paths | Existing blocker handling in `AdminReachabilityReasoner`, `AssumeRoleChainReasoner`, and other reasoners | partial | blocked verdict rows with permission-boundary blocker refs | Requires `constraints` and edge-constraint bindings in replay-compatible sidecar shape; current fixture has descriptive blockers only. | Add conversion/readiness checks for boundary constraints before claiming replay. |
| SCP blocked paths | Existing SCP blocker handling in multiple reasoners | partial | blocked or inconclusive rows with SCP blocker refs | Current fixture says SCP blocked only within selected synthetic fixture behavior; replay requires concrete constraints and binding metadata. | Keep SCP rows static until replay-compatible constraints are proven. |
| identity-Deny suppressed paths | Existing identity-Deny blocker helpers in reasoner tests plus static Identity Deny evidence program | partial | blocked or suppressed rows with identity-Deny blocker refs | Generic Deny correctness is not claimed; active Identity Deny runtime validation is not part of this fixture. Replay needs precise constraint binding and reasoner support for the target pattern. | Probe selected identity-Deny fixture behavior only; do not broaden to generic Deny. |
| missing `iam:PassRole` precondition | Reasoner precondition behavior and absence-of-finding semantics | no | no selected generated finding plus documented non-finding reason | Registry skips reasoners or emits no finding when preconditions fail; absence is not a finding, so frozen `precondition_only` rows may not replay as findings. | Treat as static-only unless a report-only comparison layer maps missing preconditions to non-finding explanations. |
| missing target trust precondition | Reasoner precondition behavior and absence-of-finding semantics | no | no selected generated finding plus documented non-finding reason | Existing reasoners generally do not emit precondition-only findings for missing trust; frozen oracle rows are teaching/report rows. | Keep static-only and compare as expected absence, not generated finding. |
| inconclusive/shared uncertainty rows | Reasoner inconclusive verdicts for conditions, wildcard resources, partial/unsupported SCP, boundary/session context | partial | generated inconclusive findings by pattern plus shared uncertainty grouping | Shared uncertainty classes are report-only fixture metadata; existing reasoners may emit inconclusive but not the exact grouping labels. | Split replay of inconclusive verdicts from report-only grouping equivalence. |

## Required Input Contract For Replay

A future replay feasibility probe should require:

- the complex fixture directory;
- `scenario.json`;
- `binding_metadata.json`;
- `findings.json` as the frozen oracle;
- optional output directory under `/tmp` or caller-provided scratch path outside
  the repository;
- a fixed list of existing reasoners to try, such as
  `PassRoleLambdaReasoner`, `PassRoleEcsReasoner`, `AssumeRoleChainReasoner`,
  and `CrossAccountTrustReasoner`.

The probe must not require AWS credentials, Terraform, AWS CLI, STS, Lambda
APIs, or `iam:PassRole` calls.

Before running reasoners, the probe should check whether the fixture
`scenario.json` and `binding_metadata.json` match the existing replay input
contract. If they do not, the probe should report the exact shape gap rather
than attempting to coerce the oracle silently.

## Expected Output Contract For Replay

A future replay feasibility probe should write generated outputs under `/tmp` by
default, for example:

- `/tmp/iamscope-complex-replay-feasibility/replay-feasibility-summary.md`
- `/tmp/iamscope-complex-replay-feasibility/replay-feasibility-manifest.json`
- optional generated findings JSON only if existing local replay succeeds

The output should include:

- reasoners attempted;
- reasoners skipped and skip reasons;
- replay input-contract status;
- matched rows;
- missing rows;
- extra rows;
- intentionally static-only rows;
- unsupported rows;
- safety metadata: local-only, live AWS used `false`, AWS calls made `0`.

The output must not include a composite benchmark score or pass/fail benchmark
label.

## Comparison Method

Design a future local test or script that:

1. loads the complex synthetic fixture;
2. checks whether `scenario.json` and `binding_metadata.json` satisfy the
   existing replay input contract;
3. runs only existing local IAMScope machinery where possible;
4. writes generated/replayed output under `/tmp`;
5. compares generated/replayed findings to the frozen oracle by stable
   comparison keys, such as pattern, source, target, verdict, classification,
   and uncertainty class where applicable;
6. reports matched, missing, extra, and intentionally static-only rows;
7. separately reports non-finding/precondition-only rows expected to remain
   absent from generated findings;
8. reports unsupported rows without treating them as benchmark failures;
9. fails only on schema, safety, hygiene, or regression assertions;
10. does not produce a composite score;
11. does not produce a pass/fail benchmark label.

The comparison should not weaken the fixture oracle to force replay. It should
tell reviewers what existing local IAMScope machinery can and cannot reproduce.

## Likely Gaps

Likely replay gaps:

- The fixture `scenario.json` is currently descriptive and may not match the
  emitted IAMScope scenario shape required by `load_frozen_fact_graph(...)`.
- The fixture `binding_metadata.json` is currently descriptive and may not be an
  edge-constraint binding list accepted by replay.
- `precondition_only` rows may be static/report rows rather than reasoner
  output because reasoner precondition failure usually means no finding is
  emitted.
- Shared uncertainty grouping is report-only metadata and may not be produced by
  existing reasoners.
- Some blocked rows require replay-compatible `Constraint` and
  `EdgeConstraint` objects with correct confidence and binding metadata.
- Cross-account trust-shaped rows may need synthetic cross-account attributes
  without introducing real account IDs.
- Identity-Deny suppressed rows must remain scoped to selected synthetic fixture
  behavior; no generic Deny correctness should be inferred.

Replay-equivalence is not yet proven for the complex synthetic benchmark.

## Minimal Implementation Slice

The minimal implementation slice should add a local probe/script/test that:

- reads the existing complex fixture;
- refuses repository output paths;
- writes to `/tmp` by default;
- checks replay input-contract compatibility;
- attempts replay only with existing reasoners and existing replay machinery;
- reports which rows are replayable, partially replayable, unsupported, or
  intentionally static-only;
- preserves the frozen oracle;
- preserves all non-claims;
- does not add runner integration by default.

The implementation should not change reasoners, fixture semantics, benchmark
semantics, or public evidence claims.

## Evidence Boundaries

This design is local-only. It does not run live AWS and does not reproduce the
controlled PassRole-to-Lambda live evidence.

The complex synthetic benchmark is currently a frozen synthetic oracle, not
generated/replayed IAMScope output.

Replay-equivalence must be proven before claiming IAMScope generated the complex
benchmark findings.

Unsupported or static-only rows must remain labeled as such.

## Non-Claims

This design does not claim:

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

Short-form boundaries:

- no composite benchmark score;
- no pass/fail benchmark label.

## Exact Next Slice

Recommended next slice: implement complex benchmark replay feasibility probe.
