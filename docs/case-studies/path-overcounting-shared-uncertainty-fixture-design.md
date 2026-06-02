# Path Overcounting and Shared Uncertainty Fixture Design

## Purpose

Define the synthetic fixture for the local-only IAMScope demo about path overcounting and shared uncertainty.

The demo should show a reviewer that a large list of scary-looking IAM candidate paths is not the same thing as a set of validated risks. IAMScope's value in this case study is the separation of modeled evidence into `validated`, `blocked`, `precondition_only`, and `inconclusive` paths, plus a summary of shared evidence gaps that explain many non-promoted paths.

This is a fixture design only. It does not create fixture JSON files, run live AWS, add reasoners, or make new evidence claims.

## Target Demo Behavior

A reviewer should eventually be able to run one local script and see:

```text
Naive interpretation:
23 possible escalation paths

IAMScope:
3 validated
5 blocked
4 precondition_only
11 inconclusive

Top uncertainty class:
8 paths depend on the same unresolved PassRole target-role resource-scope evidence.

Reviewer decision:
Do not treat all 23 as independent validated risks.
Resolve this one evidence gap first.
```

The exact numbers are the intended fixture contract for the future implementation slice, not evidence from a live AWS account.

## Exact Modeled Path Categories

The fixture should include four path categories:

1. `validated`
   - Candidate paths where every required modeled check is supported by local fixture evidence.
   - Intended count: `3`.
   - Demo meaning: IAMScope has sufficient modeled evidence under the fixture's rules for the scoped scenario.

2. `blocked`
   - Candidate paths where explicit local evidence blocks promotion.
   - Intended count: `5`.
   - Blocking examples may include explicit identity-Deny evidence, scoped-away service condition evidence, or missing trust compatibility where the modeled check can be evaluated as blocked.

3. `precondition_only`
   - Candidate paths where the path shape is relevant but a required service/action/resource precondition is not satisfied.
   - Intended count: `4`.
   - Examples may include PassRole-like patterns where one structural precondition is missing, scoped away, or not met in the fixture.

4. `inconclusive`
   - Candidate paths where IAMScope should refuse to promote because a required check is missing or ambiguous.
   - Intended count: `11`.
   - Demo meaning: the path is not validated, and the reviewer should inspect the shared uncertainty source before treating it as an independent risk.

## Intended Naive Candidate Count

The naive interpretation should show `23` possible escalation paths.

This naive count should be represented by a local `naive_candidates.json` file in the future fixture. It should be clear that the naive count is a teaching comparison, not IAMScope's validated finding count.

Naive candidate rule:

A naive candidate is any structurally path-shaped source -> action/precondition -> target row produced by the demo fixture without evaluating blocker, precondition, or uncertainty checks. The naive list is deterministic and fixture-defined. It is not IAMScope output and is not treated as evidence of reachability.

Future tests should assert:

- `len(naive_candidates) == 23`.
- Each naive candidate maps to exactly one IAMScope finding or one documented non-finding reason.

## Intended IAMScope Verdict Breakdown

The future fixture should produce or include findings with this exact breakdown:

| Verdict | Intended Count | Demo Role |
| --- | ---: | --- |
| `validated` | 3 | Supported by all required modeled checks |
| `blocked` | 5 | Explicit local evidence blocks the modeled path |
| `precondition_only` | 4 | Path shape is relevant, but a required precondition is not satisfied |
| `inconclusive` | 11 | Missing or ambiguous required evidence prevents promotion |

These counts should be checked by future tests. They should not be described as live validation results.

## Intended Shared Uncertainty Classes

The fixture should include repeated uncertainty causes so the demo can group inconclusive paths.

Primary class:

- `shared_passrole_target_resource_scope_unknown`
  - Intended count: `8` inconclusive paths.
  - Meaning: IAMScope cannot prove specific target-role resource coverage for a repeated PassRole-like path family.
  - Reviewer lesson: resolve this one evidence gap first instead of treating eight rows as eight independent validated risks.

Secondary classes:

- `shared_boundary_context_unresolved`
  - Intended count: `2` inconclusive paths.
  - Meaning: permission-boundary or SCP context needed by the modeled path family is unresolved.

- `session_policy_context_missing`
  - Intended count: `1` inconclusive path.
  - Meaning: session-policy context needed by the modeled path is not present.

The future grouping helper should read local findings metadata and produce a report-only grouping. It must not change verdicts, reasoner behavior, benchmark semantics, or schemas.

## Existing Repo Assets That Can Be Reused

The fixture implementation should reuse existing local-only IAMScope assets where possible:

- `iamscope validate` for local scenario validation.
- `iamscope report` for rendering a scenario and findings into reviewer-readable output.
- `iamscope why` for explaining a representative inconclusive finding.
- `iamscope replay-findings` if the future fixture includes `scenario.json` plus `binding_metadata.json`.
- `iamscope demo-pack` if a future handoff bundle is useful.
- Existing report renderer behavior for `validated`, `blocked`, `precondition_only`, and `inconclusive` findings.
- Existing tests that demonstrate fixture shape and local report behavior, including `tests/test_report_findings.py`, `tests/test_why_explainer.py`, `tests/test_replay_findings.py`, and `tests/test_demo_pack.py`.
- Existing benchmark cases under `benchmarks/cases/` as modeling references, not as direct public-demo evidence.

Useful modeling references include PassRole validated/non-promoted cases, identity-Deny cases, missing-trust-edge degradation cases, missing-permission-edge degradation cases, and missing-blocker-evidence degradation cases.

## Whether A New Synthetic Fixture Is Required

A new synthetic fixture is required.

Existing benchmark cases are useful references, but they are not arranged around the exact teaching point: one naive list with `23` candidate paths, a four-way IAMScope verdict split, and `8` inconclusive paths sharing one unresolved evidence class.

The new fixture should be:

- synthetic;
- sanitized;
- local-only;
- small enough to understand in under two minutes;
- clearly marked as a demo fixture;
- not described as live AWS evidence.

## Proposed Fixture Files

Future implementation should add proposed fixture files under:

```text
tests/fixtures/demo/path_overcounting_shared_uncertainty/
  scenario.json
  binding_metadata.json
  findings.json
  naive_candidates.json
  expected_uncertainty_groups.json
```

Proposed file roles:

- `scenario.json`
  - Local synthetic IAMScope scenario input.
  - Should include enough modeled principals, roles, policies, trust relationships, and blocker/unknown evidence to support the intended counts.

- `binding_metadata.json`
  - Local sidecar metadata for replay or explanation, if needed.
  - Should capture explicit blocker and unknown-evidence sources without credentials or raw AWS logs.

- `findings.json`
  - Local expected IAMScope-style findings for the demo.
  - Should include exactly `3` `validated`, `5` `blocked`, `4` `precondition_only`, and `11` `inconclusive` findings.

- `naive_candidates.json`
  - Local teaching artifact with `23` naive candidate paths.
  - Should explain that naive candidate rows are not validated IAMScope findings.

- `expected_uncertainty_groups.json`
  - Local expected grouping output.
  - Should include `shared_passrole_target_resource_scope_unknown` with `8` inconclusive paths.

No generated outputs should be committed by default.

## Findings Generation And Replay Legitimacy

The future fixture slice should either:

1. generate or replay `findings.json` from `scenario.json` plus `binding_metadata.json` using existing local IAMScope replay/reasoner machinery, then pin it as expected output; or
2. clearly label `findings.json` as a frozen expected output and include a follow-on replay-equivalence slice before promoting the demo as stronger than a static teaching fixture.

Prefer generate/replay first if existing tooling supports it without new reasoners or benchmark semantic changes.

## Expected Generated Outputs

Future demo runs should write generated outputs under `/tmp/iamscope-path-overcounting-demo/` by default, or under a caller-provided scratch path.

Expected generated files:

```text
/tmp/iamscope-path-overcounting-demo/
  report.md
  verdict-summary.json
  uncertainty-groups.json
  uncertainty-groups.md
  why-inconclusive.txt
```

Expected terminal summary:

```text
IAMScope path-overcounting demo (local only)
Output: /tmp/iamscope-path-overcounting-demo

Naive interpretation:
  possible escalation paths: 23

IAMScope:
  validated: 3
  blocked: 5
  precondition_only: 4
  inconclusive: 11

Top uncertainty class:
  shared_passrole_target_resource_scope_unknown: 8 inconclusive paths

Reviewer decision:
  Do not treat all 23 as independent validated risks.
  Resolve this one evidence gap first.

No AWS calls were made.
```

## Safety Boundaries

The demo and fixture must be local-only:

- No AWS calls.
- No STS probes.
- No `iam:PassRole` calls.
- No Lambda APIs.
- No service launch.
- No AWS resource creation, mutation, or deletion.
- No Terraform.
- No credentials.
- No raw AWS logs.
- No `/tmp` outputs committed.
- No generated reports committed by default.

The future runner should default to `/tmp/iamscope-path-overcounting-demo/` and should refuse repository-output paths unless a test-specific override is explicitly designed.

## What The Fixture May Claim

The fixture may claim:

- The local demo separates naive candidate interpretation from IAMScope findings.
- The local demo represents `validated`, `blocked`, `precondition_only`, and `inconclusive` path categories.
- The local demo shows that several inconclusive paths can share one missing or ambiguous evidence source.
- The local demo helps reviewers decide which evidence gap to resolve first.
- The local demo makes no AWS calls when run as designed.

The public narrative should remain centered on:

1. naive paths;
2. IAMScope verdict split;
3. shared inconclusive cause;
4. reviewer decision.

The fixture may include all four verdicts, but the story should not become a broad benchmark or completeness claim.

## What The Fixture Must Not Claim

The fixture must not claim:

- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Real-world scalability.
- Generic Deny correctness.
- Generic SCP or resource-policy Deny support.
- That any demo path is exploitable in a real AWS account.
- Downstream authorization proof.
- Live AWS validation.
- That all IAMScope findings are verified.
- Composite benchmark scoring or pass/fail benchmark scoring.

## Test Plan

Future implementation should add tests that verify:

- `naive_candidates.json` contains exactly `23` candidate paths.
- Each naive candidate maps to exactly one IAMScope finding or one documented non-finding reason.
- `findings.json` has exactly:
  - `3` `validated`;
  - `5` `blocked`;
  - `4` `precondition_only`;
  - `11` `inconclusive`.
- `expected_uncertainty_groups.json` includes:
  - `shared_passrole_target_resource_scope_unknown` with `8` inconclusive paths;
  - `shared_boundary_context_unresolved` with `2` inconclusive paths;
  - `session_policy_context_missing` with `1` inconclusive path.
- `findings.json` is either generated/replayed from `scenario.json` plus `binding_metadata.json` with existing local IAMScope tooling, or is clearly labeled as frozen expected output with a follow-on replay-equivalence slice.
- Local validation/report commands can consume the fixture without AWS credentials.
- The uncertainty grouping output does not mutate verdicts or findings.
- The future demo runner writes generated files under `/tmp` or a caller-provided scratch path.
- The future demo runner does not invoke `iamscope collect`, STS, `iam:PassRole`, Lambda APIs, Terraform, AWS CLI, or service-launch commands.
- Generated outputs are not committed by default.

## Recommended Next Slice

Recommended next slice: build local synthetic fixture.

This next slice should add only the proposed local fixture files and fixture tests. It should not add live AWS behavior, new reasoners, benchmark semantic changes, or new evidence claims.
