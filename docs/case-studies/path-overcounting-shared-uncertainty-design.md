# Path Overcounting and Shared Uncertainty Demo Design

## Demo Purpose

Design a local-only public demo that shows IAMScope's core value: it refuses to turn scary-looking IAM candidate paths into `validated` findings unless every required modeled check is supported by evidence. The demo should make uncertainty visible, group repeated uncertainty sources, and help reviewers decide which evidence gap to resolve first.

The intended public wedge is:

> Most IAM attack-path tools hide uncertainty. IAMScope makes uncertainty explicit and refuses to promote a path to `validated` unless the modeled evidence supports every required check.

## Target Audience

- Security engineers evaluating IAMScope for research-preview feedback.
- Cloud/IAM reviewers who want to see why a path is `validated`, `blocked`, `precondition_only`, or `inconclusive`.
- Reviewers comparing IAMScope against tools that emit one large undifferentiated attack-path list.

This is not a live validation demo and not an AWS exploitation demo.

## Exact Problem Being Demonstrated

A naive graph interpretation can overcount IAM attack paths by treating every structurally plausible edge sequence as equally actionable. In practice, many candidate paths should not be promoted because they depend on missing, ambiguous, or blocking evidence.

The demo should show, in under two minutes:

1. A naive candidate list with many scary path-shaped rows.
2. IAMScope's verdict breakdown across the same local fixture:
   - `validated`
   - `blocked`
   - `precondition_only`
   - `inconclusive`
3. Multiple `inconclusive` rows that share the same uncertainty source, for example a wildcard `iam:PassRole` resource edge that cannot prove specific target-role coverage.
4. A reviewer-facing recommendation: resolve the shared evidence gap first, because one missing/ambiguous fact explains several non-promoted paths.

## Existing Repo Assets That Can Be Reused

The current repository already has most of the machinery needed for a local-only case study:

- `iamscope report` can render a scenario with a sibling or explicit `findings.json` into a reviewer-readable report.
- `iamscope why` explains a selected finding and highlights `UNKNOWN` checks and refusal-to-promote behavior.
- `iamscope diff` and `iamscope diff-findings` can compare local scenario or findings files without AWS calls.
- `iamscope replay-findings` can run reasoners over frozen `scenario.json` and `binding_metadata.json` sidecars without collection.
- `iamscope demo-pack` builds frozen replay/probe/diff demo artifacts for local handoff.
- `iamscope.report.findings_renderer` already handles mixed verdicts and grouped findings in reports. Its tests cover empty findings, `validated`, `blocked`, `precondition_only`, `inconclusive`, mixed verdicts, and executive summaries.
- `iamscope.why` already calls out inconclusive findings where a required check returned `UNKNOWN`.
- `tests/test_report_findings.py`, `tests/test_why_explainer.py`, `tests/test_replay_findings.py`, and `tests/test_demo_pack.py` provide useful examples for fixture shape and expected local output behavior.
- Benchmark cases under `benchmarks/cases/` already include bounded examples of `validated`, `blocked`, and non-promoted variants, including PassRole, identity-Deny, SCP, trust-condition, permission-boundary, and degradation cases.

Useful benchmark case references for future implementation design include:

- `benchmarks/cases/env18_lambda_passrole_validated.json`
- `benchmarks/cases/env19_passedtoservice_scoped_away_nonvalidated.json`
- `benchmarks/cases/env20_ecs_passrole_validated.json`
- `benchmarks/cases/env21_ecs_passedtoservice_scoped_away_nonvalidated.json`
- `benchmarks/cases/env03_identity_deny_group_escalation.json`
- `benchmarks/cases/env16_identity_deny_removed_validated_group_escalation.json`
- `benchmarks/cases/deg01_missing_trust_edge.json`
- `benchmarks/cases/deg02_missing_permission_edge.json`
- `benchmarks/cases/deg03_missing_blocker_evidence.json`

## Whether A New Synthetic Fixture Is Needed

A new small synthetic fixture is recommended.

Existing benchmark cases are good evidence-program artifacts, but they are not optimized for a two-minute public story about path overcounting and shared uncertainty. The clearest demo should be a compact local fixture where the same source of uncertainty is intentionally reused by several candidate paths.

The fixture should be synthetic, sanitized, and explicitly marked as a demo. It should not be presented as new live AWS evidence.

## Proposed Directory Layout

Recommended future layout:

```text
docs/case-studies/
  path-overcounting-shared-uncertainty.md
  path-overcounting-shared-uncertainty-design.md

tests/fixtures/demo/path_overcounting_shared_uncertainty/
  scenario.json
  binding_metadata.json
  findings.json
  naive_candidates.json
  expected_uncertainty_groups.json

scripts/
  run_path_overcounting_shared_uncertainty_demo.sh
```

All generated demo outputs should go to `/tmp/iamscope-path-overcounting-demo/` by default, or to a caller-provided scratch directory.

Generated outputs must not be committed by default.

## Proposed Script Name

`scripts/run_path_overcounting_shared_uncertainty_demo.sh`

Proposed behavior:

```sh
scripts/run_path_overcounting_shared_uncertainty_demo.sh \
  --out /tmp/iamscope-path-overcounting-demo
```

The script should be local-only and should do only safe file operations plus IAMScope local CLI/report commands. It should not call `iamscope collect`.

Proposed local steps:

1. Copy the demo fixture files to the output directory.
2. Run `iamscope validate` on the fixture `scenario.json`.
3. Run `iamscope report` against the fixture `scenario.json` and `findings.json`.
4. Run `iamscope why` on one representative `inconclusive` finding.
5. Run a report-only uncertainty grouping helper if implemented in a future slice.
6. Print a concise terminal summary with paths to generated Markdown/JSON files.

## Proposed Expected Output

Proposed terminal shape:

```text
IAMScope path-overcounting demo (local only)
Output: /tmp/iamscope-path-overcounting-demo

Naive candidate paths: 12
IAMScope findings:
  validated: 2
  blocked: 2
  precondition_only: 3
  inconclusive: 5

Top shared uncertainty sources:
  1. passrole_target_resource_coverage_unknown: 4 inconclusive paths
     Why it matters: wildcard/hyperedge PassRole evidence cannot prove the
     specific target role is covered.
     Resolve first: collect or provide exact resource-scoped PassRole evidence.
  2. trust_condition_context_missing: 1 inconclusive path
     Why it matters: condition context needed by the modeled trust check is not
     available in the local scenario.

Generated local files:
  report: /tmp/iamscope-path-overcounting-demo/report.md
  why: /tmp/iamscope-path-overcounting-demo/why-inconclusive.txt
  uncertainty groups: /tmp/iamscope-path-overcounting-demo/uncertainty-groups.md

No AWS calls were made.
```

The exact counts should be fixed by the future fixture and tests. The counts above are a proposed design target, not current evidence.

## What The Demo May Claim

The demo may claim:

- IAMScope can represent candidate paths with separate `validated`, `blocked`, `precondition_only`, and `inconclusive` verdicts in local artifacts.
- IAMScope can show why a finding was not promoted when required modeled checks are missing, ambiguous, or blocked.
- A local report-only grouping can help reviewers identify shared uncertainty sources across multiple inconclusive findings.
- The demo is useful for understanding IAMScope's evidence-bound reporting posture.
- The demo makes no AWS calls when run as designed.

## What The Demo Must Not Claim

The demo must not claim:

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

## Safety Boundaries

The demo must be local-only:

- No AWS calls.
- No STS probes.
- No `iam:PassRole` calls.
- No Lambda APIs.
- No service launch.
- No AWS resource creation, mutation, or deletion.
- No Terraform.
- No credential/profile creation or teardown.
- No raw AWS logs.
- No `/tmp` outputs committed.
- No generated reports committed by default.

The future runner should write to `/tmp/iamscope-path-overcounting-demo/` by default and should refuse to write into the repository unless the caller passes an explicit override designed for tests.

## Recommended Implementation Slices

1. **Fixture design slice**
   - Add a small synthetic fixture under `tests/fixtures/demo/`.
   - Include `scenario.json`, `binding_metadata.json`, `findings.json`, and `naive_candidates.json`.
   - Ensure the fixture includes all four verdicts and repeated uncertainty sources.
   - No AWS calls and no live validation.

2. **Report-only uncertainty grouping helper**
   - Add a local output helper that reads `findings.json` and groups inconclusive findings by normalized missing/ambiguous required-check cause.
   - Do not change verdicts, reasoner logic, benchmark semantics, or schemas.
   - Treat grouping as explanatory reporting only.

3. **Local demo runner**
   - Add `scripts/run_path_overcounting_shared_uncertainty_demo.sh`.
   - Copy fixture files to `/tmp`.
   - Run `iamscope validate`, `iamscope report`, `iamscope why`, and the report-only uncertainty grouping helper.
   - Print a concise terminal summary.

4. **Polished case-study doc**
   - Add `docs/case-studies/path-overcounting-shared-uncertainty.md`.
   - Show the demo commands, expected local outputs, and claim boundaries.
   - Link from `docs/START_HERE.md` only if it remains concise and first-read friendly.

## Validation Plan

For this design-only slice:

- `./scripts/check.sh`
- `./scripts/test_fast.sh`
- `git diff --check`

For future implementation slices:

- Unit tests for the synthetic fixture shape and `iamscope validate` success.
- Unit tests for the uncertainty grouping helper:
  - groups multiple inconclusive findings by the same cause;
  - keeps `validated`, `blocked`, and `precondition_only` counts separate;
  - does not mutate findings or verdicts;
  - rejects or clearly handles malformed findings files.
- Script tests that run the demo into a temp directory and assert generated files are under the caller-provided output root.
- Targeted checks that the demo runner does not invoke `iamscope collect`, STS, `iam:PassRole`, Lambda APIs, Terraform, or AWS CLI commands.
- `./scripts/check.sh`
- `./scripts/test_fast.sh`
- `git diff --check`
