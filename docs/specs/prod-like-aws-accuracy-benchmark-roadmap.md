# Prod-Like AWS Accuracy Benchmark Roadmap

## Purpose

This roadmap defines a finite benchmark program for moving from IAMScope's
current public demo baseline to a bounded prod-like AWS sandbox accuracy demo
with known ground truth.

The goal is to prevent open-ended benchmark expansion. Each phase has a
specific output, gate, and stopping condition. New work should continue only
when it closes a named evidence gap in this roadmap.

## Current Evidence Baseline

The current public baseline is frozen at `public-demo-review-v2`.

That baseline includes:

- the local public demo runner:
  `python scripts/run_public_demo_review.py --out /tmp/iamscope-public-demo-review`;
- the local path-overcounting teaching demo;
- the complex frozen synthetic IAM benchmark;
- the narrow PassRole-to-Lambda replay subset generated through existing local IAMScope replay machinery;
- the two-sided controlled PassRole live-bound pair:
  - allowed case: selected local `validated` PassRole-to-Lambda finding matched live AWS `lambda:CreateFunction` success;
  - denied case: missing-PassRole shape produced live AWS `access_denied`, and local IAMScope emitted no selected validated `passrole_lambda` finding.

This baseline shows bounded reasoning behavior. It does not prove broad
IAMScope correctness or accuracy on messy production AWS.

## End Goal

Show IAMScope on a messy prod-like AWS sandbox with known ground truth, compare
findings against an oracle, and produce a bounded reviewer-facing accuracy
report.

## Non-Goals

This benchmark program is not:

- not broad IAMScope correctness;
- production readiness;
- a real production test;
- no composite benchmark score;
- no pass/fail benchmark label;
- arbitrary exploitability proof;
- Lambda invocation behavior;
- generic Deny correctness;
- resource-policy Deny support unless explicitly included in a frozen oracle slice;
- SCP Deny support beyond selected benchmark behavior unless explicitly included in a frozen oracle slice.

## Finite Phase Plan

### Phase 0: Public Demo Baseline Freeze

- Status: done.
- Artifact/tag: `public-demo-review-v2`.
- Gate: tag exists and points to the public demo baseline.
- Stop condition: do not continue Phase 0 work unless the baseline tag is missing or points to the wrong commit.

### Phase 1: Prod-Like Accuracy Benchmark Design

- Status: this PR.
- Output: this roadmap/spec.
- Gate: reviewers agree that the phase plan, gates, and maximum v1 scope are finite.
- Stop condition: do not continue Phase 1 work unless the roadmap lacks a required gate, stop condition, risk control, or claim boundary.

### Phase 2: Local Prod-Like Oracle Fixture

- Output: local synthetic/prod-like fixture with oracle rows.
- AWS use: no AWS.
- Expected categories: `validated`, `blocked`, `precondition_only`, `inconclusive`, and `unsupported` or `static-only`.
- Gate: fixture rows are frozen with row IDs, expected categories, expected evidence, and explicit unsupported/static-only labels.
- Stop condition: do not add another local case unless it covers a named missing evidence category in the benchmark target shape.

### Phase 3: Terraform Sandbox Design

- Output: Terraform-only design for a dedicated AWS sandbox.
- AWS use: no apply yet.
- Required content: teardown plan, account guard, cost/risk guard, and explicit no production account usage.
- Gate: design review confirms account guard, expected account ID variable, teardown path, resource prefixing, and artifact hygiene.
- Stop condition: do not apply Terraform until this design is reviewed and the local oracle from Phase 2 is frozen.

### Phase 4: Controlled Sandbox Deployment and Collection

- Output: live sandbox artifact, sanitized result, and cleanup proof.
- Gate: Phase 3 review is complete, the operator uses a dedicated sandbox account, and live commands are explicitly authorized.
- Stop condition: stop collection after the approved live sandbox artifact and cleanup proof exist. Do not expand live cases unless a Phase 5 comparison identifies a named evidence gap.

### Phase 5: Accuracy Comparison Report

- Output: local comparison of IAMScope findings vs oracle.
- Required categories: matched, missing, extra, false positive, false negative, blocked, inconclusive, and unsupported.
- Scoring: no composite score.
- Gate: comparison report links each result row to oracle evidence, IAMScope evidence, and a reviewer note.
- Stop condition: do not patch IAMScope until every mismatch is classified as a tool bug, fixture/oracle bug, harness bug, or unsupported behavior.

### Phase 6: Public Prod-Like Demo Freeze

- Output: one-command reviewer runner and report.
- Tag: `prod-like-accuracy-demo-v1`.
- Gate: runner uses sanitized local artifacts by default and does not run live AWS.
- Stop condition: stop engineering unless review identifies a specific evidence gap.

## Benchmark Target Shape

The v1 benchmark should be a messy but bounded prod-like AWS sandbox:

- 2 AWS accounts maximum for v1;
- 6 to 10 IAM principals;
- 8 to 12 roles;
- 2 to 4 permission boundaries;
- 2 to 4 SCP-like or account-level guardrail cases if feasible;
- 2 to 3 service-mediated paths;
- 2 to 3 AssumeRole chains;
- 2 to 3 PassRole cases;
- 1 to 2 cross-account trust cases;
- 2 explicit Deny cases;
- 2 wildcard/resource-scope uncertainty cases;
- 2 missing-precondition cases;
- 1 unsupported/static-only category.

## Oracle Categories

- `validated`: IAMScope should emit a finding with sufficient modeled evidence under the benchmark oracle.
- `blocked`: IAMScope should emit or preserve a blocked result because the oracle includes a selected blocker.
- `precondition_only`: IAMScope should identify a path-shaped row where a required modeled precondition is missing.
- `inconclusive`: IAMScope should avoid promotion because a selected uncertainty source prevents a stronger category.
- `unsupported`: the row is intentionally outside current benchmark or IAMScope support and must not be treated as a correctness failure.
- `false_positive`: IAMScope emits a stronger finding than the oracle supports.
- `false_negative`: IAMScope misses a finding the oracle expects it to emit.
- `extra_finding`: IAMScope emits a finding without a corresponding oracle row.
- `missing_finding`: an oracle row has no corresponding IAMScope finding.

## Accuracy Report Shape

The accuracy report must be a table, not a composite score.

| Expected row id | Expected category | IAMScope emitted category | Match status | Evidence used | Blocker/precondition/uncertainty reason | Reviewer note |
| --- | --- | --- | --- | --- | --- | --- |
| `oracle-row-001` | `validated` | `validated` | `matched` | Modeled permission, trust, and blocker evidence | None | Example row shape only. |
| `oracle-row-002` | `blocked` | `blocked` | `matched` | Modeled blocker evidence | Selected blocker applies | Example row shape only. |
| `oracle-row-003` | `inconclusive` | `inconclusive` | `matched` | Modeled uncertainty evidence | Resource scope unresolved | Example row shape only. |

The report may include counts by category, but it must not collapse them into a
single score or pass/fail label.

## Gates And Stop Conditions

- Do not build live AWS until local oracle is frozen.
- Do not apply Terraform until Terraform design is reviewed.
- Do not run in any real production account.
- Do not add a new case unless it covers a named missing evidence category.
- Stop after Phase 6 unless a reviewer identifies a specific correctness gap.
- Maximum v1 live sandbox size: 2 accounts, 10 principals, 12 roles.
- Maximum v1 live validation probes: 4.
- No broad correctness claim even if v1 passes.
- Any failure must be classified as tool bug, fixture/oracle bug, harness bug, or unsupported behavior before patching.

## Public Claim Ladder

- Phase 2 claim: local oracle exists.
- Phase 4 claim: sandbox collection executed and cleaned up.
- Phase 5 claim: IAMScope matched selected oracle categories in a bounded prod-like sandbox.
- Phase 6 claim: runnable prod-like demo exists.

Never allow:

- broad IAMScope correctness;
- production readiness;
- generic Deny correctness;
- exploitability proof.

## Risk Controls

- Dedicated sandbox only.
- Account ID redaction in committed docs.
- No raw AWS result JSON committed.
- Cleanup proof required.
- Terraform state/cache/lock/plan/output not committed.
- No secrets.
- No production account.
- No destructive service actions.
- No Lambda invocation unless separately designed and approved.

## Exact Next Implementation Slice

Recommended next slice: implement local prod-like oracle fixture design.

The next slice should remain local design or fixture-only. It must not run live
AWS, apply Terraform, add live evidence claims, or broaden the benchmark beyond
the finite v1 target shape above.
