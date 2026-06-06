# IAMScope Reviewer Demo Package

## What This Demo Is

This demo package gives reviewers a short, bounded walkthrough of IAMScope’s differentiated value: evidence-grade IAM findings with explicit verdicts, required checks, blockers, `collection_context`, capability boundaries, replay, human labels, and an owner-confirmation trail.

The strongest current milestone is the frozen tag:

- `real-pilot-dev-001-final-calibrated-reviewed`

The main case study is:

- [`docs/case-studies/real-pilot-dev-001-human-review-summary.md`](../case-studies/real-pilot-dev-001-human-review-summary.md)

The capability boundary reference is:

- [`docs/reference/capability-honesty-matrix.md`](../reference/capability-honesty-matrix.md)

## What This Demo Proves In The Narrow Sense

The final calibrated real-pilot summary records:

- 18 findings.
- 18 validated.
- 15 `cross_account_trust` findings.
- 3 `admin_reachability` findings.
- 18 labeled findings.
- 14 `valid_path` labels.
- 3 `expected_benign` labels.
- 1 `needs_more_evidence` label.
- 5 `owner_confirmed` labels.
- complete `collection_context`.
- sanitized output hygiene clean.

This proves only a bounded workflow point: IAMScope can turn a collected IAM graph into reviewable, evidence-grade findings with explicit capability boundaries, human-review labels, and owner-confirmation metadata for the documented pilot. It does not prove broad correctness or safety.

## What This Demo Does Not Prove

No findings does not mean safe. Validated does not mean exploited. The demo evidence is bounded.

This package does not claim:

- production readiness.
- exploitability proof.
- full IAM safety.
- full AWS authorization semantics.
- complete IAM privilege-escalation coverage.
- broad IAMScope correctness.
- a composite score.
- a pass/fail benchmark label.

## What To Open First

1. [`demo-narrative-one-pager.md`](demo-narrative-one-pager.md) — shortest public-facing story.
2. [`iamscope-vs-pacu-pmapper.md`](iamscope-vs-pacu-pmapper.md) — positioning against Pacu and PMapper without disparaging either tool.
3. [`recorded-demo-script.md`](recorded-demo-script.md) — 7-10 minute recording script.
4. [`live-demo-runbook.md`](live-demo-runbook.md) — safe no-AWS and authorized-AWS demo modes.
5. [`../case-studies/real-pilot-dev-001-human-review-summary.md`](../case-studies/real-pilot-dev-001-human-review-summary.md) — final calibrated real-pilot evidence.

## How To Use The Final Real-Pilot Case Study

Use the case study as the evidence anchor, not as a broad score. The useful review path is:

- confirm the final calibrated replay counts;
- inspect how `cross_account_trust` and `admin_reachability` findings are separated;
- explain how `collection_context` and non-claims keep the evidence bounded;
- show how human labels and owner-confirmation add reviewer accountability without claiming exploitability.

## Related Demo Files

- [`recorded-demo-script.md`](recorded-demo-script.md)
- [`live-demo-runbook.md`](live-demo-runbook.md)
- [`iamscope-vs-pacu-pmapper.md`](iamscope-vs-pacu-pmapper.md)
- [`demo-narrative-one-pager.md`](demo-narrative-one-pager.md)
