# IAMScope Demo Narrative

IAMScope is not trying to be Pacu.

IAMScope is not trying to be a full replacement for PMapper.

IAMScope is trying to answer a narrower reviewer question: what IAM paths can we support with evidence, what remains uncertain, and what should a human review first?

## The Short Version

Many IAM tools help you exploit, query, or graph an AWS environment. Those are useful jobs. IAMScope is focused on a different job: evidence-grade review.

In the current final calibrated real-pilot milestone, IAMScope produced:

- 18 findings.
- 18 validated.
- 15 `cross_account_trust`.
- 3 `admin_reachability`.
- 14 `valid_path`.
- 3 `expected_benign`.
- 1 `needs_more_evidence`.
- 5 `owner_confirmed`.
- complete `collection_context`.

The point is not that these numbers are a score. They are not. The point is that each finding can be discussed as a review artifact with checks, evidence boundaries, labels, and non-claims.

## Why This Is Different

IAMScope keeps the reviewer workflow visible:

- collect or replay the IAM graph;
- run bounded reasoners;
- emit findings with verdicts and required checks;
- show blockers and uncertainty;
- preserve `collection_context`;
- map findings to human labels;
- add owner-confirmation when available;
- keep raw artifacts local unless sanitized.

This is why the demo uses phrases like evidence-grade, bounded, reviewable, and owner-confirmed instead of “exploited” or “safe.”

## The Lines We Do Not Cross

No findings does not mean safe.

Validated does not mean exploited.

The demo evidence is bounded.

This demo does not claim:

- production readiness.
- exploitability proof.
- full IAM safety.
- full AWS authorization semantics.
- complete IAM privilege-escalation coverage.
- broad IAMScope correctness.
- a composite score.
- a pass/fail benchmark label.

## Reviewer Takeaway

IAMScope is for the moment after a graph looks scary but before a reviewer can act. It helps separate “the evidence supports this,” “this looks expected-benign,” “this needs more evidence,” and “this is outside current modeled capability.”
