# External Reviewer Start Here

## What IAMScope Is

IAMScope is a research-preview AWS IAM reasoning project. It builds local
scenario graphs from IAM evidence, reasons about selected IAM risk patterns, and
keeps verdict boundaries explicit instead of collapsing every path-shaped row
into one broad claim. The current public evidence is meant for review and
bounded testing, not production readiness.

## What Evidence Exists Now

The strongest current evidence point is a frozen corrected prod-like v3 slice:

- frozen tag: `prod-like-v3-i001-corrected-collect-compare-001`;
- controlled prod-like AWS IAM sandbox;
- live collection from the sandbox;
- v3 deterministic IDs;
- known-ground-truth oracle comparison;
- sanitized checkpoint and reviewer evidence brief;
- no composite score;
- no pass/fail label.

IAMScope also has a local synthetic path-overcounting teaching demo and a
separate two-sided controlled PassRole-to-Lambda validation pair. This page
focuses on the corrected prod-like v3 evidence because it is the best current
entry point for external reviewers who want to decide whether IAMScope is worth
bounded testing.

## The Corrected Prod-Like v3 Result

For one controlled prod-like AWS IAM sandbox run, Terraform created 41 IAM-only
resources, IAMScope collected the live sandbox with v3 deterministic IDs, and
Terraform destroyed 41 resources. Cleanup checks returned no remaining sandbox
users, roles, or local policies.

The collected scenario contained 45 nodes, 103 edges, 14 constraints, and 24
edge_constraints. IAMScope emitted 20 findings: 3 validated, 2 blocked, and 15
inconclusive. The pattern split was 16 `passrole_lambda` findings and 4
`passrole_ecs` findings.

The known-ground-truth oracle comparison reported:

- 6 currently comparable oracle matches;
- 0 oracle mismatches;
- 12 environmental extras separated;
- 2 unmapped sandbox extras documented;
- 14 not-currently-live-comparable rows preserved;
- 4 unsupported static-only rows excluded.

The `oracle-i-001` correction fixed fixture semantics. It did not change the
oracle expectation to improve the count.

## What The Result Does Not Prove

This result is not production-ready evidence. It is not broad IAMScope
correctness, full IAM correctness, exploitability proof, downstream
authorization proof, Lambda invocation behavior, generic Deny correctness, or
v2/v3 ID compatibility.

The 12 environmental extras are not labeled false positives here. They are
messy-account signal: existing non-sandbox source principals had relationships
to sandbox target roles. The 14 not-currently-live-comparable rows are preserved
rather than treated as misses. The 4 unsupported static-only rows are excluded
from false-positive and false-negative treatment.

There is no composite score and no pass/fail benchmark label because the result
is evidence-layered. The category boundaries are part of the result.

## Why This Is Ready For External Review

This evidence is ready for external review because it is concrete, bounded, and
sanitized:

- the sandbox was live-collected rather than hand-authored only;
- Terraform lifecycle evidence records 41 IAM-only resources created and
  destroyed;
- the comparator separates currently comparable oracle rows from unsupported,
  not-currently-live-comparable, environmental, and unmapped rows;
- the public docs state non-claims directly;
- raw AWS account IDs, raw IAM ARNs, raw live outputs, Terraform state, plans,
  locks, and output JSON are not committed.

The intended reviewer question is not whether IAMScope is production-ready. The
question is whether the evidence boundaries, comparator categories, and current
findings are credible enough to justify a bounded real-environment pilot.

## What Kind Of Help/Testing Is Useful

Useful external help would include:

- reviewing whether the oracle rows are meaningful;
- checking whether the non-claims are clear enough;
- reviewing whether environmental extras are classified reasonably;
- challenging whether the comparator logic is defensible;
- proposing a safe bounded real-environment pilot;
- identifying IAM edge cases that should be added next.

Useful testing should stay explicitly authorized and bounded. A good pilot would
use agreed scope, approved AWS profiles/accounts, redaction rules, and a small
set of reviewer-selected questions. It should not start by treating IAMScope as
a production control or by converting layered evidence into a score.

## Links To Evidence Files

- Evidence brief:
  [`docs/case-studies/prod-like-v3-i001-corrected-evidence-brief.md`](prod-like-v3-i001-corrected-evidence-brief.md)
- Corrected checkpoint:
  [`docs/specs/prod-like-aws-sandbox-v3-i001-corrected-collect-and-compare-001-checkpoint.md`](../specs/prod-like-aws-sandbox-v3-i001-corrected-collect-and-compare-001-checkpoint.md)
- Reviewer guide:
  [`docs/REVIEWER_GUIDE.md`](../REVIEWER_GUIDE.md)
- Start-here guide:
  [`docs/START_HERE.md`](../START_HERE.md)

## Suggested Reviewer Questions

- Are the oracle rows meaningful?
- Are the non-claims clear enough?
- Are environmental extras classified reasonably?
- Is the comparator logic defensible?
- What would be a safe bounded real-environment pilot?
- What IAM edge cases should be added next?

## Non-Claims

This page does not claim:

- broad IAMScope correctness;
- production readiness;
- full IAM correctness;
- exploitability proof;
- downstream authorization proof;
- Lambda invocation behavior;
- generic Deny correctness;
- v2/v3 ID compatibility;
- composite benchmark score;
- pass/fail benchmark label.
