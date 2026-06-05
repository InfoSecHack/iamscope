# Prod-Like v3 Corrected Evidence Brief

## One-Paragraph Summary

IAMScope was run against a controlled prod-like IAM sandbox under v3/current
main after correcting `oracle-i-001` fixture semantics. Terraform created 41
IAM-only sandbox resources, IAMScope collected live sandbox artifacts with
`sha256_null_separated_v3_case_sensitive_provider_ids`, and the local comparator
matched 6 currently comparable oracle rows with 0 oracle mismatches while
separating environmental extras, unmapped sandbox extras,
not-currently-live-comparable rows, and unsupported/static-only rows. This
supports reviewer readiness for a bounded real-environment pilot; it is not
production readiness, full IAM correctness, or broad IAMScope correctness.

## What Was Tested

The frozen evidence point is tagged
`prod-like-v3-i001-corrected-collect-compare-001` and summarized in
[`docs/specs/prod-like-aws-sandbox-v3-i001-corrected-collect-and-compare-001-checkpoint.md`](../specs/prod-like-aws-sandbox-v3-i001-corrected-collect-and-compare-001-checkpoint.md).

The run used a controlled prod-like IAM sandbox, not real production AWS.
The live lifecycle was bounded to IAM-only sandbox resources:

- Terraform apply created 41 IAM-only resources.
- IAMScope collection emitted `scenario.json`, `binding_metadata.json`, and
  `findings.json` artifacts.
- Terraform destroy removed 41 resources.
- Prefix cleanup checks returned no remaining sandbox users, roles, or local
  policies.
- Raw AWS logs, account IDs, IAM ARNs, Terraform state, plans, locks, output
  JSON, and live findings artifacts are not committed.

## Why This Is More Than A Toy Demo

This result is more than a hand-authored fixture because it used a freshly
applied live IAM sandbox, current v3 deterministic IDs, IAMScope collection
against that sandbox, and a local comparator over oracle rows. The sandbox is
still controlled and bounded, but it exercises IAMScope on live-collected IAM
relationships rather than only static teaching data.

The result also includes messy-account signal: 12 environmental extras were
separated because existing non-sandbox source principals had relationships to
sandbox target roles. Those rows are useful reviewer context, not hidden or
collapsed into currently comparable oracle rows.

## Result Snapshot

| Item | Result |
| --- | --- |
| ID algorithm | `sha256_null_separated_v3_case_sensitive_provider_ids` |
| Terraform apply | 41 added, 0 changed, 0 destroyed |
| Terraform destroy | 41 destroyed |
| Scenario size | 45 nodes, 103 edges, 14 constraints, 24 edge_constraints |
| Findings | 20 |
| Verdicts | 3 validated, 2 blocked, 15 inconclusive |
| Patterns | 16 `passrole_lambda`, 4 `passrole_ecs` |
| Sandbox-prefixed findings | 20 |
| Sandbox-prefixed nodes | 19 |
| Sandbox-prefixed edges | 41 |
| Cleanup checks | no remaining sandbox users, roles, or local policies |

## Oracle/Comparator Result

| Comparator category | Count |
| --- | ---: |
| Oracle rows | 24 |
| Emitted findings | 20 |
| Sandbox-source findings | 8 |
| Environmental extras | 12 |
| Unmapped sandbox extras | 2 |
| Oracle match | 6 |
| Oracle mismatch | 0 |
| Not-currently-live-comparable | 14 |
| Unsupported static-only | 4 |

The comparator result is intentionally partitioned. The 6 matches are currently
comparable oracle rows, not all rows. The 12 environmental extras were separated,
not called false positives. The 14 not-currently-live-comparable rows were preserved,
not called misses. The 4 unsupported/static-only rows are excluded
from false-positive and false-negative treatment.

`oracle-i-001` matched as inconclusive for
`iamscope-prodlike-v1-uncertainty-resource-probe` to
`iamscope-prodlike-v1-lambda-exec-scoped`. That improvement came from fixing
fixture semantics, not from changing the oracle expectation to improve the
count.

## What IAMScope Did Correctly

For this bounded run, IAMScope:

- collected the live sandbox into scenario, binding, and findings artifacts;
- emitted 20 findings involving sandbox-prefixed targets;
- preserved verdict distinctions across validated, blocked, and inconclusive
  findings;
- matched 6 currently comparable oracle rows with 0 oracle mismatches;
- separated 12 environmental extras from sandbox-source comparisons;
- documented 2 unmapped sandbox extras instead of hiding them;
- preserved not-currently-live-comparable and unsupported/static-only rows
  outside false-positive and false-negative treatment.

## What Remains Unproven

This result does not prove broad IAMScope correctness, full IAM correctness, or
production readiness. It does not show exploitability, downstream authorization,
Lambda invocation behavior, generic Deny correctness, or correctness for other
accounts, regions, principals, roles, conditions, permission boundaries, SCPs,
resource policies, or findings.

It also does not prove v2/v3 ID compatibility. This evidence point is current
v3/current-main evidence; older pre-v3 `/tmp` collections are stale for current
claims.

## Why There Is No Score

There is no composite score and no pass/fail benchmark label because this
benchmark is evidence-layered, not score-based. Rows have different support
levels: currently comparable, environmental extra, unmapped sandbox extra,
not-currently-live-comparable, and unsupported/static-only. Collapsing those
categories into one score would hide the boundary information reviewers need.

## How This Moves Toward Real Production Validation

This checkpoint supports reviewer readiness for a bounded real-environment
pilot. It shows that IAMScope can collect a controlled prod-like IAM sandbox,
retain v3 deterministic IDs, emit findings, separate environmental context, and
compare currently comparable oracle rows without claiming production readiness.

A useful next step is not a broader claim. It is a narrower external pilot with
explicit authorization, agreed scope, redaction rules, and reviewer-defined
questions about whether IAMScope surfaces useful findings and uncertainty in a
real environment.

## Recommended Next External Validation Step

Run a bounded real-environment pilot in an explicitly authorized account or
organization unit. The pilot should start read-only where possible, use approved
profiles and scopes, redact account-specific identifiers before publication,
and compare a small set of reviewer-selected IAMScope findings against manual
review. It should preserve the same evidence categories used here instead of
turning the result into a composite score.

## Non-Claims

This brief does not claim:

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
