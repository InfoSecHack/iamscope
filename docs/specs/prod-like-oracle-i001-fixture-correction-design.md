# Prod-Like Oracle I001 Fixture Correction Design

## Purpose

Design a bounded local fixture correction for `oracle-i-001` before changing
Terraform, oracle rows, comparator expectations, or running live AWS again.

This design follows the merged triage decision:
`fixture_should_change_to_make_row_truly_inconclusive`.

## Correction Goal

`oracle-i-001` should become genuinely inconclusive due wildcard
resource-scope uncertainty, not blocked by complete-confidence boundary
evidence.

The intended row remains:

- row: `oracle-i-001`;
- source: `iamscope-prodlike-v1-uncertainty-probe`;
- target: `iamscope-prodlike-v1-lambda-exec-scoped`;
- expected category: `inconclusive`;
- intended uncertainty: wildcard target resource scope cannot be proven
  specific enough.

The current fixture conflict is that `uncertainty_probe` also has a permission
boundary attached for a different uncertainty shape. That boundary blocks
`lambda:CreateFunction` and `iam:PassRole` with complete confidence, so the
reasoner emits `blocked` before the wildcard-resource uncertainty can remain
the decisive outcome.

## Option A: Split Uncertainty Source Principals

Split the shared `uncertainty_probe` source into separate test-only principals:

- `uncertainty-resource-probe` for wildcard resource-scope uncertainty with no
  blocking permission boundary;
- `uncertainty-boundary-probe`, or an equivalent scoped name, for
  boundary/session uncertainty rows if those rows still need a boundary or
  unresolved context model.

For `oracle-i-001`, the resource-scope source would keep the wildcard
`iam:PassRole` and `lambda:CreateFunction` policy shape, keep the same selected
target role family, and avoid any complete-confidence boundary that blocks the
required actions.

Benefits:

- preserves the purpose of `oracle-i-001`;
- avoids cross-contaminating unrelated uncertainty rows;
- keeps boundary-blocked and wildcard-resource uncertainty cases separate;
- makes comparator mapping easier to explain;
- reduces future reviewer confusion when one source principal emits both
  intended uncertainty and complete blocker evidence.

Risks:

- changes source principal names in Terraform and local oracle fixture files;
- requires comparator mapping updates if source names change;
- may change cleanup counts or fixture inventory tests;
- requires one fresh controlled live run before updating current evidence
  checkpoints or claims.

## Option B: Keep One Source and Remove Boundary

Keep `uncertainty_probe` as the single source principal and remove its current
permission boundary assignment.

Benefits:

- smaller Terraform diff;
- fewer source principal names to update;
- likely fixes `oracle-i-001` if no other complete blocker remains.

Risks:

- may weaken or alter other uncertainty rows that intentionally depend on the
  boundary/session context shape;
- continues to overload one source principal with multiple uncertainty models;
- makes later triage harder if one row's fixture change affects another row;
- can leave the current two unmapped sandbox extras ambiguous unless they are
  explicitly remapped or removed by the new fixture shape.

## Option C: Model Unresolved Boundary or Session Context

Keep an uncertainty-specific source principal but model boundary/session context
as genuinely unresolved rather than complete-confidence blocking.

Possible approaches include:

- using condition or context shapes that IAMScope cannot fully resolve locally;
- limiting boundary evidence so it is not a complete blocker for
  `lambda:CreateFunction` or `iam:PassRole`;
- representing session-policy uncertainty only in rows intended to test session
  context.

Benefits:

- may preserve boundary/session uncertainty coverage;
- can keep a narrower conceptual fixture if designed carefully.

Risks:

- higher design complexity;
- easier to accidentally create another complete blocker or a false ambiguity;
- harder to validate without broadening the benchmark;
- could drift into reasoner or comparator semantics, which is out of scope for
  the correction slice.

## Recommendation

Recommended correction option: Option A, split source principals.

Option A is cleaner because `oracle-i-001` is a wildcard resource-scope
uncertainty row, not a permission-boundary row. Splitting the source principals
lets `oracle-i-001` preserve its intended wildcard policy shape while moving
boundary/session uncertainty to a separate source that cannot accidentally block
the selected `oracle-i-001` path.

Do not change the oracle expectation to `blocked` merely to improve comparison
counts. The correct fix is to align the fixture shape with the row's stated
purpose.

## Likely Affected Files for Later Implementation

The later local implementation slice will likely need to update:

- `tests/live/aws/prod_like_accuracy_sandbox/terraform/main.tf`;
- `tests/live/aws/prod_like_accuracy_sandbox/README.md`;
- `tests/test_prod_like_terraform_sandbox_files.py`;
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/oracle_rows.json`;
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/scenario.json`;
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/binding_metadata.json`;
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/expected_findings.json`;
- `tests/fixtures/prod_like/aws_accuracy_oracle_v1/expected_comparison.json`;
- `scripts/compare_prod_like_oracle_findings.py`, only if comparator source
  names change.

The implementation should avoid production code, reasoner logic, comparator
category logic, and benchmark claim changes.

## Expected Post-Correction Result

Expected result after local implementation and one fresh controlled validation
run:

- `oracle-i-001` emits `inconclusive`;
- the two current unmapped sandbox extras from `uncertainty_probe` either
  disappear or are explicitly remapped if they remain intended;
- comparator summary moves from `oracle_match=5, oracle_mismatch=1` to likely
  `oracle_match=6, oracle_mismatch=0`, only after a fresh live run proves it;
- environmental extras may remain because they are messy-account signals;
- unsupported/static-only rows remain excluded from false-positive and
  false-negative counts;
- no score/pass-fail label is introduced.

This expected result is a design target, not current evidence.

## Implementation Stop Gates

- Do not run live AWS until local Terraform/source/oracle tests pass.
- Do not change oracle expectations merely to improve count.
- Do not expand the benchmark beyond the `oracle-i-001` correction.
- Do not add new oracle rows.
- Do not add a composite score.
- Do not add a pass/fail benchmark label.
- Stop after corrected fixture design/implementation and one fresh validation
  run.

## Later Validation Sequence

The later implementation slice should use this sequence:

1. update local Terraform/source/oracle fixtures only;
2. run local tests for fixture and oracle files;
3. run Terraform formatting and validation locally;
4. run Terraform plan only, with account/profile guards and reviewer approval;
5. review the plan for IAM-only resources and the expected source-principal
   split;
6. apply, collect, compare, destroy only after plan review;
7. verify cleanup for prod-like users, roles, and local policies;
8. rerun the local comparator;
9. add a sanitized checkpoint only if the fresh run supports the improved
   result.

## Non-Claims

- not broad IAMScope correctness
- not production readiness
- not full oracle success
- not production AWS
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- not v2/v3 cross-version ID compatibility
- no composite benchmark score
- no pass/fail benchmark label

## Exact Next Slice

Recommended next slice: implement oracle-i-001 fixture correction locally without live AWS.
