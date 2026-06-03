# Public Demo Review Runbook

## Purpose

This runbook describes the local-only public demo review command for IAMScope's current public evidence chain.

It does not add new evidence, run live AWS, or broaden claims. Live AWS evidence is represented only by sanitized checkpoint documents.

## How to run

From the repository root:

```bash
python scripts/run_public_demo_review.py --out /tmp/iamscope-public-demo-review
```

The runner writes generated files under the selected output directory and refuses to write inside the repository tree.

## What the runner checks

The runner performs local checks only:

- focused live-binding fixture and live-harness unit tests;
- account ID hygiene scan for `docs/` and `tests/`;
- IAM ARN hygiene scan for `docs/` and `tests/`;
- generated artifact hygiene scan for live result JSON, Terraform state/cache/plan/output files, and Terraform lock files;
- report-only path-overcounting uncertainty grouping from the local synthetic fixture.
- report-only summary of the complex synthetic benchmark fixture.

The runner treats non-empty account, ARN, or artifact hygiene scan output as a failure. The current expected scan result is no output.

## Generated outputs

The runner generates:

- `/tmp/iamscope-public-demo-review/summary.md`
- `/tmp/iamscope-public-demo-review/manifest.json`
- `/tmp/iamscope-public-demo-review/path-overcounting-uncertainty-groups.json`

Generated outputs are local scratch outputs and are not committed by default.

## Complex Synthetic Benchmark Section

The generated `summary.md` and `manifest.json` include a report-only complex
synthetic benchmark section for
`complex_shared_uncertainty_iam_benchmark_001`.

That fixture is a local-only frozen synthetic oracle. It has `42` naive
candidates, `18` findings, and a verdict breakdown of `4` `validated`, `5`
`blocked`, `3` `precondition_only`, and `6` `inconclusive` rows. Its uncertainty
groups are `shared_passrole_target_resource_scope_unknown`: `3`,
`shared_cross_account_trust_condition_unknown`: `2`, and
`shared_boundary_or_session_policy_context_missing`: `1`.

The complex synthetic benchmark section is not live AWS evidence, was not
generated/replayed by IAMScope, and is not a composite score or pass/fail
benchmark label.

## Claim boundary

IAMScope currently has a local synthetic path-overcounting teaching demo and one two-sided controlled PassRole-to-Lambda validation pair. This is not broad IAMScope correctness.

## Supported claims

- Local synthetic path-overcounting demo shows how IAMScope separates naive path-shaped candidates from validated, blocked, precondition-only, and inconclusive fixture verdicts.
- Allowed PassRole-to-Lambda case: selected local `validated` finding matched live AWS `lambda:CreateFunction` success.
- Denied missing-PassRole case: live AWS returned `access_denied`, and local IAMScope emitted no selected validated `passrole_lambda` finding for the corresponding source/target shape.

## Non-claims

- no broad IAMScope correctness
- no broad PassRole correctness
- no generic Deny correctness
- no resource-policy Deny support
- no SCP Deny support
- no exploitability proof
- no downstream authorization proof
- no Lambda invocation behavior
- no production readiness
- no correctness for other principals, roles, accounts, regions, conditions, permission boundaries, SCPs, resource policies, or findings
- no composite benchmark score
- no pass/fail benchmark label

## Evidence links

- [`docs/REVIEWER_GUIDE.md`](../REVIEWER_GUIDE.md)
- [`docs/case-studies/passrole-lambda-controlled-live-validation.md`](passrole-lambda-controlled-live-validation.md)
- [`docs/case-studies/path-overcounting-shared-uncertainty.md`](path-overcounting-shared-uncertainty.md)
- [`docs/specs/controlled-passrole-lambda-live-binding-001-checkpoint.md`](../specs/controlled-passrole-lambda-live-binding-001-checkpoint.md)
- [`docs/specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md`](../specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md)
- [`tests/fixtures/live_binding/passrole_lambda_selected_finding/`](../../tests/fixtures/live_binding/passrole_lambda_selected_finding/)
- [`tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/`](../../tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/)

## Safety

This runner is local-only. It does not reproduce live AWS, call AWS CLI, call STS, call Lambda APIs, call `iam:PassRole`, or apply/destroy Terraform.
