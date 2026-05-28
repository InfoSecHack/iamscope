# Validator Safety Helper Consistency Review

## Purpose

Review safety-helper consistency across the controlled validation report
validators before any shared helper extraction. This is a docs/review slice only:
it does not change validator behavior, report schemas, benchmark semantics,
public claims, or live validation posture.

## Validators Reviewed

- `benchmarks/runtime/controlled_sts_validation_report.py`
- `benchmarks/runtime/controlled_passrole_validation_report.py`
- `benchmarks/runtime/controlled_identity_deny_validation_report.py`

## Consistency Findings

All three validators share the same high-level safety pattern:

- Validate one controlled report shape.
- Reject unknown top-level fields.
- Recursively scan JSON object keys for unsafe terms.
- Require bounded outcome classifications.
- Require artifact-safety fields.
- Require non-claim coverage.
- Emit a safe validation summary.
- Make no AWS calls and require no credentials.

The recursive key scanning implementation is structurally the same in all three
validators: normalize a key, compare against forbidden terms, allow a narrow
safe-key exception set, recurse into dictionaries/lists, and report the JSON path
on rejection.

Common unsafe-label rejection is consistent for:

- `composite_score`
- `overall_score`
- `pass_fail`
- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`
- `benchmark_passed`

Common credential-shaped rejection is consistent for normalized forms of:

- `AccessKeyId`
- `SecretAccessKey`
- `SessionToken`
- `credentials`
- `credential`
- `secret`
- `token`
- `raw_credentials`
- `aws_session_token`
- `secret_value`
- `access_key_id`

The last four are not listed literally in every validator, but they are rejected
by normalized substring matching against the broader credential/secret/token
terms.

Artifact-safety checks are also consistent at the invariant level:

- `credentials_committed=false`
- `raw_artifacts_committed=false`
- `tmp_outputs_committed=false`
- `sanitized_summary_only=true`
- `reviewer_checked` must be boolean

## Intentional Behavior Differences

Some differences are report-domain-specific and should remain local to each
validator:

- STS reports have `runtime_probe`, `sts_assume_role_called`, and
  `credentials_obtained` fields.
- PassRole reports have `iam_passrole_called`, `service_launch_attempted`, and
  service-principal/target-role fields.
- Identity Deny reports have explicit `allow_basis`, `deny_basis`,
  `condition_context`, `destructive_action_called`, and `resource_modified`
  fields.
- STS allows observed outcomes such as `unexpected_account` and
  `skipped_safety_guard`.
- PassRole and Identity Deny allow `unsupported_method`.
- Identity Deny requires generic-Deny, resource-policy Deny, SCP Deny,
  all-findings-verified, and real-world scalability non-claims because those are
  specific risks for that evidence boundary.
- PassRole requires downstream service execution and downstream authorization
  non-claims.
- STS allows `credentials_obtained` as safe metadata because assumed-role proof
  reports need to state whether temporary credentials were obtained without
  exposing credentials.

These differences are expected and should not be flattened by a broad helper.

## Differences That Should Be Fixed

No P1 or P2 blocker was found.

One P3 consistency gap should be fixed before broader helper extraction:

- Identity Deny explicitly forbids `raw_aws_log` and `raw_error`; STS and
  PassRole do not list those exact terms in `FORBIDDEN_KEY_TERMS`. The existing
  artifact-safety fields reject committed raw artifacts, and tests cover many
  credential/unsafe-label cases, so this is not currently a release blocker.
  Still, the three report validators should converge on the same exact
  raw-log/raw-error forbidden terms.

## Proposed Helper Extraction Boundaries

Safe first extraction:

- `_normalize_key`
- `_has_forbidden_key_term`
- recursive forbidden-key scanning
- shared baseline forbidden-key terms
- shared baseline safe-key exceptions

Keep domain-specific in each validator:

- required top-level fields
- report type and schema version checks
- allowed observed outcomes
- allowed outcome classifications if they remain report-specific
- report-specific safety flags such as `sts_assume_role_called`,
  `iam_passrole_called`, `service_launch_attempted`,
  `destructive_action_called`, and `resource_modified`
- report-specific non-claim marker sets
- summary payload shape

Do not extract artifact-safety validation in the first helper slice. The
invariants are similar, but field names differ enough that a premature common
helper would either become too generic or accidentally weaken domain-specific
checks.

Do not extract report schema validation or report generators as part of the
forbidden-key helper slice.

## Test Requirements Before Any Refactor

Before extracting shared helper code, tests should cover all three validators
with the same unsafe-key matrix:

- `raw_credentials`
- `aws_session_token`
- `secret_value`
- `access_key_id`
- `raw_aws_log`
- `raw_error`
- `composite_score`
- `overall_score`
- `pass_fail`
- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`
- `benchmark_passed`

Tests should also confirm allowed safe metadata remains allowed only where
intended:

- `credentials_committed`
- `no_raw_credentials`
- `sanitized_reasons`
- `safe_error_category`
- `allow_statement_summary`
- `deny_statement_summary`
- `condition_evaluation_summary`

Minimum validation for a helper extraction slice:

- targeted validator tests for STS, PassRole, and Identity Deny
- script-level validator smoke tests where present
- `./scripts/check.sh`
- `./scripts/test_fast.sh`
- `git diff --check`

## P1 Findings

None.

## P2 Findings

None.

## P3 Findings

- Add exact `raw_aws_log` / `raw_error` forbidden-key coverage to STS and
  PassRole, or confirm with tests that the shared helper rejects those terms for
  all controlled report types.
- Add an explicit cross-validator unsafe-key test matrix before helper
  extraction.

## Recommended Next Slice

Implement shared recursive forbidden-key helper for controlled validation
reports.

That next slice should be narrow:

- Add a shared helper module for key normalization and recursive key scanning.
- Use the helper from the STS, PassRole, and Identity Deny validators.
- Preserve current report schema behavior.
- Add cross-validator unsafe-key tests.
- Do not refactor artifact-safety validation, non-claim validation, report
  generators, report schemas, or live validation behavior in the same slice.
