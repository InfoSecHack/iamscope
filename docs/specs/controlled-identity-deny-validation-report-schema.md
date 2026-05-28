# Controlled Identity Deny Validation Report Schema

## Purpose

This document defines a schema for one controlled explicit identity-Deny suppression validation report. The report records whether bounded evidence corroborates, refutes, or leaves unresolved a selected IAMScope prediction that a structurally allowed action/path should be denied, suppressed, or classified infeasible because an explicit identity `Deny` applies.

This is a docs/schema design only. It does not implement a parser, run AWS, change IAMScope reasoning behavior, or claim generic Deny correctness.

## Non-Goals

This schema is not:

- An implementation.
- Live AWS execution.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Production testing.
- Exploitability proof.
- Composite scoring.
- CI gating.
- Broad IAMScope correctness proof.

## Report Scope

One controlled identity Deny validation report covers exactly:

- One controlled environment.
- One source principal.
- One candidate action.
- One candidate resource.
- One explicit identity `Deny`.
- One allow basis if relevant to the structurally allowed path/action.
- One prediction.
- One evidence method.
- One outcome classification.
- One safe evidence summary.

The report must not aggregate multiple principals, actions, resources, Deny statements, or validation outcomes.

## Required Top-Level Fields

Every report must include:

- `schema_version`
- `report_type`
- `validation_id`
- `created_at`
- `environment_label`
- `input_bundle_reference`
- `finding_reference`
- `source_principal_arn`
- `candidate_action`
- `candidate_resource`
- `allow_basis`
- `deny_basis`
- `condition_context`
- `predicted_behavior`
- `evidence_method`
- `observed_or_static_evidence`
- `outcome_classification`
- `evidence_summary`
- `caveats`
- `non_claims`
- `artifact_safety_status`

The expected `report_type` is `controlled_identity_deny_validation_report`.

## `finding_reference`

`finding_reference` identifies the IAMScope or validation-layer source for the selected case:

- `finding_id` or `path_id`, if an IAMScope-native identifier is available.
- `validation_layer_id`, if a native finding/path identifier is unavailable.
- `reasoner_or_finding_type`
- `prediction_source`
- `source_document` or `source_bundle`

At least one of `finding_id`, `path_id`, or `validation_layer_id` should be present. A validation-layer identifier must not be presented as an IAMScope-native finding/path ID.

## `allow_basis`

`allow_basis` records the structurally allowed side of the selected case, if relevant:

- `allow_present`
- `allow_source_type`: `identity_policy`, `group_policy`, `role_policy`, `boundary_context`, or `unknown`
- `allow_statement_summary`
- `allowed_action_match`
- `allowed_resource_match`
- `allow_condition_context`
- `caveats`

If no allow basis exists or the report is intentionally documenting an allow-basis gap, `allow_present` should be `false` and the caveats should explain why.

## `deny_basis`

`deny_basis` records the explicit identity Deny side of the selected case:

- `deny_present`
- `deny_source_type`: `identity_policy`, `group_policy`, `role_policy`, `permission_boundary`, `session_policy`, or `unknown`
- `deny_statement_summary`
- `denied_action_match`
- `denied_resource_match`
- `deny_condition_context`
- `explicit_deny_applies`
- `caveats`

For this report type, `deny_basis` is required. A report without a selected Deny basis should be classified as an evidence gap or rejected by a future validator, depending on the validator mode.

## `predicted_behavior`

`predicted_behavior` records the selected IAMScope prediction:

- `predicted_action`
- `predicted_resource`
- `predicted_outcome`: `denied`, `allowed`, `suppressed`, or `inconclusive`
- `prediction_basis`
- `prediction_caveats`

For identity-Deny suppression validation, the expected predicted outcome is usually `denied` or `suppressed`. `allowed` is valid only when the selected report is documenting a refutation or mismatch case.

## `evidence_method`

Allowed `method_type` values:

- `static_policy_corroboration`
- `iam_simulation`
- `harmless_active_read`
- `no_active_check`

Required fields:

- `method_type`
- `live_aws_used`
- `aws_calls_made`
- `active_action_called`
- `destructive_action_called`: `false`
- `resource_modified`: `false`
- `output_paths`
- `safe_error_category`

`iam_simulation` and `harmless_active_read` require a separately approved protocol before use. This schema can describe those evidence methods, but it does not authorize live AWS or active validation.

## `observed_or_static_evidence`

`observed_or_static_evidence` records the bounded evidence summary:

- `observed_outcome`: `denied`, `allowed`, `suppressed`, `inconclusive`, `configuration_error`, `unsupported_method`, or `environment_mismatch`
- `static_allow_summary`
- `static_deny_summary`
- `condition_evaluation_summary`
- `sanitized_reasons`
- `no_raw_credentials`
- `no_raw_aws_errors`

The report must use sanitized reasons only. It must not include raw credentials, raw AWS errors, raw logs, or copied `/tmp` artifacts.

## Outcome Classifications

Allowed `outcome_classification` values:

- `corroborated`
- `refuted`
- `inconclusive`
- `environment_mismatch`
- `evidence_gap`
- `probe_harness_issue`
- `tool_bug_candidate`
- `model_limitation`
- `unsupported_method`

Avoid labels such as:

- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`

## `artifact_safety_status`

`artifact_safety_status` must include:

- `raw_artifacts_committed`: `false`
- `credentials_committed`: `false`
- `tmp_outputs_committed`: `false`
- `destructive_actions`: `false`
- `resource_modifications`: `false`
- `sanitized_summary_only`: `true`
- `reviewer_checked`: boolean

If any required safety flag is unsafe, a future validator should reject the report unless a later approved protocol explicitly changes the boundary.

## Required Non-Claims

`non_claims` must clearly cover:

- No production readiness.
- No broad IAMScope correctness.
- No generic Deny correctness.
- No resource-policy Deny support.
- No SCP Deny support.
- No broad runtime exploitability.
- No downstream authorization proof.
- No all-findings-verified claim.
- No real-world scalability.

## Example Report

This example uses placeholder values and sanitized summaries only:

```json
{
  "schema_version": "2026-05-identity-deny-v1",
  "report_type": "controlled_identity_deny_validation_report",
  "validation_id": "controlled-identity-deny-static-example-001",
  "created_at": "2026-05-26T00:00:00Z",
  "environment_label": "sanitized-controlled-example",
  "input_bundle_reference": {
    "bundle_id": "sanitized-identity-deny-example",
    "source": "committed sanitized summary"
  },
  "finding_reference": {
    "finding_id": null,
    "path_id": null,
    "validation_layer_id": "identity-deny-example-path-001",
    "reasoner_or_finding_type": "identity_deny_suppression",
    "prediction_source": "sanitized policy summary",
    "source_document": "docs/specs/controlled-identity-deny-validation-report-schema.md"
  },
  "source_principal_arn": "arn:aws:iam::123456789012:user/example-identity-deny-source",
  "candidate_action": "iam:AddUserToGroup",
  "candidate_resource": "arn:aws:iam::123456789012:group/example-admins",
  "allow_basis": {
    "allow_present": true,
    "allow_source_type": "identity_policy",
    "allow_statement_summary": "Sanitized Allow summary for the selected action and group resource.",
    "allowed_action_match": true,
    "allowed_resource_match": true,
    "allow_condition_context": "No relevant Allow condition in sanitized example.",
    "caveats": ["Static summary only."]
  },
  "deny_basis": {
    "deny_present": true,
    "deny_source_type": "identity_policy",
    "deny_statement_summary": "Sanitized explicit Deny summary for the selected action and group resource.",
    "denied_action_match": true,
    "denied_resource_match": true,
    "deny_condition_context": "No relevant Deny condition in sanitized example.",
    "explicit_deny_applies": true,
    "caveats": ["Static summary only; no live AWS."]
  },
  "condition_context": {
    "context_keys_required": [],
    "context_values_supplied": {},
    "condition_caveats": []
  },
  "predicted_behavior": {
    "predicted_action": "iam:AddUserToGroup",
    "predicted_resource": "arn:aws:iam::123456789012:group/example-admins",
    "predicted_outcome": "suppressed",
    "prediction_basis": "Structurally allowed action/resource is suppressed by explicit identity Deny.",
    "prediction_caveats": ["Static validation example."]
  },
  "evidence_method": {
    "method_type": "static_policy_corroboration",
    "live_aws_used": false,
    "aws_calls_made": [],
    "active_action_called": null,
    "destructive_action_called": false,
    "resource_modified": false,
    "output_paths": [],
    "safe_error_category": null
  },
  "observed_or_static_evidence": {
    "observed_outcome": "suppressed",
    "static_allow_summary": "Allow side matches the selected action and resource in sanitized metadata.",
    "static_deny_summary": "Explicit identity Deny side matches the selected action and resource in sanitized metadata.",
    "condition_evaluation_summary": "No unsatisfied Deny condition in sanitized example.",
    "sanitized_reasons": [
      "Explicit identity Deny applies to the selected action/resource.",
      "No live AWS or active action was used."
    ],
    "no_raw_credentials": true,
    "no_raw_aws_errors": true
  },
  "outcome_classification": "corroborated",
  "evidence_summary": "Static sanitized evidence corroborates identity-Deny suppression for one selected example.",
  "caveats": [
    "Static evidence only.",
    "No generic Deny correctness claim.",
    "No resource-policy or SCP Deny claim."
  ],
  "non_claims": [
    "no production readiness",
    "no broad IAMScope correctness",
    "no generic Deny correctness",
    "no resource-policy Deny support",
    "no SCP Deny support",
    "no broad runtime exploitability",
    "no downstream authorization proof",
    "no all-findings-verified claim",
    "no real-world scalability"
  ],
  "artifact_safety_status": {
    "raw_artifacts_committed": false,
    "credentials_committed": false,
    "tmp_outputs_committed": false,
    "destructive_actions": false,
    "resource_modifications": false,
    "sanitized_summary_only": true,
    "reviewer_checked": true
  }
}
```

## Future Validator Rules

A future parser or validator should:

- Reject unknown `report_type`.
- Require `schema_version`.
- Require exactly one source principal, candidate action, and candidate resource.
- Require `deny_basis`.
- Reject raw credential-shaped fields.
- Reject raw AWS error/log fields.
- Reject `composite_score` and `pass_fail` fields.
- Reject `vulnerable`, `exploited`, and `production_ready` labels.
- Reject `destructive_action_called=true`.
- Reject `resource_modified=true` unless a future approved protocol explicitly allows it.
- Require all artifact-safety fields.
- Require `non_claims`.
- Require `outcome_classification` from the allowed set.
- Require `observed_or_static_evidence.observed_outcome` from the allowed set.
- Require `evidence_method.method_type` from the allowed set.

The validator should validate report shape and safety boundaries only. It must not run AWS or infer runtime authorization.

## Validator Checkpoint

The minimal controlled identity Deny validation report schema validator now exists:

- Module: `benchmarks/runtime/controlled_identity_deny_validation_report.py`
- Script: `scripts/validate_controlled_identity_deny_validation_report.sh`
- Supported input: one JSON report only.
- Scope: report-shape and safety-boundary validation only.
- AWS behavior: no AWS calls, no STS calls, no `iam:PassRole` calls, no Lambda API calls, no active validation, no resource creation or modification, and no credentials required.

The validator enforces:

- Required top-level report fields.
- One source/action/resource/identity-Deny scope.
- `finding_reference` fields and native-ID-or-validation-layer-ID rules.
- `allow_basis` fields.
- `deny_basis` fields.
- `condition_context` object presence.
- `predicted_behavior` fields.
- `evidence_method` fields.
- `observed_or_static_evidence` fields.
- Allowed observed outcomes.
- Allowed outcome classifications.
- Artifact safety flags.
- Required non-claims.

The validator rejects unsafe fields and behavior:

- Credential-shaped fields recursively.
- `AccessKeyId`, `SecretAccessKey`, and `SessionToken`.
- `raw_credentials`.
- `aws_session_token`.
- `secret_value`.
- `access_key_id`.
- `raw_aws_log` and `raw_error`.
- `composite_score` and `overall_score`.
- `pass_fail`, `pass`, and `fail` style fields.
- `vulnerable`, `exploited`, `production_ready`, and `benchmark_passed`.
- `destructive_action_called=true`.
- `resource_modified=true`.
- Static and no-active-check methods that claim AWS calls.
- Unsafe artifact-safety flags.

Safe allowed metadata is intentionally narrow:

- `credentials_committed` is allowed only as an artifact-safety boolean.
- `no_raw_credentials` is allowed only as safe metadata if present.
- `sanitized_reasons` is allowed.
- `safe_error_category` is allowed.
- `allow_statement_summary` and `deny_statement_summary` are allowed.
- `condition_evaluation_summary` is allowed.

This checkpoint proves only that controlled identity Deny reports can be schema/safety checked offline, unsafe credential-shaped fields, raw logs/errors, destructive/resource-modifying claims, and unsafe labels can be rejected before report acceptance, safe non-claim/artifact-safety boundaries can be enforced, and report validation can occur without AWS credentials or AWS calls.

This checkpoint does not prove live identity Deny validation, IAMScope reasoning behavior changes, active AWS calls, finding corroboration or refutation, generic Deny correctness, resource-policy Deny support, SCP Deny support, production readiness, broad IAMScope correctness, broad runtime exploitability, downstream authorization proof, or real-world scalability.

## Recommended Next Slice

Recommend exactly one next slice: select controlled identity Deny validation candidate.

That next slice should be planning/inspection only. It must not run live AWS, perform active validation, create or modify resources, add a benchmark framework, add CI gates, introduce composite scoring, or recommend multiple slices at once.
