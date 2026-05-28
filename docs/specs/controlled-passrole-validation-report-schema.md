# Controlled PassRole Validation Report Schema

## Purpose

This document defines the minimal schema for one controlled PassRole finding/path validation report. It also records the checkpoint for the minimal offline validator now that report-shape validation exists. This remains docs/schema/checkpoint material only: it does not run live AWS, call `iam:PassRole`, call STS, launch a service, create resources, perform controlled PassRole validation execution, or change IAMScope reasoning behavior.

The schema represents one bounded validation result for one selected IAMScope PassRole-to-service prediction. The validator checks whether such reports preserve the declared shape and safety boundaries.

## Non-Goals

This schema is not:

- An implementation.
- Live AWS execution.
- `iam:PassRole` execution.
- A service launch.
- Downstream action proof.
- A benchmark framework.
- CI gating.
- Pass/fail scoring.
- Composite scoring.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.

## Report Scope

Each report covers exactly:

- One controlled environment.
- One selected IAMScope PassRole finding/path.
- One source principal.
- One target role.
- One service principal.
- One evidence method.
- One outcome classification.
- One safe evidence summary.

A report must not aggregate multiple findings, multiple source principals, multiple target roles, or multiple service principals.

## Required Top-Level Fields

A report must contain these top-level fields:

- `schema_version`: schema version string, initially `controlled-passrole-validation-report/v0`.
- `report_type`: must be `controlled_passrole_validation_report`.
- `validation_id`: stable validation-layer identifier for this selected validation.
- `created_at`: report creation timestamp in ISO 8601 form.
- `environment_label`: controlled environment label.
- `input_bundle_reference`: reference to the sanitized input bundle or evidence package, if any.
- `finding_reference`: object identifying the selected IAMScope finding/path or validation-layer substitute.
- `predicted_behavior`: object describing the IAMScope prediction.
- `evidence_method`: object describing the evidence method used.
- `observed_evidence`: object describing the observed safe evidence.
- `outcome_classification`: one allowed classification from this schema.
- `evidence_summary`: short sanitized prose summary.
- `caveats`: list of caveats and unresolved boundaries.
- `non_claims`: list of explicit non-claims.
- `artifact_safety_status`: object describing artifact safety flags and review state.

## Finding Reference Fields

`finding_reference` must contain:

- `finding_id`: IAMScope-native finding ID when available, otherwise `null`.
- `path_id`: IAMScope-native path ID when available, otherwise `null`.
- `validation_layer_id`: required when `finding_id` and `path_id` are unavailable; must be clearly labeled as validation-layer, not IAMScope-native.
- `source_principal_arn`: selected source principal ARN.
- `target_role_arn`: selected target role ARN.
- `service_principal`: selected service principal, for example `lambda.amazonaws.com` or `ec2.amazonaws.com`.
- `expected_account_id`: expected controlled account ID.
- `reasoner_or_finding_type`: IAMScope reasoner/finding type, for example `passrole_lambda` or `passrole_ecs`.
- `prediction_source`: source of the prediction, such as frozen benchmark evidence, controlled report bundle, or sanitized selected-path document.
- `source_document`: path or identifier for the sanitized source document.
- `source_bundle`: optional path or identifier for the sanitized source bundle.

## Predicted Behavior Fields

`predicted_behavior` must contain:

- `predicted_action`: must be `iam:PassRole`.
- `predicted_service_principal`: selected service principal.
- `predicted_target_role_arn`: selected target role ARN.
- `predicted_outcome`: one of `allowed`, `denied`, or `inconclusive`.
- `prediction_basis`: sanitized explanation of why IAMScope predicted that outcome.
- `prediction_caveats`: list of known caveats, unsupported dimensions, or modeled assumptions.

## Evidence Method Fields

`evidence_method` must contain:

- `method_type`: one of:
  - `static_policy_trust_corroboration`
  - `iam_simulation`
  - `non_destructive_service_validation`
  - `deferred_service_launch`
- `live_aws_used`: boolean.
- `aws_calls_made`: boolean.
- `iam_passrole_called`: boolean; must be `false` unless a future approved protocol explicitly permits an `iam:PassRole` call.
- `service_launch_attempted`: boolean; must be `false` in the current schema unless a future approved protocol explicitly permits service launch.
- `downstream_actions_performed`: boolean; must be `false`.
- `output_paths`: list of output paths or references, if any; committed reports must not include raw `/tmp` outputs.
- `safe_error_category`: optional sanitized category such as `access_denied`, `configuration_error`, `unsupported_method`, or `none`.

## Observed Evidence Fields

`observed_evidence` must contain:

- `source_permission_evidence`: sanitized summary of source-side `iam:PassRole` permission evidence.
- `target_trust_evidence`: sanitized summary of target role trust evidence.
- `service_principal_match`: one of `matched`, `mismatched`, `unknown`, or `not_evaluated`.
- `condition_context`: sanitized condition/context summary, including unresolved condition keys if relevant.
- `observed_outcome`: one of:
  - `allowed`
  - `denied`
  - `inconclusive`
  - `configuration_error`
  - `unsupported_method`
  - `environment_mismatch`
- `sanitized_reasons`: list of sanitized reason strings.
- `no_raw_credentials`: optional safe metadata flag; when supplied, must be `true`.
- `no_raw_aws_errors`: optional safe metadata flag; when supplied, must be `true`.

Raw credentials, raw AWS errors, raw AWS logs, or raw `/tmp` outputs must not be embedded in `observed_evidence`.

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

## Artifact Safety Status

`artifact_safety_status` must contain:

- `raw_artifacts_committed`: must be `false`.
- `credentials_committed`: must be `false`.
- `tmp_outputs_committed`: must be `false`.
- `downstream_actions`: must be `false`.
- `service_launch_attempted`: must be `false` unless a future approved protocol explicitly permits service launch.
- `sanitized_summary_only`: must be `true` for committed reports.
- `reviewer_checked`: boolean.

## Required Non-Claims

`non_claims` must include statements equivalent to:

- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No broad runtime exploitability.
- No downstream service execution proof.
- No downstream authorization proof.
- No resource-policy Deny support unless explicitly in scope.
- No finding-level reachability unless explicitly in scope.
- No all-findings-verified claim.
- No real-world scalability claim.

## Example Report

This example uses placeholder values and sanitized summaries only.

```json
{
  "schema_version": "controlled-passrole-validation-report/v0",
  "report_type": "controlled_passrole_validation_report",
  "validation_id": "passrole-validation-example-001",
  "created_at": "2026-05-19T00:00:00Z",
  "environment_label": "controlled-passrole-example",
  "input_bundle_reference": "sanitized://example/passrole-bundle",
  "finding_reference": {
    "finding_id": null,
    "path_id": null,
    "validation_layer_id": "validation-layer-passrole-example-001",
    "source_principal_arn": "arn:aws:iam::123456789012:user/iamscope-test/example-alice",
    "target_role_arn": "arn:aws:iam::123456789012:role/iamscope-test/example-service-role",
    "service_principal": "lambda.amazonaws.com",
    "expected_account_id": "123456789012",
    "reasoner_or_finding_type": "passrole_lambda",
    "prediction_source": "sanitized_selected_path",
    "source_document": "docs/example/sanitized-passrole-selection.md",
    "source_bundle": null
  },
  "predicted_behavior": {
    "predicted_action": "iam:PassRole",
    "predicted_service_principal": "lambda.amazonaws.com",
    "predicted_target_role_arn": "arn:aws:iam::123456789012:role/iamscope-test/example-service-role",
    "predicted_outcome": "allowed",
    "prediction_basis": "Sanitized metadata shows source permission scoped to the target role and target trust for the selected service principal.",
    "prediction_caveats": ["Static corroboration does not prove service launch or downstream authorization."]
  },
  "evidence_method": {
    "method_type": "static_policy_trust_corroboration",
    "live_aws_used": false,
    "aws_calls_made": false,
    "iam_passrole_called": false,
    "service_launch_attempted": false,
    "downstream_actions_performed": false,
    "output_paths": [],
    "safe_error_category": "none"
  },
  "observed_evidence": {
    "source_permission_evidence": "Sanitized policy summary indicates iam:PassRole is scoped to the selected target role.",
    "target_trust_evidence": "Sanitized trust summary indicates the target role trusts lambda.amazonaws.com.",
    "service_principal_match": "matched",
    "condition_context": "No modeled condition context was required for this static example.",
    "observed_outcome": "allowed",
    "sanitized_reasons": ["source_permission_matches", "target_trust_matches", "service_principal_matches"],
    "no_raw_credentials": true,
    "no_raw_aws_errors": true
  },
  "outcome_classification": "corroborated",
  "evidence_summary": "Static sanitized evidence corroborates the selected PassRole-to-service prediction under the documented assumptions.",
  "caveats": ["No service was launched.", "No downstream authorization was tested."],
  "non_claims": [
    "No production readiness.",
    "No broad IAMScope correctness.",
    "No arbitrary enterprise graph correctness.",
    "No broad runtime exploitability.",
    "No downstream service execution proof.",
    "No downstream authorization proof.",
    "No resource-policy Deny support unless explicitly in scope.",
    "No finding-level reachability unless explicitly in scope."
  ],
  "artifact_safety_status": {
    "raw_artifacts_committed": false,
    "credentials_committed": false,
    "tmp_outputs_committed": false,
    "downstream_actions": false,
    "service_launch_attempted": false,
    "sanitized_summary_only": true,
    "reviewer_checked": true
  }
}
```

## Validator Checkpoint

The controlled PassRole validation report validator is implemented for offline report-shape and safety-boundary validation only.

Implementation state:

- Module: `benchmarks/runtime/controlled_passrole_validation_report.py`.
- Script: `scripts/validate_controlled_passrole_validation_report.sh`.
- Input: one JSON report file supplied with `--report`.
- Scope: JSON report shape, allowed values, non-claims, and artifact-safety boundary validation only.
- No AWS calls, no `iam:PassRole` calls, no STS calls, no service launch, no controlled validation execution, and no AWS resource creation or modification.

The validator enforces:

- Required top-level fields: `schema_version`, `report_type`, `validation_id`, `created_at`, `environment_label`, `input_bundle_reference`, `finding_reference`, `predicted_behavior`, `evidence_method`, `observed_evidence`, `outcome_classification`, `evidence_summary`, `caveats`, `non_claims`, and `artifact_safety_status`.
- One-report, one-finding/path, and one-service-principal scope.
- Finding reference fields for native `finding_id` or `path_id` when available, or `validation_layer_id` when native identifiers are unavailable, plus source principal, target role, service principal, expected account, reasoner/finding type, and prediction source.
- Predicted behavior fields for `iam:PassRole`, selected service principal, selected target role, predicted outcome, prediction basis, and prediction caveats.
- Evidence method fields for method type, live/AWS-call flags, `iam_passrole_called`, `service_launch_attempted`, `downstream_actions_performed`, output paths, and safe error category.
- Observed evidence fields for source permission evidence, target trust evidence, service principal match, condition context, observed outcome, and sanitized reasons.
- Allowed observed outcomes: `allowed`, `denied`, `inconclusive`, `configuration_error`, `unsupported_method`, and `environment_mismatch`.
- Allowed outcome classifications: `corroborated`, `refuted`, `inconclusive`, `environment_mismatch`, `evidence_gap`, `probe_harness_issue`, `tool_bug_candidate`, `model_limitation`, and `unsupported_method`.
- Artifact safety flags requiring no committed raw artifacts, credentials, `/tmp` outputs, downstream actions, or service launch, and requiring sanitized summaries.
- Required non-claims covering production readiness, broad IAMScope correctness, arbitrary enterprise graph correctness, broad runtime exploitability, downstream service execution, and downstream authorization.

The validator rejects unsafe fields or behavior:

- Credential-shaped fields are rejected recursively, including `raw_credentials`, `aws_session_token`, `secret_value`, `access_key_id`, `AccessKeyId`, `SecretAccessKey`, and `SessionToken`.
- `composite_score`, `overall_score`, `pass_fail`, `pass`, `fail`, `vulnerable`, `exploited`, `production_ready`, and `benchmark_passed` fields or labels are rejected.
- `iam_passrole_called=true`, `service_launch_attempted=true`, `downstream_actions_performed=true`, and unsafe artifact-safety flags are rejected.

Safe allowed fields:

- `credentials_committed` is allowed only as an artifact-safety boolean and must be `false`.
- `no_raw_credentials` is allowed only as safe metadata when present and must be `true`.
- The report does not require `credentials_obtained` because this is PassRole validation, not STS credential acquisition.

What this proves:

- Controlled PassRole validation reports can be schema/safety checked offline.
- Unsafe credential-shaped fields and unsafe runtime/action flags can be rejected before a report is accepted.
- Safe non-claim and artifact-safety boundaries can be enforced.
- Report validation can occur without AWS credentials or AWS calls.

What this does not prove:

- No live PassRole validation was executed.
- No `iam:PassRole` call was made.
- No service launch occurred.
- No downstream action was performed.
- No finding was corroborated or refuted.
- No production readiness.
- No broad IAMScope correctness.
- No broad runtime exploitability.
- No downstream authorization proof.
- No resource-policy Deny support.
- No finding-level reachability.
- No real-world scalability.

## Generator Checkpoint

The controlled PassRole validation report generator is implemented for sanitized-summary-to-report generation only.

Implementation state:

- Module: `benchmarks/runtime/controlled_passrole_validation_report_generator.py`.
- Script: `scripts/generate_controlled_passrole_validation_report.sh`.
- Supported cases: `corroborated_allowed_static`, `corroborated_denied_static`, and `inconclusive_static`.
- Output: caller-provided JSON output path only.
- Repo-local output is rejected by default.
- Generated reports are not committed by default.
- No AWS calls, no `iam:PassRole` calls, no STS calls, and no service launch.

The generator emits:

- `controlled_passrole_validation_report` JSON.
- A `corroborated_allowed_static` report with `predicted_outcome=allowed`, `observed_outcome=allowed`, and `outcome_classification=corroborated`.
- A `corroborated_denied_static` report with `predicted_outcome=denied`, `observed_outcome=denied`, and `outcome_classification=corroborated`.
- An `inconclusive_static` report with `predicted_outcome=inconclusive`, `observed_outcome=inconclusive`, and `outcome_classification=inconclusive`.
- Artifact safety fields, required non-claims, and static `iam_passrole_called=false`, `service_launch_attempted=false`, and `downstream_actions_performed=false` flags.
- No composite score, pass/fail labels, vulnerable/exploited/production-ready labels, or credential-shaped fields.

Validator integration:

- Generated allowed reports pass the controlled PassRole report validator.
- Generated denied reports pass the controlled PassRole report validator.
- Generated inconclusive reports pass the controlled PassRole report validator.
- The validator rejects unsafe credential-shaped fields; the generator does not emit raw credentials or credential-shaped fields.
- The validator rejects unsafe runtime/action flags; the generator does not emit `iam_passrole_called=true`, `service_launch_attempted=true`, or `downstream_actions_performed=true`.

Safety boundaries:

- No live AWS.
- No `iam:PassRole`.
- No STS `AssumeRole`.
- No service launch.
- No AWS resource creation or modification.
- No raw AWS artifact ingestion.
- No raw `/tmp` output ingestion.
- No credentials.
- No raw logs.
- No Terraform state.
- No generated reports committed by default.

What this proves:

- Sanitized PassRole evidence summaries can be transformed into controlled validation reports.
- Those reports can pass schema/safety validation.
- Allowed, denied, and inconclusive static summary cases can be represented without unsafe labels or raw artifacts.
- Report generation can occur without AWS credentials or AWS calls.

What this does not prove:

- No live PassRole validation was executed.
- No `iam:PassRole` call was made.
- No service launch occurred.
- No downstream action was performed.
- No finding was live-corroborated or live-refuted.
- No production readiness.
- No broad IAMScope correctness.
- No broad runtime exploitability.
- No downstream authorization proof.
- No resource-policy Deny support.
- No finding-level reachability.
- No real-world scalability.

## Recommended Next Slice

Recommend exactly one next slice: design controlled PassRole validation bundle/readiness review.

That next slice should be docs/review only and decide whether to bundle generated reports to `/tmp` for artifact-safety review. It should not run AWS, call `iam:PassRole`, call STS, launch services, create or modify AWS resources, commit generated reports by default, introduce a new benchmark framework, add CI gates, add composite scoring, or bundle multiple slices at once.
