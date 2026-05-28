# Controlled PassRole Validation Report Generator Design

## Purpose

Design a future generator that transforms already-sanitized PassRole evidence summaries into `controlled_passrole_validation_report` JSON that can pass `scripts/validate_controlled_passrole_validation_report.sh`.

This is a docs/design slice only. It does not implement the generator or add runtime validation behavior.

## Non-Goals

This design is not:

- An implementation.
- Live AWS execution.
- An `iam:PassRole` call.
- An STS `AssumeRole` call.
- A service launch for EC2, Lambda, ECS, Glue, or any other service.
- AWS resource creation or modification.
- Raw artifact ingestion.
- Raw `/tmp` output ingestion.
- A benchmark framework.
- A CI gate.
- Pass/fail labeling.
- Composite scoring.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.

## Input Source Model

The future generator should accept only reviewed, sanitized inputs:

- Committed sanitized evidence summaries.
- Selected PassRole finding/path metadata.
- Manually reviewed source principal, target role, and service principal summaries.
- Sanitized prediction source references, such as a reviewed document or evidence bundle identifier.

The generator must not ingest:

- Raw AWS logs.
- Credentials or credential-shaped values.
- Raw `/tmp` outputs.
- Terraform state, cache, or provider artifacts.
- Raw scenario, findings, binding, or run logs unless separately sanitized and reviewed.

## Supported Initial Cases

The initial generator should support exactly these static evidence cases:

- `corroborated_allowed_static`: sanitized static permission/trust evidence supports the predicted `iam:PassRole` allowance for the selected source, target role, and service principal.
- `corroborated_denied_static`: sanitized static evidence supports a denied or blocked PassRole prediction for the selected source, target role, and service principal.
- `inconclusive_static`: sanitized evidence is insufficient, mismatched, or caveated enough that the selected prediction remains inconclusive.

These cases are based on sanitized static trust and permission evidence only. They do not use live service launch, downstream action execution, or raw AWS artifacts.

## Output Model

The future generator should emit one JSON document with `report_type` set to `controlled_passrole_validation_report`.

Output rules:

- The caller must provide an explicit output path.
- Generated reports should not be committed by default.
- Repo-local output should be rejected by default unless a future review explicitly approves committing a sanitized report.
- Generated output must pass `scripts/validate_controlled_passrole_validation_report.sh` before it is treated as acceptable.
- The generator should emit no raw logs, credentials, Terraform state, or generated bundles.

## Field Mapping

The generator should map sanitized inputs to report fields as follows:

- `validation_id`: caller-provided or deterministically derived validation-layer ID; never presented as an IAMScope-native finding/path ID unless the source evidence includes a native ID.
- `environment_label`: reviewed controlled environment label from the sanitized source summary.
- `input_bundle_reference`: sanitized evidence bundle or document reference, not a raw artifact path.
- `finding_reference`: selected native `finding_id` or `path_id` when available, otherwise `validation_layer_id`, plus source principal ARN, target role ARN, service principal, expected account ID, reasoner/finding type, and prediction source.
- `predicted_behavior`: `predicted_action=iam:PassRole`, selected service principal, selected target role, predicted outcome, sanitized prediction basis, and prediction caveats.
- `evidence_method`: `method_type=static_policy_trust_corroboration`, with `live_aws_used=false`, `aws_calls_made=false`, `iam_passrole_called=false`, `service_launch_attempted=false`, and `downstream_actions_performed=false` for initial cases.
- `observed_evidence`: sanitized source permission evidence, target trust evidence, service principal match, condition context, observed outcome, and sanitized reasons.
- `outcome_classification`: `corroborated`, `refuted`, `inconclusive`, `environment_mismatch`, `evidence_gap`, `probe_harness_issue`, `tool_bug_candidate`, `model_limitation`, or `unsupported_method`, as allowed by the schema.
- `evidence_summary`: short sanitized summary that explains the selected case without raw logs or secrets.
- `caveats`: explicit unresolved assumptions and boundaries.
- `non_claims`: required non-claims from the PassRole report schema.
- `artifact_safety_status`: flags showing no raw artifacts, credentials, `/tmp` outputs, downstream actions, or service launch were committed or performed.

## Safety Rules

The future generator must:

- Not import or use `boto3`.
- Not call AWS APIs.
- Not call `iam:PassRole`.
- Not call STS.
- Not launch services.
- Not create or modify AWS resources.
- Reject raw credential-shaped fields and values.
- Reject composite scores.
- Reject pass/fail labels.
- Reject vulnerable, exploited, or production-ready labels.
- Reject `service_launch_attempted=true`.
- Reject `downstream_actions_performed=true`.
- Reject `iam_passrole_called=true` for this static generator scope.
- Require sanitized summaries and explicit non-claims.

## Validation Integration

Every generated report must be validated with:

```bash
bash scripts/validate_controlled_passrole_validation_report.sh \
  --report /tmp/iamscope-controlled-passrole-validation-report.json
```

The validator remains the acceptance boundary for report shape and safety metadata. Passing validation does not make a live PassRole claim and does not corroborate a finding unless the sanitized evidence summary supports that classification within the report boundary.

## Future Implementation Tests

A future implementation should include focused tests that verify:

- Generates `corroborated_allowed_static` report JSON.
- Generates `corroborated_denied_static` report JSON.
- Generates `inconclusive_static` report JSON.
- Each generated report passes `scripts/validate_controlled_passrole_validation_report.sh`.
- Unknown case names are rejected.
- Output path is required.
- Repo-local output is rejected by default.
- Credential-shaped fields are rejected.
- Composite score and pass/fail labels are rejected.
- `boto3` is not imported or used.
- No AWS calls are made.
- No service launch flags are emitted.
- `iam_passrole_called`, `service_launch_attempted`, and `downstream_actions_performed` remain `false` for initial static cases.

## What This Future Generator Would Prove

If implemented as designed, the generator would prove only that:

- Sanitized PassRole evidence summaries can be represented as controlled validation reports.
- Generated reports can pass schema and safety validation.
- Artifact-safety and non-claim boundaries can be preserved during report generation.

## What This Future Generator Would Not Prove

It would not prove:

- Live PassRole validation.
- `iam:PassRole` execution.
- STS `AssumeRole` execution.
- Service launch.
- Downstream authorization.
- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Real-world scalability.
- All findings verified.

## Recommended Next Slice

Recommend exactly one next slice: document controlled PassRole validation report generator checkpoint.

That next slice should be docs/checkpoint only. It should not run AWS, call `iam:PassRole`, call STS, launch services, create or modify AWS resources, ingest raw artifacts, commit generated reports, add CI gates, add pass/fail labels, add composite scoring, or bundle multiple slices at once.
