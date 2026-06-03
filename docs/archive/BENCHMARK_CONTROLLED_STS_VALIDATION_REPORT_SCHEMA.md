# Benchmark Controlled STS Validation Report Schema

## 1. Purpose

This document defines the minimal report schema for one controlled STS
finding/path validation result.

The schema is a design target only. It does not implement report parsing, report
validation, live AWS execution, STS AssumeRole execution, benchmark framework
behavior, or runtime validation logic.

The schema exists to preserve the evidence boundaries from
`BENCHMARK_CONTROLLED_REAL_ENV_VALIDATION_PROTOCOL.md` when representing one
controlled STS validation result.

## 2. Non-Goals

This schema is not:

- Implementation.
- Live AWS execution.
- A benchmark framework.
- CI gating.
- Pass/fail scoring.
- Composite scoring.
- Production readiness evidence.
- Broad correctness evidence.
- Broad exploitability evidence.

It also does not add raw artifact ingestion, fixtures, Terraform, downstream AWS
actions, collector changes, reasoner changes, scorer changes,
scenario-validation changes, threshold changes, comparator changes, reporting
changes, or harness changes.

## 3. Report Scope

One controlled STS validation report covers:

- One controlled environment.
- One selected IAMScope finding or path.
- One runtime STS probe or evidence check.
- One outcome classification.
- One safe evidence summary.

The report must not combine multiple findings, multiple paths, multiple
environments, broad scans, benchmark aggregates, or composite scores.

## 4. Required Top-Level Fields

Required top-level fields:

- `schema_version`: version string for this report shape.
- `report_type`: must identify this as a controlled STS validation report.
- `validation_id`: stable identifier for this single validation report.
- `created_at`: report creation timestamp.
- `environment_label`: non-sensitive label for the controlled environment.
- `input_bundle_reference`: reference to the frozen sanitized input bundle.
- `finding_reference`: object describing the selected finding or path.
- `predicted_behavior`: object describing IAMScope's selected prediction.
- `runtime_probe`: object summarizing the STS probe or evidence check.
- `observed_behavior`: object summarizing the safe observed result.
- `outcome_classification`: one allowed validation outcome classification.
- `evidence_summary`: safe summary of inputs, observation, and review context.
- `caveats`: explicit interpretation caveats.
- `non_claims`: explicit non-claims.
- `artifact_safety_status`: object describing artifact safety checks.

Recommended `report_type` value:

`controlled_sts_validation_report`

Recommended initial `schema_version` value:

`controlled-sts-validation-report/v1`

## 5. Finding Reference Fields

`finding_reference` should include:

- `finding_id` or `path_id`: exactly one selected IAMScope finding or path
  identifier. If both are available, one should be marked primary.
- `source_principal_arn`: source principal ARN used by the selected prediction.
- `target_role_arn`: target role ARN used by the selected prediction.
- `expected_account_id`: expected AWS account ID for the controlled target
  account.
- `reasoner_or_finding_type`: IAMScope reasoner, finding family, or path type.
- `prediction_source`: source of the prediction, such as a frozen finding
  summary or selected path report.
- `source_document` or `source_bundle`: safe reference to the source document or
  frozen sanitized input bundle.

The report must not include raw credentials, raw AWS debug output, or raw
unreviewed collection directories as a source reference.

## 6. Predicted Behavior Fields

`predicted_behavior` should include:

- `predicted_action`: must be `sts:AssumeRole`.
- `predicted_outcome`: one of `assumed`, `denied`, or `inconclusive`.
- `prediction_basis`: safe summary of why IAMScope predicted the outcome.
- `prediction_caveats`: caveats on the selected prediction, including any
  known model limitations, unsupported policy features, or frozen-bundle
  assumptions.

The prediction basis should be enough for review, but it should not copy raw
scenario artifacts or raw policy dumps unless they have been separately frozen,
sanitized, and approved for inclusion.

## 7. Runtime Probe Fields

`runtime_probe` should include:

- `probe_id`: stable identifier for the selected probe or evidence check.
- `probe_type`: must be `sts_assume_role`.
- `mode`: execution mode used by the STS executor or evidence path.
- `operator_confirmation_used`: boolean.
- `live_aws_used`: boolean.
- `aws_calls_made`: boolean.
- `sts_assume_role_called`: boolean.
- `downstream_actions_performed`: must be `false`.
- `credentials_obtained`: boolean only.
- `output_paths`: safe caller-provided or `/tmp` output path summary.
- `safe_error_category`: safe error category, if relevant.

The runtime probe section must not include:

- `AccessKeyId`
- `SecretAccessKey`
- `SessionToken`
- Raw `Credentials` objects.
- Raw AWS debug logs.
- Raw exception dumps with sensitive values.
- Any downstream AWS API call result.

## 8. Observed Behavior Fields

`observed_behavior` should include:

- `observed_outcome`: one of `assumed`, `denied`, `inconclusive`,
  `configuration_error`, `unexpected_account`, or `skipped_safety_guard`.
- `observed_account_id`: expected account ID only if safely available and
  appropriate to summarize.
- `result_classification`: executor or probe-level safe classification.
- `sanitized_reasons`: safe human-readable reason summary.
- `no_raw_credentials`: must be `true`.
- `no_raw_aws_errors`: must be `true`.

The observed behavior summary should be sufficient to interpret the selected
validation result without exposing credential material, raw debug logs, or raw
unreviewed AWS responses.

## 9. Outcome Classifications

Allowed `outcome_classification` values:

- `corroborated`
- `refuted`
- `inconclusive`
- `environment_mismatch`
- `probe_harness_issue`
- `evidence_gap`
- `tool_bug_candidate`
- `model_limitation`

Avoid these labels:

- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`

Interpretation rules:

- `corroborated` means the bounded observed behavior supports the selected
  IAMScope prediction under the stated conditions.
- `refuted` means the bounded observed behavior contradicts the selected
  prediction under the stated conditions.
- `inconclusive` means the evidence does not support a bounded conclusion.
- `environment_mismatch` means the controlled environment does not match the
  frozen bundle or documented assumptions.
- `probe_harness_issue` means the runtime check cannot be trusted because of a
  probe, harness, executor, or setup issue.
- `evidence_gap` means required evidence is missing.
- `tool_bug_candidate` means the result may indicate an IAMScope bug, but still
  requires investigation.
- `model_limitation` means the selected behavior is outside IAMScope's current
  supported model or evidence boundary.

## 10. Artifact Safety Status

`artifact_safety_status` should include:

- `raw_artifacts_committed`: must be `false`.
- `credentials_committed`: must be `false`.
- `tmp_outputs_committed`: must be `false`.
- `downstream_actions`: must be `false`.
- `sanitized_summary_only`: must be `true`.
- `reviewer_checked`: boolean.

Optional safety fields:

- `raw_aws_logs_committed`: should be `false`.
- `terraform_artifacts_committed`: should be `false`.
- `credential_shaped_fields_present`: should be `false`.
- `separate_summary_review_required`: boolean.

## 11. Caveats And Non-Claims

Every report must include explicit caveats that the report covers:

- One controlled environment only.
- One selected IAMScope finding or path only.
- One STS probe or evidence check only.
- One outcome classification only.
- No downstream AWS actions.

Every report must include these non-claims:

- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No broad runtime exploitability.
- No downstream authorization proof.
- No resource-policy Deny support unless explicitly in scope.
- No finding-level reachability unless explicitly in scope.

## 12. Example Report

The following example uses already-safe style and placeholder values. It is a
sanitized summary, not raw runtime output.

```json
{
  "schema_version": "controlled-sts-validation-report/v1",
  "report_type": "controlled_sts_validation_report",
  "validation_id": "controlled-sts-example-001",
  "created_at": "2026-05-16T00:00:00Z",
  "environment_label": "controlled-test-lab-placeholder",
  "input_bundle_reference": "frozen-sanitized-bundle-placeholder",
  "finding_reference": {
    "path_id": "path-placeholder-001",
    "source_principal_arn": "arn:aws:iam::<redacted-aws-account-id>:user/example-source",
    "target_role_arn": "arn:aws:iam::<redacted-aws-account-id>:role/example-target-role",
    "expected_account_id": "<redacted-aws-account-id>",
    "reasoner_or_finding_type": "sts_assume_role_path",
    "prediction_source": "selected sanitized IAMScope finding summary",
    "source_bundle": "frozen-sanitized-bundle-placeholder"
  },
  "predicted_behavior": {
    "predicted_action": "sts:AssumeRole",
    "predicted_outcome": "denied",
    "prediction_basis": "sanitized trust and permission summary",
    "prediction_caveats": [
      "selected path only",
      "controlled test environment only"
    ]
  },
  "runtime_probe": {
    "probe_id": "sts-probe-placeholder-001",
    "probe_type": "sts_assume_role",
    "mode": "live_probe",
    "operator_confirmation_used": true,
    "live_aws_used": true,
    "aws_calls_made": true,
    "sts_assume_role_called": true,
    "downstream_actions_performed": false,
    "credentials_obtained": false,
    "output_paths": {
      "json": "/tmp/example-controlled-sts-validation.json",
      "markdown": "/tmp/example-controlled-sts-validation.md"
    },
    "safe_error_category": "access_denied"
  },
  "observed_behavior": {
    "observed_outcome": "denied",
    "observed_account_id": "<redacted-aws-account-id>",
    "result_classification": "denied",
    "sanitized_reasons": [
      "STS AssumeRole was denied under the configured test condition"
    ],
    "no_raw_credentials": true,
    "no_raw_aws_errors": true
  },
  "outcome_classification": "corroborated",
  "evidence_summary": {
    "sanitized_inputs": "one selected source principal and one target role",
    "runtime_observation": "one STS AssumeRole attempt was denied",
    "manual_context_review": "safe trust and permission context summary"
  },
  "caveats": [
    "one selected finding/path only",
    "one controlled environment only",
    "no downstream AWS actions",
    "no broad exploitability conclusion"
  ],
  "non_claims": [
    "no production readiness",
    "no broad IAMScope correctness",
    "no arbitrary enterprise graph correctness",
    "no broad runtime exploitability",
    "no downstream authorization proof",
    "no generic resource-policy Deny support",
    "no finding-level reachability proof"
  ],
  "artifact_safety_status": {
    "raw_artifacts_committed": false,
    "credentials_committed": false,
    "tmp_outputs_committed": false,
    "downstream_actions": false,
    "sanitized_summary_only": true,
    "reviewer_checked": true
  }
}
```

This example intentionally includes `/tmp` output path references only as safe
path summaries. It does not include raw `/tmp` output contents.

## 13. Validation Rules For Future Implementation

A future shape-only parser or validator should:

- Reject unknown `report_type` values.
- Require `schema_version`.
- Require one finding or path only.
- Reject raw credential-shaped fields, including `AccessKeyId`,
  `SecretAccessKey`, `SessionToken`, and raw `Credentials` objects.
- Reject `composite_score`.
- Reject `pass_fail`, `pass`, `fail`, or pass/fail grading fields.
- Require `artifact_safety_status`.
- Require `non_claims`.
- Require `outcome_classification` from the allowed set.
- Require `runtime_probe.probe_type == "sts_assume_role"`.
- Require `runtime_probe.downstream_actions_performed == false`.
- Require `artifact_safety_status.credentials_committed == false`.
- Require `artifact_safety_status.tmp_outputs_committed == false`.
- Require `artifact_safety_status.sanitized_summary_only == true`.

The validator should validate report shape only. It should not run AWS, call
STS, interpret live credentials, create resources, read raw logs, ingest raw
artifacts, or decide benchmark pass/fail status.

## 15. Validator Checkpoint

A minimal controlled STS validation report schema validator now exists.

- Module: `benchmarks/runtime/controlled_sts_validation_report.py`
- Script: `scripts/validate_controlled_sts_validation_report.sh`
- Supported input: JSON report only.
- Boundary: report-shape validation only.
- AWS calls: none.
- STS calls: none.
- Controlled validation execution: not implemented by this validator.

Supported command shape:

```bash
bash scripts/validate_controlled_sts_validation_report.sh \
  --report /tmp/iamscope-controlled-sts-validation-report.json
```

### What The Validator Enforces

The validator parses one JSON report and enforces:

- Required top-level fields: `schema_version`, `report_type`,
  `validation_id`, `created_at`, `environment_label`,
  `input_bundle_reference`, `finding_reference`, `predicted_behavior`,
  `runtime_probe`, `observed_behavior`, `outcome_classification`,
  `evidence_summary`, `caveats`, `non_claims`, and
  `artifact_safety_status`.
- One-report / one-finding scope: a report must represent one selected finding
  or path only.
- Finding reference fields: `finding_id` or `path_id`,
  `source_principal_arn`, `target_role_arn`, `expected_account_id`,
  `reasoner_or_finding_type`, and `prediction_source`.
- Predicted behavior fields: `predicted_action: sts:AssumeRole`,
  `predicted_outcome`, `prediction_basis`, and `prediction_caveats`.
- Runtime probe fields: `probe_id`, `probe_type: sts_assume_role`, `mode`,
  `operator_confirmation_used`, `live_aws_used`, `aws_calls_made`,
  `sts_assume_role_called`, `downstream_actions_performed: false`,
  `credentials_obtained`, `output_paths`, and `safe_error_category`.
- Observed behavior fields: `observed_outcome`, `result_classification`, and
  `sanitized_reasons`.
- Allowed outcome classifications: `corroborated`, `refuted`,
  `inconclusive`, `environment_mismatch`, `probe_harness_issue`,
  `evidence_gap`, `tool_bug_candidate`, and `model_limitation`.
- Artifact safety flags: raw artifacts, credentials, `/tmp` outputs, and
  downstream actions must not be committed or performed; sanitized summaries
  must be explicit.
- Required non-claims: no production readiness, no broad IAMScope correctness,
  no arbitrary enterprise graph correctness, no broad runtime exploitability,
  no downstream authorization proof, no resource-policy Deny support unless in
  scope, and no finding-level reachability unless in scope.

The validator emits a safe validation summary to stdout.

### Unsafe Field Rejection

The validator rejects credential-shaped and unsafe fields recursively across
nested dictionaries and lists. Rejected examples include:

- `raw_credentials`
- `aws_session_token`
- `secret_value`
- `access_key_id`
- `AccessKeyId`
- `SecretAccessKey`
- `SessionToken`
- `composite_score`
- `pass_fail`
- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`
- `benchmark_passed`

Forbidden key checks normalize keys before matching so separator variants are
rejected rather than accepted by spelling differences.

### Safe Allowed Fields

The validator allows these safe schema fields only in their intended roles:

- `credentials_obtained` is allowed as a boolean runtime-probe field.
- `credentials_committed` is allowed as an artifact-safety boolean that must be
  `false`.
- `credential_shaped_fields_present` is allowed only as explicit artifact-safety
  metadata and must be `false` when supplied.
- `no_raw_credentials` is allowed as observed-behavior metadata and must be
  `true` when supplied.

The allowlist is exact and intentionally small. It does not permit arbitrary
keys merely because they contain an allowed substring.

### What This Proves

This checkpoint proves only:

- Controlled STS validation reports can be schema/safety checked offline.
- Unsafe credential-shaped fields can be rejected before a report is accepted.
- Safe non-claim and artifact-safety boundaries can be enforced.
- Report validation can occur without AWS credentials or AWS calls.

### What This Does Not Prove

This checkpoint does not prove:

- Runtime validation was executed.
- STS AssumeRole was called.
- Any finding was corroborated or refuted.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Downstream authorization.
- Resource-policy Deny support.
- Finding-level reachability.

## 16. Controlled STS Validation Report Generator Checkpoint

The controlled STS validation report generator now exists as an offline
sanitized-summary-to-report bridge for the two already-committed STS proof
summaries.

- Module: `benchmarks/runtime/controlled_sts_validation_report_generator.py`
- Script: `scripts/generate_controlled_sts_validation_report.sh`
- Supported cases: `denied` and `assumed`.
- Input source: already-sanitized committed proof-summary facts only.
- Output destination: caller-provided JSON paths only.
- Generated reports: not committed by default.
- AWS calls: none.
- STS calls: none.
- Raw `/tmp` proof output ingestion: none.
- Raw AWS artifact ingestion: none.
- Credential ingestion: none.
- Raw log ingestion: none.
- Controlled validation execution: not implemented by this generator.
- Terraform state: not read or written.

Supported command shape:

```bash
bash scripts/generate_controlled_sts_validation_report.sh \
  --case denied \
  --json-out /tmp/iamscope-controlled-sts-denied-validation-report.json

bash scripts/generate_controlled_sts_validation_report.sh \
  --case assumed \
  --json-out /tmp/iamscope-controlled-sts-assumed-validation-report.json
```

The generator validates each in-memory report with
`benchmarks/runtime/controlled_sts_validation_report.py` before writing JSON.
Generated reports are not committed by default, and repo-local output is refused
unless explicitly allowed.

### What The Generator Emits

The generator emits controlled STS validation report JSON only.

The `denied` report records:

- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`.
- Target role: `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.
- Predicted outcome: `denied`.
- Observed outcome: `denied`.
- Outcome classification: `corroborated`.
- `credentials_obtained=false`.
- `downstream_actions_performed=false`.

The `assumed` report records:

- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-positive-source`.
- Target role:
  `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-positive-target-role`.
- Predicted outcome: `assumed`.
- Observed outcome: `assumed`.
- Outcome classification: `corroborated`.
- `credentials_obtained=true` as a boolean only.
- `downstream_actions_performed=false`.

Both reports include artifact safety fields and required non-claims. Neither
report emits a composite score, pass/fail label, raw credential material, or
credential-shaped field.

### Validator Integration

Generated reports are validated by the existing controlled STS validation report
validator.

- Generated `denied` reports pass the validator.
- Generated `assumed` reports pass the validator.
- The validator rejects unsafe credential-shaped fields.
- The generator does not emit raw credentials or credential-shaped fields.
- `credentials_obtained` is represented only as a boolean summary field.

### Safety Boundaries

The generator is offline and bounded:

- No AWS calls.
- No STS calls.
- No raw `/tmp` proof output ingestion.
- No raw AWS artifact ingestion.
- No credentials.
- No raw logs.
- No Terraform state.
- No generated reports committed by default.

### What This Adds

This checkpoint proves only:

- Sanitized STS proof summaries can be transformed into controlled validation
  reports.
- Those reports can pass schema and safety validation.
- Denied and assumed proof summaries can be represented without raw credentials
  or unsafe labels.
- The report generator can operate without AWS credentials or AWS calls.

### What This Does Not Add

This checkpoint does not prove:

- New runtime validation was executed.
- STS AssumeRole was called.
- Any new finding was corroborated or refuted.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Downstream authorization.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.

## 17. Safe Bundle Generator Checkpoint

A safe controlled STS validation report bundle generator now exists as an
offline wrapper around the existing sanitized report generator and report
validator.

- Module: `benchmarks/runtime/controlled_sts_validation_report_bundle.py`
- Script: `scripts/generate_controlled_sts_validation_bundle.sh`
- Input source: already-sanitized committed proof summaries through the existing
  report generator.
- Output destination: caller-provided directory only.
- Repo-local output: refused by default.
- AWS calls: none.
- STS calls: none.
- Raw `/tmp` proof output ingestion: none.
- Raw AWS artifact, credential, or log ingestion: none.
- Controlled validation execution: not implemented.
- Generated bundle outputs: not committed by default.

Supported command shape:

```bash
bash scripts/generate_controlled_sts_validation_bundle.sh \
  --out-dir /tmp/iamscope-controlled-sts-validation-bundle
```

### Bundle Contents

The generated bundle contains:

- `controlled-sts-denied-validation-report.json`
- `controlled-sts-assumed-validation-report.json`
- `bundle_index.md`
- `artifact_safety_manifest.json`
- `validator_summary.json`

The denied and assumed report JSON files are generated by the existing
controlled STS validation report generator and are validated by the existing
report validator before bundle generation succeeds.

### Artifact Safety Manifest

The bundle manifest records safe artifact boundaries:

- `raw_artifacts_included=false`
- `credentials_included=false`
- `tmp_proof_outputs_included=false`
- `raw_aws_logs_included=false`
- `terraform_state_included=false`
- `composite_score_included=false`
- `pass_fail_labels_included=false`
- `downstream_actions_claimed=false`
- `sanitized_summaries_only=true`
- `reports_validated=true`

### Bundle Index Boundaries

The Markdown index summarizes the bundle contents, denied report, assumed
report, evidence boundary, non-claims, and artifact safety statement. It states
that the bundle does not claim production readiness, broad runtime
exploitability, broad IAMScope correctness, downstream authorization,
resource-policy Deny support, finding-level reachability, real-world
scalability, composite scoring, or pass/fail benchmark labels.

### Validator Integration

The bundle generator integrates with the controlled STS validation report
validator:

- The denied report passes the validator.
- The assumed report passes the validator.
- Unsafe credential-shaped fields are rejected by the validator.
- The bundle contains no raw credentials.
- `credentials_obtained` remains a boolean-only field in generated reports.

### What This Adds

This checkpoint proves only:

- Sanitized denied and assumed STS proof summaries can be bundled safely.
- Generated reports can pass schema and safety validation.
- Bundle metadata can preserve artifact safety and non-claims.
- Bundle generation can occur without AWS calls or raw artifact ingestion.

### What This Does Not Add

This checkpoint does not prove:

- New runtime validation was executed.
- A new STS call was made.
- Any new finding was corroborated or refuted.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Downstream authorization.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.

## 18. Generated Bundle Review Checkpoint

This checkpoint records the controlled STS validation bundle that was generated to /tmp and reviewed without committing generated outputs.

### Bundle Generation And Review State

- Bundle path: /tmp/iamscope-controlled-sts-validation-bundle
- The generated denied and assumed controlled STS validation reports were validated.
- The bundle was reviewed for artifact safety.
- Generated bundle outputs were not committed.
- No live AWS call, STS AssumeRole call, or new bundle generation is performed by this checkpoint.

### Bundle Contents Reviewed

- artifact_safety_manifest.json
- bundle_index.md
- controlled-sts-assumed-validation-report.json
- controlled-sts-denied-validation-report.json
- validator_summary.json

### Validation Result

- Denied report: valid=true, observed_outcome=denied, outcome_classification=corroborated, credentials_obtained=false, downstream_actions_performed=false.
- Assumed report: valid=true, observed_outcome=assumed, outcome_classification=corroborated, credentials_obtained=true, downstream_actions_performed=false.
- The denied report passed the validator.
- The assumed report passed the validator.

### Artifact Safety Result

The reviewed artifact safety manifest recorded safe boundaries:

- raw_artifacts_included=false
- credentials_included=false
- tmp_proof_outputs_included=false
- raw_aws_logs_included=false
- terraform_state_included=false
- composite_score_included=false
- pass_fail_labels_included=false
- downstream_actions_claimed=false
- sanitized_summaries_only=true
- reports_validated=true

### Evidence Boundary

This reviewed bundle proves only that sanitized denied and assumed STS proof summaries can be represented as controlled STS validation reports and pass schema and artifact-safety validation.

This checkpoint does not add new runtime evidence.

### Non-Claims

This checkpoint explicitly does not claim:

- No new STS call.
- No new AWS call.
- No new finding corroborated or refuted beyond existing sanitized summaries.
- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No broad runtime exploitability.
- No downstream authorization proof.
- No resource-policy Deny support.
- No finding-level reachability.
- No real-world scalability.

### Recommended Next Slice

Recommended next slice: final controlled real-environment validation maturity checkpoint.

That next slice should be docs/checkpoint only.

Do not recommend more live probes, more bundle generation, raw artifact inclusion, committing generated bundle outputs by default, a new benchmark framework, CI gates, composite scoring, or multiple slices at once.
