# Benchmark Runtime STS Executor Interface

## Purpose

This document designs the minimal future executor interface and safety contract for live STS AssumeRole probes, without implementing execution.

The executor interface is the boundary between the existing dry-run STS probe plan validator and any future live STS call. It exists to make the future live mode explicit, operator-confirmed, bounded, and separate from frozen reasoning benchmarks.

This is design-only. It does not implement live STS execution, call AWS, call STS AssumeRole, require AWS credentials, add Terraform, add live AWS environments, mutate IAM roles or policies, create or modify resources, change dry-run validator logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, change threshold/comparator/reporting/harness logic, add fixtures, copy raw artifacts, add raw artifacts, add CI gates, add pass/fail benchmark labels, or add composite scoring.

## Non-Goals

This design is not:

- Implementation.
- Live execution in this PR.
- Terraform.
- Production testing.
- Destructive testing.
- Downstream AWS action testing.
- Role or policy mutation.
- Broad exploitability proof.
- Production-readiness proof.
- Arbitrary IAMScope correctness proof.
- CI gating.
- Composite scoring.

The future executor must not be framed as broad runtime exploitability, production readiness, or broad IAMScope correctness.

## Executor Input Contract

A future live STS executor command should accept explicit caller-provided inputs:

- `validated_probe_plan_path`: path to a probe plan that has already passed dry-run validation.
- `probe_id` or all-probes selector: one explicit probe ID by default, with all-probes support only if tightly bounded by `max_probes`.
- `aws_profile`: caller-supplied AWS profile for live execution.
- `expected_account_id`: expected target account ID for safety checks.
- `json_out`: caller-provided JSON output path.
- `markdown_out`: caller-provided Markdown output path.
- `operator_confirmation`: explicit flag or phrase acknowledging that live STS execution is being requested.
- `max_probes`: upper bound on live probes in one invocation.
- `allow_live_mode`: explicit boolean that must be true for any future AWS call.
- `evidence_boundary_acknowledgement`: explicit acknowledgement that live STS results are narrow runtime observations, not production-readiness or broad exploitability proof.

The interface should reject implicit live mode. A command that omits `allow_live_mode=true` or the exact operator confirmation must refuse before any AWS client is constructed.

## Preconditions

Before a future live executor may call AWS, all preconditions must be true:

- Dry-run validator must pass.
- Probe plan mode must be explicitly `live_probe` or an equivalent future live-mode value, not accidentally `dry_run`.
- Operator confirmation must be explicit.
- `aws_profile` must be supplied.
- `expected_account_id` must match the target role account.
- Target/source ARNs must pass validator checks.
- Output paths must be caller-provided.
- Probe count must be bounded.
- Production markers must be absent unless explicitly allowlisted by a separately reviewed test-only policy.
- Wildcard targets must be rejected.
- Evidence boundaries must be present.
- `duration_seconds` must be safe and bounded.
- Downstream actions must not be configured.

If any precondition fails, the future executor should return a non-live refusal or safety classification without constructing an AWS STS client.

## Live Executor Allowed Action Boundary

The only future allowed live action is:

- `sts:AssumeRole` for the specified target role.

The future executor must explicitly forbid:

- Using returned credentials for downstream API calls.
- Listing resources.
- Modifying IAM.
- Creating resources.
- Deleting resources.
- Policy mutation.
- Persistence.
- Retries beyond a narrow bounded policy.

Returned STS credentials, if any, must never be written to disk, logs, JSON, Markdown, stdout, or stderr.

## Future Runtime Result Classifications

Use non-overclaiming classifications:

- `assumed`
- `denied`
- `inconclusive`
- `skipped_safety_guard`
- `configuration_error`
- `unexpected_account`
- `malformed_probe`

Avoid labels such as:

- `exploited`
- `vulnerable`
- `pwned`
- `pass`
- `fail`
- `production_ready`
- `benchmark_passed`

Result classifications are evidence labels for a narrow runtime probe only. They are not benchmark grades, production-readiness labels, or exploitability claims.

## Output Contract

Future safe output fields:

- `report_type`
- `live_aws_used`
- `aws_calls_made`
- `probe_id`
- `attempted_at`
- `source_principal_arn`
- `target_role_arn`
- `expected_account_id`
- Result classification.
- Safe error category.
- Caveats.
- Evidence boundary statement.

Future output must explicitly forbid:

- Raw credentials.
- Access keys.
- Session tokens.
- Secrets.
- Raw AWS debug logs.
- Full botocore debug traces.
- Raw exception dumps with sensitive material.

Output should be safe JSON and Markdown summaries only, written to caller-provided paths.

## Error Handling Semantics

Future safe error categories:

- `access_denied`
- `validation_error`
- `profile_error`
- `account_mismatch`
- `sts_error`
- `network_or_timeout`
- `unexpected_response`
- `unknown_sanitized`

The executor should not require or emit raw AWS error dumps. Error messages should be sanitized to preserve enough category information for review without leaking credentials, tokens, request signatures, account secrets, or raw debug traces.

## Account / Profile Safety

Future account/profile safety rules:

- Validate `expected_account_id` against the target role ARN before any live call.
- Support an explicit profile allowlist if future operators need an additional guard.
- Test accounts only.
- No production account by default.
- Profile/account mismatch must produce a refusal or `unexpected_account` style result, not a live retry.
- Operator confirmation is required for live mode.

The executor must not infer profile or account context from ambient defaults when live mode is requested.

## Artifact Hygiene

Future executor artifacts must preserve benchmark artifact hygiene:

- Outputs must go to caller-provided paths.
- No raw AWS logs.
- No credentials, tokens, or secrets.
- No Terraform artifacts.
- No `collect/` directories.
- Safe JSON/Markdown summaries only.
- Generated outputs are not committed by default.

Any committed sample output must be synthetic or sanitized, small, deterministic, and separately justified.

## Relationship To Benchmarks

The live STS executor would be separate from frozen reasoning benchmarks.

Relationship boundaries:

- Live results can corroborate a narrow AssumeRole hypothesis.
- Live results do not replace mutation-pair evidence.
- Live results do not expand broad semantic correctness claims.
- Live results do not imply downstream authorization.
- Live results do not prove production readiness.
- Live results do not prove broad runtime exploitability.

Any future live result should be interpreted alongside the probe plan, safety notes, account/profile assumptions, and evidence boundary.

## Readiness Gate For Implementation

Before implementation starts, all of the following must be true:

- This interface design is merged.
- Dry-run validator tests are green.
- Safety contract is accepted.
- Minimal live executor implementation prompt is scoped to one action only.
- No broad live plan support.
- No production accounts.
- No downstream API calls.

If implementation is later approved, it should begin with refusal and simulation/no-call paths before any AWS client construction.

## Recommended Next Slice

Recommended next slice: implement minimal live STS executor skeleton in no-call mode / simulation mode that wires CLI, validation, output contract, and refusal paths, but still does not call AWS.

The next slice should not call AWS. It should prepare only the executor skeleton and refusal behavior.

Do not recommend immediate live STS call implementation, production account testing, Terraform, destructive probes, downstream action testing, broad runtime validation, CI gating, composite scoring, or multiple slices at once.

## No-Call Executor Skeleton Checkpoint

The minimal STS executor skeleton is now implemented in no-call/simulation mode only.

Implementation paths:

- Skeleton module: `benchmarks/runtime/sts_probe_executor.py`
- Runner script: `scripts/run_sts_probe_executor.sh`
- Slice spec: `docs/specs/sts-probe-executor-skeleton.md`

Simulate command shape:

```bash
bash scripts/run_sts_probe_executor.sh \
  --plan /tmp/iamscope-sts-probe-plan.json \
  --json-out /tmp/iamscope-sts-probe-execution.json \
  --markdown-out /tmp/iamscope-sts-probe-execution.md \
  --mode simulate
```

Validate-only command shape:

```bash
bash scripts/run_sts_probe_executor.sh \
  --plan /tmp/iamscope-sts-probe-plan.json \
  --json-out /tmp/iamscope-sts-probe-execution.json \
  --markdown-out /tmp/iamscope-sts-probe-execution.md \
  --mode validate_only
```

At the no-call checkpoint, supported modes were `simulate` and `validate_only`.

At the no-call checkpoint, rejected modes included `live`, `live_probe`, `execute`, `assume_role`, and unknown modes.

The skeleton reuses the dry-run STS probe plan validator before producing executor-shaped output. Valid probe plans can produce non-live simulation results, while invalid or unsafe plans produce safe refusal/configuration results.

Output boundaries:

- JSON report type: `sts_probe_executor_simulation`
- Markdown simulation summary
- `live_aws_used=false`
- `aws_calls_made=false`
- `sts_assume_role_called=false`
- `credentials_obtained=false`
- No composite score
- No pass/fail benchmark labels
- No credentials, tokens, secrets, raw AWS logs, or Terraform artifacts

Allowed non-live result classifications:

- `simulated_not_executed`
- `skipped_safety_guard`
- `configuration_error`
- `malformed_probe`

Avoided live/proof labels:

- `assumed`
- `denied`
- `pass`
- `fail`
- `exploited`
- `vulnerable`
- `pwned`
- `production_ready`
- `benchmark_passed`

What this proves:

- The executor CLI and output contract can run deterministically without AWS.
- Dry-run validator integration and refusal paths work before executor-shaped output is produced.
- Safe JSON and Markdown summaries can be generated.
- Live execution remains unimplemented.

What this does not prove:

- Successful STS AssumeRole.
- Denied STS AssumeRole.
- Runtime exploitability.
- Production readiness.
- Downstream authorization.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.

This checkpoint does not imply live execution exists. It does not call AWS, does not call STS AssumeRole, does not require AWS credentials, does not obtain credentials, does not perform downstream AWS actions, and does not produce runtime proof.

Recommended next slice: live STS execution readiness gate review.

That next slice should be design/review only, not implementation. It should not recommend immediate live STS execution, production account testing, Terraform, destructive probes, downstream AWS actions, broad runtime validation, CI gating, composite scoring, or multiple slices at once.

The readiness gate review now lives in `BENCHMARK_RUNTIME_STS_LIVE_EXECUTION_READINESS_GATE.md`.

## Minimal Live-Capable Executor Checkpoint

The minimal live-capable STS executor is now implemented in `benchmarks/runtime/sts_probe_executor.py`.

Implementation state:

- `live_probe` is implemented behind explicit safety gates.
- `simulate` and `validate_only` remain no-call modes.
- Tests use fake/mock STS clients only.
- Real AWS is not called in tests.
- No downstream AWS actions are allowed after `sts:AssumeRole`.
- Raw credentials are not emitted.
- No pass/fail benchmark labels or composite score are emitted.

Command shape:

```bash
bash scripts/run_sts_probe_executor.sh \
  --plan /tmp/iamscope-sts-probe-plan.json \
  --json-out /tmp/iamscope-sts-probe-execution.json \
  --markdown-out /tmp/iamscope-sts-probe-execution.md \
  --mode live_probe \
  --allow-live-mode \
  --operator-confirmation "I understand this will call sts:AssumeRole once for test IAM resources only"
```

Safety gates:

- `simulate` and `validate_only` remain no-call modes.
- `live_probe` requires `--allow-live-mode`.
- `live_probe` requires the explicit operator confirmation phrase.
- Dry-run validation must pass before any STS client path.
- `aws_profile` must be supplied by the validated probe plan.
- Target role account must match `expected_account_id`.
- Only one probe is allowed per live invocation.
- JSON and Markdown output paths must both be caller-provided.
- Target/source ARNs, expected account, profile, duration, production-marker, and wildcard safety checks are inherited from the dry-run validator.
- Downstream actions and raw debug logging are refused.
- Wildcard source or target ARNs are refused by validation.
- Production markers require a test-marker allowlist condition or are refused by validation.
- The STS client boundary is injectable so tests use fake clients and do not call AWS.

Allowed live action:

- `sts:AssumeRole` for the validated target role only.

Still forbidden:

- Downstream AWS API calls.
- Using returned credentials.
- `list`, `get`, `describe`, enumerate, mutate, delete, create, or policy operations.
- IAM mutation.
- Resource creation or deletion.
- Policy changes.
- Terraform.
- `collect/` pipeline invocation.
- Raw credentials, access keys, session tokens, secrets, raw AWS debug logs, or sensitive exception dumps in output.

Output boundaries:

- `live_aws_used`, `aws_calls_made`, `sts_assume_role_called`, and `credentials_obtained` flags are emitted.
- `credentials_obtained` is a boolean only.
- No `AccessKeyId`.
- No `SecretAccessKey`.
- No `SessionToken`.
- No credentials object.
- No raw credential-shaped fields.
- No raw debug logs.
- No composite score.
- No pass/fail field.

Result classifications remain non-overclaiming: `assumed`, `denied`, `inconclusive`, `skipped_safety_guard`, `configuration_error`, `unexpected_account`, `malformed_probe`, and `simulated_not_executed`.

Avoided labels remain: `pass`, `fail`, `exploited`, `vulnerable`, `pwned`, `production_ready`, and `benchmark_passed`.

Mocked tests cover success, AccessDenied, unexpected responses, unexpected accounts, refusal gates, and credential sanitization. Tests do not call real AWS and do not require AWS credentials.

What this proves:

- Executor safety gates can be enforced in tests.
- Mocked STS success can classify `assumed` without leaking credentials.
- Mocked STS AccessDenied can classify `denied` without raw sensitive dumps.
- No-call modes remain no-call.
- The output contract preserves evidence boundaries.

What this does not prove:

- Real live STS AssumeRole success.
- Real live STS denial.
- Production readiness.
- Broad runtime exploitability.
- Downstream AWS authorization.
- Arbitrary IAMScope correctness.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence or impact.

This checkpoint does not claim production readiness, broad runtime exploitability, downstream authorization, broad IAMScope correctness, or correctness of every static finding.

Recommended next slice: design a single-case live STS proof-run protocol.

That next slice should be design/protocol only, not a live run. It should define account/profile assumptions, inputs, expected outputs, artifact handling, and abort conditions before any real live proof run is attempted. It should not recommend immediate live STS execution, production account testing, Terraform, destructive probes, downstream AWS actions, broad runtime validation, CI gating, composite scoring, or multiple slices at once.
