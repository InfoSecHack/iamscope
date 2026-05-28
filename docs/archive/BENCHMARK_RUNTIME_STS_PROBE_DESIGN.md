# Benchmark Runtime STS Probe Design

## Purpose

This document designs non-destructive STS AssumeRole runtime validation probes for IAMScope as a separate runtime evidence track.

The goal is to define how a future probe system could check one narrow runtime question: whether a specific test principal can assume a specific test role under explicit test conditions. This is intentionally separate from the reasoning corpus, frozen live benchmark snapshots, synthetic scalability fixtures, offline reports, baseline comparators, and threshold review outputs.

This is design-only. It does not implement runtime probes, run live AWS, add live AWS environments, add Terraform, change collector logic, change reasoner logic, change scorer logic, change scenario-validation logic, change benchmark logic, change threshold evaluator logic, change comparator/reporting/harness logic, add fixtures, add CI gates, add pass/fail benchmark labels, or add composite scoring.

## Non-Goals

This design is not:

- Implementation.
- Live execution in this PR.
- Destructive testing.
- Privilege modification.
- Persistence.
- Production resource testing.
- Broad exploitability proof.
- Production-readiness proof.
- Arbitrary enterprise graph correctness proof.
- Generic runtime validation for all IAMScope findings.
- CI gating.
- Composite scoring.

Runtime probes must not be framed as marketing claims. They must remain bounded, explicit, reversible, and separate from the reasoning/frozen-corpus benchmark evidence.

## Evidence Boundary

An STS AssumeRole probe could prove only this narrow fact:

- Under explicit test conditions, a specific test principal either can or cannot successfully call `sts:AssumeRole` for a specific test role.

The evidence must include the source principal ARN, target role ARN, expected account, profile/account assumptions, probe time, result classification, and safe request metadata summary. It must not include raw credentials, tokens, secrets, broad account inventory, or raw AWS debug logs.

An STS AssumeRole probe does not prove:

- Broad exploitability.
- Persistence.
- Downstream action authorization after role assumption.
- Production impact.
- Arbitrary IAMScope correctness.
- Broad IAMScope semantic correctness.
- Arbitrary enterprise graph correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Real-world scalability.
- Production readiness.

Probe success can corroborate one narrow edge/path hypothesis. Probe denial can narrow investigation. Neither outcome is a global correctness or exploitability statement.

## Safety Model

Future runtime probes must require:

- Test identities only.
- Test roles only.
- Test accounts only.
- Explicit AWS profile/account assumptions.
- No production resources.
- No destructive API calls.
- No policy mutation.
- No role creation or modification during probe execution.
- No persistence.
- No privilege escalation beyond the intended `sts:AssumeRole` call.
- No credential exfiltration.
- No broad enumeration.

Allowed probe behavior should be limited to validating configuration, resolving the caller identity safely, checking that the expected account/role constraints match, and attempting the single intended STS AssumeRole call only after safety checks pass.

Disallowed probe behavior includes creating resources, modifying policies, attaching policies, enumerating broad account state, invoking downstream service actions with assumed credentials, writing raw debug logs, storing temporary credentials, or testing production identities/resources.

## Probe Input Model

A future probe config should be explicit and small. Suggested fields:

- `probe_id`: stable identifier for the probe.
- `source_principal_arn`: expected source principal ARN for the test identity.
- `target_role_arn`: target test role ARN.
- `aws_profile`: explicitly supplied local AWS profile to use.
- `expected_account_id`: expected AWS account ID for the target role and safety checks.
- `region`: optional AWS region if a future probe needs regional context.
- `session_name_prefix`: bounded prefix for the STS session name.
- `external_id`: optional external ID when the target trust policy requires one.
- `duration_seconds`: bounded session duration value.
- `expected_outcome`: expected narrow result, such as `assumed`, `denied`, or `inconclusive`.
- `evidence_boundary`: human-readable statement of what this probe can and cannot prove.
- `safety_notes`: required notes describing why the identities, role, account, and action are safe for this probe.

Input validation should reject missing profile/account assumptions, production-looking targets, unbounded session durations, unsupported ARN patterns, broad selectors, raw credential material, or configs without an evidence boundary and safety notes.

## Probe Output Model

A future probe output should be a safe JSON or Markdown summary. Suggested fields:

- `probe_id`
- `attempted_at`
- `source_principal_arn`
- `target_role_arn`
- `expected_account_id`
- `observed_account_id`, if safely available
- `result_classification`
- `error_category`, if denied or inconclusive
- `request_metadata_safe_summary`
- `evidence_boundary`
- `safety_notes`
- `caveats`

Output must not include:

- Raw credentials.
- STS access keys.
- STS secret keys.
- STS session tokens.
- Cloud tokens.
- Account secrets.
- Raw AWS debug logs.
- Broad account inventory.
- Raw live benchmark artifacts.

## Result Classifications

Use non-overclaiming classifications:

- `assumed`: the intended STS AssumeRole call succeeded under explicit test conditions.
- `denied`: the intended STS AssumeRole call was denied under explicit test conditions.
- `inconclusive`: the probe could not establish assumed or denied because of a bounded, explainable uncertainty.
- `skipped_safety_guard`: safety validation blocked the probe before live execution.
- `configuration_error`: required probe config, profile, account, or environment assumptions were invalid.
- `unexpected_account`: resolved account context did not match `expected_account_id`.
- `malformed_probe`: probe input was malformed or unsupported.

Avoid classifications and labels such as:

- `exploited`
- `pwned`
- `vulnerable`
- `production_ready`
- `pass`
- `fail`
- Benchmark pass/fail labels

## Required Guardrails

Before any future probe can run live, it must pass safety checks:

- Target account must match `expected_account_id`.
- Target role ARN must match an allowlisted test-role pattern.
- Source profile must be explicitly supplied.
- Source principal ARN must match the expected test identity if it can be resolved safely.
- Session duration must be bounded.
- Session name must use an allowed prefix.
- External ID use must match the probe config.
- Dry-run/config validation mode must exist before live mode.
- Output path must be caller-provided.
- No raw credential material may be logged.
- No broad account enumeration may occur.
- No downstream authorization checks may run in the first implementation slice.

The safest first implementation should validate only the probe plan and safety guards. It should not call AWS.

## Artifact Hygiene

Runtime probe artifacts must preserve benchmark artifact hygiene:

- Probe outputs must go to caller-provided paths.
- No raw AWS debug logs.
- No credentials, tokens, secrets, profiles, or account secrets.
- No Terraform state/cache/provider artifacts.
- No `collect/` directories.
- No raw `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.
- No uncontrolled generated run directories.
- Safe JSON and Markdown summaries only.

Generated probe outputs should not be committed by default. Any future committed fixture must be synthetic or sanitized, small, deterministic, purpose-specific, and explicitly justified.

## Relationship To The IAMScope Benchmark Corpus

Runtime probes are separate from frozen reasoning evidence:

- Runtime probe success or failure can corroborate a narrow edge/path hypothesis.
- Runtime probes do not replace mutation-pair benchmarks.
- Runtime probes do not replace frozen live benchmark snapshots.
- Runtime probes do not expand semantic correctness claims.
- Runtime probes do not prove broad exploitability or production readiness.
- Runtime probes should be reviewed as a separate evidence track with their own caveats.

Failed probes require classification before patching. A failed or denied probe may indicate:

- Real tool bug.
- Harness/probe issue.
- Evidence gap.
- Benchmark/probe design flaw.
- Environmental/account setup issue.

Probe results should not automatically trigger reasoner, collector, scorer, scenario-validation, or benchmark changes. Any such change would require a separate bounded diagnosis and PR.

## Dry-Run Plan Validator Checkpoint

The dry-run STS probe plan validator is now implemented. The validator lives at `benchmarks/runtime/sts_probe_plan.py`, and the runner lives at `scripts/validate_sts_probe_plan.sh`.

The validator checks probe config shape and safety guardrails only. It does not call AWS, does not call STS AssumeRole, does not execute runtime probes, and does not require AWS credentials.

Command shape:

```bash
bash scripts/validate_sts_probe_plan.sh \
  --plan /tmp/iamscope-sts-probe-plan.json \
  --json-out /tmp/iamscope-sts-probe-validation.json \
  --markdown-out /tmp/iamscope-sts-probe-validation.md
```

Validator boundaries:

- JSON probe plans only.
- `dry_run` / `validate_only` modes only.
- No AWS calls.
- No STS AssumeRole calls.
- No AWS credentials required.
- No runtime probe execution.
- No live AWS evidence.
- No Terraform.
- No role creation or modification.
- No policy mutation.
- No broad enumeration.
- No CI gating.
- No pass/fail benchmark labels.
- No composite score.

Implemented safety checks:

- Allowed mode is `dry_run` or `validate_only`.
- `target_role_arn` account matches `expected_account_id`.
- `target_role_arn` is an IAM role ARN.
- `source_principal_arn` is an IAM principal ARN.
- `aws_profile` is explicitly supplied.
- `duration_seconds` is bounded.
- `session_name_prefix` is bounded and STS-safe.
- `evidence_boundary` is present.
- `safety_notes` is present.
- Wildcard role/source ARNs are rejected.
- Duplicate `probe_id` values are rejected.
- Caller-provided output paths are used when JSON or Markdown outputs are requested.
- Production-like markers without a test marker are treated as safety-guard issues.

Output boundaries:

- Safe JSON validation summary.
- Safe Markdown validation summary.
- `dry_run_only=true`.
- `live_aws_used=false`.
- `aws_calls_made=false`.
- No credentials, tokens, or secrets.
- No raw AWS debug logs.
- No composite score.
- No pass/fail benchmark labels.

Validator result classifications are intentionally non-overclaiming:

- `valid`
- `invalid`
- `skipped_safety_guard`
- `malformed_probe`

Avoid labels such as:

- `pass` / `fail`
- `exploited`
- `vulnerable`
- `pwned`
- `production_ready`
- `benchmark_passed`

This proves only that STS probe plans can be schema/safety validated offline, unsafe or malformed plans can be rejected before any AWS call, safe JSON/Markdown summaries can be generated, and runtime probe execution remains unimplemented.

This does not prove successful STS AssumeRole, runtime exploitability, production readiness, broad IAMScope correctness, arbitrary enterprise graph correctness, downstream action authorization, resource-policy Deny support, or finding-level resource-policy reachability.

## Recommended Next Slice

Recommended next slice: design minimal live STS AssumeRole probe execution readiness review.

This next slice must be design/review-only, not implementation. The dry-run validator exists, but live STS execution is a materially higher safety and evidence boundary. Before any AWS call is implemented, the project needs an explicit readiness review.

Do not recommend immediate live STS execution, production account testing, Terraform, destructive probes, broad runtime validation, CI gating, composite scoring, or multiple slices at once.
