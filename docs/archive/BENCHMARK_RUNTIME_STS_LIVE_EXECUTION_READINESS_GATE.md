# Benchmark Runtime STS Live Execution Readiness Gate

## Purpose

This review assesses whether IAMScope is ready to implement a minimal live `sts:AssumeRole` executor path after the dry-run validator and no-call/simulation executor skeleton.

This is a design/review gate only. It does not implement live STS execution, call AWS, call STS AssumeRole, require AWS credentials, add Terraform, add live AWS environments, mutate IAM roles or policies, create or modify resources, or change IAMScope runtime, benchmark, threshold, comparator, reporting, harness, collector, reasoner, scorer, or scenario-validation logic.

## Current State

- Dry-run STS probe plan validator exists.
- No-call/simulation executor skeleton exists.
- Executor JSON and Markdown output contract exists.
- Refusal paths exist for unsupported live-like modes and invalid plans.
- No AWS calls exist yet in this runtime-probe track.
- No STS AssumeRole calls exist yet.
- No live runtime evidence exists yet.

## Evidence Boundary

A future minimal live STS execution would prove only:

- One configured STS AssumeRole attempt was made for one specific test principal and one specific test role under explicit test conditions.
- The result was classified as one of `assumed`, `denied`, `inconclusive`, `skipped_safety_guard`, `configuration_error`, `unexpected_account`, or `malformed_probe`.

It would not prove:

- Production readiness.
- Broad exploitability.
- Downstream action authorization.
- Arbitrary IAMScope correctness.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence or impact.
- Correctness of every static finding.

## Required Preconditions Before Live Implementation

Hard preconditions before any live implementation may merge:

- No-call executor skeleton is merged.
- Dry-run validator is merged and green.
- Live executor interface design is merged.
- This readiness gate review is merged.
- Operator confirmation is required.
- Explicit `allow_live_mode` or an equivalent live opt-in is required.
- Probe plan must already pass dry-run validation.
- Probe count must be bounded.
- Role, principal, and account must be test-only or explicitly allowlisted.
- Production accounts are forbidden by default.
- Output paths must be caller-provided.
- Credential, token, and secret logging must be impossible.
- No downstream API action may occur after AssumeRole.
- Retries must be absent or limited to a narrow bounded policy.

## Hard Refusal Conditions

A future live executor must refuse live execution if any of these conditions is true:

- Mode is not explicit live mode.
- Operator confirmation is missing.
- Dry-run validation fails.
- Target account does not match `expected_account_id`.
- `aws_profile` is missing.
- Target role ARN is malformed or wildcarded.
- Source principal ARN is malformed or wildcarded.
- Production markers are present and not explicitly allowlisted.
- `duration_seconds` is unsafe.
- Output paths are missing.
- Probe count is too high.
- Downstream actions are configured.
- Raw debug logging is requested.

Refusal should happen before constructing any AWS client whenever possible.

## Minimal Allowed Live Action

The only allowed future live action is:

- `sts:AssumeRole` for the target role specified in the validated probe plan.

Explicitly forbidden:

- Using returned credentials for any downstream API call.
- Listing resources.
- IAM mutation.
- Resource creation or deletion.
- Policy changes.
- Persistence.
- Broad enumeration.
- Terraform.
- `collect/` pipeline invocation.

## Output And Sanitization Contract

Future live output must:

- Set `live_aws_used=true`.
- Set `aws_calls_made=true`.
- Set `sts_assume_role_called=true` only if the API call was actually attempted.
- Set `credentials_obtained=true` only as a boolean if AssumeRole succeeds.
- Never output raw credentials, access keys, session tokens, secrets, raw AWS debug logs, or full sensitive exception dumps.
- Include only safe error categories.
- Include evidence-boundary caveats.

Safe error categories should remain sanitized review signals, not raw AWS debug dumps.

## Result Classifications

Allowed classifications:

- `assumed`
- `denied`
- `inconclusive`
- `skipped_safety_guard`
- `configuration_error`
- `unexpected_account`
- `malformed_probe`

Avoid labels such as:

- `pass`
- `fail`
- `exploited`
- `vulnerable`
- `pwned`
- `production_ready`
- `benchmark_passed`

## Required Tests For Future Implementation

Before a future live implementation can merge, tests must cover:

- Live mode is impossible without explicit confirmation.
- Dry-run validation failure blocks live mode.
- Missing profile blocks live mode.
- Mismatched expected account blocks live mode.
- Production marker without allowlist blocks live mode.
- Downstream action configuration blocks live mode.
- Raw debug logging request blocks live mode.
- Output never contains credential-shaped fields.
- No boto3 or STS call occurs in tests unless explicitly mocked.
- Mocked STS success classifies `assumed` without leaking credentials.
- Mocked STS AccessDenied classifies `denied`.
- Mocked unexpected response classifies `inconclusive` or `unexpected_account`.

## Rollback And Cleanup

No cleanup should be required for the minimal STS-only live call because no resources are created or modified.

Any future resource creation, resource modification, Terraform, or cleanup requirement is out of scope and requires a separate design before implementation.

## Artifact Hygiene

- Outputs must go to caller-provided paths.
- Generated outputs are not committed by default.
- Raw AWS logs are forbidden.
- Credentials, tokens, and secrets are forbidden.
- Terraform state, cache, and provider artifacts are forbidden.
- `collect/` directories are forbidden.
- Safe JSON and Markdown summaries only.

## Readiness Verdict

Verdict: `ready_to_design_minimal_live_executor_implementation`.

This means IAMScope is ready to design and implement a minimal, carefully mocked, refusal-first live executor path. It does not mean IAMScope is ready for broad live execution, production account testing, downstream action testing, CI gating, or any production-readiness claim.

## Recommended Next Slice

Recommended next slice: implement minimal live STS executor with mocked tests and refusal-first safety gates.

The next implementation still must not run real AWS in tests. It may introduce code capable of a live STS call only behind explicit live mode, explicit operator confirmation, and safety guards.

Do not recommend production account testing, Terraform, destructive probes, downstream action testing, broad runtime validation, CI gating, composite scoring, or multiple slices at once.
