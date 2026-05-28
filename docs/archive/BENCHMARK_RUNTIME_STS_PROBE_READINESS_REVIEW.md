# Benchmark Runtime STS Probe Readiness Review

## Purpose

This review assesses whether IAMScope is ready to implement minimal live STS AssumeRole probe execution after the dry-run STS probe plan validator.

This is a design/review slice only. It does not implement live STS execution, call AWS, call STS AssumeRole, require AWS credentials, add Terraform, add live AWS environments, mutate IAM roles or policies, create or modify resources, change runtime probe validator logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, change threshold/comparator/reporting/harness logic, add fixtures, copy raw artifacts, add raw artifacts, add CI gates, add pass/fail benchmark labels, or add composite scoring.

## Current State

The dry-run STS probe plan validator exists. It validates probe plan/config shape and safety guardrails only.

Current runtime-probe state:

- Dry-run validator exists at `benchmarks/runtime/sts_probe_plan.py`.
- Runner exists at `scripts/validate_sts_probe_plan.sh`.
- Validator checks schema and safety guardrails.
- Validator makes no AWS calls.
- Validator does not call STS AssumeRole.
- Validator does not require AWS credentials.
- Validator does not produce runtime proof.
- Runtime probe execution remains unimplemented.

The current state is intentionally pre-runtime. It is useful for rejecting unsafe or malformed plans before any AWS call, but it is not evidence that any role can be assumed.

## Evidence Boundary

Minimal live STS AssumeRole execution would prove only this narrow fact:

- One specified test principal can or cannot assume one specified test role under explicit test conditions.

Minimal live STS AssumeRole execution would not prove:

- Production readiness.
- Broad exploitability.
- Downstream action authorization.
- Arbitrary IAMScope correctness.
- Broad IAMScope correctness.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Real-world enterprise coverage.
- Persistence.
- Production impact.

Even a successful future STS AssumeRole probe would be a bounded runtime observation for one test principal, one test role, one profile/account context, and one point in time.

## Readiness Criteria

All of the following must be true before any live STS execution implementation is considered:

- Dry-run validator must pass.
- Probe plan must be `validate_only` or `dry_run` validated first.
- Source principal must be test-only.
- Target role must be test-only.
- Expected account ID must match the target role account.
- `aws_profile` must be explicitly supplied.
- Session duration must be bounded.
- Session name prefix must be safe.
- Output paths must be caller-provided.
- No raw credentials, tokens, or secrets may be logged.
- No production markers may appear in role, principal, or account names unless explicitly allowlisted by a separately reviewed test-only policy.
- Clear operator confirmation must be required before any live call if a future implementation adds live mode.

This readiness review does not itself satisfy those criteria for any concrete live probe. It defines the criteria a future design must preserve.

## Safety Model

Future live STS probe execution must require:

- Test identities only.
- Test roles only.
- Test accounts only.
- No production resources.
- No destructive actions.
- No policy mutation.
- No role/user creation or modification.
- No broad enumeration.
- No persistence.
- No downstream AWS action after AssumeRole.
- No credential material in artifacts.
- No automatic retry loops that could look suspicious.

The minimal safe posture is one explicit operator-approved STS AssumeRole attempt against a test role, using a caller-supplied profile, after dry-run validation succeeds.

## Minimal Live Execution Design Boundary

If later implemented, minimal live execution should only:

- Call `sts:AssumeRole` for one probe at a time or a tightly bounded plan.
- Use a caller-supplied profile.
- Use bounded `duration_seconds`.
- Use a safe session name.
- Record only safe metadata.
- Classify the result without overclaiming.
- Avoid using returned credentials for any downstream API call.

It must not use assumed-role credentials to test downstream permissions. It must not enumerate account resources. It must not mutate IAM or any other AWS service. It must not create cleanup burden.

## Result Classifications

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
- `passed`
- `failed`
- `production_ready`

Classifications are review signals. They are not benchmark pass/fail labels and are not production-readiness statements.

## Output Model

Future live output should include:

- `probe_id`
- `attempted_at`
- `source_principal_arn`
- `target_role_arn`
- `expected_account_id`
- Observed account only if safely available without downstream action.
- Result classification.
- Safe error category.
- Caveats.
- `live_aws_used=true` only for actual live mode.
- `aws_calls_made=true` only for actual live mode.

Future live output must not include:

- Raw credentials.
- STS access keys.
- STS secret keys.
- STS session tokens.
- Other tokens.
- Secrets.
- Raw AWS debug logs.
- Broad account inventory.
- Raw benchmark artifacts.

Safe JSON and Markdown summaries are acceptable if written only to caller-provided paths.

## Rollback / Cleanup

No cleanup should be required because minimal live STS probes must not create or modify resources.

If a future implementation adds any resource creation, role/user modification, policy mutation, Terraform, or persistent state, that is out of scope for this readiness path and requires a separate design.

Terraform is out of scope.

## Failure Handling

Failed, denied, inconclusive, or unexpected live probes must be classified before patching. Possible explanations include:

- Tool/reasoner bug.
- Probe/harness bug.
- Evidence gap.
- Benchmark/probe design flaw.
- Environment/account/profile setup issue.
- AWS control-plane/transient issue.

No failed probe should automatically trigger collector, reasoner, scorer, scenario-validation, benchmark, or fixture changes. Any such change requires a separate bounded diagnosis.

## Artifact Hygiene

Future live STS probe outputs must preserve benchmark artifact hygiene:

- Outputs must go to caller-provided paths.
- No raw AWS logs.
- No credentials, tokens, or secrets.
- No Terraform artifacts.
- No `collect/` directories.
- Safe JSON/Markdown summaries only.
- Generated outputs are not committed by default.

Any committed fixture must be synthetic or sanitized, small, deterministic, and separately justified.

## Readiness Verdict

Readiness verdict: `ready_for_minimal_live_design_only`.

Rationale:

- The dry-run validator creates a useful precondition for future live work.
- The project has not yet designed the live executor interface, operator confirmation, live-mode command shape, output contract, or safety contract in enough detail.
- Live STS execution is a materially higher safety and evidence boundary than dry-run validation.
- Implementation should not begin until the live executor interface and safety contract are designed and reviewed.

This review does not mark IAMScope ready for live STS implementation.

## Recommended Next Slice

Recommended next slice: design the minimal live STS probe executor interface and safety contract.

That next slice should remain design-only unless the review explicitly changes the readiness verdict. It should define command shape, operator confirmation, live-mode gating, exact AWS call boundary, output schema, safe error categories, artifact hygiene, and stop conditions.

Do not recommend immediate broad live STS execution, production account testing, Terraform, destructive probes, downstream action testing, CI gating, composite scoring, or multiple slices at once.
