# Controlled STS Run #1 Environment/Profile Mismatch Checkpoint

## Scope

This checkpoint records the environment/profile mismatch observed while preparing Controlled STS Validation Run #1 for possible future live execution.

This is docs/checkpoint only. It does not run live AWS, call STS AssumeRole, run `live_probe`, modify AWS resources, change IAMScope logic, change benchmark logic, add raw artifacts, commit `/tmp` outputs, add pass/fail labels, or add composite scoring.

## Planned Run

- `validation_run_id`: `controlled-sts-run-001-env06-admin-reachability-assume-role`
- Environment label: `acceptance/env06_ar_validated_admin`
- Expected account ID: `<redacted-aws-account-id>`
- Planned source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env06-alice`
- Planned target role: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-test/env06-admin`
- Expected outcome: `assumed`
- IAMScope-native `finding_id`: unavailable in committed sanitized evidence
- IAMScope-native `path_id`: unavailable in committed sanitized evidence
- Identifier used for planning: validation-layer ID only

## Observed Live-Readiness Checks

The following checks had already been performed before this checkpoint slice:

- `aws sts get-caller-identity --profile iamscope-test` returned `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`.
- That caller identity does not match the planned source principal `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env06-alice`.
- `aws iam get-role --role-name iamscope-test/env06-admin` failed because that is invalid `role-name` syntax for IAM `get-role`.
- `aws iam get-role --role-name env06-admin` returned `NoSuchEntity`.

No additional live AWS checks were run by this checkpoint slice.

## Checkpoint Classification

Classification: `environment_mismatch`.

This is not classified as `tool_bug_candidate`, because the observed issue is that the current AWS profile/environment does not correspond to the sanitized Env06 path selected for Run #1. The pre-live plan and sanitized Env06 benchmark evidence expected `env06-alice` and `env06-admin`; the checked live profile resolved to `iamscope-verify`, and the checked role names did not find the target role.

## Execution Status

- Live execution is blocked.
- `live_probe` was not run.
- `sts:AssumeRole` was not called.
- No runtime validation result exists for Controlled STS Run #1.
- No credentials were obtained.
- No downstream AWS actions were performed.

## Abort Reason

Controlled STS Run #1 must not proceed to live execution under the currently checked setup because:

1. The `iamscope-test` profile resolves to `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`, not the planned source principal `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env06-alice`.
2. The target role was not found by the checked role-name forms.
3. The currently checked AWS environment/profile setup therefore does not match the sanitized Env06 path selected for Run #1.

## Evidence Boundary

This checkpoint only records the mismatch between the planned sanitized Env06 path and the observed live-readiness identity/role checks.

It does not invalidate the sanitized Env06 benchmark evidence. That evidence remains a committed benchmark snapshot for the Env06 controlled benchmark corpus. The mismatch means only that the currently checked AWS profile/environment is not ready to execute this specific Controlled STS Run #1 live probe.

## Non-Claims

This checkpoint does not claim:

- IAMScope made a wrong prediction.
- The Env06 sanitized evidence is invalid.
- A live STS AssumeRole result exists.
- Runtime reachability was corroborated or refuted.
- `env06-admin` cannot exist in any intended Env06 test setup.
- The profile mismatch is an IAMScope tool bug.
- IAMScope is production-ready.
- IAMScope is broadly correct.
- Broad runtime exploitability was shown.

## Next Slice

Decide whether to map/create the exact Env06 test profile and role setup, or select a different controlled STS path that matches the current live profiles.

That next slice must still require explicit approval before any live STS call and must not treat this checkpoint as live execution authorization.
