# Controlled STS Live-Profile Path Selection

## Purpose

This planning/inspection slice selects a controlled STS validation candidate that matches currently available live AWS profiles and committed sanitized evidence.

This slice does not run `live_probe`, call `sts:AssumeRole`, create or modify AWS resources, run Terraform, mutate IAM, change IAMScope logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, add raw artifacts, commit `/tmp` outputs, add pass/fail labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Current Live Profile Mapping

Known local profile identities from prior discovery:

| Profile | Observed identity |
| --- | --- |
| `iamscope-test` | `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify` |
| `iamscope-admin` | `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin` |
| `serim-dev-admin` | `arn:aws:sts::<redacted-aws-account-id>:assumed-role/OrganizationAccountAccessRole/...` |
| `serim-prod-admin` | `arn:aws:sts::<redacted-aws-account-id>:assumed-role/OrganizationAccountAccessRole/...` |
| `serim2-devengineer` | `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-DevEngineerRole/...` |
| `serim2-jump` | `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-JumpRole/...` |
| `serim2-terraform` | `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-TerraformRole/...` |

This slice did not rerun identity discovery. It uses the prior mapping as input.

## Candidate Search Method

Search was limited to committed sanitized repository evidence and one safe read-only IAM role lookup for the selected target role.

Searches checked for currently available source principals or profile-related role names in:

- `benchmarks/`
- `docs/`
- `acceptance/`
- `.agent/`

Findings from committed evidence:

- `iamscope-verify` appears only in the Run #1 environment-mismatch checkpoint and a Step 8 comment, not as a committed sanitized STS validation path.
- `iamscope-admin` appears in committed controlled STS sanitized proof/report references.
- The available assumed-role profiles did not appear in committed sanitized controlled STS path evidence.

A read-only target role existence check was performed for the selected `iamscope-admin` candidate:

```bash
aws iam get-role \
  --profile iamscope-admin \
  --role-name arf-rt-DevRole \
  --query Role.Arn \
  --output text
```

Observed result:

```text
arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole
```

No `sts:AssumeRole` call was made, no `live_probe` was run, and no AWS resources were modified.

## Candidates Found

### Selected Candidate: iamscope-admin denied STS path

- Candidate status: selected.
- Environment label: `controlled-sts-denied-proof-summary`.
- Source profile: `iamscope-admin`.
- Exact source principal ARN: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`.
- Exact target role ARN: `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.
- Expected account ID: `<redacted-aws-account-id>`.
- Predicted behavior: `denied`.
- Target role existence: confirmed by read-only IAM `get-role` lookup.
- Native IAMScope `finding_id`: unavailable.
- Native IAMScope `path_id`: unavailable.
- Existing sanitized proof/report path ID: `runtime-sts-denied-single-case-proof`.
- Recommended validation-layer ID for a future pre-live plan: `controlled-sts-run-002-iam-admin-arf-rt-devrole-denied`.
- Readiness for pre-live plan: yes.

Evidence source documents:

- `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`
- `docs/archive/BENCHMARK_RUNTIME_STS_SINGLE_CASE_PROOF_PROTOCOL.md`
- `benchmarks/runtime/controlled_sts_validation_report_generator.py`
- `benchmarks/runtime/controlled_sts_validation_report_bundle.py`

The committed sanitized proof checkpoint records this denied single-case proof as:

- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`
- Target role: `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`
- Expected outcome: `denied`
- Observed result: `denied`
- `credentials_obtained=false`
- Downstream AWS actions: none

### Rejected Candidate: Env06 Run #1 path

- Candidate status: rejected for current live profile matching.
- Planned source: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env06-alice`.
- Current `iamscope-test` profile identity from prior discovery: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`.
- Target role lookup for checked `env06-admin` names did not resolve in the prior checkpoint.
- Reason rejected: documented `environment_mismatch`.

### Rejected Candidate: sanitized positive STS proof path

- Candidate status: rejected for current live profile matching.
- Source principal in sanitized evidence: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-positive-source`.
- Target role in sanitized evidence: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-positive-target-role`.
- Reason rejected: source principal does not match any currently available live profile identity from the prior mapping.

### Rejected Candidate: available assumed-role profiles

- Candidate status: rejected for lack of committed sanitized path evidence.
- Available profiles include `serim-dev-admin`, `serim-prod-admin`, `serim2-devengineer`, `serim2-jump`, and `serim2-terraform`.
- Reason rejected: no committed sanitized controlled STS path evidence was found for these assumed-role principals in this slice.

## Selected Candidate

The selected candidate is the `iamscope-admin` denied STS path:

```text
arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin
  -- sts:AssumeRole expected denied -->
arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole
```

Selection rationale:

- The source principal matches a currently available live profile identity from prior discovery.
- The target role exists by safe read-only IAM lookup.
- The predicted behavior is explicit: `denied`.
- Committed sanitized evidence exists and already records the expected/observed denied outcome for this single-case proof.
- The candidate avoids the Env06 profile mismatch that blocked Run #1.

## Identifier Strategy

This candidate has no IAMScope-native `finding_id` or `path_id` available in committed sanitized evidence.

The existing `runtime-sts-denied-single-case-proof` ID is a sanitized proof/report path identifier, not an IAMScope-native finding/path identifier.

A future Controlled STS Run #2 pre-live plan should use a clearly labeled validation-layer ID such as:

`controlled-sts-run-002-iam-admin-arf-rt-devrole-denied`

That ID must not be presented as an IAMScope-native `finding_id` or `path_id`.

## Abort Conditions

Abort any future pre-live or live execution if any of these are true:

- The `iamscope-admin` profile no longer resolves to `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`.
- The target role ARN differs from `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.
- The target role cannot be read by safe IAM lookup immediately before planning.
- The future probe plan contains more than one probe.
- The future probe plan changes expected outcome from `denied` without a new selection review.
- A validation-layer ID is presented as an IAMScope-native `finding_id` or `path_id`.
- The future command would call STS without explicit approval.
- The future command would perform downstream AWS actions, mutate IAM, run Terraform, commit raw artifacts, or commit `/tmp` outputs.

## Evidence Boundary

This slice selects a candidate and records why it is a better live-profile match than Env06 Run #1. It does not create a pre-live plan, execute live validation, run `live_probe`, call STS, or add runtime proof.

The existing sanitized denied proof remains bounded evidence for one historical single-case runtime proof. Selecting it as a future candidate does not expand that evidence into production readiness, broad IAMScope correctness, broad runtime exploitability, downstream authorization proof, or general STS path correctness.

## Non-Claims

This slice does not claim:

- A new live AWS validation was run.
- `sts:AssumeRole` was called.
- `live_probe` was executed.
- Runtime reachability was newly corroborated or refuted.
- The candidate has an IAMScope-native `finding_id` or `path_id`.
- IAMScope is production-ready.
- IAMScope is broadly correct.
- Broad runtime exploitability was shown.
- Downstream authorization was proven.
- The rejected candidates can never be made valid with new setup.

## Recommended Next Slice

Create Controlled STS Run #2 pre-live plan using the selected `iamscope-admin` denied STS path and run dry-run validation/simulation only.

That next slice must still avoid live STS execution unless a later, separate live-approval step explicitly authorizes exactly one `sts:AssumeRole` probe.