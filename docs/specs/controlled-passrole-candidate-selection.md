# Controlled PassRole Candidate Selection

## Purpose

Select one controlled PassRole validation candidate that matches currently available live AWS profiles and committed sanitized evidence, or explicitly conclude that no candidate is ready.

This is a planning/inspection slice only. It does not call `iam:PassRole`, run live validation, launch services, create or modify AWS resources, run Terraform, mutate IAM, or change IAMScope behavior.

## Current Live Profile Identity Mapping

This slice did not rerun live AWS identity checks because the previous controlled validation profile mapping is already committed and sufficient for selection triage.

Known profile identities from committed planning/checkpoint docs:

| Profile | Known identity |
| --- | --- |
| `iamscope-test` | `arn:aws:iam::516525145310:user/iamscope-verify` |
| `iamscope-admin` | `arn:aws:iam::516525145310:user/iamscope-admin` |
| `serim-dev-admin` | assumed `OrganizationAccountAccessRole` in account `377114445031` |
| `serim-prod-admin` / `serim2-*` profiles | assumed roles in account `737923406074` |

Sources: `docs/specs/controlled-sts-live-profile-path-selection.md`, `docs/specs/controlled-sts-run-001-env-mismatch.md`, and `docs/specs/controlled-sts-run-002-prelive-plan.md`.

## Sanitized Evidence Searched

Committed sanitized evidence and metadata searched for PassRole candidates:

- `benchmarks/cases/env18_lambda_passrole_validated.json`
- `benchmarks/cases/env20_ecs_passrole_validated.json`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/run_manifest.json`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/run_manifest.json`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/report.md`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/report.md`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/scorer_result.json`
- `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/scorer_result.json`
- `acceptance/env18_lambda_passrole_validated/expected_findings.json`
- `acceptance/env20_ecs_passrole_validated/expected_findings.json`
- Repository-wide text search for `PassRole`, `iam:PassRole`, `passrole_lambda`, `passrole_ecs`, `iamscope-admin`, and `iamscope-verify`.

No raw AWS artifacts, raw `/tmp` outputs, raw scenario JSON, raw findings JSON, raw binding metadata, or run logs were inspected.

## Candidates Considered

### Env18 Lambda PassRole Validated

- Environment: `env18_lambda_passrole_validated`.
- Source principal ARN: `arn:aws:iam::516525145310:user/iamscope-test/env18-alice`.
- Target role ARN: `arn:aws:iam::516525145310:role/iamscope-test/env18-lambda-admin-exec`.
- Service principal: `lambda.amazonaws.com`.
- Expected account ID: `516525145310`.
- Predicted behavior: `allowed` / validated `passrole_lambda` from sanitized benchmark evidence.
- Evidence source documents:
  - `benchmarks/cases/env18_lambda_passrole_validated.json`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/run_manifest.json`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/report.md`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env18-24940398230/scorer_result.json`
  - `acceptance/env18_lambda_passrole_validated/expected_findings.json`
- Native finding ID/path ID: unavailable from committed sanitized evidence inspected here.
- Validation-layer ID strategy if this were ever selected: use a clearly labeled deterministic validation-layer ID, not an IAMScope-native finding/path ID.
- Candidate status: not selected because the source principal does not match any currently available live profile identity. Known `iamscope-test` resolves to `arn:aws:iam::516525145310:user/iamscope-verify`, not `env18-alice`.

### Env20 ECS PassRole Validated

- Environment: `env20_ecs_passrole_validated`.
- Source principal ARN: `arn:aws:iam::516525145310:user/iamscope-test/env20-alice`.
- Target role ARN: `arn:aws:iam::516525145310:role/iamscope-test/env20-ecs-admin-task`.
- Service principal: `ecs-tasks.amazonaws.com`.
- Expected account ID: `516525145310`.
- Predicted behavior: `allowed` / validated `passrole_ecs` from sanitized benchmark evidence.
- Evidence source documents:
  - `benchmarks/cases/env20_ecs_passrole_validated.json`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/run_manifest.json`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/report.md`
  - `benchmarks/snapshots/phase0-20260506-env23/runs/env20-24940398230/scorer_result.json`
  - `acceptance/env20_ecs_passrole_validated/expected_findings.json`
- Native finding ID/path ID: unavailable from committed sanitized evidence inspected here.
- Validation-layer ID strategy if this were ever selected: use a clearly labeled deterministic validation-layer ID, not an IAMScope-native finding/path ID.
- Candidate status: not selected because the source principal does not match any currently available live profile identity. Known `iamscope-test` resolves to `arn:aws:iam::516525145310:user/iamscope-verify`, not `env20-alice`.

## Selected Candidate

No controlled PassRole validation candidate is selected in this slice.

No committed sanitized PassRole evidence was found where the source principal exactly matches a currently available live profile identity. The strongest committed PassRole evidence is Env18/Env20, but both use environment-specific Alice principals rather than `iamscope-admin`, `iamscope-verify`, or the known assumed-role profiles.

## Read-Only Checks Performed

No AWS read-only IAM checks were performed in this slice.

Reason: the candidate selection failed at the source-principal matching step. Checking target role existence would not make Env18 or Env20 suitable for live-profile-matched controlled validation because the available live profile identities do not match the source principals in committed sanitized PassRole evidence.

## Abort Conditions

Controlled PassRole pre-live planning remains blocked until at least one of these becomes true:

- A current live profile resolves to the exact Env18 source principal `arn:aws:iam::516525145310:user/iamscope-test/env18-alice`.
- A current live profile resolves to the exact Env20 source principal `arn:aws:iam::516525145310:user/iamscope-test/env20-alice`.
- New committed sanitized evidence identifies a PassRole path involving an existing live profile identity such as `iamscope-admin` or `iamscope-verify`.
- A minimal test-only controlled PassRole setup is designed and reviewed for current live profiles.

Do not proceed to pre-live or live PassRole validation from this slice.

## Evidence Boundary

This slice proves only that committed sanitized PassRole evidence was inspected for source-principal overlap with known live profiles and that no ready live-profile-matched candidate was found.

It does not invalidate Env18 or Env20. Those benchmarks remain useful sanitized evidence for IAMScope PassRole reasoning, but they do not currently map to an available live AWS profile for controlled PassRole validation.

## Non-Claims

This slice does not claim:

- Live PassRole validation.
- An `iam:PassRole` call.
- Service launch.
- AWS resource creation or modification.
- Downstream authorization proof.
- Any new finding corroborated or refuted.
- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Real-world scalability.

## Readiness for Pre-Live Plan

Readiness for Controlled PassRole pre-live plan: no.

Reason: no selected candidate has exact source-principal alignment between committed sanitized PassRole evidence and currently available live profile identities.

## Recommended Next Slice

Recommend exactly one next slice: design minimal test-only controlled PassRole setup.

That next slice should be design-only and should define how to create or map one current live profile to one controlled PassRole path without live execution, service launch, raw artifact ingestion, CI gates, composite scoring, or broad claims.
