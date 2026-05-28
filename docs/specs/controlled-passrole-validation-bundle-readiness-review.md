# Controlled PassRole Validation Bundle Readiness Review

## Purpose

Assess readiness to create a safe bundle of controlled PassRole validation reports generated from sanitized static evidence summaries.

This is a docs/review slice only. It decides whether a future bundle generator is bounded enough to produce `/tmp` or caller-provided artifacts for artifact-safety review.

## Non-Goals

This review is not:

- An implementation.
- Report generation in this PR.
- Live AWS execution.
- `iam:PassRole` execution.
- STS `AssumeRole` execution.
- Service launch for EC2, Lambda, ECS, Glue, or any other service.
- AWS resource creation or modification.
- Raw artifact ingestion.
- Raw `/tmp` output ingestion.
- Committing generated reports by default.
- Production readiness.
- Broad IAMScope correctness.
- Exploitability proof.
- Composite scoring.
- A benchmark framework.
- A CI gate.

## Candidate Bundle Contents

A future safe bundle should be limited to sanitized, validator-checked outputs:

- `corroborated_allowed_static` controlled PassRole validation report JSON.
- `corroborated_denied_static` controlled PassRole validation report JSON.
- `inconclusive_static` controlled PassRole validation report JSON.
- Optional Markdown summary or bundle index.
- Validator output summaries for each generated report.
- Caveat and non-claim file.
- Artifact safety manifest.

The bundle should not include raw AWS artifacts, raw logs, raw scenario/findings/binding/run logs, Terraform state, credentials, or generated reports committed by default.

## Bundle Safety Rules

A future bundle generator must require:

- Generated reports from sanitized summaries only.
- No raw `/tmp` outputs as inputs.
- No raw AWS logs.
- No credentials.
- No credential-shaped fields.
- No Terraform state, cache, or provider artifacts.
- No collect directories.
- No raw scenario, findings, binding metadata, or `run.log` artifacts.
- No composite score.
- No pass/fail labels.
- No vulnerable, exploited, or production-ready labels.
- Validator success before any report is included.

## Bundle Location Policy

A future bundle should be written only to a caller-provided path or to `/tmp` by default.

Generated bundles are not committed by default. Commit a bundle only after a separate artifact inclusion review confirms that the bundle contains safe JSON and Markdown summaries only. If a bundle is ever committed later, it must exclude raw AWS artifacts, credentials, raw logs, raw `/tmp` outputs, Terraform state, collect directories, and unsafe labels.

## Readiness Criteria

The current repo is ready to design a safe bundle generator because:

- The controlled PassRole report generator exists.
- The controlled PassRole report validator exists.
- The generator emits allowed, denied, and inconclusive static reports.
- Generated reports pass the validator.
- The required artifact safety manifest can be defined from existing safety fields and bundle metadata.
- Output can be directed outside the repo by default.
- No raw inputs are required.
- No AWS credentials are required.

Readiness verdict: ready_for_tmp_bundle_generator_design_and_implementation, with generated bundle output restricted to `/tmp` or a caller-provided non-repo path by default.

## Evidence Boundary

A future bundle would prove only that:

- Sanitized PassRole static evidence summaries can be represented as controlled PassRole validation reports.
- Those reports pass schema and safety validation.
- A bundle can preserve non-claims and artifact safety boundaries.

The bundle would not add live runtime evidence.

## Non-Claims

The bundle would not prove:

- Live PassRole validation.
- An `iam:PassRole` call.
- Service launch.
- Downstream authorization.
- A new finding corroborated or refuted beyond the sanitized static summaries.
- Production readiness.
- Broad IAMScope correctness.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.
- All findings verified.

## Recommended Next Slice

Recommend exactly one next slice: implement safe controlled PassRole validation report bundle generator to `/tmp` only.

That next slice should generate the bundle to `/tmp` or a caller-provided path only, not commit generated reports by default. It should not run AWS, call `iam:PassRole`, call STS, launch services, create or modify AWS resources, ingest raw artifacts, add a benchmark framework, add CI gates, add composite scoring, or bundle multiple slices at once.
