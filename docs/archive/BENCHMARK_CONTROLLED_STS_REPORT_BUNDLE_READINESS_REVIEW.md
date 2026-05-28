# Benchmark Controlled STS Report Bundle Readiness Review

## 1. Purpose

This review assesses whether IAMScope is ready to create a safe bundle of
controlled STS validation reports generated from the sanitized denied and
assumed STS proof summaries.

The review is docs-only. It does not generate reports, run live AWS, call STS
AssumeRole, ingest raw artifacts, or implement bundle generation.

## 2. Non-Goals

This review is not:

- Implementation.
- Report generation in this PR.
- Live AWS execution.
- STS execution.
- Raw artifact ingestion.
- Committing generated reports by default.
- Production readiness evidence.
- Broad correctness evidence.
- Exploitability proof.
- Composite scoring.

It also does not add Terraform, fixtures, CI gates, pass/fail benchmark labels,
controlled validation execution, generator logic changes, validator logic
changes, executor changes, collector changes, reasoner changes, scorer changes,
scenario-validation changes, threshold changes, comparator changes, reporting
changes, or harness changes.

## 3. Candidate Bundle Contents

The candidate bundle should be small and explicitly safe.

| Candidate | Readiness | Safe Use | Caveat |
| --- | --- | --- | --- |
| Denied controlled STS validation report JSON | Ready to generate outside repo by default | Represents the sanitized denied proof summary in validator-compatible JSON | Does not add new runtime evidence |
| Assumed controlled STS validation report JSON | Ready to generate outside repo by default | Represents the sanitized assumed proof summary in validator-compatible JSON | `credentials_obtained=true` is boolean only |
| Markdown summary or index | Useful | Explains files, source summaries, caveats, and non-claims | Must not include raw proof outputs |
| Validator output summaries | Useful | Shows generated reports passed schema/safety validation | Should be generated from safe reports only |
| Caveat/non-claim file | Useful | Keeps evidence boundaries visible for demos/reviewers | Must avoid marketing or production-readiness framing |
| Artifact safety manifest | Required before inclusion | Documents no raw artifacts, no credentials, and no generated reports committed by default | Must be reviewed before any committed bundle |

The candidate bundle is ready to design, not ready to commit by default.

## 4. Bundle Safety Rules

Any future bundle must follow these rules:

- Generate only from already-sanitized committed summaries.
- Do not read raw `/tmp` proof outputs.
- Do not include raw AWS logs.
- Do not include credentials.
- Do not include credential-shaped fields.
- Do not include Terraform state.
- Do not include collect directories.
- Do not include raw `scenario.json`, `findings.json`,
  `binding_metadata.json`, or `run.log`.
- Do not include composite scores.
- Do not include pass/fail labels.
- Require validator success before any report is considered for inclusion.

## 5. Bundle Location Policy

The safest default is to generate the bundle to `/tmp` or another
caller-provided path outside the repository.

Generated bundle contents should not be committed by default. A future commit of
any generated bundle should require a separate artifact inclusion review. If any
bundle artifact is later committed, it should be limited to safe JSON and
Markdown summaries that have passed explicit artifact-safety review.

## 6. Readiness Criteria

The project is ready to design a bundle generator because:

- The controlled STS validation report generator exists.
- The controlled STS validation report validator exists.
- The generator supports the `denied` and `assumed` sanitized-summary cases.
- Generated `denied` and `assumed` reports pass the validator.
- No raw inputs are required.
- No AWS credentials are required.
- Output paths are caller-provided and outside the repository by default.

Before generating a bundle, the next slice should define:

- Artifact safety manifest fields.
- Bundle index or summary shape.
- Output directory policy.
- Validator invocation expectations.
- Required caveats and non-claims.

## 7. Evidence Boundary

A future safe bundle would prove only:

- Sanitized denied and assumed runtime proof summaries can be represented as
  controlled STS validation reports.
- Those reports pass schema and safety validation.
- The bundle preserves non-claims and artifact safety boundaries.

It should not be interpreted as new runtime evidence.

## 8. Non-Claims

This readiness review does not claim:

- New runtime validation.
- A new STS call.
- A new finding corroborated or refuted beyond existing summaries.
- Production readiness.
- Broad IAMScope correctness.
- Downstream authorization proof.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.

## 9. Readiness Verdict

Verdict: `ready_to_design_tmp_only_bundle_generator`.

Rationale:

- The generator and validator are already merged.
- Denied and assumed report generation is already supported.
- Generated reports pass schema and safety validation.
- The remaining risk is artifact handling, not evidence generation.

The project is not ready to commit generated report bundles by default.

## 10. Recommended Next Slice

Recommended next slice:

`implement safe controlled STS validation report bundle generator to /tmp only`

That next slice should generate the bundle to `/tmp` or another caller-provided
path only. It should not commit generated reports by default.

Do not recommend:

- Committing the generated bundle by default.
- Live validation execution.
- Raw artifact ingestion.
- A new benchmark framework.
- CI gates.
- Composite scoring.
- Multiple slices at once.
