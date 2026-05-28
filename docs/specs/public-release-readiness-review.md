# Public Release Readiness Review

## Purpose

Decide whether IAMScope is ready to be released publicly as a research-preview / evidence-checkpoint tool.

This is a docs/review slice only. It does not make the repository public, create a GitHub release, create or move tags, run live AWS, call `iam:PassRole`, call STS, call Lambda APIs, create or modify AWS resources, generate reports, commit `/tmp` outputs, change implementation, add pass/fail labels, add composite scoring, or broaden IAMScope claims.

## Verdict

Selected verdict: `ready_for_public_research_preview`.

Rationale: the README, `docs/START_HERE.md`, supported/unsupported evidence matrix, release notes, controlled validation checkpoints, and artifact hygiene boundaries now describe IAMScope as a research-preview bounded evidence program. The public-facing docs visibly preserve non-claims and do not require live AWS by default.

This verdict does not mean production readiness or broad correctness.

## Current Evidence Summary

Current public-facing evidence includes:

- Frozen live AWS semantic benchmark layer for selected IAM cases.
- Mutation-pair sensitivity for selected semantic deltas.
- Synthetic scalability/degradation fixtures for controlled analysis.
- Reporting/comparison layer for benchmark summaries.
- Report-only threshold review; no CI gate, pass/fail grade, or composite score.
- Standalone STS denied and assumed runtime proofs.
- Controlled STS Run #1 `environment_mismatch`, blocked before live execution.
- Controlled STS Run #2 denied/access_denied selected-path corroboration.
- PassRole static validation through controlled report/schema validation.
- Active PassRole-to-Lambda service-mediated corroboration for one test-only source, one test-only target role, and one Lambda `CreateFunction` operation; no invocation; cleanup verified.
- Artifact hygiene checks and documented artifact safety boundaries.
- README, `docs/START_HERE.md`, and `docs/specs/supported-unsupported-evidence-matrix.md` for reviewer orientation.

## Public Readiness Checks

| Check | Status | Notes |
| --- | --- | --- |
| README clarity | Ready | README frames IAMScope as research-preview / bounded evidence and links to START_HERE and the evidence matrix. |
| START_HERE clarity | Ready | `docs/START_HERE.md` gives reviewer-safe orientation, safe commands, approval gates, non-claims, and reading order. |
| Evidence matrix clarity | Ready | `docs/specs/supported-unsupported-evidence-matrix.md` separates evidenced, bounded, and unsupported areas. |
| Safe quickstart | Ready | Default public commands are local check/test commands; live AWS is not required by default. |
| Tests green | Ready at review time | `./scripts/test_fast.sh` is expected to pass before merge/tag/visibility changes. |
| Artifact hygiene green | Ready at review time | `./scripts/check.sh` includes artifact hygiene checks. |
| No raw artifacts | Ready | Public docs require no raw AWS artifacts committed or attached. |
| No credentials | Ready | Public docs prohibit committing credentials or credential-shaped values. |
| No `/tmp` outputs | Ready | Generated `/tmp` outputs are not committed by default. |
| No generated bundles attached/committed | Ready | Generated bundles are excluded unless separately reviewed. |
| Live AWS not required by default | Ready | Live AWS, STS probes, `iam:PassRole`, Lambda APIs, and resource mutation require separate approval. |
| Limitations visible | Ready | README, START_HERE, evidence matrix, release notes, and checkpoints make non-claims visible. |

## Public Claim Boundaries

Allowed public framing:

- Research-preview.
- Bounded evidence program.
- Selected AWS IAM escalation patterns.
- Controlled STS and PassRole evidence.
- Artifact-safe benchmark/reporting workflow.
- Evidence checkpoint, not production release.

Forbidden public framing:

- Production ready.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad exploitability.
- Downstream authorization proof.
- All findings verified.
- Real-world scalability.
- Composite benchmark score.
- Pass/fail grade.

## Remaining Limitations

Known limitations remain visible and should not block a research-preview release:

- No production readiness.
- Limited controlled runtime validations.
- No broad resource-policy Deny support.
- No all-findings-verified claim.
- No enterprise-scale live validation.
- No downstream authorization proof.
- No broad condition-key coverage unless explicitly documented.
- No real-world scalability proof.
- No broad IAMScope correctness.
- No broad runtime exploitability.

## Release Mode Recommendation

Recommend exactly one release mode: make public as research preview.

This recommendation is appropriate because the public-facing docs now state the evidence basis and non-claims clearly, artifact safety is documented, live AWS is not required by default, and the release/evidence checkpoint already exists.

This recommendation does not authorize changing repository visibility in this slice. Visibility change requires a separate checklist and explicit operator action.

## Required Final Pre-Public Actions

Before any actual visibility change:

- Sync `main`.
- Run `./scripts/check.sh`.
- Run `./scripts/test_fast.sh`.
- Confirm `git status` is clean.
- Confirm no raw artifacts or credentials are staged or committed.
- Confirm no `/tmp` outputs are staged or committed.
- Confirm no generated bundles, ZIP files, or raw logs are attached.
- Confirm GitHub visibility change is intended.
- Optionally verify the existing research/evidence prerelease page.
- Do not attach artifacts by default.

## What Should Wait Until After Public Release

These can wait until after the research-preview public release:

- `SECURITY.md`.
- `CONTRIBUTING.md` refresh.
- Issue templates.
- Roadmap.
- More controlled validations.
- Deny, stale-principal, and cross-account evidence expansion.
- Additional release automation.
- CI gates, if ever separately designed without pass/fail evidence inflation.

## Blockers

No public-release blockers are identified for research-preview visibility, assuming the final pre-public actions pass and the visibility change is explicitly intended.

This is not a statement that IAMScope is production ready.

## Recommended Next Slice

Recommend exactly one next slice: public visibility change readiness checklist.

That next slice should still be docs/checklist or operational checklist only. It should not perform the visibility change unless separately approved, and it must not recommend more live validation before public release, production testing, a new benchmark framework, CI gates, composite scoring, or multiple slices at once.