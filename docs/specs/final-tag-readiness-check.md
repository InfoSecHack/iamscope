# Final Tag Readiness Check

## Purpose

This document records the final docs/check readiness review before creating the IAMScope research/evidence checkpoint Git tag. It does not create a Git tag, create a GitHub release, change package metadata, add validation scope, run live AWS, call STS, generate benchmark outputs, or change IAMScope behavior.

## Selected Tag Name

The selected tag name is read from `docs/specs/release-tag-versioning-decision.md`:

- Selected tag name: `evidence-2026-05-controlled-validation`
- Selected tag type: research/evidence checkpoint tag
- Production-release status: not a production release tag

## Release Notes Check

`docs/releases/research-checkpoint-release-notes.md` exists and matches the selected tag decision:

- It uses `evidence-2026-05-controlled-validation` as the proposed tag name.
- It frames the release type as a research/evidence checkpoint.
- It states that no Git tag or GitHub release is created by the release-notes document.
- It keeps release-note claims bounded to the current benchmark, runtime proof, controlled-validation, README, documentation, and artifact-hygiene evidence package.
- It excludes raw AWS artifacts, credentials, `/tmp` outputs, Terraform state/cache/provider artifacts, raw live logs, generated controlled STS bundles, and generated presentation binaries unless separately sanitized and reviewed.

## README And Release Framing Check

`README.md` contains the merged research-facing framing. It presents IAMScope as a bounded evidence program for cloud IAM reasoning, not as a production-ready oracle. The README makes the following boundaries visible:

- The benchmark evidence is bounded to named, controlled cases.
- Runtime STS proof and controlled validation are complete for the current scope.
- Live AWS collection or STS probes are not part of the default quickstart and require separate protocol, explicit scope, and operator approval.
- IAMScope does not claim production readiness, broad correctness, arbitrary enterprise graph correctness, broad runtime exploitability, real-world scalability, all-findings verification, or a composite benchmark score.

## Validation State

At this readiness-check slice:

- `./scripts/check.sh` passed.
- `./scripts/test_fast.sh` passed.
- `git status` was clean before authoring this docs/check slice, and actual tag creation must again confirm a clean worktree after this readiness document is merged.

## Artifact Hygiene Check

This readiness check confirms the release/tag boundary remains artifact-safe:

- No raw AWS artifacts are intentionally included in the release-facing package.
- No credentials, tokens, or credential-shaped values should be staged or tagged as generated evidence.
- No `/tmp` outputs should be committed or tagged as generated outputs.
- No Terraform state, cache, plan, or provider artifacts should be committed.
- Generated controlled STS bundles are not committed by default.
- Raw live logs are excluded unless separately sanitized and reviewed.
- No composite score is introduced.
- No pass/fail benchmark label is introduced.

## Tag Meaning

The tag `evidence-2026-05-controlled-validation` would mean:

- A research/evidence checkpoint for IAMScope's bounded current evidence package.
- A stable reviewer reference for the current benchmark/runtime/controlled-validation milestone.
- The research-facing README, release hygiene checkpoint, release notes, and related documentation were prepared for this evidence checkpoint.
- `./scripts/check.sh`, `./scripts/test_fast.sh`, and artifact hygiene were green at tag-readiness time.

## Tag Non-Meaning

The tag would not mean:

- Production ready.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Real-world scalability.
- All findings verified.
- CI threshold gate validity.
- Generic resource-policy Deny support.
- Finding-level reachability.

## Preconditions Before Actual Tag Creation

Before creating the tag, the tag-execution slice must verify:

- `main` is synced to the intended checkpoint commit.
- `./scripts/check.sh` passed.
- `./scripts/test_fast.sh` passed.
- `git status` is clean.
- Tag name is confirmed as `evidence-2026-05-controlled-validation`.
- `docs/releases/research-checkpoint-release-notes.md` is reviewed and approved.
- No raw artifacts are staged.
- No credentials or credential-shaped values are staged.
- No generated outputs are staged.
- No Terraform state/cache/provider artifacts are staged.

## Readiness Verdict

`ready_for_research_evidence_checkpoint_tag_after_merge`

This verdict is narrow: the repository is ready for a separate tag-execution slice after this readiness check is reviewed and merged. It does not authorize a GitHub release, new validation, live AWS, STS calls, CI gates, composite scoring, or broader claims.

## Recommended Next Slice

Recommend exactly one next slice: create research/evidence checkpoint Git tag.

That next slice may create the Git tag `evidence-2026-05-controlled-validation`, but it must not create a GitHub release unless separately approved. It should not add new validation, run live probes, add CI gates, introduce composite scoring, or bundle multiple phases at once.
