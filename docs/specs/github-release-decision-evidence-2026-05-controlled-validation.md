# GitHub Release Decision: `evidence-2026-05-controlled-validation`

## Purpose

This document decides whether IAMScope should create a GitHub release for the existing research/evidence checkpoint tag `evidence-2026-05-controlled-validation`. It is docs/decision only: it does not create a GitHub release, create or move a Git tag, change package metadata, add validation, run live AWS, call STS, generate benchmark outputs, or change IAMScope behavior.

## Current Tag State

- Tag name: `evidence-2026-05-controlled-validation`
- Tagged commit: `158320e`
- Full tagged commit: `158320e1c67711d160af50170c76f332341aa7d5`
- Tag status: already created and pushed.
- GitHub release status: not created yet.
- Release notes source: `docs/releases/research-checkpoint-release-notes.md`.
- Tag/versioning decision source: `docs/specs/release-tag-versioning-decision.md`.
- Final tag readiness check source: `docs/specs/final-tag-readiness-check.md`.

The tag identifies the reviewed research/evidence checkpoint commit. If `main` has advanced beyond the tag, a GitHub release for this tag must describe the tagged checkpoint only and must not imply that later commits are included in the tagged artifact.

## Options

| Option | Visibility | Overclaim Risk | Reviewer Usefulness | Maintenance Expectations | User Expectation Risk | Alignment With Evidence Boundaries |
| --- | --- | --- | --- | --- | --- | --- |
| A. Keep tag only for now | Low; visible to Git users but less discoverable in GitHub UI | Lowest | Moderate for reviewers comfortable with tags | Lowest | Lowest | Compatible, but hides the reviewed release-note boundary |
| B. Create GitHub prerelease from reviewed release notes | Good; visible in GitHub releases while marked as non-final | Low if prerelease and non-claims are prominent | High; gives reviewers one stable landing point | Low to moderate; release text needs careful maintenance | Low to moderate; prerelease reduces product expectation | Strong fit for research/evidence checkpoint framing |
| C. Create normal GitHub release | Highest visibility | High; normal release can imply production or package readiness | High, but misleading for current maturity | Moderate to high | High | Poor fit because current evidence intentionally avoids production-readiness claims |
| D. Defer release until more cleanup | Low now; avoids premature visibility | Low | Low in the near term | Low | Low | Compatible, but less useful after release notes and tag readiness are already reviewed |

## Recommendation

Recommend exactly one option: create a GitHub prerelease from the reviewed release notes.

This recommendation is conditional on preserving the evidence-checkpoint boundary in the release title, body, settings, and attachments. It does not recommend a normal GitHub release, a package release, new validation, more live probes, CI gates, composite scoring, or any broader claim.

## Why Prerelease

A GitHub prerelease is the safest release form for this checkpoint because it:

- Makes the checkpoint visible to reviewers in GitHub's release UI.
- Avoids implying production readiness or package maturity.
- Preserves the research/evidence framing selected by `docs/specs/release-tag-versioning-decision.md`.
- Allows the reviewed release notes to carry the non-claims and artifact boundaries clearly.
- Keeps the existing tag immutable and does not require moving the tag to later documentation commits.

## Release Title

Recommended release title:

`IAMScope evidence checkpoint: controlled validation`

This title is intentionally descriptive and avoids production-release or semantic-version language.

## Release Body Source

Use `docs/releases/research-checkpoint-release-notes.md` as the release body source.

Do not invent broader release claims. If the release body needs small GitHub-formatting adjustments, keep them equivalent to the reviewed release notes and preserve the non-claims, limitations, and artifact exclusions.

## Required Release Settings

If the prerelease is created, use these settings:

- Mark the GitHub release as a prerelease.
- Use tag `evidence-2026-05-controlled-validation`.
- Use title `IAMScope evidence checkpoint: controlled validation`.
- Use `docs/releases/research-checkpoint-release-notes.md` as the release body source.
- Do not attach raw AWS artifacts.
- Do not attach generated controlled STS bundles.
- Do not attach generated PPTX or presentation binaries unless separately reviewed.
- Do not attach `/tmp` outputs.
- Do not attach credentials, credential-shaped values, raw logs, Terraform state, Terraform cache, Terraform plan files, or provider binaries.
- Do not mark the release as latest if GitHub allows avoiding that for prereleases.
- Link to `README.md` and `docs/releases/research-checkpoint-release-notes.md` in the release body.

## Non-Claims Visible In Release

The GitHub prerelease text must visibly state:

- Not production ready.
- No broad IAMScope correctness claim.
- No arbitrary enterprise graph correctness claim.
- No broad exploitability claim.
- No real-world scalability claim.
- No all-findings-verified claim.
- No composite benchmark score.
- No pass/fail benchmark grade.
- No generic resource-policy Deny support claim.
- No finding-level reachability claim.

## Preconditions Before Creating The Release

Before creating the GitHub prerelease, require:

- Confirm the tag exists remotely: `evidence-2026-05-controlled-validation`.
- Confirm the tagged commit is `158320e`.
- Confirm the release notes in `docs/releases/research-checkpoint-release-notes.md` are reviewed.
- Confirm the main/tag context is understood: the release describes the tagged checkpoint, not any later commits that may exist on `main`.
- Confirm the GitHub release will be marked as a prerelease.
- Confirm no raw artifacts are attached.
- Confirm no generated outputs are attached.
- Confirm no credentials, raw logs, Terraform artifacts, `/tmp` outputs, generated bundles, or generated presentation binaries are attached.

## Recommended Next Slice

Recommend exactly one next slice: create GitHub prerelease for `evidence-2026-05-controlled-validation` from reviewed release notes.

That next slice may create the GitHub prerelease, but it must not create a normal release, attach artifacts, add new validation, run live probes, add CI gates, introduce composite scoring, or bundle multiple slices at once.
