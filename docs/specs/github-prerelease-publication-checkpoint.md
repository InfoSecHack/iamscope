# GitHub Prerelease Publication Checkpoint

## Purpose

This document records that the IAMScope research/evidence checkpoint GitHub prerelease was published for the existing tag `evidence-2026-05-controlled-validation`. It is docs/checkpoint only: it does not create another GitHub release, move or recreate the tag, attach artifacts, add validation, run live AWS, call STS, generate benchmark outputs, or change IAMScope behavior.

## Published Release Metadata

- Tag name: `evidence-2026-05-controlled-validation`
- Release name: `IAMScope evidence checkpoint: controlled validation`
- Release URL: `https://github.com/InfoSecHack/iamscope/releases/tag/evidence-2026-05-controlled-validation`
- Prerelease status: `true`
- Draft status: `false`
- Created at: `2026-05-19T01:38:46Z`
- Artifact attachment status: no artifacts attached

## What The Release Means

The published GitHub prerelease means:

- A research/evidence checkpoint is visible in GitHub Releases.
- The release is tied to the existing `evidence-2026-05-controlled-validation` tag.
- The release represents a bounded benchmark/runtime/controlled-validation milestone.
- The reviewed release notes were used as the evidence-bound release text.
- The Git tag was already created and pushed before the GitHub prerelease publication.

## What The Release Does Not Mean

The published GitHub prerelease does not mean:

- Production ready.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Real-world scalability.
- All findings verified.
- A composite benchmark score.
- A pass/fail benchmark grade.
- Generic resource-policy Deny support.
- Finding-level reachability.

## Artifact Safety

The published GitHub prerelease preserved the artifact boundary:

- No raw AWS artifacts were attached.
- No credentials, tokens, or credential-shaped values were attached.
- No `/tmp` outputs were attached.
- No generated controlled STS bundles were attached.
- No PPTX or generated presentation binaries were attached.
- No Terraform state/cache/provider artifacts were attached.
- No raw live logs were attached.

## Verification

`gh release view evidence-2026-05-controlled-validation --json tagName,name,url,isPrerelease,isDraft,createdAt,assets` confirmed:

- `isPrerelease=true`
- `isDraft=false`
- `tagName=evidence-2026-05-controlled-validation`
- `url=https://github.com/InfoSecHack/iamscope/releases/tag/evidence-2026-05-controlled-validation`
- `assets=[]`

## Recommended Next Phase

Recommend exactly one next phase: post-release cleanup / stale worktree hygiene.

That phase should be hygiene/review oriented. It should not add new validation, run live probes, create a new benchmark framework, add CI gates, introduce composite scoring, create another release, or bundle multiple phases at once.
