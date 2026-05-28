# Local Worktree Hygiene

IAMScope review work should start from the primary clean `main` clone and use
temporary `/tmp` worktrees only for individual PR slices.

## Canonical Layout

- Primary clean clone: `~/src/iamscope`
- Primary branch: `main`
- Temporary PR worktrees: `/tmp/iamscope-*`
- Health-check helper: `scripts/iamscope-sync-health`

Do not treat a detached `/tmp/iamscope-*` worktree as canonical `main`. Temporary
worktrees are disposable PR surfaces and can become stale after a merge.

## Sync Health

Run sync health from the primary clone:

```bash
cd ~/src/iamscope
scripts/iamscope-sync-health
```

The helper refuses to run from a `/tmp/iamscope-*` worktree. It fetches
`origin`, switches the primary clone to `main`, fast-forwards to `origin/main`,
activates `~/src/iamscope/.venv`, and runs the safe local checks:

```bash
./scripts/check.sh
./scripts/test_fast.sh
```

If a personal shell command named `iamscope-sync-health` exists, it should invoke
`~/src/iamscope/scripts/iamscope-sync-health` instead of using a detached
`/tmp` worktree.

## Pre-Review Checklist

Before reviewing a PR, run these checks from the PR worktree:

```bash
git fetch origin
git status --short
git diff origin/main...HEAD --stat
gh pr view
```

Confirm:

- The PR exists.
- The PR branch is the branch being reviewed.
- The PR is not stale relative to `origin/main`.
- The diff is scoped to the requested slice.
- The worktree is clean after committed changes.
- Draft PRs are not merged until intentionally marked ready.

Do not review or merge a branch with no PR, a stale detached worktree, or a diff
that does not match the requested slice.

## Post-Merge Checklist

After a PR merges:

```bash
cd ~/src/iamscope
git fetch origin
git switch main
git merge --ff-only origin/main
source .venv/bin/activate
./scripts/check.sh
./scripts/test_fast.sh
git worktree list
git worktree prune
```

Then remove the merged temporary worktree if it still exists:

```bash
git worktree remove /tmp/iamscope-example-slice
git worktree prune
```

Use the actual merged worktree path. Do not remove `~/src/iamscope`.

## Draft PR Guardrails

- Do not review/merge until a PR exists.
- Draft PRs may be inspected for early scope issues, but should not be merged.
- Mark the PR ready only after validation passes and the worktree is clean.
- Re-run `git diff origin/main...HEAD --stat` after rebasing or syncing.

## Boundaries

These workflow checks are local hygiene only. They do not run live AWS, call STS,
call `iam:PassRole`, call Lambda APIs, create or modify AWS resources, change
IAMScope reasoning behavior, change benchmark semantics, or add validation
evidence.
