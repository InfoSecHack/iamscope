# IAMScope v0.2.38 — lambda/ec2 mode enforcement for wildcard permissions

## Summary

v0.2.38 ships **Reviewer Top 10 #3**: `--lambda-mode=skip` and
`--ec2-mode=skip` now correctly suppress hyperedge emission for
wildcard Lambda and EC2 permissions. Previously these flags were
silently ignored due to a BUG-022 bypass that predated the
per-family mode overrides. Single-file production change in
`iamscope/collector/passrole.py`. Zero fixture regeneration. Zero
collateral on BUG-022 regression tests (22 tests, all passing
unchanged).

## The defect

`_get_expansion_edge_type()` at `passrole.py:397` hardcoded exactly
three return values: `"passrole"` for `iam:PassRole`,
`"assume_role"` for `sts:*` actions, and `"permission"` for
everything else. Lambda (`lambda:InvokeFunction`,
`lambda:CreateFunction`) and EC2 (`ec2:RunInstances`) actions fell
through to the generic `"permission"` bucket.

`_handle_wildcard_resource()` had a BUG-022 early-return at the old
line 155 for `edge_type_key == "permission"` that bypassed expansion
mode checking entirely and went straight to `_build_hyperedge()`.
BUG-022's intent was correct — non-role resources can't meaningfully
expand against `known_role_arns` (zero matches by construction) — but
the fix was too coarse: it bypassed the **mode check** along with the
**expansion matching**. The result: an operator who configured
`lambda_mode="skip"` at the CLI or API level got a hyperedge for
wildcard `lambda:InvokeFunction` regardless. The skip directive was
silently ignored.

`ExpansionController.get_mode()` in
`iamscope/controls/expansion.py` was already correct — it matches
`"lambda"` and `"ec2"` substrings in the `edge_type` string and
returns the per-family override. The bug was entirely upstream: the
caller never passed an `edge_type` string containing those substrings
for wildcard lambda/ec2 permissions.

**Source:** Reviewer Top 10 #3. Reproduced by the reviewer with
`lambda_mode="skip"` + wildcard `lambda:InvokeFunction` → observed
one warn hyperedge where zero edges were expected.

## The fix

Two production-code changes, both in `iamscope/collector/passrole.py`:

### Change 1 — `_get_expansion_edge_type()` extended

Added `"lambda"` for `lambda:*` actions and `"ec2"` for `ec2:*`
actions, inserted before the `"permission"` catch-all. These keys
now match `ExpansionController.get_mode()`'s substring dispatch
correctly. Actions that don't have a per-family override
(secretsmanager, s3, ecs, iam:AddUserToGroup, etc.) still map to
`"permission"` and fall through to `global_mode` as before.

### Change 2 — `_handle_wildcard_resource()` restructured

Mode-checking via `expansion_controller.check_expansion()` now runs
**before** the BUG-022 non-role bypass. The bypass uses a whitelist
pattern (`edge_type_key not in ("passrole", "assume_role")`) rather
than enumerating specific non-role types, which is forward-compatible
with future per-family expansion modes (`secretsmanager_mode`,
`s3_mode`, etc.) without further changes to this function.

Flow after the fix:
1. Get `edge_type_key` — now returns `"lambda"`, `"ec2"`, etc.
2. If non-role target: check mode via `check_expansion(0, key)`. If
   `"skip"` → return empty. Otherwise → hyperedge (BUG-022 intent
   preserved, mode check added).
3. If role target (`passrole` / `assume_role`): filter roles, check
   mode with expansion count, expand or hyperedge per existing logic.

## What didn't change

- **`iamscope/controls/expansion.py`** was not modified.
  `ExpansionController.get_mode()` was already correct; the bug was
  entirely in `passrole.py`'s routing.
- **Zero fixture regeneration.** The hyperedge `edge_type` string is
  built from `pr.action` in `_build_hyperedge()`, not from
  `edge_type_key`, so the routing fix doesn't change any emitted
  edge content — only whether the edge is emitted at all.
- **All 22 existing BUG-022 regression tests pass unchanged.** They
  use `ExpansionController()` with no per-family overrides, so the
  bug's failure mode (per-family skip being ignored) can't manifest.
  Pattern: tests using production-default configurations don't break
  when bugs in override paths get fixed.

## Test additions

Five new tests in `tests/test_expansion_mode_enforcement.py`:

- **Step 0 reproducer:**
  `test_lambda_mode_skip_suppresses_wildcard_invoke_hyperedge` —
  the canonical repro from the reviewer's report.

- **Step 2 reciprocal coverage:**
  - `test_ec2_mode_skip_suppresses_wildcard_runinstances_hyperedge` —
    symmetric partner for EC2 skip mode.
  - `test_lambda_mode_warn_emits_hyperedge_with_suppressed_flag` —
    verifies warn mode still emits a hyperedge with
    `edge.features["suppressed"] == True` and
    `edge.features["expansion_mode"] == "warn"`.
  - `test_ec2_mode_warn_emits_hyperedge_with_suppressed_flag` —
    symmetric partner for EC2 warn mode.
  - `test_lambda_mode_none_falls_through_to_global_skip` —
    verifies that `lambda_mode=None` (no override) correctly falls
    through to `global_mode="skip"`, suppressing the hyperedge.

Combined coverage: explicit per-family skip, per-family warn (with
observability-marker assertions), and fall-through to `global_mode`
when no per-family override is set.

## Test count

v0.2.37 baseline: **1199 tests**. v0.2.38 adds **5 tests** (all in
the new `test_expansion_mode_enforcement.py` file).
**Net: 1204 passing, 0 failing.** Full suite runtime ~42 seconds.

## Known limitations — not addressed in v0.2.38

### From the reviewer's Top 10:
- **#4 Metadata duration** — Session 4 scope.
- **#5 Scan manifest / completeness model** — post-v0.2.39 roadmap.
- **#6 Collector failure handling normalization** — post-v0.2.39.
- **#7 mypy honesty** — Session 4 scope.
- **#8 Concurrency + checkpoint/resume** — post-v0.2.39 roadmap.
- **#9 Reasoner adjacency indexes** — post-v0.2.39 roadmap.
- **#10 Packaging hygiene** — Session 4 scope (includes DRY-ing
  hardcoded `id_algorithm` strings to use `constants.ID_ALGORITHM`).

### From Phase 3 security threats:
- **#3 Plaintext artifact leakage / redacted output modes** —
  post-v0.2.39 roadmap.
- **#4 Enrichment input poisoning / GhostGates provenance** —
  post-v0.2.39 roadmap.
- **#5 Dependency supply chain / SBOM / lockfile** — post-v0.2.39.
- **#6 Reasoner evidence fabrication / taint tracking** —
  post-v0.2.39 roadmap.
