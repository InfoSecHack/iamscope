# IAMScope v0.2.36 — Fix A changelog

## Summary

v0.2.36 lands **Fix A** from the Tier 1 external security review: the
scenario validator can no longer be bypassed by a tampered
`scenario.json` with a plausible-looking but fabricated canonical hash,
and can no longer silently accept edges whose `src`/`dst` endpoints
don't resolve to real nodes. The external reviewer flagged validator
trust as **HIGHEST PRIORITY** because every downstream consumer of
`iamscope validate` ultimately relies on the validator to answer the
question "is this scenario intact and un-tampered?" — prior to v0.2.36
that answer was unsound.

## The three changes (listed in dependency order)

### Change 1 — Pipeline symmetric dangling-endpoint materialization

`iamscope/pipeline.py`: the helper formerly named
`_materialize_dangling_targets` has been renamed to
`_materialize_dangling_endpoints` and extended to loop both
`e.src` and `e.dst` in a single pass. A synthetic placeholder Node
is emitted for every unique `(provider, node_type, provider_id)`
endpoint that isn't already in the collected node set, whether that
endpoint is a src or a dst.

Placeholder nodes carry distinct `dangling_reason` strings so an
operator can tell the two drift patterns apart:

- **dst case** (BUG-023, unchanged semantics): "referenced by IAM
  policy but not returned by collection — may be a restricted
  resource (e.g. rds! SecretsManager secrets), in an unscanned
  region, in another account, or deleted"
- **src case** (new in Fix A): "principal named in a trust policy
  but not resolvable — may be a deleted or renamed same-account
  IAM role/user, a not-yet-created principal mid-Terraform-apply,
  or eventual-consistency drift between Organizations and IAM"

**Why this change is listed first, even though it wasn't in the
original Fix A patch:** the Session 1 Step 0 synthetic-src grep
identified Change 1 as a **necessary prerequisite** to Changes 2
and 3. Without it, Change 3 (rule 8b — edge src/dst referential
integrity) would have rejected every realistic trust-edge scenario
where a customer environment has stale same-account principal
references — a routine drift pattern in real AWS estates. The
gap traced back to `cross_account._create_synthetic_node`
(iamscope/resolver/cross_account.py:156-171), which returns
`None` for same-account IAMRole/IAMUser principals on the
assumption that the IAM collector will supply the real node.
When a trust policy references a deleted, renamed, or
not-yet-created same-account role, that assumption silently
breaks — and before Fix A, the validator never noticed because
it only checked dst. Shipping Changes 2 and 3 without Change 1
would have regressed v0.2.35 scans that worked today.

Touched files:
- `iamscope/pipeline.py` — function rename, body extension, call
  site update, Phase 3.5 comment update, docstring fixes
- `tests/test_bug023_dangling_targets.py` — 9 call sites renamed,
  module-level docstring updated
- `tests/test_secrets_blast_radius_reasoner.py` — one docstring
  reference updated for consistency

### Change 2 — Validator canonical hash recomputation

`iamscope/validate.py` rule 8: pre-fix, the validator only checked
that `metadata.canonical_hash` was shaped like a 64-character SHA-256
hex string. It never recomputed the hash from the content, so a
scenario.json with a plausible but fabricated hash field passed
validation cleanly. Any attacker or buggy tool that handed out a
modified scenario could forge a PASS from `iamscope validate`.

Post-fix, rule 8 recomputes the canonical hash using the exact
same payload shape as `iamscope.output.scenario_json.emit_scenario`
(lines 124-134) and rejects any mismatch. A clean scenario
round-trips `emit_scenario` → `validate_scenario` with zero errors;
a tampered scenario fails with a clear error message comparing the
claimed hash against the content-derived hash.

### Change 3 — Validator edge src/dst referential integrity

`iamscope/validate.py` rule 8b: pre-fix, the validator never checked
that an edge's `src` and `dst` `provider_id` fields actually
resolved to real nodes in the `nodes` list. A scenario with a
dangling endpoint passed validation, and downstream reasoners
crashed or produced wrong answers.

Post-fix, rule 8b builds a `(provider, node_type, provider_id)`
lookup set from the nodes list and verifies every edge endpoint is
in it. Error messages report the `edge_id` (not the list index) so
operators triaging a failed scan can grep the scenario.json directly
for the offender — list indices shift whenever edge order changes
and make the error message useless for root-cause work.

Also hardened in this rule: defensive handling of non-dict `src` or
`dst` fields. A tampered or hand-edited scenario may have
`src = "some-string"`; the validator's job is to report that as a
rule 5 error and keep going, never to crash with an AttributeError
from calling `.get()` on a string. Covered by
`TestValidatorErrorMessageConventions::test_malformed_non_dict_src_returns_errors_not_raises`.

## Test count reconciliation

v0.2.35 baseline was **1186 tests** (captured at
`~/projects/baseline-v0_2_35-pytest.log`). v0.2.36 adds **9 new tests**
and rewrites **3 legacy tests** that pinned the pre-Fix-A broken
behavior (they hand-crafted scenario dicts with fabricated hashes and
dangling src/dst endpoints — the exact tamper pattern Change 2 and
Change 3 now correctly reject). The 3 rewrites stay net-zero: they
were passing in the baseline and they pass after rewriting, they just
now build scenarios via `emit_scenario()` so they exercise the real
valid-scenario codepath.

**Net: 1195 passing, 0 failing.**

The 9 new tests break down as:

- **4 Fix A validator integrity tests** (from the Tier 1 security
  review, delivered verbatim from the `fix-a-patch` bundle):
  `tests/test_validate_fix_a.py::TestFixAValidate` — clean scenario
  validates, dst-missing-node rejected, fabricated-hash rejected,
  stale-hash-with-modified-content rejected.

- **3 dangling-src pipeline materialization regression tests**
  (Session 1 addition — Change 1 guard), split one per behavior
  claim so a future regression gives an immediately-localized failure
  message instead of a generic "the pipeline test failed somewhere":
  `tests/test_validate_fix_a.py::TestDanglingSrcMaterialization::test_materializes_synthetic_for_dangling_src`
  (synthetic-node-properties),
  `::test_src_dangling_reason_mentions_trust_case` (dangling_reason-wording),
  `::test_emitted_scenario_validates_clean` (end-to-end-clean-scenario-validates).

- **2 validator hardening tests** (Session 1 addition — operator-facing
  quality fixes from private agent context Step 5):
  `tests/test_validate_fix_a.py::TestValidatorErrorMessageConventions::test_malformed_non_dict_src_returns_errors_not_raises`
  (validator returns errors rather than raising AttributeError on
  tampered non-dict endpoints) and
  `::test_rule_8b_error_message_includes_edge_id` (rule 8b errors
  carry `edge_id` rather than list index).

Full suite runtime: ~43 seconds (v0.2.35 baseline was ~48 seconds, so
no meaningful regression).

## Session 1 process notes

This changelog was written BEFORE the release zip was built, per the
"never ship broken, write the changelog first" project discipline
recorded in private agent context. The Step 0 synthetic-src grep was performed
before any code was edited, the findings were reviewed by the operator
before proceeding, and every batch of edits was independently verified
by the operator running `git diff` in a second terminal. The three
changes shipped in a single zip as a single commit tagged `v0.2.36`
— one session, one zip, one changelog entry, per the project's
release discipline.

## Credit

Validator trust was flagged as **HIGHEST PRIORITY** by the external
Tier 1 security reviewer whose review triggered this session. Changes
2 and 3 implement the exact fix they asked for. Change 1 is a
Session 1 addition identified by the synthetic-src grep required to
ship Changes 2 and 3 without regressing stale-trust scans — it's the
architectural corollary that the reviewer's audit scope didn't
explicitly cover, but that the fix-forward work made visible.
