# IAMScope v0.2.37 — edge_id uniqueness + canonicalization extraction

## Summary

v0.2.37 ships **Reviewer Top 10 #2** (edge identity redesign) and
the **canonicalization infrastructure extraction** that the fix
depends on. Two semantically different edges between the same
principals — for example, an MFA-conditioned trust and an
unconditioned trust — can no longer collide on a single `edge_id`.
The downstream corruption vector where the pipeline's
`seen_edge_ids` dedup silently dropped one of two colliding edges
is now structurally eliminated.

The canonicalization extraction (`iamscope.identity.canonical`)
is the architectural investment that makes the fix possible without
introducing a second canonicalization path. Having one canonicalizer
in the codebase eliminates a class of silent correctness bugs where
two independent canonicalizer definitions could drift apart across
future versions — a drift-landmine the design report identified as
the single most important thing to avoid in a security tool where
`iamscope validate` is a PASS/FAIL trust gate.

## The three changes (listed in dependency order)

### Change 1 — Canonicalization extraction to `iamscope.identity.canonical`

New module `iamscope/identity/canonical.py` housing `canonical_json_bytes`
and `compute_hash` as **public API**. These functions were previously
duplicated as private copies (`_canonical_json_bytes`, `_compute_hash`)
in two separate modules:

- `iamscope/output/scenario_json.py` — the original definition
- `iamscope/output/findings_json.py` — a copy with a docstring
  comment at line 248 that literally said *"Mirrors
  `scenario_json._canonical_json_bytes` exactly so that the
  canonical-JSON convention is consistent across all sidecar files"*

That comment was the drift-landmine documented in the Session 2
design report's Finding 3 — two independent canonicalizer definitions
with a prose assertion that they should match and zero tooling
enforcing the match. The extraction eliminates the entire class of
bug by making it structurally impossible: every consumer now imports
from the same module.

Three consumers migrated in a single atomic sub-step (Step 1b):
- `iamscope/output/scenario_json.py` — local defs deleted, imports
  from `canonical.py`
- `iamscope/output/findings_json.py` — local defs deleted, imports
  from `canonical.py`; the "Mirrors..." docstring removed as it
  documented a risk the extraction eliminates
- `iamscope/validate.py` — Session 1's hoisted cross-layer import
  (`from iamscope.output.scenario_json import _canonical_json_bytes`)
  replaced with a clean same-layer import from `canonical.py`

The `findings_json.py` dual-canonicalizer was a **bonus discovery**
caught by a syntactic grep at the start of Step 1b that the original
design report hadn't anticipated. The design report's Finding 1 grep
focused on edge_id producers and missed canonicalizer consumers
outside `scenario_json.py`. The lesson — syntactic greps over the
full codebase before any rename or signature change, not semantic
greps scoped to where callers "should" be — is documented in private agent context
as a process note for future sessions.

### Change 2 — Edge identity redesign: features included in `edge_id` hash

`Edge.edge_id` now incorporates
`canonical_json_bytes(features).decode("utf-8")` as a **required
fifth input** to the `edge_id()` hashing primitive in
`iamscope/identity/deterministic_ids.py`.

**Before (v1):** `edge_id = sha256(edge_type \0 src_provider_id \0
dst_provider_id \0 region)` — features were computed but never fed
to the ID function.

**After (v2):** `edge_id = sha256(edge_type \0 src_provider_id \0
dst_provider_id \0 region \0 features_digest)` where
`features_digest` is the canonical JSON encoding of the entire
features dict.

The v1 formula allowed two semantically different edges between the
same principals to share the same `edge_id`. The reviewer reproduced
this with an MFA-conditioned trust edge vs an unconditioned one
between the same src/dst — both got identical `edge_id` values. The
pipeline-level `seen_edge_ids` dedup at `pipeline.py:660-666` then
silently dropped one of the two, and the surviving edge's
`features.has_mfa_condition` depended on statement-index iteration
order within the role's trust policy. In the worst case the MFA
protection evaporated from the fact graph entirely, causing
downstream reasoner findings to report naked trust where MFA-gated
trust existed.

**Source:** Reviewer Top 10 #2.

### Change 3 — Algorithm version bump: `sha256_null_separated_v1` → `sha256_null_separated_v2`

The `id_algorithm` metadata field in `ScenarioMetadata` and the
constant `ID_ALGORITHM` in `iamscope/constants.py` are bumped from
`sha256_null_separated_v1` to `sha256_null_separated_v2`.

**Migration contract for downstream consumers:**
- v1 and v2 scenarios are NOT edge-id-comparable. A v1 scenario's
  `edge_id` values cannot be correlated to a v2 scenario's for the
  same logical edges — the hash inputs differ.
- The `id_algorithm` metadata field documents which formula produced
  the IDs. Consumers should gate any edge-id comparison on equality
  of the `id_algorithm` field.
- `node_id` and `constraint_id` formulas are **unchanged** between
  v1 and v2 — only `edge_id` gained the `features_digest` field.

Updated in: `iamscope/constants.py`, `iamscope/models.py`
(ScenarioMetadata default), `iamscope/pipeline.py` (runtime
construction), `iamscope/identity/deterministic_ids.py` (module
docstring), `README.md` (example scenario), plus 7 test files that
constructed `ScenarioMetadata` with hardcoded v1 strings.

## Fixture regeneration

42 golden fixtures under `tests/fixtures/expected_output/` were
regenerated atomically with the algorithm bump. Edge_id changes
cascade into `canonical_hash`, `finding_id`, and
`evidence_bundle_digest`, so every fixture's hash values shifted
even for zero-findings fixtures (because `id_algorithm` is inside
the findings hash payload).

**Phase B** (2 non-harnessed scenario fixtures): regenerated via
Python one-liner executing the test files' inline construction code.
`scp_binding_scenario.json`'s edges list reordered because the new
v2 edge_ids sort in different lexicographic order than v1; structural
verification confirmed content preservation via tuple-matching.
`minimal_scenario.json` did not reorder. Both test files'
`PINNED_CANONICAL_HASH` and `PINNED_FILE_HASH` constants updated to
v2 values.

**Phase A** (40 findings fixtures via `_REGEN` toggle): all 40
regenerated via `test_golden_findings.py`'s built-in `_REGEN=True`
harness. Identity-tuple structural verification confirmed no content
drift across all 40 fixtures. 2 of 37 multi-finding fixtures (both
in `admin_reachability/`) reordered at the findings-list level due to
`finding_id` cascading from `evidence_bundle_digest` which cascades
from `edge_id`.

**Structural verification scaffolding** surfaced four classes of
embedded-hash references that needed cascade-handling during Phase A:
1. `blockers_observed[*].edge_id` — explicit `edge_id` field inside
   blocker entries
2. `required_checks[*].reason` — reasoner prose interpolating
   edge_ids into human-readable check rationale
3. `reasoning_trace[*].reason` — same pattern inside trace entries
4. Truncated 12-char hex prefix with `U+2026` horizontal ellipsis in
   `iam_group_membership_escalation` reasoner prose (e.g.,
   `"witness edge 3f017b22b204…"`)

The final verifier handles all four via regex hash masking
(`\b[0-9a-f]{64}\b|[0-9a-f]{8,}(?:\u2026|\.{3})`) before structural
comparison.

## Test count

v0.2.36 baseline: **1195 tests** (from Session 1 closeout).
v0.2.37 adds **4 tests**:
- 1 reproducer (`TestEdgeIdFeatureCollision::test_mfa_and_unconditioned_trust_edges_have_distinct_ids`)
  — pins the v1 collision bug; now passes under v2
- 3 determinism checks (`TestEdgeIdDeterminism`) — same-features-same-id,
  feature-key-order-independent, nested-feature-order-independent

42 fixtures regenerated without changing their test count (same
number of test methods, only the on-disk fixture bytes and 4 pinned
hash constants updated).

**Net: 1199 passing, 0 failing.** Full suite runtime ~42 seconds.

## Known limitations — not addressed in v0.2.37

### From the reviewer's Top 10:
- **#3 Lambda/EC2 mode enforcement** — `--lambda-mode` and
  `--ec2-mode` are dead for wildcard permissions. Session 3 scope.
- **#4 Metadata duration** — collection timing metadata not
  accurately recorded. Session 4 scope.
- **#5 Scan manifest / completeness model** — post-v0.2.39 roadmap.
- **#6 Collector failure handling normalization** — post-v0.2.39.
- **#7 mypy honesty** — type checking is not clean. Session 4 scope.
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
