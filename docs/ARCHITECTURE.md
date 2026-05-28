# IAMScope Architecture

This document captures the architectural rules that govern how IAMScope is built — the non-obvious decisions that shape every reasoner, collector, parser, and verdict. It's a reference for future contributors (including future-you) to avoid re-learning these rules the hard way.

The intended audience is someone adding a new reasoner, fixing a bug in an existing reasoner, or making a change to the shared infrastructure (fact graph, verdict mapping, evidence model). If you're reading this before touching code, you're doing it right.

Every rule in this document was learned from a concrete incident — a bug, a false positive, a silent regression, or a refactor that almost introduced one. The rule is stated first, then the incident that taught us the rule, then the code that enforces it.

---

## Rule 1: UNKNOWN is a first-class tristate, not a fallback

**The rule.** A reasoner that cannot determine whether a condition holds must emit `CheckState.UNKNOWN` explicitly rather than guessing `PASS` or `FAIL`. The `has_action` primitive returns tristate (PASS / UNKNOWN / FAIL), every reasoner's verdict mapping explicitly handles UNKNOWN as its own case, and the `Finding._validate_validated_invariants` guard crashes the Finding constructor if a VALIDATED finding contains any non-PASS check.

**The incident.** Plan §3.3 and §4B.6 identified "collapsing UNKNOWN into FAIL" as the single most common false-positive production path for IAM analysis tools. Every commercial AWS security scanner at the time treated ambiguous permission edges (wildcard resources, hyperedge expansions, conditioned statements) as either "definitely allowed" (false positive: alert fatigue) or "definitely blocked" (false negative: missed exploitation path). IAMScope was built around a refuses-to-lie invariant: when in doubt, say unknown and let the reviewer judge.

**The code.**
- `iamscope/reasoner/fact_graph.py::has_action` — the tristate primitive. Returns `PASS` only when at least one matching edge is a clean witness; returns `UNKNOWN` when all matching edges are ambiguous; returns `FAIL` only when no matching edges exist.
- `iamscope/reasoner/fact_graph.py::_is_unknown_witness` — encodes the three ambiguity flags (hyperedge dst, `is_wildcard_resource=True`, `has_conditions=True`).
- `iamscope/reasoner/verdict.py::Finding._validate_validated_invariants` — the last-line-of-defense. Crashes the Finding constructor with `InvalidFindingError` if a VALIDATED finding has any non-PASS check. This has caught real bugs during reasoner development (see the priority 3b `Check.evidence_refs` incident in the changelog).
- Every reasoner's `_compute_verdict_and_severity` method has an explicit `unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]` scan that produces `INCONCLUSIVE` verdicts when triggered.
- Every reasoner's enumeration step uses `state is not CheckState.FAIL` rather than `state is CheckState.PASS` to include UNKNOWN candidates. Excluding UNKNOWN at the enumeration layer would violate refuses-to-lie at the pre-filter.

**The tests.** The priority 4 audit verified all of the above across 6 reasoners and the shared `admin_detection.py`, `chain_walking.py`, and `combinators.py` modules. Zero bugs found. The audit is documented in the v0.2.22 changelog.

---

## Rule 2: Adding a new resource type requires BOTH a parser change AND a collector change

**The rule.** Adding a new AWS resource type to the reasoner surface (e.g., `secretsmanager:GetSecretValue` targeting `SecretsManagerSecret` nodes) requires two fact-layer changes:

1. **Parser change (3-touch)** in `iamscope/parser/permission_policy.py`:
   - Add an action set constant like `SECRETS_ACTIONS = {"secretsmanager:getsecretvalue"}`
   - Extend the `RELEVANT_ACTIONS` union to include it
   - Add a `canonical_map` entry for proper-casing (e.g., `"secretsmanager:getsecretvalue": "secretsmanager:GetSecretValue"`)

2. **Collector change** in `iamscope/collector/<resource>_collector.py`:
   - A new boto3-based collector module following the `lambda_collector.py` or `secrets_collector.py` pattern
   - Wired into `iamscope/pipeline.py` at BOTH the single-account and org-mode flows
   - A new config flag (e.g., `collect_secrets: bool = True`) in the `CollectionConfig` dataclass
   - Added to `iamscope/collector/__init__.py` exports

**The incident.** Priority 3d (`secrets_blast_radius`) initially assumed "no collector code needed" because the parser could create Secret nodes implicitly from resource ARNs in existing IAM policies. **This assumption was wrong.** The `iamscope/output/scenario_json.py` validator enforces that every edge's src/dst references a pre-existing node. When the parser created a `secretsmanager:GetSecretValue_permission` edge pointing to a Secret node that didn't exist in the `nodes` tuple, the scenario-emit step crashed with `ValueError: Edge ... dst references non-existent node`.

The fix was writing a proper `secrets_collector.py` matching the `lambda_collector.py` pattern (~95 lines, minimal surface). Lambda, EC2, ECS all have dedicated collectors for this exact reason — there's no shortcut.

**The code.**
- `iamscope/collector/lambda_collector.py` — the reference pattern. ~144 lines, creates `LambdaFunction` nodes via `list_functions` pagination, optionally emits service edges to execution roles.
- `iamscope/collector/secrets_collector.py` — the minimal pattern. ~95 lines, creates `SecretsManagerSecret` nodes via `list_secrets` pagination, emits NO edges (secrets have no lateral-movement primitive).
- `iamscope/collector/ec2_collector.py` — the instance-profile pattern.
- `iamscope/output/scenario_json.py` lines 180-203 — the edge-reference validator that catches missing nodes.
- `iamscope/parser/permission_policy.py` lines 30-60 — the action sets and `RELEVANT_ACTIONS` union.
- `iamscope/parser/permission_policy.py` line 281 onward — the `canonical_map` dict.
- `iamscope/pipeline.py` line 89 onward — the `CollectionConfig` dataclass with collector flags.
- `iamscope/pipeline.py` lines 179+ and 238+ — the two flows (single-account and org-mode) where collectors are called.

**The checklist.** When adding a new resource type:

1. Add the action set constant to `permission_policy.py`
2. Extend `RELEVANT_ACTIONS`
3. Add the canonical_map entry
4. Add the node type constant to `iamscope/constants.py` (if not already present)
5. Add an ARN classifier case to `iamscope/collector/passrole.py::_classify_resource_arn` (if needed)
6. Write the collector module (`iamscope/collector/<resource>_collector.py`)
7. Add the config flag to `pipeline.py::CollectionConfig`
8. Wire the collector into both pipeline flows
9. Export from `iamscope/collector/__init__.py`
10. Write the reasoner (`iamscope/reasoner/<resource>_<pattern>.py`)
11. Register in `iamscope/reasoner/__init__.py` `__all__`
12. Register in `iamscope/cli.py` `_AVAILABLE_REASONER_FACTORIES`

Steps 1-9 are the fact-layer. Steps 10-12 are the reasoner layer. **Skipping the collector step is the canonical mistake.**

---

## Rule 3: Admin equivalence detection is two-tier, with a service-prefix threshold

**The rule.** The shared `iamscope/reasoner/admin_detection.py::find_admin_witness_edge` helper uses two-tier matching:

- **Tier 1:** explicit `*_permission` or `iam:*_permission` permission edge. Matches unit-test fixtures that build `_admin_grant_edge` or similar directly.
- **Tier 2:** wildcard expansion hyperedges spanning **≥3 distinct service prefixes** (e.g., `sts`, `iam`, `lambda`, `ec2`, `ecs`, `secretsmanager`). Matches real collected data where `Action: "*"` is fanned out into per-action permission edges pointing to `__hyperedge__:wildcard_*` dsts.

**The ≥3 threshold is non-negotiable.** Lowering it to ≥1 produces false positives on non-admin principals with single-service scoped wildcard grants (e.g., Alice with `Action: "lambda:CreateFunction", Resource: "*"` being classified as admin-equivalent, which is wrong). Raising it to ≥5 would miss legitimately-admin roles in smaller orgs where not all RELEVANT_ACTIONS classes are expanded.

**The incident.** Priority 3b introduced tier-2 detection (`any wildcard hyperedge dst = admin`) to fix a silent dead-code path in `passrole_lambda._is_admin_equivalent` that didn't work on real collected data. The fix worked for the intended case (AdminRole with `Action: "*"`) but the priority 3d smoke test exposed a false positive: Alice, a non-admin user with scoped wildcard grants on `lambda:CreateFunction` + `ecs:*`, was being classified as admin-equivalent by `secrets_blast_radius` (which uses admin detection on the SOURCE principal, unlike the earlier reasoners that check TARGETS).

The fix was tightening tier-2 to require wildcard hyperedges across ≥3 distinct service prefixes. Alice has 2 prefixes (lambda, ecs) → excluded. AdminRole has 6 prefixes → included. All 981 prior tests still passed because they use tier-1 explicit `iam:*_permission` edges.

**The code.**
- `iamscope/reasoner/admin_detection.py::find_admin_witness_edge` — the two-tier detection. Walks `facts.edges_from(role)` once, short-circuits on tier 1, collects tier-2 witnesses by service prefix, returns the lex-first witness only if ≥3 distinct prefixes are observed.
- `iamscope/reasoner/admin_detection.py::is_admin_equivalent` — the boolean wrapper.
- 4 reasoner delegates: `passrole_lambda`, `passrole_ecs`, `assume_role_chain`, `admin_reachability`. Each has a thin `_is_admin_equivalent` / `_find_admin_witness_edge` method that imports and delegates to the shared module. Call sites are stable.

**The test that validates this.** The priority 3d E2E smoke test in the repository history:

- Alice with 2 service-prefix wildcards → `secrets_blast_radius validated/high` (correct, non-admin)
- AdminRole with `Action: "*"` (6 service prefixes) → `admin_reachability validated/high`, `assume_role_chain validated/high` (correct, admin)

If you change the threshold, re-run the smoke test and verify both assertions hold.

---

## Rule 4: `Check.evidence_refs` can only reference edges, statements, or constraints

**The rule.** The `Check.evidence_refs` tuple (attached to each check in a Finding) can only contain values that appear in the `EvidenceBundle`'s `statement_digests`, `edge_refs`, or `constraint_refs`. **Not `node_refs`.** The `Finding._validate_evidence_cross_references` validator enforces this and raises `InvalidEvidenceError` on construction if any check cites a dangling reference.

**The incident.** Priority 3b (`assume_role_chain`) had a bug where check 2 (`endpoint_is_admin_equivalent`) cited `target.node_id` as its evidence reference — a node ID is an opaque identifier, not in any of the three allowed categories. The Finding constructor crashed with `InvalidFindingError: Check 'endpoint_is_admin_equivalent' cites evidence_refs that are not present in the EvidenceBundle` and all 20 affected unit tests failed.

The fix was extracting `_find_admin_witness_edge` as a helper that returns the actual permission edge proving admin equivalence (the `iam:*_permission` self-edge or a wildcard expansion hyperedge). The reasoner added the witness edge to `edge_refs` in the evidence bundle and cited its `edge_id` in check 2's `evidence_refs`. Reviewers now get a concrete pointer to audit in `scenario.json` instead of an opaque node reference.

**The code.**
- `iamscope/reasoner/verdict.py::Finding._validate_evidence_cross_references` — the validator. Runs in `__post_init__` and raises `InvalidEvidenceError` on dangling refs.
- `iamscope/reasoner/admin_detection.py::find_admin_witness_edge` — returns the concrete edge (not None) so reasoners can cite `edge.edge_id` in `evidence_refs`.

**The pattern.** When a reasoner's check asserts "X is true about node Y" (e.g., "the target role is admin-equivalent"), the evidence should be the edge that proves it (e.g., the `iam:*_permission` edge on the target role), not the node itself. Node-level claims are captured in `evidence.node_refs`; edge/statement/constraint citations go in `Check.evidence_refs`.

---

## Rule 5: The refuses-to-lie invariant is enforced at three layers

**The rule.** Three layers independently enforce the refuses-to-lie invariant. A bug has to slip past all three to produce a false positive.

1. **Fact layer** (`fact_graph.py::has_action` and `_is_unknown_witness`). The primitive never returns PASS on ambiguous edges and never returns FAIL on present-but-ambiguous edges. Ambiguity is classified via three flags: hyperedge dst, `is_wildcard_resource`, `has_conditions`.

2. **Reasoner layer** (each reasoner's `_compute_verdict_and_severity`). Every reasoner explicitly handles UNKNOWN as its own verdict-mapping case, producing `INCONCLUSIVE` verdicts rather than silently falling through to `VALIDATED`. The pattern is uniform: an `unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]` scan, then `if unknown_checks: return INCONCLUSIVE`.

3. **Invariant layer** (`verdict.py::Finding._validate_validated_invariants`). The Finding constructor crashes if a VALIDATED finding contains any non-PASS check. This is the last-line-of-defense — even if both upstream layers have bugs, a reasoner can't produce a false-positive VALIDATED finding without the construction itself failing.

**The point.** Each layer is independent. A regression in the fact layer gets caught by the reasoner layer (which produces INCONCLUSIVE on UNKNOWN checks). A regression in the reasoner layer gets caught by the invariant layer (which crashes on non-PASS checks in VALIDATED findings). A regression in the invariant layer is caught by the unit tests + goldens.

**The code.**
- Fact layer: `iamscope/reasoner/fact_graph.py::has_action` (lines 197-265)
- Reasoner layer: every `_compute_verdict_and_severity` method across 6 reasoners
- Invariant layer: `iamscope/reasoner/verdict.py::Finding._validate_validated_invariants` (lines 291-310)

---

## Rule 6: Byte-pinned golden fixtures are the ground truth of reasoner behavior

**The rule.** Every reasoner ships with byte-pinned golden fixtures in `tests/fixtures/expected_output/findings/<reasoner>/fixture_*.json`. The `_verify_or_regen` helper in `tests/test_golden_findings.py` compares the current emit byte-by-byte against the on-disk fixture and fails loudly on any drift. **Any change that doesn't perturb the golden fixtures is safe by construction; any change that does perturb them needs an explicit regen + handoff.**

**The lesson.** During the priority 3c-refactor (shared modules extraction), I extracted `admin_detection.py` and `chain_walking.py` from duplicated inline code across 5 reasoners. The refactor was a pure code-movement — no semantic change — and I verified this by running the 29 byte-pinned goldens PLUS the E2E smoke test `findings_hash`. Both matched pre and post refactor exactly (`2cc99fe793169a65...`). Byte-level equivalence across 8 findings from 5 reasoners proved the refactor was semantically neutral.

**The workflow for a refactor that's supposed to be byte-stable:**

1. Make the change
2. Run `python3 -m pytest tests/test_golden_findings.py -q` — expect 0 failures
3. Run the E2E smoke test — expect the `findings_hash` to match the previous run
4. If either step fails, the change isn't byte-stable; investigate whether the drift is intentional

**The workflow for a feature that INTENTIONALLY changes behavior:**

1. Make the change
2. Edit `tests/test_golden_findings.py` — flip `_REGEN: bool = False` → `True`
3. Run the affected golden tests — new fixture files get written
4. Flip `_REGEN` back to `False`
5. Re-run the affected golden tests — expect them to pass in verify mode
6. Run the full suite and ruff
7. Update the changelog to note the intentional behavior change

**The code.**
- `tests/test_golden_findings.py::_verify_or_regen` — the workhorse
- `tests/test_golden_findings.py::_emit_for_fixture` — the byte-emit helper
- `tests/fixtures/expected_output/findings/` — the fixture directory

**Current fixture counts:** cross_account_trust 9, passrole_lambda 7, passrole_ecs 7, assume_role_chain 3, admin_reachability 3, secrets_blast_radius 3. Total: 32.

---

## Rule 7: Shared modules are extracted only when 3+ reasoners share the same primitive

**The rule.** Premature abstraction is a real cost. Extracting a helper into a shared module before 3+ reasoners use it makes the module harder to design (you don't know what the shared interface should look like) and harder to change (the interface is now load-bearing for code you haven't written yet). The IAMScope pattern is to clone helpers inline across reasoners until a third reasoner needs the same primitive, then extract.

**The examples.**

- `combinators.py` (`and_tristate`, `and_tristate_many`) — extracted in priority 3b when `assume_role_chain` needed the same `_and_tristate` helper that `passrole_ecs` had introduced in priority 3a. Two reasoners was the trigger for extraction because the second reasoner's use case (`and_tristate_many` for variable-length chains) clarified the interface.

- `admin_detection.py` (`find_admin_witness_edge`, `is_admin_equivalent`) — extracted in priority 3c-refactor when 4 reasoners (`passrole_lambda`, `passrole_ecs`, `assume_role_chain`, `admin_reachability`) all had identical two-tier detection logic. Waiting until 4 reasoners had it meant the shared interface was already battle-tested.

- `chain_walking.py` (`find_node`, `assumerole_permission_edges_from`, `find_admitting_trust_edge`) — extracted in priority 3c-refactor when 2 reasoners (`assume_role_chain`, `admin_reachability`) shared identical BFS primitives. Two reasoners was the minimum threshold because the helpers are pure functions with obvious shapes.

**What's NOT yet extracted (even though it COULD be):**

- The BFS walker *loops* themselves (not just the primitives) across `assume_role_chain` and `admin_reachability`. Only 2 reasoners share the loop shape, and the emit semantics differ (per-chain vs per-principal), so extraction would require a "driver + callback" pattern that's premature until a 3rd reasoner appears.

- The `_compute_verdict_and_severity` FAIL-short-circuit pattern at the top of every reasoner's verdict mapping. All 6 reasoners have this shape, but the specific rules differ (cross_account_trust has org-membership side-channel, passrole_lambda has precondition_only, etc.), so extracting into a shared verdict-mapping driver would add coupling for minimal savings.

- The `_absorb_digests` helper. All 6 reasoners have a nearly-identical version that pulls DIG-1 statement digests from `edge.features["allow_controls"]`. Extracting is tempting but the helper is 10 lines and each reasoner's copy has subtly different comments / trace behavior.

**The principle.** Clone until the third caller. Then extract, and keep the interface minimal. Never extract preemptively based on "we might need this later."

---

## Rule 8: Finding construction requires explicit node_ref + edge_ref + constraint_ref tracking

**The rule.** Every reasoner that constructs a Finding must maintain three separate accumulators during the build: `node_refs`, `edge_refs`, and `constraint_refs`. These flow into the `EvidenceBundle` and are cross-validated by `Finding._validate_evidence_cross_references`. The reasoner is responsible for:

- Adding the source and target node IDs to `node_refs` (always needed for provenance)
- Adding every edge referenced in any `Check.evidence_refs` to `edge_refs`
- Adding every constraint referenced in any `Check.evidence_refs` to `constraint_refs`
- Adding `f"{edge_id}:{constraint_id}"` pairs to `edge_constraint_refs` when the reasoner cites edge-constraint bindings

**The pattern.** Every reasoner's `_build_finding` method starts with:

```python
check_results: list[Check] = []
blockers: list[Blocker] = []
statement_digests: set[str] = set()
statement_sources: dict[str, tuple[str, int, str]] = {}
edge_refs: list[str] = [primary_witness_edge.edge_id]  # or similar
constraint_refs: set[str] = set()
edge_constraint_refs: set[str] = set()
node_refs: list[str] = [source.node_id, target.node_id]
trace: list[TraceEntry] = []
```

Then each check-building block adds to the relevant accumulators. At the end, the `EvidenceBundle` is constructed from the accumulators, and the Finding validator cross-checks that every citation in `Check.evidence_refs` appears in one of `statement_digests`, `edge_refs`, or `constraint_refs`.

**The incident.** The priority 3b bug in `assume_role_chain` (citing `target.node_id` in check 2's `evidence_refs`) was the first time this invariant was violated in the post-rebuild codebase. The fix was structural: extract a helper that returns the actual witness edge, add it to `edge_refs`, cite `edge.edge_id` in `evidence_refs`. The pattern is now uniform across 6 reasoners.

**The code.**
- `iamscope/reasoner/verdict.py::Finding._validate_evidence_cross_references` (lines 260-290)
- Reference implementations: any of the 6 reasoners' `_build_finding` methods

---

## Rule 9: Reasoner severity scaling is per-pattern, not centralized

**The rule.** Each reasoner owns its own severity scaling logic. There's no central "severity map" shared across reasoners because the mapping is pattern-specific. The severities themselves are drawn from a shared enum (`critical`, `high`, `medium`, `low`, `info`), but the rules for assigning them are reasoner-local.

**The examples.**

- **`cross_account_trust`** — severity from the `naked_trust_value` classification (BROAD_NAKED → critical, SPECIFIC_NAKED → high, etc.), with a same-org modifier that downgrades by one level.

- **`passrole_lambda` / `passrole_ecs`** — severity = critical if target is admin-equivalent, else high. Admin equivalence checked via the shared `admin_detection` module.

- **`assume_role_chain`** — severity scales with chain length: 2-3 hops to admin → high, 4+ hops to admin → critical (deeper chains are harder to spot in audits). Non-admin endpoint → medium.

- **`admin_reachability`** — severity scales with the count of reachable admins: 1 admin → high, 2+ admins → critical (multiple paths means SCP can't single-handedly break the chain).

- **`secrets_blast_radius`** — severity scales with principal admin-equivalence: admin-equivalent reader → critical, non-admin reader → high. Uses the shared `admin_detection` module with the ≥3 service prefix threshold (Rule 3).

- **`inconclusive` findings** — severity varies by reasoner: most use `high` (chain/trust reasoners, because inconclusive multi-hop paths are still high-value for reviewers to investigate), but `secrets_blast_radius` uses `medium` (because wildcard-resource grants on secrets are common in real-world policies and would flood pentest reports if classified as high).

**The rationale.** Each pattern has its own severity semantics because the "worst case" differs. A 4-hop AssumeRole chain is harder to spot than a 2-hop chain, so the 4-hop case gets escalated. A wildcard secrets grant is common, so the inconclusive case gets de-escalated. Centralizing this logic would flatten the nuance without saving much code.

**What IS shared.** The severity constants themselves come from `iamscope/constants.py` (`SEVERITY_CRITICAL`, `SEVERITY_HIGH`, etc.). The verdict enum comes from `verdict.py`. The FAIL short-circuit pattern (e.g., `if check_X is FAIL: return BLOCKED/info`) is repeated in every reasoner's verdict mapping.

---

## Rule 10: Reasoner-addition workflow is six phases

**The phases.** Every new reasoner should follow this workflow:

1. **Identification.** Name the pattern. Write a one-paragraph description of what it detects and why. Identify the distinguishing features relative to existing reasoners. Decide the `pattern_id` (stable identifier used in findings.json) and `pattern_title` (human-readable).

2. **Ground truth.** Survey the fact-layer primitives the reasoner will need. Does the existing parser support the action? Does a collector produce the node types involved? Read the relevant `has_action`, `edges_from`, `trust_policy_of` helpers to confirm they provide what you need. If fact-layer changes are required, scope them explicitly (this is where the "parser AND collector" rule from Rule 2 gets applied).

3. **Plan.** Lock the check structure. Write out the check names, their descriptions, and the verdict mapping rules. Decide the severity scaling. Identify which existing shared helpers (`admin_detection`, `chain_walking`, `combinators`) the reasoner will use. Write a short Phase 3 plan document that the maintainer can review before you commit to implementation.

4. **Implement.** Write the reasoner module, register it in `iamscope/reasoner/__init__.py` and `iamscope/cli.py::_AVAILABLE_REASONER_FACTORIES`. Write the unit tests in `tests/test_<reasoner>_reasoner.py`. Verify imports cleanly, run the unit tests, iterate until all pass.

5. **Verify.** Run the full suite (`python3 -m pytest tests/ -q`), run ruff (`ruff check iamscope/ tests/`), run the E2E smoke test with a moto fixture that exercises the new pattern. Add golden fixtures if the pattern is stable and worth locking.

6. **Handoff.** Package the deliverable (tarball under `/mnt/user-data/outputs/`), write a handoff message covering cumulative state and recommended next steps, call `present_files` on the tarball.

**The points that matter:**

- Phase 1 is where you decide the pattern's scope. Scope creep starts here.
- Phase 2 is where you discover fact-layer gaps. Don't skip this — it's where "no collector code needed" assumptions get tested (Rule 2).
- Phase 3 is where the maintainer has agency over the design. Write the plan out; don't just start coding.
- Phase 4 is where the 6-phase pattern pays off. The unit tests come before the goldens because unit tests are cheaper to iterate.
- Phase 5 is where the byte-stability guarantees get locked in. Don't ship without running the full suite.
- Phase 6 is where the handoff message becomes the record-of-truth for the next invocation. Capture cumulative state, deferred items, and recommended next.

**The template.** Every priority 3 reasoner followed this workflow. Priority 3a (`passrole_ecs`) was the cleanest example because it cloned from `passrole_lambda` with minor semantic additions. Priority 3d (`secrets_blast_radius`) was the messiest example because the Phase 2 ground-truth survey missed the collector requirement — the workflow would have caught it earlier if Phase 2 had been more rigorous.

---

## Quick reference: where things live

| Concern | File |
|---|---|
| Tristate primitive | `iamscope/reasoner/fact_graph.py::has_action` |
| Ambiguity detection | `iamscope/reasoner/fact_graph.py::_is_unknown_witness` |
| Tristate combinators | `iamscope/reasoner/combinators.py` |
| Admin equivalence detection | `iamscope/reasoner/admin_detection.py` |
| Chain walking primitives | `iamscope/reasoner/chain_walking.py` |
| Finding validator (last-line-of-defense) | `iamscope/reasoner/verdict.py::Finding._validate_validated_invariants` |
| Evidence cross-reference validator | `iamscope/reasoner/verdict.py::Finding._validate_evidence_cross_references` |
| Permission policy parser | `iamscope/parser/permission_policy.py` |
| Action canonicalization | `iamscope/parser/permission_policy.py::canonical_map` |
| Node type constants | `iamscope/constants.py` |
| Collectors | `iamscope/collector/*.py` |
| Pipeline (collector orchestration) | `iamscope/pipeline.py` |
| CLI reasoner registry | `iamscope/cli.py::_AVAILABLE_REASONER_FACTORIES` |
| Scenario.json edge validator | `iamscope/output/scenario_json.py` lines 180-203 |
| Byte-pinned golden fixtures | `tests/fixtures/expected_output/findings/<reasoner>/` |
| Golden test driver | `tests/test_golden_findings.py::_verify_or_regen` |
| Report renderer (inconclusive handling) | `iamscope/report/findings_renderer.py` |

## Quick reference: current shipping reasoners (6)

| Reasoner | Pattern | Admin detection used? | Fact-layer dependency |
|---|---|---|---|
| `cross_account_trust` | Single-hop external trust analysis with OIDC + same-org awareness | No | Trust edges |
| `passrole_lambda` | Principal with lambda:CreateFunction + iam:PassRole to a Lambda-trusting role | Yes (target check) | Lambda collector + PassRole parser |
| `passrole_ecs` | Principal with ecs:RegisterTaskDefinition + ecs:RunTask + iam:PassRole to an ECS-trusting role | Yes (target check) | ECS action set + PassRole parser |
| `assume_role_chain` | Multi-hop sts:AssumeRole chain to admin endpoint via BFS | Yes (endpoint check) | Trust edges + assume_role permission edges |
| `admin_reachability` | Per-principal blast-forward reachability set of admin-equivalent roles | Yes (endpoint check) | Trust edges + assume_role permission edges |
| `secrets_blast_radius` | Per-secret IAM-layer blast radius analysis | Yes (source check) | SecretsManager collector + GetSecretValue parser |

## Quick reference: what NOT to do

- **Don't treat UNKNOWN as a fallback.** It's a first-class state. Rule 1.
- **Don't skip the collector step for a new resource type.** Rule 2.
- **Don't lower the ≥3 service prefix threshold for tier-2 admin detection.** Rule 3.
- **Don't cite node IDs in `Check.evidence_refs`.** Rule 4.
- **Don't extract a helper into a shared module until 3+ reasoners use it.** Rule 7.
- **Don't ship a refactor without running the 32 golden fixtures AND the E2E smoke test `findings_hash`.** Rule 6.
- **Don't bypass `Phase 2: ground truth` in the reasoner workflow.** Rule 10.
- **Don't try to centralize severity mapping across reasoners.** Rule 9.

## Historical context: why IAMScope exists

The original commercial AWS IAM analysis tools treated ambiguous permission edges as either definitely-allowed (flood of false positives) or definitely-blocked (missed exploitation paths). IAMScope was built around the refuses-to-lie invariant: when in doubt, say unknown and let the reviewer judge. This architecture document exists to preserve that discipline across contributions — the invariant is load-bearing, and every rule in this document exists to prevent it from being accidentally violated.

If you're adding a reasoner, tightening a fact-layer primitive, or refactoring shared infrastructure, the single question to keep in mind is: **"could this change cause a finding to be emitted as VALIDATED when at least one of its required conditions is actually ambiguous?"** If yes, the change is wrong. If you can't prove no, the change needs more tests.
