# Contributing to IAMScope

This is the short version. For the long version, read `docs/ARCHITECTURE.md`.

## Before you change anything

1. **Run the full suite.** `./scripts/test_fast.sh` should report the current fast-suite count (1795 passing at this checkpoint). If it doesn't, something is broken before you touched it — fix that first.
2. **Run the project check script.** `./scripts/check.sh` should report artifact hygiene, formatting, lint, and type checks passing.
3. **Read `docs/ARCHITECTURE.md`.** The 10 architectural rules there are non-negotiable. Every rule was learned from a concrete incident — don't relearn them.

## The refuses-to-lie invariant

IAMScope exists because commercial AWS IAM analysis tools treat ambiguous permission edges as either definitely-allowed (false positive flood) or definitely-blocked (missed exploitation paths). IAMScope refuses to lie: when in doubt, it says `UNKNOWN` and produces an `INCONCLUSIVE` finding that lets the reviewer judge.

This invariant is load-bearing. **Every change must preserve it.** The single question to keep in mind is: *"could this change cause a finding to be emitted as VALIDATED when at least one of its required conditions is actually ambiguous?"* If yes, the change is wrong.

Three layers enforce the invariant independently:

1. **Fact layer** — `has_action` returns tristate (`PASS` / `UNKNOWN` / `FAIL`) and never collapses UNKNOWN
2. **Reasoner layer** — every verdict mapping explicitly handles UNKNOWN as its own case
3. **Invariant layer** — `Finding._validate_validated_invariants` crashes if a VALIDATED finding has any non-PASS check

See ARCHITECTURE.md Rule 1 and Rule 5 for details.

## Adding a new reasoner

Follow the 6-phase workflow from ARCHITECTURE.md Rule 10:

1. **Identification** — name the pattern, write a one-paragraph description, pick the `pattern_id`
2. **Ground truth** — survey the fact-layer primitives. **Does the parser support the action? Does a collector produce the node types?** If either answer is no, you need fact-layer changes FIRST. Don't skip this phase — it's where "no collector code needed" assumptions get tested. See Rule 2.
3. **Plan** — lock the check structure, verdict mapping, severity scaling. Write it out before coding.
4. **Implement** — write the reasoner + register in `__init__.py` + `cli.py` + write unit tests
5. **Verify** — full suite + ruff + E2E smoke test + add golden fixtures
6. **Handoff** — package + changelog entry + handoff message

## Adding a new resource type

If your reasoner references a new AWS resource type (e.g., Secrets Manager secrets, KMS keys, SNS topics), you need TWO fact-layer changes:

**1. Parser change (3-touch)** in `iamscope/parser/permission_policy.py`:
- Add an action set constant (e.g., `KMS_ACTIONS = {"kms:decrypt"}`)
- Extend the `RELEVANT_ACTIONS` union
- Add a `canonical_map` entry for proper-casing

**2. Collector change** in `iamscope/collector/<resource>_collector.py`:
- New boto3-based module following `secrets_collector.py` or `lambda_collector.py` as the reference
- Wired into `iamscope/pipeline.py` at BOTH the single-account and org-mode flows
- New config flag in `CollectionConfig`
- Exported from `iamscope/collector/__init__.py`

**You cannot skip step 2.** The `scenario_json.py` validator enforces that every edge references a pre-existing node. If your reasoner needs Secret nodes but no collector pulls them from the AWS API, the scenario-emit step will crash. This was the priority 3d lesson. See Rule 2 for the full 12-step checklist.

## Golden fixtures

Every reasoner ships with byte-pinned golden fixtures in `tests/fixtures/expected_output/findings/<reasoner>/`. The rule from Rule 6:

- **A refactor that doesn't perturb the goldens is safe by construction.**
- **A refactor that perturbs them needs an explicit regen + handoff.**

For a refactor that's supposed to be byte-stable:

```bash
python3 -m pytest tests/test_golden_findings.py -q    # expect 0 failures
```

Also re-run the E2E smoke test and verify the `findings_hash` matches the previous run.

For a feature that intentionally changes behavior:

1. Edit `tests/test_golden_findings.py` — flip `_REGEN: bool = False` → `True`
2. Run the affected golden tests — new fixture files get written
3. Flip `_REGEN` back to `False`
4. Re-run to verify
5. Update the changelog to note the intentional behavior change

## Shared modules

The IAMScope extraction rule (Rule 7): **don't extract a helper into a shared module until 3+ reasoners use it.** Premature abstraction is a real cost. Clone helpers inline across reasoners until a third caller appears, then extract with the interface the first two callers plus the new caller actually need.

Current shared modules:

- `iamscope/reasoner/combinators.py` — `and_tristate`, `and_tristate_many` (used by 2 reasoners, extracted because the interface is pure)
- `iamscope/reasoner/admin_detection.py` — `find_admin_witness_edge`, `is_admin_equivalent` (used by 4+ reasoners)
- `iamscope/reasoner/chain_walking.py` — `find_node`, `assumerole_permission_edges_from`, `find_admitting_trust_edge` (used by 2 reasoners)

What's NOT extracted yet (even though it could be): the BFS walker loops themselves, the `_compute_verdict_and_severity` FAIL-short-circuit pattern, the `_absorb_digests` helper. See Rule 7 for why.

## Evidence citations

`Check.evidence_refs` can ONLY reference:

- Statement digests (from `EvidenceBundle.statement_digests`)
- Edge refs (from `EvidenceBundle.edge_refs`)
- Constraint refs (from `EvidenceBundle.constraint_refs`)

**NOT node refs.** See Rule 4. If your check asserts something about a node (e.g., "the target role is admin-equivalent"), cite the EDGE that proves it (e.g., the `iam:*_permission` self-edge), not the node itself.

The `Finding._validate_evidence_cross_references` validator will crash the constructor if you cite a dangling reference. This has caught real bugs during reasoner development.

## Pull request checklist

Before opening a PR:

- [ ] Activate the local environment: `source .venv/bin/activate`
- [ ] `./scripts/check.sh` passes
- [ ] `./scripts/test_fast.sh` passes
- [ ] If you added a reasoner: registered in `iamscope/reasoner/__init__.py` `__all__` and `iamscope/cli.py::_AVAILABLE_REASONER_FACTORIES`
- [ ] If you added a resource type: parser + collector + pipeline wiring complete (see Rule 2 12-step checklist)
- [ ] E2E smoke test with the new reasoner produces findings (not just unit tests)
- [ ] If behavior changed: golden fixtures regenerated and changelog updated
- [ ] If behavior didn't change: golden fixtures still pass AND findings_hash matches
- [ ] README changelog entry added for the change

## Quick reference

| Question | Answer |
|---|---|
| Where's the tristate primitive? | `iamscope/reasoner/fact_graph.py::has_action` |
| Where's the Finding validator? | `iamscope/reasoner/verdict.py::Finding._validate_validated_invariants` |
| Where do collectors live? | `iamscope/collector/` |
| Where do reasoners live? | `iamscope/reasoner/` |
| Where are golden fixtures? | `tests/fixtures/expected_output/findings/` |
| Where's the CLI reasoner registry? | `iamscope/cli.py::_AVAILABLE_REASONER_FACTORIES` |
| How do I regen goldens? | Flip `_REGEN: bool = True` in `tests/test_golden_findings.py` |
| What's the severity enum? | `iamscope/constants.py::SEVERITY_*` |
| What's the verdict enum? | `iamscope/reasoner/verdict.py::Verdict` |
| What's the CheckState enum? | `iamscope/reasoner/verdict.py::CheckState` |

For everything else, read `docs/ARCHITECTURE.md`.
