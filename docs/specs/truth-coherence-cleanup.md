# Truth Coherence Cleanup

## Goal

Make the branch more truthful and coherent without broadening IAMScope architecture.

## Non-goals

- No new major subsystems
- No broad resource-policy-deny implementation
- No finding_key redesign unless verification disproves the current fix

## Inputs / Outputs

- Input: current dirty branch state after reorg work
- Output: one grounded audit report, stale-drift end-to-end wiring, ARF truth remap fix, reduced overclaim where features remain partial

## Files likely affected

- `CODEX_CLEANUP_AUDIT.md`
- `iamscope/pipeline.py`
- `iamscope/cli.py`
- `iamscope/truth/stale_principal_drift.py`
- `tools/serim_arf_rt_compare.py`
- focused tests/docs only

## Edge cases

- original IAMScope `edge_id` missing from normalized ARF edges
- stale drift should only claim support where pipeline actually emits it
- resource-policy-deny claims must match real end-to-end wiring

## Security / abuse notes

- No new privilege model
- No new planner logic
- Changes stay in deterministic artifact wiring and truthful reporting

## Acceptance criteria

- audit report is repo-grounded
- stale drift is either real end to end or its claims are reduced
- ARF wrapper can reattach truth using original IAMScope edge identity or a deterministic mapping
- resource-policy-deny claims are scaled to reality if not fully wired

## Definition of done

- targeted tests pass
- `./scripts/check.sh` passes
- `./scripts/test_fast.sh` passes

## Current repo-grounded state

- `finding_key` is likely good: implemented, wired, and test-backed in emitted findings.
- stale-principal-drift is implemented and wired through scenario export plus `iamscope stale-drift`, but manually verified only through repo tests; current reasoner consumption is `assume_role_chain` only.
- ARF edge-id remap is implemented and wired with focused regression coverage, but live external runtime verification is still unverified.
- resource-policy-deny is explicitly de-scoped: helper exists for pre-existing bindings, collect does not emit it end to end.
- `scripts/review_security.sh` is hygiene only and should not be treated as truth-contract evidence.

