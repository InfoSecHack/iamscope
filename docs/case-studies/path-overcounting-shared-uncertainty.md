# Path Overcounting and Shared Uncertainty

## What this demo shows

This local-only case study shows why a naive structural path count can overstate actionability.

A naive structural view sees `23` possible escalation paths. IAMScope's local synthetic fixture separates those rows into fixture-level verdicts:

- `3` `validated`
- `5` `blocked`
- `4` `precondition_only`
- `11` `inconclusive`

Most of the inconclusive paths share one unresolved evidence class: `shared_passrole_target_resource_scope_unknown`. The reviewer should resolve that evidence gap first instead of treating all `23` rows as independent validated risks.

This demo is synthetic, local-only, and uses frozen expected output. Replay equivalence is not proven.

## Why naive path counts overstate actionability

The fixture's naive candidate list is deterministic and fixture-defined. A naive candidate is a source -> action/precondition -> target row produced without evaluating blocker, precondition, or uncertainty checks.

That naive list is not IAMScope output. It is not evidence of reachability.

The demo uses it as a teaching contrast:

1. start with naive paths;
2. compare them to IAMScope fixture verdicts;
3. inspect the shared inconclusive cause;
4. decide which evidence gap to resolve first.

The point is not to count more paths. The point is to avoid promoting path-shaped rows when the modeled evidence is missing, blocked, or only precondition-level.

## How to run it

From the repository root, run:

```bash
./scripts/run_path_overcounting_shared_uncertainty_demo.sh
```

The default output directory is `/tmp/iamscope-path-overcounting-demo`.

You can also pass an explicit scratch path:

```bash
./scripts/run_path_overcounting_shared_uncertainty_demo.sh --out /tmp/iamscope-path-overcounting-demo
```

The runner refuses to write generated outputs inside the repository tree. It reads the local fixture under `tests/fixtures/demo/path_overcounting_shared_uncertainty/` and writes generated outputs only under the selected output directory.

## Expected terminal summary

```text
IAMScope path-overcounting demo (local only)
Output: /tmp/iamscope-path-overcounting-demo

Naive interpretation:
possible escalation paths: 23

IAMScope fixture verdicts:
validated: 3
blocked: 5
precondition_only: 4
inconclusive: 11

Top uncertainty class:
shared_passrole_target_resource_scope_unknown: 8 inconclusive paths

Reviewer decision:
Do not treat all 23 as independent validated risks.
Resolve the primary evidence gap first.

Replay equivalence:
not proven
reason: Existing run_reasoners_on_frozen_artifacts expects binding_metadata.json to be an edge-constraint binding list produced by IAMScope emit_binding_metadata. This synthetic teaching fixture currently uses descriptive demo metadata, so local replay stops before reasoner equivalence. Replay-equivalence follow-up must either build replay-compatible binding metadata and scenario edges, or keep the fixture as static teaching material.

Safety:
AWS calls made: 0
Live AWS used: false
Findings mode: frozen expected output
Generated/replayed by IAMScope: false
Stronger demo claims allowed: false
```

## Generated outputs

The runner writes these files under `/tmp/iamscope-path-overcounting-demo/` by default:

- `/tmp/iamscope-path-overcounting-demo/verdict-summary.json`
- `/tmp/iamscope-path-overcounting-demo/uncertainty-groups.json`
- `/tmp/iamscope-path-overcounting-demo/summary.md`

Generated outputs are not committed by default.

## What the output means

`verdict-summary.json` summarizes the naive candidate count, fixture verdict counts, and safety metadata.

`uncertainty-groups.json` summarizes the uncertainty classes represented by the fixture. The top class is `shared_passrole_target_resource_scope_unknown` with `8` inconclusive paths.

`summary.md` contains the same reviewer-facing summary as the terminal output.

The useful reviewer decision is narrow: do not treat all `23` naive rows as independent validated risks. Resolve the primary evidence gap first.

## Claim boundaries

This case study may claim:

- the fixture is local-only;
- the fixture is synthetic;
- the fixture uses frozen expected output;
- replay equivalence is not proven;
- the runner makes `0` AWS calls;
- the runner shows the difference between naive candidate rows and fixture-level verdicts;
- the runner shows a shared uncertainty class that explains several inconclusive paths.

The case study should be read as a local teaching demo, not as new evidence about a live AWS environment.

## What this does not prove

This demo does not prove:

- live AWS validation;
- runtime exploitability;
- production readiness;
- broad IAMScope correctness;
- real-world scalability;
- replay-proven IAMScope reasoner output;
- generated-by-IAMScope reasoner findings;
- downstream authorization;
- that all IAMScope findings are verified.

It also does not use percentages, composite scores, or accuracy claims.

## Next implementation slice

Recommended next slice: no further path-overcounting demo scaffolding; use the PassRole-to-Lambda controlled live validation case study for current live evidence.

This next slice should group inconclusive findings by uncertainty class from the local fixture/report output without changing verdicts, reasoner logic, schemas, or benchmark semantics.
