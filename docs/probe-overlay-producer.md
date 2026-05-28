# Probe Overlay Producer

IAMScope can consume `probe_overlay.json` sidecars without changing `scenario.json`. The `probe-overlay` command is the thinnest producer for those sidecars. It is engagement-scoped: it joins an explicit probe plan to existing scenario edges, runs only the requested checks, and emits the existing `iamscope.probe_overlay.v1` schema.

This command does not change graph semantics. Static graph collection remains a hypothesis. Simulator output is advisory. Runtime STS output is stronger evidence for the credentials/profile used to run the probe. A `confounded_skip` record means the operator intentionally preserved evidence that the validation surface is not clean enough for a live probe.

## Probe Plan

A plan is JSON:

```json
{
  "engagement_run_id": "run-example",
  "probes": [
    {
      "mode": "both",
      "edge_id": "edge-id-from-scenario",
      "action_class": "sts:AssumeRole",
      "external_id": "optional-external-id",
      "simulator_profile": "optional-admin-profile",
      "runtime_profile": "optional-source-role-profile"
    }
  ]
}
```

Each item may identify an edge by `edge_id`, or by `source_arn` plus `target_arn`. Supported modes are:

- `simulator`: calls `iam:SimulatePrincipalPolicy` and emits `simulator_only_allowed` or `simulator_only_denied`.
- `runtime`: calls `sts:AssumeRole` using the runtime profile and emits `probed_correlated_allowed` or `probed_correlated_denied`.
- `both`: runs simulator and runtime. Agreement emits `probed_correlated_allowed` or `probed_correlated_denied`; disagreement emits `probed_correlated_disagreement`.
- `confounded_skip`: emits `confounded_skip` without AWS calls. Include `confounded_reason` and `contributing_control_refs` when known.

For runtime probes, the selected profile must already represent the intended source principal. IAMScope does not bootstrap into the source role in this command.

## Command

```bash
source .venv/bin/activate && iamscope probe-overlay \
  --scenario scenario.json \
  --plan probe_plan.json \
  --output probe_overlay.json \
  --profile default \
  --region us-east-1
```

Add `--respect-confounders` to emit `confounded_skip` instead of making AWS calls when the scenario's effective controls mark the edge as confounded.

The output can be passed back to collection/reasoning:

```bash
source .venv/bin/activate && iamscope collect --probe-overlay probe_overlay.json --reasoners cross_account_trust,assume_role_chain
```

## Current Limits

Only `sts:AssumeRole` action-class probes are supported. CloudTrail correlation is intentionally left out of this thin producer; the sidecar schema already has a `cloudtrail_state` slot for a later enrichment pass.

## Frozen Finding Replay

Use `replay-findings` to prove overlay-aware reasoner behavior without recollecting AWS:

```bash
source .venv/bin/activate && iamscope replay-findings \
  --scenario scenario.json \
  --binding-metadata binding_metadata.json \
  --probe-overlay probe_overlay.json \
  --reasoners cross_account_trust,assume_role_chain \
  --output findings.json
```

The replay command verifies that `scenario.metadata.canonical_hash` still matches the frozen graph payload, validates the overlay hash against that same frozen scenario, reconstructs the `FactGraph`, and runs the requested reasoners. This is the preferred surface for demonstrating finding mutation because no AWS recollection occurs between baseline and overlay runs.

## Stable Finding Identity

`findings.json` now carries both `finding_id` and `finding_key`:

- `finding_id` is the existing backward-compatible ID. It remains evidence-derived and can change when a replay adds probe checks, blockers, trace entries, or control refs.
- `finding_key` is the stable semantic identity for replay diffs and reporting. It is derived from the reasoner pattern, source, target, and reasoner-selected core relation material. It intentionally excludes verdict, probe IDs, mutable trace text, blockers, and runtime evidence.

Use `finding_key` to compare baseline replay against overlay replay when you want to see an underlying finding mutate rather than appear as a delete/add pair.

## AssumeRole Probe Edge Semantics

A live `sts:AssumeRole` probe validates the combined AWS authorization relation for that exact caller credential and target role. AWS evaluates both source-side permission and target-side trust, plus relevant organization controls and runtime context. It is not pure evidence for only one graph edge.

IAMScope still records probe evidence by `edge_id`, but replay expands `sts:AssumeRole_permission` and `sts:AssumeRole_trust` IDs into the same combined AssumeRole relation when the source principal and target role match. Account-root trust uses the same admission rule as chain walking: `arn:aws:iam::<account>:root` admits principals from that account.

- Permission edge: the source principal has an identity-side `sts:AssumeRole` grant to the target role.
- Trust edge: the target role trust policy admits the source principal, directly or through account-root trust.
- Combined relation: a runtime STS attempt that depends on both halves and the surrounding AWS authorization context.

For `assume_role_chain` and `cross_account_trust`, a runtime probe attached to either the permission half or trust half of the same AssumeRole relation can influence the relevant finding. This avoids forcing operators to guess which graph half a live STS result should target while preserving the graph distinction between declared permission and declared trust.

## Semantic Findings Diff

Use `diff-findings` to compare baseline and overlay replay output by stable `finding_key`:

```bash
source .venv/bin/activate && iamscope diff-findings   findings.baseline.json findings.overlay.json   --output findings.diff.md
```

For machine-readable output:

```bash
source .venv/bin/activate && iamscope diff-findings   findings.baseline.json findings.overlay.json   --format json   --output findings.diff.json
```

Interpretation:

- Added or removed semantic findings mean a `finding_key` exists in only one side.
- Verdict changes mean the same underlying semantic finding changed state, for example `validated -> blocked` after a correlated runtime denial.
- Evidence and reasoning-trace changes mean the finding body changed even if the verdict did not.
- Probe evidence additions mean the candidate finding gained a `probe_overlay_runtime_truth` check, an `apply_probe_overlay` trace entry, or a `probe_overlay` blocker.

`finding_id` may still change in these cases because it remains evidence-derived for backward compatibility. Use `finding_key` for semantic replay diffs.

## Demo Pack Workflow

Use `demo-pack` to create a compact handoff folder from frozen artifacts:

```bash
source .venv/bin/activate && iamscope demo-pack   --scenario scenario.json   --binding-metadata binding_metadata.json   --probe-overlay probe_overlay.json   --reasoners cross_account_trust,assume_role_chain   --output-dir demo-pack
```

The folder contains:

- `inputs/scenario.json`
- `inputs/binding_metadata.json`
- `inputs/probe_overlay.json`
- `findings.baseline.json`
- `findings.overlay.json`
- `findings.diff.json`
- `findings.diff.md`
- `manifest.json`
- `README.md`

This proves the truth-aware loop without live AWS access during presentation: frozen scenario -> probe overlay -> replay -> semantic diff. The pack is intentionally small; it is not a packaging system and does not claim new validation beyond the supplied frozen artifacts and probe overlay.

To inspect one changed finding, open `findings.diff.md`, copy the candidate `finding_id` prefix, then run:

```bash
source .venv/bin/activate && iamscope why   --findings demo-pack/findings.overlay.json   --finding-id <candidate-finding-id-prefix>
```
