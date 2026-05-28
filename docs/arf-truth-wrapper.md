# ARF Wrapper Truth Artifact Ingestion

IAMScope's ARF-facing wrapper can now load IAMScope truth artifacts for reporting without changing ARF-RT core planner logic or the frozen `scenario.json`. The normalized scenario passed to ARF-RT remains the declared graph structure, and the wrapper remaps planner-selected edges back to original IAMScope `edge_id` values with an exact source/target/type/region key first. If the live planner row is regionless, the wrapper only falls back to a source/target/type key when that mapping is unique; ambiguous regionless fallback stays unjoined. That keeps truth keyed to IAMScope's canonical edge identity instead of assuming the ARF planner row ID is the same thing.

## Inputs

The thin wrapper at `tools/serim_arf_rt_compare.py` accepts:

```bash
source .venv/bin/activate && python tools/serim_arf_rt_compare.py \
  --scenario scenario.json \
  --binding-metadata binding_metadata.json \
  --probe-overlay probe_overlay.json \
  --findings findings.json \
  --output-dir out/arf_truth_compare
```

`--probe-overlay` and `--findings` are optional. With neither supplied, the wrapper uses the same planner path and output shape as before. `--binding-metadata` is accepted as an explicit artifact path for the wrapper report, but this pass does not reinterpret planner internals from it.

## Exposed Truth Labels

For each selected first-probe candidate, the wrapper can report:

- `declared_edge`: the edge exists in the frozen IAMScope scenario.
- `validated_allow`: a `probed_correlated_allowed` overlay record exists for the edge.
- `validated_deny`: a `probed_correlated_denied` overlay record exists for the edge.
- `confounded`: a `confounded_skip` overlay record exists, or the probe record itself is marked confounded.
- `probe_disagreement`: runtime and simulator/declaration disagreed in a correlated probe.
- `stale_drift_evidence`: a `STALE_PRINCIPAL_DRIFT` constraint is attached to the edge.
- `permission_boundary_evidence`: a `PERMISSION_BOUNDARY` constraint is attached to the edge.
- `resource_policy_deny_evidence`: a `RESOURCE_POLICY_DENY` constraint is attached to the edge when the input scenario already contains one. IAMScope collect does not currently emit that constraint end-to-end.
- `finding_refs`: stable `finding_key` references from an optional replayed `findings.json` whose evidence cites the edge.

These labels are wrapper/reporting facts. They do not cause ARF-RT to re-rank candidates in this pass.

## Current Limits

This is intentionally not ARF-RT truth-aware planning. It does not modify EIG, centrality, uncertainty, random selection, correlation groups, or path enumeration. It also does not consume CloudTrail, session-policy intersection, or any future truth evidence not already present in IAMScope sidecars/constraints. The current wrapper contract is regression-backed inside this repo, manually verified in one minimal live external `arf_rt` runtime path, stress-verified on one larger live SeRIM bundle where planner rows remained regionless but all candidate remaps stayed exact, manually verified for non-empty probe-overlay-backed truth reattachment on that larger bundle using a minimal overlay sidecar built from real bundle edge IDs, and manually verified to fail closed in one minimal live runtime reproduction of an ambiguous regionless remap case with non-empty overlay truth. A naturally occurring ambiguous case has still not been observed in the larger existing SeRIM bundle.

Use this integration to compare declared planner behavior against IAMScope's truth-aware evidence layer and to carry stable `finding_key` references into ARF-facing reports. ARF core consumption of these labels remains a later integration step, and wrapper truth is only as complete as the IAMScope artifacts it can legitimately map back onto original edge identities.