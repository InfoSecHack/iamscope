# ARF runtime edge-id remap verification

- Scope: verify one real external `arf_rt` wrapper run can remap planner-selected edges back to original IAMScope `edge_id` values
- Contract: truth artifacts keyed to original IAMScope edge IDs must reattach after wrapper normalization and planner selection
- Minimal fix allowed: preserve exact matching and add a truthful unique regionless fallback only when ARF planner rows omit region
- Proof required: one real runtime run plus one focused regression test around the live path