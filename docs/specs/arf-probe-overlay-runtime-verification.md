# ARF probe overlay runtime verification

- Scope: verify non-empty probe-overlay truth keyed to original IAMScope edge IDs survives the real ARF wrapper path on a larger live SeRIM bundle
- Contract: original overlay edge IDs must reattach after wrapper normalization/planner selection, producing non-empty `probe_ids`, `probe_states`, and validated/confounded truth labels on the remapped edge
- Proof path: use the real external `arf_rt` runtime with the larger SeRIM scenario and a minimal overlay built from real bundle edge IDs
- If no natural overlay exists: use the smallest truthful live-style overlay sidecar and document that limitation explicitly