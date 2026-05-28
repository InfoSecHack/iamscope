# ARF runtime collision verification

- Scope: verify a larger live SeRIM bundle still remaps ARF planner edges back to original IAMScope edge IDs truthfully
- Contract: exact match is authoritative, unique regionless fallback is allowed, ambiguous regionless fallback must fail closed
- Live proof target: inspect one larger external `arf_rt` run and classify exact, regionless, and unresolved remaps across planner candidates
- If live ambiguity is not present: leave behavior unchanged, document that fact, and add a guardrail test proving ambiguous fallback does not attach truth