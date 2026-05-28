"""Reasoner evidence model — S09.

Every `Finding` ships with an `EvidenceBundle` sufficient for a human to
audit the reasoning without re-running the tool. The bundle carries:

- statement digests (for cross-referencing source policies)
- statement source locators (policy_arn, statement_index, statement_sid)
- graph references (edge IDs, constraint IDs, edge_constraint pairs, node IDs)
- condition context assumptions (the "we couldn't verify this" register)
- a reasoning trace (ordered Q&A list)

The `bundle_digest` property computes a deterministic SHA-256 over a
canonical JSON representation of the bundle. This digest is part of the
`finding_id` formula, so two findings with identical (pattern, source,
target) but different evidence get distinct IDs.

Per plan §3.5, three evidence-model invariants apply:

1. **Cross-validation** — every value in any `Check.evidence_refs` must
   appear in the bundle's `statement_digests`, `edge_refs`, or
   `constraint_refs`. No dangling references. **Enforced at
   `Finding.__post_init__` (step 3 below) because cross-validation needs
   both `required_checks` and `evidence` in the same scope.**
2. **Non-empty contiguous trace** — `reasoning_trace` must be non-empty
   and `step` values must be contiguous from 1. A finding with an empty
   trace is not a finding. **Enforced here in `EvidenceBundle.__post_init__`.**
3. **statement_sources covers statement_digests** — every value in
   `statement_digests` must be a key in `statement_sources`. A cited
   digest with no source locator is a documentation failure.
   **Enforced here.**
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


class InvalidEvidenceError(ValueError):
    """Raised when an `EvidenceBundle` violates one of the §3.5 invariants
    that can be checked locally (non-empty contiguous trace, statement
    sources cover statement digests).

    Cross-validation against `required_checks` is enforced at
    `Finding.__post_init__` and raises `InvalidFindingError` from
    `reasoner.verdict`. The two exception types deliberately differ so
    callers can localize the violation: `InvalidEvidenceError` means
    "the bundle itself is malformed," `InvalidFindingError` means "the
    finding's checks reference evidence the bundle doesn't carry."

    Inherits from ValueError for the same reason `InvalidFindingError`
    does — generic error handling that catches ValueError still picks
    this up.
    """


@dataclass(frozen=True)
class TraceEntry:
    """One step in the reasoner's decision process.

    Per plan §3.5: trace entries form an ordered Q&A log a reviewer can
    walk through to reproduce the reasoner's decision. `step` is 1-based
    and must be contiguous within an EvidenceBundle. `result` is one of
    "PASS", "FAIL", "UNKNOWN" plus a short suffix; `reason` is the longer
    human-readable explanation.
    """

    step: int
    action: str
    inputs: tuple[str, ...]
    result: str
    reason: str


@dataclass(frozen=True)
class EvidenceBundle:
    """Everything needed to audit a finding without re-running the tool.

    Construction enforces invariants 2 and 3 from plan §3.5 (non-empty
    contiguous trace, statement_sources covers statement_digests).
    Invariant 1 (cross-validation against required_checks) is enforced
    at the Finding level because it needs both halves in scope.
    """

    # Statements cited
    statement_digests: tuple[str, ...]
    # Maps digest → (policy_arn_or_id, statement_index, statement_sid)
    statement_sources: dict[str, tuple[str, int, str]]

    # Graph refs
    edge_refs: tuple[str, ...]
    constraint_refs: tuple[str, ...]
    edge_constraint_refs: tuple[str, ...]  # "edge_id|constraint_id" strings
    node_refs: tuple[str, ...]

    # Context assumptions (key, explanation) pairs
    condition_context_assumed: tuple[tuple[str, str], ...]

    # Reasoning trace
    reasoning_trace: tuple[TraceEntry, ...]

    def __post_init__(self) -> None:
        # Invariant 2: non-empty trace with contiguous 1-based step values.
        if not self.reasoning_trace:
            raise InvalidEvidenceError(
                "EvidenceBundle.reasoning_trace must be non-empty. "
                "A finding without a reasoning trace is not a finding — "
                "the trace is what makes the verdict auditable."
            )
        for i, entry in enumerate(self.reasoning_trace):
            expected_step = i + 1
            if entry.step != expected_step:
                raise InvalidEvidenceError(
                    f"EvidenceBundle.reasoning_trace step values must be "
                    f"contiguous from 1. Entry at index {i} has step="
                    f"{entry.step}, expected {expected_step}. "
                    f"A reasoner that skips or duplicates steps has a bug."
                )

        # Invariant 3: statement_sources must cover every statement_digest.
        missing_sources = [digest for digest in self.statement_digests if digest not in self.statement_sources]
        if missing_sources:
            raise InvalidEvidenceError(
                f"EvidenceBundle.statement_sources must contain an entry for "
                f"every value in statement_digests. Missing source locators "
                f"for {len(missing_sources)} digest(s): "
                f"{sorted(missing_sources)[:3]!r}{'...' if len(missing_sources) > 3 else ''}. "
                f"A cited digest with no source locator is a documentation "
                f"failure — the reviewer cannot find the original statement."
            )

    @property
    def bundle_digest(self) -> str:
        """SHA-256 over a canonical JSON serialization of the bundle.

        Used as part of `finding_id` so two findings with identical
        verdicts but different evidence get different IDs. Determinism
        is critical: two runs over the same fact graph must produce the
        same bundle_digest, regardless of dict iteration order or trace
        construction order. The canonical form sorts every field that
        is order-insensitive (digests, refs, assumptions) but preserves
        the trace order because trace order is meaningful (it's the
        reasoner's decision path).

        Note that `statement_sources` is INTENTIONALLY excluded from the
        digest. The locator data (policy_arn, statement_index, statement_sid)
        is presentation-only — its purpose is to point a reviewer at the
        original statement, not to be part of the finding's identity.
        Including it would mean a finding's ID changes whenever AWS
        renames a managed policy or shifts a statement's index, which
        is not the semantic we want.
        """
        canonical = {
            "statement_digests": sorted(self.statement_digests),
            "edge_refs": sorted(self.edge_refs),
            "constraint_refs": sorted(self.constraint_refs),
            "edge_constraint_refs": sorted(self.edge_constraint_refs),
            "node_refs": sorted(self.node_refs),
            "condition_context_assumed": sorted([list(pair) for pair in self.condition_context_assumed]),
            "reasoning_trace": [
                {
                    "step": t.step,
                    "action": t.action,
                    "inputs": sorted(t.inputs),
                    "result": t.result,
                }
                for t in self.reasoning_trace
            ],
        }
        return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
