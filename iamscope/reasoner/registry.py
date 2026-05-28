"""Reasoner registry — S09.

A `Registry` is a pluggable container for `Reasoner` instances. It
supports registration, listing without invocation, and bulk execution
via `run_all`. Per plan §3.3 and the S09 plan row, the registry must
be able to register and list reasoners without running any — so the
listing API does not consult `preconditions_met` or `run`.

Two safety properties:

1. **Duplicate pattern_id rejection.** Two reasoners with the same
   `pattern_id` cannot coexist in one registry. The pattern_id is
   part of the `finding_id` formula, so a collision would silently
   produce duplicate finding IDs across reasoners. Registration of
   the second reasoner raises `ValueError`.

2. **Protocol conformance check.** `register` calls
   `isinstance(reasoner, Reasoner)` before accepting the candidate.
   A class missing one of the four identity attributes or two methods
   gets rejected at registration time, not at run time.

`run_all` semantics:
- For each registered reasoner (in registration order):
  - Call `preconditions_met(facts)`. If `(False, reason)`, skip the
    reasoner entirely. **No findings are emitted for a precondition
    failure** — per plan: "absence of reasoning is not a finding."
  - Else call `run(facts)`. Findings from each reasoner are appended
    to a single output list.
- Returns the combined list. Order within each reasoner's contribution
  is preserved (the reasoner is responsible for emitting in
  deterministic order); order across reasoners follows registration
  order.
- If a reasoner's `run` raises `ReasonerError`, the exception
  propagates (registry does NOT swallow it). The CLI layer (S14) will
  decide whether to log + continue or hard-fail based on the user's
  flag set.

The registry stores `(reasoner, registration_index)` pairs internally
so the registration order can be preserved even if the underlying
container is a dict (for O(1) lookup by pattern_id).
"""

from __future__ import annotations

from dataclasses import dataclass

from iamscope.reasoner.base import Reasoner
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import Finding


@dataclass
class _RegistryEntry:
    """Internal entry: a reasoner plus its registration order index.

    Registration order is preserved so `list_reasoners` and `run_all`
    return reasoners in a stable, predictable sequence.
    """

    reasoner: Reasoner
    registration_index: int


class Registry:
    """Pluggable container for reasoner instances.

    Construction is parameterless; reasoners are added via `register`.
    A typical usage pattern:

        registry = Registry()
        registry.register(CrossAccountTrustReasoner())
        registry.register(PassRoleLambdaReasoner())
        findings = registry.run_all(facts)

    The registry is mutable — you can add or remove reasoners after
    construction — but it is NOT thread-safe. Reasoner registration
    is a setup-time concern, not a run-time concern.
    """

    def __init__(self) -> None:
        # Dict for O(1) pattern_id lookup, keyed by pattern_id.
        # Insertion order is preserved by dict semantics in Python 3.7+,
        # so listing in registration order is free.
        self._entries: dict[str, _RegistryEntry] = {}
        self._next_index: int = 0

    def register(self, reasoner: Reasoner) -> None:
        """Add a reasoner to the registry.

        Args:
            reasoner: An instance of a class satisfying the `Reasoner`
                Protocol structurally. The Protocol check is enforced
                via `isinstance(reasoner, Reasoner)` because the
                Protocol is `runtime_checkable`.

        Raises:
            TypeError: If `reasoner` does not satisfy the `Reasoner`
                Protocol (missing one of the four identity attributes
                or two methods).
            ValueError: If a reasoner with the same `pattern_id` is
                already registered. Pattern IDs must be unique within
                a registry to prevent finding_id collisions.
        """
        if not isinstance(reasoner, Reasoner):
            raise TypeError(
                f"register() requires a Reasoner Protocol implementer, "
                f"got {type(reasoner).__name__}. The candidate is missing "
                f"one of the required attributes (pattern_id, "
                f"pattern_version, pattern_title, severity_default) or "
                f"methods (preconditions_met, run)."
            )

        pattern_id = reasoner.pattern_id
        if pattern_id in self._entries:
            existing = self._entries[pattern_id].reasoner
            raise ValueError(
                f"Cannot register reasoner with pattern_id={pattern_id!r}: "
                f"already registered (existing instance: "
                f"{type(existing).__name__}, new instance: "
                f"{type(reasoner).__name__}). Pattern IDs must be unique "
                f"within a registry — they are part of the finding_id "
                f"formula, and a collision would produce duplicate "
                f"finding IDs across reasoners."
            )

        self._entries[pattern_id] = _RegistryEntry(
            reasoner=reasoner,
            registration_index=self._next_index,
        )
        self._next_index += 1

    def list_reasoners(self) -> tuple[Reasoner, ...]:
        """Return all registered reasoners in registration order.

        Does NOT call `preconditions_met` or `run` on any reasoner —
        listing is purely an introspection operation. The CLI uses
        this to print available reasoners without executing them.
        """
        return tuple(entry.reasoner for entry in self._entries.values())

    def get(self, pattern_id: str) -> Reasoner | None:
        """Look up a reasoner by pattern_id, or None if not registered.

        Convenience for callers that want to invoke a single reasoner
        by name (e.g., the CLI's `--only=passrole_lambda` flag in S14).
        """
        entry = self._entries.get(pattern_id)
        return entry.reasoner if entry is not None else None

    def __len__(self) -> int:
        """Number of registered reasoners."""
        return len(self._entries)

    def __contains__(self, pattern_id: str) -> bool:
        """`pattern_id in registry` membership test."""
        return pattern_id in self._entries

    def run_all(self, facts: FactGraph) -> list[Finding]:
        """Run every registered reasoner against the given fact graph.

        For each reasoner, in registration order:
            1. Call `preconditions_met(facts)`.
            2. If `(False, reason)` — skip the reasoner. No findings
               emitted for this reasoner. **Absence of reasoning is
               not a finding.**
            3. Else call `run(facts)` and append every returned Finding
               to the result list.

        The returned list combines findings from all reasoners that ran
        successfully. Order across reasoners follows registration order;
        order within a reasoner's contribution is preserved as the
        reasoner returned them.

        Args:
            facts: The `FactGraph` to evaluate against.

        Returns:
            A list of `Finding` objects, possibly empty if no reasoner
            ran or all that ran returned `[]`.

        Raises:
            ReasonerError: Propagated unchanged from any reasoner whose
                `run` method raised it. The registry does NOT swallow
                ReasonerError — the caller (CLI) decides whether to
                log + continue or hard-fail.
        """
        all_findings: list[Finding] = []
        for entry in self._entries.values():
            reasoner = entry.reasoner
            ran, _reason = reasoner.preconditions_met(facts)
            if not ran:
                # Skip — absence of reasoning is not a finding. The
                # reason string is available to the caller via separate
                # introspection (S11+ findings_diff may surface it),
                # but it does not appear in the findings list.
                continue
            findings = reasoner.run(facts)
            all_findings.extend(findings)
        return all_findings
