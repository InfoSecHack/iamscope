"""Reasoner base contract — S09.

Defines the `Reasoner` Protocol that every pattern reasoner must satisfy,
plus the `ReasonerError` exception type for unrecoverable reasoner state.
The Protocol is `runtime_checkable` so the registry (S09 step 6) can
verify a candidate via `isinstance` at registration time rather than
discovering a missing method at run time.

Per plan §3.3, every reasoner exposes four class-level identity
attributes (pattern_id, pattern_version, pattern_title, severity_default)
and two methods (preconditions_met, run). The `preconditions_met` method
gates execution: a reasoner that returns `(False, reason)` is skipped
entirely — the caller emits NO findings. Per the plan: "absence of
reasoning is not a finding."

The `run` method returns `list[Finding]`. It must:
- never silently return `[]` for an unrecoverable error condition
  (raise `ReasonerError` instead)
- emit only findings whose `finding_id` is deterministic (Step 1
  finding_id formula) and whose evidence bundle has a non-empty
  reasoning_trace (Step 2 EvidenceBundle invariants)
- return findings in a deterministic order (the registry sorts on
  finding_id during emission, but reasoners that return findings in
  source-derived order make debugging easier)
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import Finding


class ReasonerError(RuntimeError):
    """Raised by a reasoner's `run` method for unrecoverable state.

    Examples of when to raise:
    - The fact graph is missing a required node type the reasoner needs
      (e.g., the cross_account_trust reasoner expects `IAMRole` nodes
      and gets none).
    - The reasoner attempted to compute against malformed binding metadata
      that the validator should have caught earlier.
    - An internal consistency check failed (e.g., the fact graph claims
      an edge has no src node but the reasoner needs to walk back from
      it).

    Examples of when NOT to raise:
    - The fact graph has zero relevant edges for this pattern. That's
      a `preconditions_met == False` case, NOT an error.
    - The reasoner found ambiguity in the evidence. That's an
      `INCONCLUSIVE` finding, NOT an error.
    - The reasoner's checks all FAIL. That's a `BLOCKED` or
      `precondition_only` finding, NOT an error.

    Inherits from RuntimeError because reasoners run inside a registry
    that catches generic RuntimeErrors as a safety net. A custom subclass
    lets the registry distinguish "the reasoner explicitly rejected this
    input" from "the reasoner crashed unexpectedly" in its error logs.
    """


@runtime_checkable
class Reasoner(Protocol):
    """Protocol every pattern reasoner must satisfy.

    Per plan §3.3, runtime_checkable so the registry can call
    `isinstance(candidate, Reasoner)` at registration time. The four
    identity attributes are read by the registry to surface the reasoner
    in CLI listings without invoking it; the two methods carry the
    actual reasoning logic.

    Reasoner authors implement this Protocol via a regular class with
    matching attribute and method signatures. Inheritance is NOT
    required — Protocol membership is structural. A class that happens
    to define all four attributes and both methods satisfies the
    Protocol whether or not it explicitly inherits from `Reasoner`.
    """

    # Identity attributes — read by the registry, never mutated.
    pattern_id: str
    """Stable lowercase snake_case identifier (e.g., "passrole_lambda").
    Part of the finding_id formula. Must be unique within a registry."""

    pattern_version: str
    """Semver string. Bump on logic change. Part of finding_id, so a
    bump produces new IDs against unchanged fact data — that's how
    findings_diff (S11+) surfaces a logic change as old_id deleted +
    new_id added rather than silently changing the verdict on the
    same ID."""

    pattern_title: str
    """Human-readable title for reports and CLI listings."""

    severity_default: str
    """Default severity from SEVERITY_VALUES. The reasoner may override
    per-finding (e.g., upgrade to critical when admin-equivalent), but
    a reasoner with no special-case logic emits this default."""

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Check if the fact graph has enough data to run this reasoner.

        Returns:
            A `(ran, reason)` tuple. If `ran=False`, `reason` explains
            what's missing in human-readable form (e.g., "no Lambda
            functions collected", "edge_budget_exhausted").

        The caller emits NO findings when preconditions fail — not a
        `blocked` or `inconclusive` finding. **Absence of reasoning is
        not a finding.** This is what makes the
        `preconditions_met == False` path different from a reasoner
        that runs but produces zero findings: the former is "I cannot
        evaluate this pattern against this collection," the latter is
        "I evaluated and nothing matched."
        """
        ...

    def run(self, facts: FactGraph) -> list[Finding]:
        """Execute reasoning against the fact graph.

        Returns:
            Zero or more `Finding` objects. Each finding must have:
            - a deterministic `finding_id` (computed from pattern_id,
              pattern_version, source/target provider_ids, and the
              evidence bundle digest)
            - at least one `required_check`
            - an `EvidenceBundle` with non-empty `reasoning_trace`

            The reasoner may return `[]` if it ran successfully but
            found no matching pattern instances. This is distinct from
            `preconditions_met == False`: the empty-result case means
            "I checked and there's nothing here," whereas the
            preconditions case means "I cannot check this collection."

        Raises:
            ReasonerError: For unrecoverable state (malformed fact
                graph, missing required node type, internal
                consistency failure). Never silently returns `[]` for
                error conditions — the registry distinguishes empty
                results from error states for its run summary.
        """
        ...
