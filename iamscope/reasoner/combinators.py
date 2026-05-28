"""Tristate CheckState combinators for multi-action and multi-hop reasoners.

These pure functions combine multiple `CheckState` values into a single
state for reasoners that need to express "all of these must hold" or
"any of these must hold" semantics.

Refuses-to-lie property: every combinator preserves UNKNOWN as a
first-class state. If a combinator can't determine the result without
guessing, it returns UNKNOWN, never PASS or FAIL.

History: `and_tristate` was first added as a `@staticmethod` on
`PassRoleEcsReasoner` for the two-action check 1 (RegisterTaskDefinition
+ RunTask). Promoted to a module-level function here in priority 3b
prep so future multi-action reasoners (Secrets blast radius needs
GetSecretValue + kms:Decrypt) and multi-hop reasoners (AssumeRole chain
needs all hops to be PASS) can import it without copy-pasting.
"""

from __future__ import annotations

from iamscope.reasoner.verdict import CheckState


def and_tristate(a: CheckState, b: CheckState) -> CheckState:
    """AND-combine two tristate CheckStates.

    Truth table::

        a       b       result
        PASS    PASS    PASS
        PASS    UNKNOWN UNKNOWN
        PASS    FAIL    FAIL
        UNKNOWN PASS    UNKNOWN
        UNKNOWN UNKNOWN UNKNOWN
        UNKNOWN FAIL    FAIL
        FAIL    PASS    FAIL
        FAIL    UNKNOWN FAIL
        FAIL    FAIL    FAIL

    Semantics: PASS only if both PASS; FAIL if either FAIL; UNKNOWN
    otherwise (refuses to guess).

    Used by:
        - passrole_ecs check 1 (combine RegisterTaskDefinition + RunTask)
        - passrole_ecs checks 4 and 6 (combine SCP/boundary blockers
          across both ECS witnesses)
        - assume_role_chain (each hop must PASS for the chain to PASS)
    """
    if a is CheckState.FAIL or b is CheckState.FAIL:
        return CheckState.FAIL
    if a is CheckState.PASS and b is CheckState.PASS:
        return CheckState.PASS
    return CheckState.UNKNOWN


def and_tristate_many(states: tuple[CheckState, ...]) -> CheckState:
    """AND-combine N tristate CheckStates.

    Reduces `and_tristate` over a sequence. Empty sequence returns PASS
    (vacuous truth — no checks to fail). Single-element sequence
    returns that element unchanged.

    Used by reasoners with variable-length check lists, like
    assume_role_chain where the number of hops varies per finding.
    """
    if not states:
        return CheckState.PASS
    result = states[0]
    for s in states[1:]:
        result = and_tristate(result, s)
        if result is CheckState.FAIL:
            return CheckState.FAIL  # short-circuit
    return result
