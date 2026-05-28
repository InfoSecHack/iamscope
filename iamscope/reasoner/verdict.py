"""Reasoner verdict taxonomy and Finding dataclass — S08.

This module defines the closed verdict enum, check state enum, and the
`Finding` dataclass that every reasoner will emit. Invariants are enforced
at `Finding.__post_init__` time so a buggy reasoner cannot ship an
internally inconsistent finding (e.g. `VALIDATED` with an `UNKNOWN` check).

Scope note: this is the S08 subset of the full plan spec. S09 will extend
`Finding` with an `evidence: EvidenceBundle` field and a `finding_id`
property that calls `identity.deterministic_ids.finding_id()`. Both depend
on infrastructure that S09 owns (`reasoner/evidence.py` and the new
`finding_id()` helper in deterministic_ids). S08 ships the structural
skeleton and the invariant validator so S09 can drop evidence in without
rewriting the core.

Per §3.4 of the rebuild plan:
    1. VALIDATED implies all checks PASS AND no assumptions of kind
       "condition_context". A reasoner that assumed anything about runtime
       context cannot claim validated.
    2. BLOCKED implies at least one check FAIL with governance_confidence=
       "complete". The governance_confidence half of this invariant is
       reasoner-level (Finding does not hold the constraint directly); the
       "at least one FAIL" half is enforced here.
    3. edge_budget_exhausted=True forces the reasoner to downgrade any
       VALIDATED or BLOCKED to INCONCLUSIVE. This invariant is enforced at
       the reasoner level because Finding does not hold scenario metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from iamscope.constants import SEVERITY_VALUES
from iamscope.identity.deterministic_ids import finding_id as _compute_finding_id
from iamscope.identity.deterministic_ids import finding_key as _compute_finding_key
from iamscope.models import NodeRef
from iamscope.reasoner.evidence import EvidenceBundle


class InvalidFindingError(ValueError):
    """Raised when a reasoner attempts to construct an internally
    inconsistent `Finding` (e.g. VALIDATED with an UNKNOWN check).

    Inherits from ValueError so generic error-handling code that catches
    ValueError on dataclass construction still picks this up, while
    reasoners that specifically want to distinguish invariant violations
    can `except InvalidFindingError`.
    """


class Verdict(Enum):
    """Closed 4-value reasoner verdict taxonomy.

    See plan §3.4 for the strict, asymmetric definition of each value.
    """

    VALIDATED = "validated"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    PRECONDITION_ONLY = "precondition_only"


class CheckState(Enum):
    """Tristate for individual reasoner checks.

    UNKNOWN is a first-class state, not a fallback. A reasoner that cannot
    determine whether a condition holds must emit UNKNOWN explicitly rather
    than guessing PASS or FAIL.
    """

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Check:
    """One required condition the reasoner evaluated.

    Per plan §3.5 evidence model: each check carries the evidence refs that
    support (or fail to support) the check's state, and a human-readable
    reason. evidence_refs is a tuple of opaque strings that downstream tools
    resolve against scenario.json — typically statement digests, edge IDs,
    or constraint IDs.
    """

    name: str
    description: str
    state: CheckState
    evidence_refs: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, CheckState):
            raise InvalidFindingError(
                f"Check.state must be a CheckState enum member, got {type(self.state).__name__}: {self.state!r}"
            )


@dataclass(frozen=True)
class Blocker:
    """Something the reasoner observed that prevents the pattern.

    Per plan §3.5: blockers attribute concretely why a `BLOCKED` or
    `PRECONDITION_ONLY` verdict was reached. `kind` is an open string (not
    a closed enum) because reasoner authors will add new blocker categories
    as new patterns land. Suggested values: "scp", "boundary",
    "trust_missing", "deny".
    """

    kind: str
    constraint_id: str | None
    edge_id: str | None
    reason: str


@dataclass(frozen=True)
class Assumption:
    """A condition the reasoner assumed favorable because it could not verify.

    The critical kind is `"condition_context"` — if a finding has any
    assumption of this kind, it cannot be `VALIDATED`. See Finding.__post_init__
    invariant 2.
    """

    kind: str
    detail: str


# Sentinel for the condition_context assumption kind. Defined as a module
# constant so reasoners referencing it get a single source of truth.
ASSUMPTION_KIND_CONDITION_CONTEXT = "condition_context"


@dataclass(frozen=True)
class Finding:
    """A reasoner's output: verdict + evidence + invariants.

    Per plan §3.4 verdict invariants and §3.5 evidence invariants
    (enforced at __post_init__):
    1. severity ∈ SEVERITY_VALUES
    2. verdict is a Verdict enum member (runtime type check because
       dataclasses do not validate type annotations at runtime)
    3. required_checks contains only Check instances (same reason)
    4. VALIDATED requires every Check.state == PASS
    5. VALIDATED requires no Assumption.kind == "condition_context"
    6. VALIDATED requires blockers_observed == ()
    7. BLOCKED requires at least one Check.state == FAIL
    8. BLOCKED requires at least one blocker in blockers_observed
    9. PRECONDITION_ONLY requires at least one PASS check AND at least one
       FAIL check (overpermission exists, path is blocked)
    10. PRECONDITION_ONLY requires at least one blocker
    11. INCONCLUSIVE is permissive at the dataclass level (the plan's
        inconclusive rules involve scenario-level state like
        edge_budget_exhausted that Finding does not hold; enforced in the
        reasoner layer, not here)
    12. **§3.5 invariant 1 (S09): every value in any Check.evidence_refs
        must appear in evidence.statement_digests, evidence.edge_refs, or
        evidence.constraint_refs.** No dangling references — a check that
        cites evidence the bundle doesn't carry is a documentation failure
        and prevents the reviewer from auditing the finding.

    The `finding_id` property is lazily computed and cached on first
    access. The cache uses `object.__setattr__` because the dataclass is
    frozen. The formula is part of the deterministic ID layer; see
    `identity.deterministic_ids.finding_id` for the contract.
    """

    # Identity (part of finding_id)
    pattern_id: str
    pattern_version: str
    source: NodeRef
    target: NodeRef

    # Verdict
    verdict: Verdict
    severity: str
    title: str

    # Evidence
    required_checks: tuple[Check, ...]
    blockers_observed: tuple[Blocker, ...]
    assumptions: tuple[Assumption, ...]
    evidence: EvidenceBundle

    # Context
    scenario_hash: str
    reasoner_exit_reason: str = ""

    # Lazy-computed finding_id/finding_key caches. The frozen dataclass cannot use
    # ordinary assignment in `__post_init__`, so the cache uses
    # `object.__setattr__` from the property accessor. `compare=False`
    # ensures two findings with the same identity but uncomputed caches
    # still equal each other.
    _finding_id_cache: str | None = field(default=None, repr=False, compare=False)
    _finding_key_cache: str | None = field(default=None, repr=False, compare=False)

    @property
    def finding_id(self) -> str:
        """Deterministic finding ID — lazily computed on first access.

        Formula: `canonical_id(pattern_id, pattern_version,
                                source.provider_id, target.provider_id,
                                evidence.bundle_digest)`

        Two findings with the same identity must produce the same ID
        across runs. Bumping `pattern_version` produces a new ID even
        against unchanged scenario data — that's how reasoner logic
        changes appear in findings_diff (S11+) as old_id deleted +
        new_id added rather than silently changing the verdict on the
        same ID.
        """
        if self._finding_id_cache is None:
            computed = _compute_finding_id(
                self.pattern_id,
                self.pattern_version,
                self.source.provider_id,
                self.target.provider_id,
                self.evidence.bundle_digest,
            )
            object.__setattr__(self, "_finding_id_cache", computed)
            return computed
        return self._finding_id_cache

    @property
    def finding_key(self) -> str:
        """Stable semantic finding key for replay/diff joins.

        The key identifies the semantic relation for a pattern within a
        scenario: `(pattern_id, scenario_hash, source, target)`. It excludes
        evidence, verdict, and `pattern_version`, so overlays that mutate
        proof details can change `finding_id` while preserving this join key.
        """
        if self._finding_key_cache is None:
            computed = _compute_finding_key(
                self.pattern_id,
                self.source.to_dict(),
                self.target.to_dict(),
                self.scenario_hash,
            )
            object.__setattr__(self, "_finding_key_cache", computed)
            return computed
        return self._finding_key_cache

    def __post_init__(self) -> None:
        # Structural type checks — dataclass annotations do not validate
        # at runtime, and callers could pass a bare string or wrong enum.
        if not isinstance(self.verdict, Verdict):
            raise InvalidFindingError(
                f"Finding.verdict must be a Verdict enum member, got {type(self.verdict).__name__}: {self.verdict!r}"
            )
        if self.severity not in SEVERITY_VALUES:
            raise InvalidFindingError(
                f"Finding.severity must be one of {sorted(SEVERITY_VALUES)}, got {self.severity!r}"
            )
        for i, chk in enumerate(self.required_checks):
            if not isinstance(chk, Check):
                raise InvalidFindingError(
                    f"Finding.required_checks[{i}] must be a Check instance, got {type(chk).__name__}"
                )
        if not isinstance(self.evidence, EvidenceBundle):
            raise InvalidFindingError(
                f"Finding.evidence must be an EvidenceBundle instance, got {type(self.evidence).__name__}"
            )

        # §3.5 invariant 1: every Check.evidence_refs value must appear
        # somewhere in the bundle's reference sets. A dangling ref means
        # the reviewer cannot audit the check.
        self._validate_evidence_cross_references()

        # Verdict-level invariants.
        if self.verdict is Verdict.VALIDATED:
            self._validate_validated_invariants()
        elif self.verdict is Verdict.BLOCKED:
            self._validate_blocked_invariants()
        elif self.verdict is Verdict.PRECONDITION_ONLY:
            self._validate_precondition_only_invariants()
        # INCONCLUSIVE is permissive at the dataclass level — see class
        # docstring for why.

    def _validate_evidence_cross_references(self) -> None:
        """§3.5 invariant 1: every Check.evidence_refs value must appear
        in evidence.statement_digests, evidence.edge_refs, or
        evidence.constraint_refs.

        Implemented as a single pass building a union set rather than
        three repeated lookups, so the error message can list every
        dangling ref at once instead of bailing on the first miss.
        """
        known_refs: set[str] = (
            set(self.evidence.statement_digests) | set(self.evidence.edge_refs) | set(self.evidence.constraint_refs)
        )
        for chk in self.required_checks:
            dangling = [ref for ref in chk.evidence_refs if ref not in known_refs]
            if dangling:
                raise InvalidFindingError(
                    f"Check {chk.name!r} cites evidence_refs that are not "
                    f"present in the EvidenceBundle: {dangling!r}. Every "
                    f"Check.evidence_refs value must appear in the bundle's "
                    f"statement_digests, edge_refs, or constraint_refs. "
                    f"Dangling refs prevent the reviewer from auditing the "
                    f"finding."
                )

    def _validate_validated_invariants(self) -> None:
        """VALIDATED implies all checks PASS, no condition_context
        assumption, and no blockers."""
        for chk in self.required_checks:
            if chk.state is not CheckState.PASS:
                raise InvalidFindingError(
                    f"VALIDATED finding cannot contain a non-PASS check: "
                    f"check {chk.name!r} has state {chk.state.value!r}. "
                    f"A reasoner that cannot prove every required condition "
                    f"must emit INCONCLUSIVE, not VALIDATED."
                )
        for asm in self.assumptions:
            if asm.kind == ASSUMPTION_KIND_CONDITION_CONTEXT:
                raise InvalidFindingError(
                    f"VALIDATED finding cannot rely on a "
                    f"{ASSUMPTION_KIND_CONDITION_CONTEXT!r} assumption. "
                    f"A reasoner that assumed anything about runtime "
                    f"context cannot claim validated. Assumption detail: "
                    f"{asm.detail!r}"
                )
        if self.blockers_observed:
            raise InvalidFindingError(
                f"VALIDATED finding cannot have blockers_observed. "
                f"Got {len(self.blockers_observed)} blocker(s): "
                f"{[b.kind for b in self.blockers_observed]!r}"
            )

    def _validate_blocked_invariants(self) -> None:
        """BLOCKED implies at least one FAIL check and at least one blocker."""
        has_fail = any(chk.state is CheckState.FAIL for chk in self.required_checks)
        if not has_fail:
            raise InvalidFindingError(
                "BLOCKED finding must contain at least one FAIL check. "
                "Got no FAIL checks; use INCONCLUSIVE if the blocker is "
                "not evidenced."
            )
        if not self.blockers_observed:
            raise InvalidFindingError(
                "BLOCKED finding must have at least one entry in "
                "blockers_observed. A reasoner that cannot attribute the "
                "block to a concrete constraint must emit INCONCLUSIVE."
            )

    def _validate_precondition_only_invariants(self) -> None:
        """PRECONDITION_ONLY implies ≥1 PASS check (overpermission exists)
        and ≥1 FAIL check (path is blocked) and ≥1 blocker."""
        has_pass = any(chk.state is CheckState.PASS for chk in self.required_checks)
        has_fail = any(chk.state is CheckState.FAIL for chk in self.required_checks)
        if not has_pass:
            raise InvalidFindingError(
                "PRECONDITION_ONLY finding must contain at least one PASS "
                "check — the overpermission itself must be proven. Without "
                "a PASS check, the correct verdict is INCONCLUSIVE or "
                "BLOCKED."
            )
        if not has_fail:
            raise InvalidFindingError(
                "PRECONDITION_ONLY finding must contain at least one FAIL "
                "check — the working path must be proven blocked. Without "
                "a FAIL check, the correct verdict is VALIDATED (if the "
                "path is open) or INCONCLUSIVE (if the path is unknown)."
            )
        if not self.blockers_observed:
            raise InvalidFindingError(
                "PRECONDITION_ONLY finding must have at least one entry "
                "in blockers_observed, attributing the path block."
            )
