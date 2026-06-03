"""Hypothesis strategies for IAMScope domain objects.

Property-based testing needs generators ("strategies") that produce
random but well-typed instances of the domain objects we want to
exercise. This module provides strategies for `Check`, `Blocker`,
`Assumption`, `TraceEntry`, `EvidenceBundle`, `NodeRef`, and `Finding`
in each of its four verdict shapes (VALIDATED, BLOCKED,
PRECONDITION_ONLY, INCONCLUSIVE).

The strategies respect the domain invariants — a `validated_finding`
strategy only generates findings where ALL checks are PASS, there are
no blockers, and there are no condition_context assumptions. This
means property tests can use the strategies to drive Finding
construction without tripping the `_validate_validated_invariants`
guards on every attempt.

Cross-reference handling: because `Finding.__post_init__` enforces
that every `Check.evidence_refs` value appears in the bundle's
reference pools, the strategies use a shared reference pool
internally — the EvidenceBundle strategy generates a pool of
statement/edge/constraint refs, then the Check strategy draws from
that same pool for its `evidence_refs` field.

Design principle: strategies compose. The `finding_strategy`
functions take optional keyword args to inject custom sub-strategies
when a test needs a specific shape (e.g., "generate a finding with
exactly this many checks" or "generate a finding with these source
and target ARNs").
"""

from __future__ import annotations

from hypothesis import strategies as st

from iamscope.constants import (
    PROVIDER_AWS,
    REGION_GLOBAL,
    SEVERITY_VALUES,
)
from iamscope.models import NodeRef
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.verdict import (
    ASSUMPTION_KIND_CONDITION_CONTEXT,
    Assumption,
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

#: All four verdict shapes.
_VERDICTS = tuple(Verdict)

#: All three check states.
_CHECK_STATES = tuple(CheckState)

#: All five severity values.
_SEVERITIES = tuple(sorted(SEVERITY_VALUES))

#: Node types that appear in real fact graphs. The strategy deliberately
#: uses a closed set because arbitrary strings would produce NodeRefs
#: that no reasoner would ever emit.
_NODE_TYPES = (
    "IAMUser",
    "IAMRole",
    "IAMGroup",
    "S3Bucket",
    "SecretsManagerSecret",
    "KMSKey",
    "LambdaFunction",
    "ECSCluster",
    "EC2Instance",
)


def severity_strategy() -> st.SearchStrategy[str]:
    """Pick one of the five canonical severity values."""
    return st.sampled_from(_SEVERITIES)


def check_state_strategy() -> st.SearchStrategy[CheckState]:
    """Pick one of PASS/FAIL/UNKNOWN."""
    return st.sampled_from(_CHECK_STATES)


def verdict_strategy() -> st.SearchStrategy[Verdict]:
    """Pick one of the four verdict shapes."""
    return st.sampled_from(_VERDICTS)


def _opaque_id_strategy(prefix: str) -> st.SearchStrategy[str]:
    """Generate opaque ref-id strings like "edge-00000001".

    Uses an integer counter mapped to a padded hex string. This is
    substantially faster than regex-based strategies because
    hypothesis can shrink integers directly without parsing regex
    backtracking state.
    """
    return st.integers(min_value=0, max_value=2**32 - 1).map(lambda n: f"{prefix}-{n:08x}")


def sha256_digest_strategy() -> st.SearchStrategy[str]:
    """Generate a 64-char hex string (statement digest shape).

    Uses two 128-bit integers concatenated as padded hex — fast to
    shrink and produces well-typed digest-shaped strings.
    """
    return st.tuples(
        st.integers(min_value=0, max_value=2**128 - 1),
        st.integers(min_value=0, max_value=2**128 - 1),
    ).map(lambda pair: f"{pair[0]:032x}{pair[1]:032x}")


def provider_id_strategy() -> st.SearchStrategy[str]:
    """Generate plausible AWS ARNs for node identities."""
    return st.sampled_from(
        [
            "arn:aws:iam::111111\u003111111:user/Alice",
            "arn:aws:iam::111111\u003111111:user/Bob",
            "arn:aws:iam::111111\u003111111:role/DeployerRole",
            "arn:aws:iam::111111\u003111111:role/AdminRole",
            "arn:aws:iam::111111\u003111111:group/Admins",
            "arn:aws:s3:::corp-secrets",
            "arn:aws:s3:::public-assets",
            "arn:aws:secretsmanager:us-east-1:111111\u003111111:secret:prod/db",
            "arn:aws:kms:us-east-1:111111\u003111111:key/abcd1234",
            "arn:aws:lambda:us-east-1:111111\u003111111:function:worker",
        ]
    )


# ---------------------------------------------------------------------------
# Model objects
# ---------------------------------------------------------------------------


def node_ref_strategy() -> st.SearchStrategy[NodeRef]:
    """Generate a NodeRef."""
    return st.builds(
        NodeRef,
        provider=st.just(PROVIDER_AWS),
        node_type=st.sampled_from(_NODE_TYPES),
        provider_id=provider_id_strategy(),
        region=st.just(REGION_GLOBAL),
    )


def trace_entry_strategy(step: int) -> st.SearchStrategy[TraceEntry]:
    """Generate a TraceEntry with a specific step number."""
    return st.builds(
        TraceEntry,
        step=st.just(step),
        action=st.text(min_size=1, max_size=30),
        inputs=st.tuples(st.text(min_size=1, max_size=20)),
        result=st.sampled_from(["PASS", "FAIL", "UNKNOWN"]),
        reason=st.text(min_size=1, max_size=60),
    )


@st.composite
def trace_strategy(
    draw: st.DrawFn,
    *,
    min_size: int = 1,
    max_size: int = 5,
) -> tuple[TraceEntry, ...]:
    """Generate a non-empty contiguous trace (step 1..n)."""
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    entries = []
    for i in range(1, n + 1):
        entries.append(draw(trace_entry_strategy(i)))
    return tuple(entries)


def blocker_strategy() -> st.SearchStrategy[Blocker]:
    """Generate a Blocker."""
    return st.builds(
        Blocker,
        kind=st.sampled_from(
            [
                "scp",
                "permission_boundary",
                "trust_missing",
                "kms_key_policy",
                "deny",
            ]
        ),
        constraint_id=st.one_of(
            st.none(),
            _opaque_id_strategy("constraint"),
        ),
        edge_id=st.one_of(st.none(), _opaque_id_strategy("edge")),
        reason=st.text(min_size=1, max_size=60),
    )


def assumption_strategy(
    *,
    exclude_condition_context: bool = False,
) -> st.SearchStrategy[Assumption]:
    """Generate an Assumption, optionally excluding condition_context."""
    kinds = ["non_binding", "partial_model"]
    if not exclude_condition_context:
        kinds.append(ASSUMPTION_KIND_CONDITION_CONTEXT)
    return st.builds(
        Assumption,
        kind=st.sampled_from(kinds),
        detail=st.text(min_size=1, max_size=60),
    )


@st.composite
def check_strategy(
    draw: st.DrawFn,
    *,
    state: CheckState | None = None,
    evidence_refs_pool: tuple[str, ...] = (),
) -> Check:
    """Generate a Check with optional forced state and ref pool.

    If `state` is None, the strategy picks one randomly. If
    `evidence_refs_pool` is provided, the Check's evidence_refs are
    drawn from that pool (so the resulting Check is cross-reference
    valid against a bundle built from the same pool).
    """
    chosen_state = state if state is not None else draw(check_state_strategy())
    if evidence_refs_pool:
        n_refs = draw(st.integers(min_value=1, max_value=min(3, len(evidence_refs_pool))))
        refs = tuple(
            draw(
                st.lists(
                    st.sampled_from(evidence_refs_pool),
                    min_size=n_refs,
                    max_size=n_refs,
                    unique=True,
                )
            )
        )
    else:
        refs = ()
    return Check(
        name=draw(st.text(min_size=1, max_size=40)),
        description=draw(st.text(min_size=0, max_size=60)),
        state=chosen_state,
        evidence_refs=refs,
        reason=draw(st.text(min_size=1, max_size=60)),
    )


@st.composite
def evidence_bundle_strategy(
    draw: st.DrawFn,
    *,
    min_refs: int = 1,
    max_refs: int = 5,
    max_trace: int = 5,
) -> tuple[EvidenceBundle, tuple[str, ...]]:
    """Generate a valid EvidenceBundle and return it with its ref pool.

    Returns (bundle, ref_pool) — the second element is the combined
    tuple of statement digests + edge refs + constraint refs that the
    Check strategy can draw from to produce cross-reference-valid
    Checks. Separating the pool from the bundle lets test callers
    build coordinated Check collections.
    """
    n_stmts = draw(st.integers(min_value=0, max_value=max_refs))
    stmt_digests = tuple(
        draw(
            st.lists(
                sha256_digest_strategy(),
                min_size=n_stmts,
                max_size=n_stmts,
                unique=True,
            )
        )
    )
    stmt_sources = {d: (f"arn:aws:iam::111:policy/P{i}", i, f"stmt-{i}") for i, d in enumerate(stmt_digests)}

    n_edges = draw(st.integers(min_value=0, max_value=max_refs))
    edge_refs = tuple(
        draw(
            st.lists(
                _opaque_id_strategy("edge"),
                min_size=n_edges,
                max_size=n_edges,
                unique=True,
            )
        )
    )

    n_constraints = draw(st.integers(min_value=0, max_value=max_refs))
    constraint_refs = tuple(
        draw(
            st.lists(
                _opaque_id_strategy("constraint"),
                min_size=n_constraints,
                max_size=n_constraints,
                unique=True,
            )
        )
    )

    n_nodes = draw(st.integers(min_value=0, max_value=max_refs))
    node_refs = tuple(
        draw(
            st.lists(
                _opaque_id_strategy("node"),
                min_size=n_nodes,
                max_size=n_nodes,
                unique=True,
            )
        )
    )

    # Ensure pool is non-empty so Checks have SOMETHING to reference.
    pool = stmt_digests + edge_refs + constraint_refs
    if not pool:
        # Force at least one ref into the pool so downstream Checks
        # can always produce a valid evidence_refs list.
        edge_refs = (draw(_opaque_id_strategy("edge")),)
        pool = stmt_digests + edge_refs + constraint_refs

    trace = draw(trace_strategy(min_size=1, max_size=max_trace))

    bundle = EvidenceBundle(
        statement_digests=stmt_digests,
        statement_sources=stmt_sources,
        edge_refs=edge_refs,
        constraint_refs=constraint_refs,
        edge_constraint_refs=(),
        node_refs=node_refs,
        condition_context_assumed=(),
        reasoning_trace=trace,
    )
    return bundle, pool


# ---------------------------------------------------------------------------
# Finding shapes — one strategy per verdict
# ---------------------------------------------------------------------------


@st.composite
def validated_finding_strategy(draw: st.DrawFn) -> Finding:
    """Generate a finding that satisfies the VALIDATED invariants.

    - All checks PASS
    - No blockers
    - No condition_context assumptions
    - Cross-reference valid
    """
    bundle, pool = draw(evidence_bundle_strategy())
    n_checks = draw(st.integers(min_value=1, max_value=5))
    checks = tuple(draw(check_strategy(state=CheckState.PASS, evidence_refs_pool=pool)) for _ in range(n_checks))
    n_assumptions = draw(st.integers(min_value=0, max_value=2))
    assumptions = tuple(draw(assumption_strategy(exclude_condition_context=True)) for _ in range(n_assumptions))
    return Finding(
        pattern_id=draw(
            st.sampled_from(
                [
                    "secrets_blast_radius",
                    "passrole_lambda",
                    "assume_role_chain",
                    "admin_reachability",
                    "cross_account_trust",
                    "iam_group_membership_escalation",
                    "s3_bucket_takeover",
                ]
            )
        ),
        pattern_version="1.0.0",
        source=draw(node_ref_strategy()),
        target=draw(node_ref_strategy()),
        verdict=Verdict.VALIDATED,
        severity=draw(severity_strategy()),
        title=draw(st.text(min_size=1, max_size=80)),
        required_checks=checks,
        blockers_observed=(),
        assumptions=assumptions,
        evidence=bundle,
        scenario_hash="s" * 64,
        reasoner_exit_reason=draw(st.text(min_size=0, max_size=60)),
    )


@st.composite
def blocked_finding_strategy(draw: st.DrawFn) -> Finding:
    """Generate a finding satisfying BLOCKED invariants.

    - ≥1 FAIL check
    - ≥1 blocker
    """
    bundle, pool = draw(evidence_bundle_strategy())
    n_other_checks = draw(st.integers(min_value=0, max_value=3))
    fail_check = draw(
        check_strategy(
            state=CheckState.FAIL,
            evidence_refs_pool=pool,
        )
    )
    other_checks = tuple(
        draw(
            check_strategy(
                state=draw(st.sampled_from([CheckState.PASS, CheckState.FAIL])),
                evidence_refs_pool=pool,
            )
        )
        for _ in range(n_other_checks)
    )
    checks = (fail_check,) + other_checks
    n_blockers = draw(st.integers(min_value=1, max_value=3))
    blockers = tuple(draw(blocker_strategy()) for _ in range(n_blockers))
    return Finding(
        pattern_id="secrets_blast_radius",
        pattern_version="1.0.0",
        source=draw(node_ref_strategy()),
        target=draw(node_ref_strategy()),
        verdict=Verdict.BLOCKED,
        severity=draw(severity_strategy()),
        title=draw(st.text(min_size=1, max_size=80)),
        required_checks=checks,
        blockers_observed=blockers,
        assumptions=(),
        evidence=bundle,
        scenario_hash="s" * 64,
        reasoner_exit_reason="blocked by constraint",
    )


@st.composite
def inconclusive_finding_strategy(draw: st.DrawFn) -> Finding:
    """Generate a finding with INCONCLUSIVE verdict.

    INCONCLUSIVE is permissive at the dataclass level — any mix of
    check states is accepted. The strategy generates a mix including
    at least one UNKNOWN check (since the reason to emit INCONCLUSIVE
    is typically an UNKNOWN check in practice).
    """
    bundle, pool = draw(evidence_bundle_strategy())
    unknown_check = draw(
        check_strategy(
            state=CheckState.UNKNOWN,
            evidence_refs_pool=pool,
        )
    )
    n_other = draw(st.integers(min_value=0, max_value=3))
    other_checks = tuple(draw(check_strategy(evidence_refs_pool=pool)) for _ in range(n_other))
    checks = (unknown_check,) + other_checks
    return Finding(
        pattern_id="secrets_blast_radius",
        pattern_version="1.0.0",
        source=draw(node_ref_strategy()),
        target=draw(node_ref_strategy()),
        verdict=Verdict.INCONCLUSIVE,
        severity=draw(severity_strategy()),
        title=draw(st.text(min_size=1, max_size=80)),
        required_checks=checks,
        blockers_observed=(),
        assumptions=(),
        evidence=bundle,
        scenario_hash="s" * 64,
        reasoner_exit_reason="inconclusive due to UNKNOWN check",
    )


@st.composite
def precondition_only_finding_strategy(draw: st.DrawFn) -> Finding:
    """Generate a finding satisfying PRECONDITION_ONLY invariants.

    - ≥1 PASS check (overpermission proven)
    - ≥1 FAIL check (path blocked)
    - ≥1 blocker
    """
    bundle, pool = draw(evidence_bundle_strategy())
    pass_check = draw(
        check_strategy(
            state=CheckState.PASS,
            evidence_refs_pool=pool,
        )
    )
    fail_check = draw(
        check_strategy(
            state=CheckState.FAIL,
            evidence_refs_pool=pool,
        )
    )
    checks = (pass_check, fail_check)
    blockers = (draw(blocker_strategy()),)
    return Finding(
        pattern_id="secrets_blast_radius",
        pattern_version="1.0.0",
        source=draw(node_ref_strategy()),
        target=draw(node_ref_strategy()),
        verdict=Verdict.PRECONDITION_ONLY,
        severity=draw(severity_strategy()),
        title=draw(st.text(min_size=1, max_size=80)),
        required_checks=checks,
        blockers_observed=blockers,
        assumptions=(),
        evidence=bundle,
        scenario_hash="s" * 64,
        reasoner_exit_reason="precondition not met",
    )


def any_finding_strategy() -> st.SearchStrategy[Finding]:
    """Union strategy: generate a finding of any valid verdict shape."""
    return st.one_of(
        validated_finding_strategy(),
        blocked_finding_strategy(),
        inconclusive_finding_strategy(),
        precondition_only_finding_strategy(),
    )
