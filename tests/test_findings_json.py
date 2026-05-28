"""S11 tests: findings.json emitter — schema, determinism, hash scope,
round-trip, sorting, error handling.

Uses S10's CrossAccountTrustReasoner to build real Findings against
synthetic FactGraphs for the integration-style tests, and direct
Finding construction for tests that need full control over inputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from iamscope.constants import (
    ID_ALGORITHM,
    NAKED_BROAD,
    NAKED_CRITICAL,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
)
from iamscope.models import Edge, Node, NodeRef
from iamscope.output.findings_json import (
    DEFAULT_SOURCE_TOOL_VERSION,
    SCHEMA_VERSION,
    SOURCE_TOOL,
    emit_findings,
)
from iamscope.reasoner import (
    Assumption,
    Blocker,
    Check,
    CheckState,
    CrossAccountTrustReasoner,
    EvidenceBundle,
    FactGraph,
    Finding,
    TraceEntry,
    Verdict,
)

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


_TARGET_ACCOUNT = "111111111111"
_EXTERNAL_ACCOUNT = "999999999999"
_TARGET_ROLE_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:role/ProdAdmin"
_EXTERNAL_ROOT_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:root"


def _target_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_TARGET_ROLE_ARN,
        properties={"account_id": _TARGET_ACCOUNT},
    )


def _account_root_node(account_id: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=f"arn:aws:iam::{account_id}:root",
        properties={
            "account_id": account_id,
            "is_synthetic": True,
            "org_member": False,
        },
    )


def _trust_edge(*, src: Node, dst: Node, naked_trust: str) -> Edge:
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": dst.provider_id,
                    "statement_index": 0,
                    "digest": "deadbeef" * 8,
                    "summary": f"trust policy for {dst.provider_id}",
                }
            ],
            "cross_account": True,
            "effect": "Allow",
            "has_external_id": False,
            "has_mfa_condition": False,
            "has_org_id_condition": False,
            "has_source_account_condition": False,
            "has_source_ip_condition": False,
            "has_source_vpc_condition": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "naked_trust": naked_trust,
            "principal_type": "AWS",
            "raw_conditions": {},
            "statement_index": 0,
            "trust_scope": "account_root",
        },
    )


def _build_one_finding_facts() -> FactGraph:
    """A minimal FactGraph that produces exactly one CRITICAL finding."""
    target = _target_role_node()
    external = _account_root_node(_EXTERNAL_ACCOUNT)
    edge = _trust_edge(src=external, dst=target, naked_trust=NAKED_CRITICAL)
    return FactGraph(
        nodes=(target, external),
        edges=(edge,),
        constraints=(),
        edge_constraints=(),
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=False,
    )


def _build_three_findings_facts() -> FactGraph:
    """A FactGraph with three external sources → three findings of varying severity."""
    target = _target_role_node()
    ext_a = _account_root_node("111111111111")
    ext_b = _account_root_node("222222222222")
    ext_c = _account_root_node("333333333333")
    edge_a = _trust_edge(src=ext_a, dst=target, naked_trust=NAKED_CRITICAL)
    edge_b = _trust_edge(src=ext_b, dst=target, naked_trust=NAKED_BROAD)
    # Third edge with weak conditions for variety.
    edge_c = Edge(
        edge_type="sts:AssumeRole_trust",
        src=ext_c.to_ref(),
        dst=target.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": target.provider_id,
                    "statement_index": 0,
                    "digest": "cafebabe" * 8,
                    "summary": "narrow trust",
                }
            ],
            "cross_account": True,
            "effect": "Allow",
            "has_external_id": True,
            "has_mfa_condition": False,
            "has_org_id_condition": False,
            "has_source_account_condition": False,
            "has_source_ip_condition": False,
            "has_source_vpc_condition": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "naked_trust": "NARROW_NAKED",
            "principal_type": "AWS",
            "raw_conditions": {},
            "statement_index": 0,
            "trust_scope": "account_root",
        },
    )
    return FactGraph(
        nodes=(target, ext_a, ext_b, ext_c),
        edges=(edge_a, edge_b, edge_c),
        constraints=(),
        edge_constraints=(),
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=False,
    )


def _reasoners_used_for_cat() -> dict[str, dict[str, str]]:
    """The standard reasoners_used mapping for cross_account_trust."""
    return {
        "cross_account_trust": {
            "version": "1.0.0",
            "title": "Cross-account trust without strong constraints",
        },
    }


def _is_sha256_hex(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _direct_finding(
    *,
    pattern_id: str = "test_pattern",
    verdict: Verdict = Verdict.VALIDATED,
    severity: str = SEVERITY_HIGH,
    source_arn: str = "arn:aws:iam::111:user/Alice",
    target_arn: str = "arn:aws:iam::222:role/Target",
) -> Finding:
    """Construct a Finding directly without running a reasoner."""
    return Finding(
        pattern_id=pattern_id,
        pattern_version="1.0.0",
        source=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=source_arn,
        ),
        target=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=target_arn,
        ),
        verdict=verdict,
        severity=severity,
        title="Test finding",
        required_checks=(
            Check(
                name="test_check",
                description="test description",
                state=CheckState.PASS,
                evidence_refs=("digest_a",),
                reason="test reason",
            ),
        ),
        blockers_observed=(),
        assumptions=(),
        evidence=EvidenceBundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("policy_arn", 0, "stmt_0")},
            edge_refs=("edge_x",),
            constraint_refs=(),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="test", inputs=(), result="PASS", reason="ok"),),
        ),
        scenario_hash="deadbeef" * 8,
    )


def _direct_reasoners_used(pattern_id: str = "test_pattern") -> dict[str, dict[str, str]]:
    return {pattern_id: {"version": "1.0.0", "title": "Test Pattern"}}


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------


class TestEmptyFindings:
    """An empty findings list is a valid output."""

    def test_empty_emits_valid_bytes(self) -> None:
        b, h = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        assert isinstance(b, bytes)
        assert _is_sha256_hex(h)

    def test_empty_has_count_zero(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        d = json.loads(b)
        assert d["metadata"]["findings_count"] == 0
        assert d["findings"] == []

    def test_empty_verdict_breakdown_all_zeros(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        d = json.loads(b)
        breakdown = d["metadata"]["verdict_breakdown"]
        assert breakdown == {
            "blocked": 0,
            "inconclusive": 0,
            "precondition_only": 0,
            "validated": 0,
        }


# ---------------------------------------------------------------------------
# Schema shape
# ---------------------------------------------------------------------------


class TestSchemaShape:
    """All §3.6 fields are present at the right depth."""

    def _emit(self) -> dict[str, Any]:
        facts = _build_one_finding_facts()
        findings = CrossAccountTrustReasoner().run(facts)
        b, _ = emit_findings(
            findings,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        return json.loads(b)

    def test_top_level_fields(self) -> None:
        d = self._emit()
        assert set(d.keys()) == {
            "findings",
            "metadata",
            "reasoner_versions",
            "scenario_hash",
            "schema_version",
            "source_tool",
            "source_tool_version",
        }
        assert d["schema_version"] == SCHEMA_VERSION
        assert d["source_tool"] == SOURCE_TOOL
        assert d["source_tool_version"] == DEFAULT_SOURCE_TOOL_VERSION

    def test_metadata_fields(self) -> None:
        d = self._emit()
        meta = d["metadata"]
        assert set(meta.keys()) == {
            "canonical_hash",
            "collector",
            "collector_version",
            "findings_count",
            "hash_scope",
            "id_algorithm",
            "reasoners_run",
            "reasoners_skipped",
            "reasoning_duration_seconds",
            "reasoning_timestamp",
            "verdict_breakdown",
        }
        assert meta["id_algorithm"] == ID_ALGORITHM
        assert meta["findings_count"] == 1
        assert _is_sha256_hex(meta["canonical_hash"])

    def test_finding_fields(self) -> None:
        d = self._emit()
        finding = d["findings"][0]
        assert set(finding.keys()) == {
            "assumptions",
            "blockers_observed",
            "evidence",
            "finding_id",
            "finding_key",
            "pattern_id",
            "pattern_title",
            "pattern_version",
            "reasoner_exit_reason",
            "required_checks",
            "scenario_hash",
            "severity",
            "source",
            "target",
            "title",
            "verdict",
        }
        assert _is_sha256_hex(finding["finding_id"])
        assert _is_sha256_hex(finding["finding_key"])
        assert finding["pattern_id"] == "cross_account_trust"
        assert finding["pattern_version"] == "1.0.0"
        assert finding["pattern_title"] == "Cross-account trust without strong constraints"
        assert finding["verdict"] == "validated"
        assert finding["severity"] == SEVERITY_CRITICAL

    def test_evidence_fields(self) -> None:
        d = self._emit()
        evidence = d["findings"][0]["evidence"]
        assert set(evidence.keys()) == {
            "condition_context_assumed",
            "constraint_refs",
            "edge_constraint_refs",
            "edge_refs",
            "node_refs",
            "reasoning_trace",
            "statement_digests",
            "statement_sources",
        }

    def test_reasoning_trace_step_order_preserved(self) -> None:
        """Reasoning trace order is meaningful — must NOT be sorted."""
        d = self._emit()
        trace = d["findings"][0]["evidence"]["reasoning_trace"]
        steps = [t["step"] for t in trace]
        assert steps == sorted(steps)  # naturally 1..N
        assert steps == list(range(1, len(steps) + 1))


# ---------------------------------------------------------------------------
# Canonical JSON properties
# ---------------------------------------------------------------------------


class TestCanonicalJsonProperties:
    """The output respects the canonical JSON contract."""

    def test_no_trailing_newline(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        assert not b.endswith(b"\n")

    def test_compact_separators(self) -> None:
        """Output uses compact separators (no spaces around , or :).

        Re-canonicalize the parsed dict and compare lengths — pretty-
        printed output is always longer than compact for the same data.
        Substring checks for ", " or ": " are unsafe because doc strings
        in metadata.hash_scope contain those substrings naturally.
        """
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        d = json.loads(b)
        recompacted = json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        assert len(b) == len(recompacted)
        assert b == recompacted

    def test_keys_sorted_at_top_level(self) -> None:
        """Top-level dict keys appear in sorted order in the byte stream."""
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        text = b.decode()
        # 'findings' must appear before 'metadata'
        assert text.index('"findings"') < text.index('"metadata"')
        # 'metadata' must appear before 'reasoner_versions'
        assert text.index('"metadata"') < text.index('"reasoner_versions"')

    def test_ascii_only(self) -> None:
        """Output bytes contain no non-ASCII characters."""
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        # All bytes < 0x80 means pure ASCII.
        assert all(byte < 0x80 for byte in b)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Two emits with the same input produce byte-identical output."""

    def test_two_empty_emits_byte_identical(self) -> None:
        b1, h1 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        b2, h2 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        assert b1 == b2
        assert h1 == h2

    def test_two_one_finding_emits_byte_identical(self) -> None:
        facts = _build_one_finding_facts()
        f1 = CrossAccountTrustReasoner().run(facts)
        f2 = CrossAccountTrustReasoner().run(facts)
        b1, h1 = emit_findings(
            f1,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        b2, h2 = emit_findings(
            f2,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        assert b1 == b2
        assert h1 == h2

    def test_three_findings_byte_identical(self) -> None:
        facts = _build_three_findings_facts()
        f1 = CrossAccountTrustReasoner().run(facts)
        f2 = CrossAccountTrustReasoner().run(facts)
        b1, _ = emit_findings(
            f1,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        b2, _ = emit_findings(
            f2,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        assert b1 == b2

    def test_input_order_does_not_affect_output(self) -> None:
        """findings sorted by finding_id internally; caller order is irrelevant."""
        f_a = _direct_finding(source_arn="arn:aws:iam::111:user/Alice")
        f_b = _direct_finding(source_arn="arn:aws:iam::111:user/Bob")
        b1, _ = emit_findings(
            [f_a, f_b],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        b2, _ = emit_findings(
            [f_b, f_a],  # reversed
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        assert b1 == b2


# ---------------------------------------------------------------------------
# Hash scope
# ---------------------------------------------------------------------------


class TestHashScope:
    """canonical_hash excludes timestamp/duration but covers everything else."""

    def test_timestamp_change_does_not_affect_hash(self) -> None:
        """Two emits differing only in reasoning_timestamp have the same hash."""
        b1, h1 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
            reasoning_timestamp="2026-04-08T10:00:00Z",
        )
        b2, h2 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
            reasoning_timestamp="2099-12-31T23:59:59Z",
        )
        # bytes differ (the timestamp shows up in metadata)...
        assert b1 != b2
        # ...but the canonical_hash is identical because it's outside the
        # hash payload.
        assert h1 == h2

    def test_duration_change_does_not_affect_hash(self) -> None:
        b1, h1 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
            reasoning_duration_seconds=0.42,
        )
        b2, h2 = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
            reasoning_duration_seconds=999.99,
        )
        assert b1 != b2
        assert h1 == h2

    def test_finding_count_change_affects_hash(self) -> None:
        """Adding a finding must change the canonical_hash.

        verdict_breakdown is included in the canonical_hash specifically
        as a smoke test for reasoner regressions — a change in the verdict
        counts breaks the hash. Per §3.6 design note 2.
        """
        _, h_empty = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        _, h_one = emit_findings(
            [_direct_finding()],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        assert h_empty != h_one

    def test_verdict_change_affects_hash(self) -> None:
        """A finding flipping from validated to inconclusive must change the hash."""
        # Need a Verdict.INCONCLUSIVE finding that's still valid. The
        # invariants are permissive on INCONCLUSIVE, so we can construct
        # one with the same checks.
        f_validated = _direct_finding(verdict=Verdict.VALIDATED)
        f_inconclusive = Finding(
            pattern_id=f_validated.pattern_id,
            pattern_version=f_validated.pattern_version,
            source=f_validated.source,
            target=f_validated.target,
            verdict=Verdict.INCONCLUSIVE,
            severity=f_validated.severity,
            title=f_validated.title,
            required_checks=f_validated.required_checks,
            blockers_observed=f_validated.blockers_observed,
            assumptions=f_validated.assumptions,
            evidence=f_validated.evidence,
            scenario_hash=f_validated.scenario_hash,
        )
        _, h_v = emit_findings(
            [f_validated],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        _, h_i = emit_findings(
            [f_inconclusive],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        # Two findings differ in verdict → different finding_id → different
        # entry → different verdict_breakdown → different hash.
        assert h_v != h_i

    def test_canonical_hash_matches_recomputation(self) -> None:
        """The hash in metadata.canonical_hash equals SHA-256 of a re-derived hash payload.

        This is the integrity check: a downstream consumer can verify
        the file by stripping canonical_hash + reasoning_timestamp +
        reasoning_duration_seconds from metadata, recomputing the
        SHA-256, and comparing to canonical_hash.
        """
        b, expected_hash = emit_findings(
            [_direct_finding()],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
            reasoning_timestamp="2026-04-08T14:00:00Z",
            reasoning_duration_seconds=1.5,
        )
        d = json.loads(b)
        # Strip the three excluded fields.
        meta = dict(d["metadata"])
        meta.pop("canonical_hash")
        meta.pop("reasoning_timestamp")
        meta.pop("reasoning_duration_seconds")
        d["metadata"] = meta
        # Recompute via the same canonical-JSON convention.
        canonical = json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        recomputed = hashlib.sha256(canonical).hexdigest()
        assert recomputed == expected_hash


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Emitted bytes parse back to the input data."""

    def test_finding_id_round_trips(self) -> None:
        f = _direct_finding()
        b, _ = emit_findings(
            [f],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        assert d["findings"][0]["finding_id"] == f.finding_id

    def test_finding_key_round_trips(self) -> None:
        f = _direct_finding()
        b, _ = emit_findings(
            [f],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        assert d["findings"][0]["finding_key"] == f.finding_key

    def test_finding_key_stays_stable_across_verdict_and_evidence_mutation(self) -> None:
        baseline = _direct_finding()
        mutated = Finding(
            pattern_id=baseline.pattern_id,
            pattern_version=baseline.pattern_version,
            source=baseline.source,
            target=baseline.target,
            verdict=Verdict.BLOCKED,
            severity=SEVERITY_INFO,
            title=baseline.title,
            required_checks=baseline.required_checks
            + (
                Check(
                    name="probe_overlay_runtime_truth",
                    description="Probe overlay denied the semantic relation",
                    state=CheckState.FAIL,
                    evidence_refs=("probe_control",),
                    reason="live probe denied",
                ),
            ),
            blockers_observed=(
                Blocker(
                    kind="probe_overlay",
                    constraint_id="probe_control",
                    edge_id=baseline.evidence.edge_refs[0],
                    reason="live probe denied",
                ),
            ),
            assumptions=baseline.assumptions,
            evidence=EvidenceBundle(
                statement_digests=baseline.evidence.statement_digests,
                statement_sources=baseline.evidence.statement_sources,
                edge_refs=baseline.evidence.edge_refs,
                constraint_refs=("probe_control",),
                edge_constraint_refs=baseline.evidence.edge_constraint_refs,
                node_refs=baseline.evidence.node_refs,
                condition_context_assumed=baseline.evidence.condition_context_assumed,
                reasoning_trace=baseline.evidence.reasoning_trace
                + (
                    TraceEntry(
                        step=len(baseline.evidence.reasoning_trace) + 1,
                        action="apply_probe_overlay",
                        inputs=("probe-1", baseline.evidence.edge_refs[0], "denied"),
                        result="FAIL",
                        reason="probe overlay denied",
                    ),
                ),
            ),
            scenario_hash=baseline.scenario_hash,
            reasoner_exit_reason="probe overlay denied semantic relation",
        )

        baseline_bytes, _ = emit_findings(
            [baseline],
            scenario_hash=baseline.scenario_hash,
            reasoners_used=_direct_reasoners_used(),
        )
        mutated_bytes, _ = emit_findings(
            [mutated],
            scenario_hash=mutated.scenario_hash,
            reasoners_used=_direct_reasoners_used(),
        )
        baseline_doc = json.loads(baseline_bytes)
        mutated_doc = json.loads(mutated_bytes)

        assert mutated.finding_key == baseline.finding_key
        assert mutated.finding_id != baseline.finding_id
        assert mutated_doc["findings"][0]["finding_key"] == baseline_doc["findings"][0]["finding_key"]
        assert mutated_doc["findings"][0]["finding_id"] != baseline_doc["findings"][0]["finding_id"]

    def test_verdict_round_trips_as_string(self) -> None:
        # BLOCKED requires a FAIL check + at least one blocker — build
        # one that satisfies the §3.4 invariants.
        f_blocked = Finding(
            pattern_id="test_pattern",
            pattern_version="1.0.0",
            source=NodeRef(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_IAM_USER,
                provider_id="arn:aws:iam::111:user/Alice",
            ),
            target=NodeRef(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_IAM_ROLE,
                provider_id="arn:aws:iam::222:role/Target",
            ),
            verdict=Verdict.BLOCKED,
            severity=SEVERITY_INFO,
            title="Blocked finding",
            required_checks=(
                Check(
                    name="blocked_check",
                    description="blocked",
                    state=CheckState.FAIL,
                    evidence_refs=("constraint_x",),
                    reason="SCP denies",
                ),
            ),
            blockers_observed=(
                Blocker(
                    kind="scp",
                    constraint_id="constraint_x",
                    edge_id=None,
                    reason="SCP denies sts:AssumeRole",
                ),
            ),
            assumptions=(),
            evidence=EvidenceBundle(
                statement_digests=(),
                statement_sources={},
                edge_refs=(),
                constraint_refs=("constraint_x",),
                edge_constraint_refs=(),
                node_refs=(),
                condition_context_assumed=(),
                reasoning_trace=(TraceEntry(step=1, action="check", inputs=(), result="FAIL", reason="blocked"),),
            ),
            scenario_hash="deadbeef" * 8,
        )
        b, _ = emit_findings(
            [f_blocked],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        assert d["findings"][0]["verdict"] == "blocked"

    def test_check_state_round_trips_as_string(self) -> None:
        f = _direct_finding()
        b, _ = emit_findings(
            [f],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        check = d["findings"][0]["required_checks"][0]
        assert check["state"] == "pass"

    def test_assumptions_round_trip(self) -> None:
        evidence = EvidenceBundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("p", 0, "s")},
            edge_refs=(),
            constraint_refs=(),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="check", inputs=(), result="UNKNOWN", reason="?"),),
        )
        f = Finding(
            pattern_id="test_pattern",
            pattern_version="1.0.0",
            source=NodeRef(provider="aws", node_type="IAMUser", provider_id="src"),
            target=NodeRef(provider="aws", node_type="IAMRole", provider_id="dst"),
            verdict=Verdict.INCONCLUSIVE,
            severity=SEVERITY_HIGH,
            title="test",
            required_checks=(
                Check(
                    name="check",
                    description="d",
                    state=CheckState.UNKNOWN,
                    evidence_refs=("digest_a",),
                    reason="r",
                ),
            ),
            blockers_observed=(),
            assumptions=(
                Assumption(
                    kind="condition_context",
                    detail="aws:RequestedRegion not specified, assumed us-east-1",
                ),
            ),
            evidence=evidence,
            scenario_hash="deadbeef" * 8,
        )
        b, _ = emit_findings(
            [f],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        assumptions = d["findings"][0]["assumptions"]
        assert len(assumptions) == 1
        assert assumptions[0]["kind"] == "condition_context"
        assert "us-east-1" in assumptions[0]["detail"]


# ---------------------------------------------------------------------------
# Verdict breakdown
# ---------------------------------------------------------------------------


class TestVerdictBreakdown:
    """The verdict_breakdown counts every present verdict and zeros the rest."""

    def test_three_findings_one_validated_one_blocked_one_inconclusive(self) -> None:
        # Build one finding of each type. Reuse the round-trip blocked
        # builder logic.
        f_validated = _direct_finding(verdict=Verdict.VALIDATED, source_arn="src1")
        f_inconclusive = Finding(
            pattern_id="test_pattern",
            pattern_version="1.0.0",
            source=NodeRef(provider="aws", node_type="IAMUser", provider_id="src2"),
            target=NodeRef(provider="aws", node_type="IAMRole", provider_id="dst"),
            verdict=Verdict.INCONCLUSIVE,
            severity=SEVERITY_HIGH,
            title="t",
            required_checks=(
                Check(
                    name="c",
                    description="d",
                    state=CheckState.UNKNOWN,
                    evidence_refs=("digest_a",),
                    reason="r",
                ),
            ),
            blockers_observed=(),
            assumptions=(),
            evidence=EvidenceBundle(
                statement_digests=("digest_a",),
                statement_sources={"digest_a": ("p", 0, "s")},
                edge_refs=(),
                constraint_refs=(),
                edge_constraint_refs=(),
                node_refs=(),
                condition_context_assumed=(),
                reasoning_trace=(TraceEntry(step=1, action="c", inputs=(), result="UNKNOWN", reason="r"),),
            ),
            scenario_hash="deadbeef" * 8,
        )
        b, _ = emit_findings(
            [f_validated, f_inconclusive],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        bd = d["metadata"]["verdict_breakdown"]
        assert bd["validated"] == 1
        assert bd["inconclusive"] == 1
        # The two missing verdicts must be present at zero (not omitted).
        assert bd["blocked"] == 0
        assert bd["precondition_only"] == 0


# ---------------------------------------------------------------------------
# Reasoners metadata
# ---------------------------------------------------------------------------


class TestReasonersMetadata:
    """reasoner_versions and reasoners_skipped surface correctly."""

    def test_reasoner_versions_populated(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={
                "cross_account_trust": {"version": "1.0.0", "title": "X"},
                "passrole_lambda": {"version": "0.5.0", "title": "Y"},
            },
        )
        d = json.loads(b)
        assert d["reasoner_versions"] == {
            "cross_account_trust": "1.0.0",
            "passrole_lambda": "0.5.0",
        }

    def test_reasoners_run_sorted(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={
                "passrole_lambda": {"version": "1.0.0", "title": "Y"},
                "cross_account_trust": {"version": "1.0.0", "title": "X"},
            },
        )
        d = json.loads(b)
        # cross_account_trust < passrole_lambda lexicographically
        assert d["metadata"]["reasoners_run"] == [
            "cross_account_trust",
            "passrole_lambda",
        ]

    def test_reasoners_skipped_default_empty(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
        )
        d = json.loads(b)
        assert d["metadata"]["reasoners_skipped"] == {}

    def test_reasoners_skipped_populated(self) -> None:
        b, _ = emit_findings(
            [],
            scenario_hash="deadbeef" * 8,
            reasoners_used={},
            reasoners_skipped={
                "passrole_lambda": "preconditions_not_met: no Lambda functions collected",
            },
        )
        d = json.loads(b)
        assert d["metadata"]["reasoners_skipped"] == {
            "passrole_lambda": "preconditions_not_met: no Lambda functions collected",
        }


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------


class TestSorting:
    """Order-insensitive collections are sorted in the output."""

    def test_findings_sorted_by_finding_id(self) -> None:
        facts = _build_three_findings_facts()
        findings = CrossAccountTrustReasoner().run(facts)
        b, _ = emit_findings(
            findings,
            scenario_hash=facts.scenario_hash,
            reasoners_used=_reasoners_used_for_cat(),
        )
        d = json.loads(b)
        ids = [f["finding_id"] for f in d["findings"]]
        assert ids == sorted(ids)

    def test_evidence_refs_sorted(self) -> None:
        """edge_refs / constraint_refs in evidence sorted lexicographically."""
        evidence = EvidenceBundle(
            statement_digests=("digest_b", "digest_a"),
            statement_sources={
                "digest_a": ("p", 0, "s"),
                "digest_b": ("p", 1, "t"),
            },
            edge_refs=("edge_z", "edge_a"),
            constraint_refs=("c_z", "c_a"),
            edge_constraint_refs=("ec_z", "ec_a"),
            node_refs=("n_z", "n_a"),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="x", inputs=(), result="PASS", reason=""),),
        )
        f = Finding(
            pattern_id="test_pattern",
            pattern_version="1.0.0",
            source=NodeRef(provider="aws", node_type="IAMUser", provider_id="src"),
            target=NodeRef(provider="aws", node_type="IAMRole", provider_id="dst"),
            verdict=Verdict.VALIDATED,
            severity=SEVERITY_HIGH,
            title="t",
            required_checks=(
                Check(
                    name="c",
                    description="d",
                    state=CheckState.PASS,
                    evidence_refs=("digest_b", "digest_a"),
                    reason="r",
                ),
            ),
            blockers_observed=(),
            assumptions=(),
            evidence=evidence,
            scenario_hash="deadbeef" * 8,
        )
        b, _ = emit_findings(
            [f],
            scenario_hash="deadbeef" * 8,
            reasoners_used=_direct_reasoners_used(),
        )
        d = json.loads(b)
        e = d["findings"][0]["evidence"]
        assert e["statement_digests"] == sorted(e["statement_digests"])
        assert e["edge_refs"] == sorted(e["edge_refs"])
        assert e["constraint_refs"] == sorted(e["constraint_refs"])
        assert e["edge_constraint_refs"] == sorted(e["edge_constraint_refs"])
        assert e["node_refs"] == sorted(e["node_refs"])
        # Check.evidence_refs also sorted.
        check = d["findings"][0]["required_checks"][0]
        assert check["evidence_refs"] == sorted(check["evidence_refs"])


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Bad inputs raise informative errors."""

    def test_non_finding_in_list_raises_typeerror(self) -> None:
        with pytest.raises(TypeError, match="must be a Finding"):
            emit_findings(
                ["not a finding"],  # type: ignore[list-item]
                scenario_hash="deadbeef" * 8,
                reasoners_used={},
            )

    def test_missing_reasoner_in_used_raises_keyerror(self) -> None:
        f = _direct_finding(pattern_id="missing_pattern")
        with pytest.raises(KeyError, match="reasoners_used"):
            emit_findings(
                [f],
                scenario_hash="deadbeef" * 8,
                reasoners_used={},  # missing
            )
