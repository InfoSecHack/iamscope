"""Probe overlay helpers for reasoner verdict adjustment.

This module keeps live probe sidecar semantics out of individual reasoners.
It never mutates scenario facts: callers supply edge IDs, and the helper
classifies the latest overlay record for each edge when one exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from iamscope.constants import (
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
    SEVERITY_HIGH,
    SEVERITY_INFO,
)
from iamscope.reasoner.evidence import TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import Blocker, Check, CheckState, Verdict
from iamscope.truth.probe_overlay import ProbeRecord


@dataclass(frozen=True)
class ProbeOverlayAssessment:
    """Reasoner-local interpretation of probe overlay records."""

    records: tuple[ProbeRecord, ...]
    check: Check | None
    blocker: Blocker | None
    verdict_override: Verdict | None
    severity_override: str | None
    exit_reason: str | None
    contributing_control_refs: tuple[str, ...]

    @property
    def has_records(self) -> bool:
        return bool(self.records)


def assess_probe_overlay_for_edges(
    facts: FactGraph,
    edge_ids: tuple[str, ...],
    *,
    check_name: str,
    check_description: str,
) -> ProbeOverlayAssessment:
    """Assess latest relevant probe records for a reasoner edge/path.

    Only live correlated states affect reasoner verdicts in this pass.
    Simulator-only and uncorrelated probe states remain advisory sidecar data
    and are deliberately ignored here.
    """
    latest_records = tuple(records[-1] for edge_id in edge_ids if (records := facts.probe_records_for_edge(edge_id)))
    relevant = tuple(
        record
        for record in latest_records
        if record.probe_state
        in {
            PROBE_STATE_PROBED_CORRELATED_DENIED,
            PROBE_STATE_CONFOUNDED_SKIP,
            PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
            PROBE_STATE_PROBED_CORRELATED_ALLOWED,
        }
    )
    if not relevant:
        return ProbeOverlayAssessment(
            records=(),
            check=None,
            blocker=None,
            verdict_override=None,
            severity_override=None,
            exit_reason=None,
            contributing_control_refs=(),
        )

    denied = _records_with_state(relevant, PROBE_STATE_PROBED_CORRELATED_DENIED)
    confounded = _records_with_state(relevant, PROBE_STATE_CONFOUNDED_SKIP)
    disagreement = _records_with_state(
        relevant,
        PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
    )
    allowed = _records_with_state(relevant, PROBE_STATE_PROBED_CORRELATED_ALLOWED)
    controls = _contributing_control_refs(relevant)

    if denied:
        record = denied[0]
        reason = _reason(
            "live correlated probe denied this edge/path",
            records=denied,
            controls=controls,
        )
        return ProbeOverlayAssessment(
            records=denied,
            check=Check(
                name=check_name,
                description=check_description,
                state=CheckState.FAIL,
                evidence_refs=(record.edge_id,),
                reason=reason,
            ),
            blocker=Blocker(
                kind="probe_overlay",
                constraint_id=controls[0] if controls else None,
                edge_id=record.edge_id,
                reason=reason,
            ),
            verdict_override=Verdict.BLOCKED,
            severity_override=SEVERITY_INFO,
            exit_reason=reason,
            contributing_control_refs=controls,
        )

    if confounded:
        reason = _reason(
            "live probe skipped because the validation surface is confounded",
            records=confounded,
            controls=controls,
        )
        return _inconclusive_assessment(
            records=confounded,
            check_name=check_name,
            check_description=check_description,
            reason=reason,
            controls=controls,
        )

    if disagreement:
        reason = _reason(
            "live probe and declared/simulated truth disagree",
            records=disagreement,
            controls=controls,
        )
        return _inconclusive_assessment(
            records=disagreement,
            check_name=check_name,
            check_description=check_description,
            reason=reason,
            controls=controls,
        )

    allowed_controls = _contributing_control_refs(allowed)
    if any(record.confounded for record in allowed):
        reason = _reason(
            "live correlated probe allowed, but the path is marked confounded",
            records=allowed,
            controls=allowed_controls,
        )
        return _inconclusive_assessment(
            records=allowed,
            check_name=check_name,
            check_description=check_description,
            reason=reason,
            controls=allowed_controls,
        )

    reason = _reason(
        "live correlated probe allowed this edge/path",
        records=allowed,
        controls=allowed_controls,
    )
    return ProbeOverlayAssessment(
        records=allowed,
        check=Check(
            name=check_name,
            description=check_description,
            state=CheckState.PASS,
            evidence_refs=tuple(sorted({record.edge_id for record in allowed})),
            reason=reason,
        ),
        blocker=None,
        verdict_override=None,
        severity_override=None,
        exit_reason=reason,
        contributing_control_refs=allowed_controls,
    )


def probe_overlay_trace_entries(
    assessment: ProbeOverlayAssessment,
    *,
    start_step: int,
) -> tuple[TraceEntry, ...]:
    """Build contiguous trace entries for a probe assessment."""
    entries: list[TraceEntry] = []
    for offset, record in enumerate(assessment.records):
        controls = tuple(record.contributing_control_refs)
        result = assessment.check.state.value.upper() if assessment.check is not None else "PASS"
        entries.append(
            TraceEntry(
                step=start_step + offset,
                action="apply_probe_overlay",
                inputs=(record.edge_id, record.probe_id, record.probe_state) + controls,
                result=result,
                reason=(
                    f"probe_id={record.probe_id}; probe_state={record.probe_state}; "
                    f"confounded={record.confounded}; contributing_controls="
                    f"{','.join(controls) if controls else 'none'}"
                ),
            )
        )
    return tuple(entries)


def _inconclusive_assessment(
    *,
    records: tuple[ProbeRecord, ...],
    check_name: str,
    check_description: str,
    reason: str,
    controls: tuple[str, ...],
) -> ProbeOverlayAssessment:
    return ProbeOverlayAssessment(
        records=records,
        check=Check(
            name=check_name,
            description=check_description,
            state=CheckState.UNKNOWN,
            evidence_refs=tuple(sorted({record.edge_id for record in records})),
            reason=reason,
        ),
        blocker=None,
        verdict_override=Verdict.INCONCLUSIVE,
        severity_override=SEVERITY_HIGH,
        exit_reason=reason,
        contributing_control_refs=controls,
    )


def _records_with_state(
    records: tuple[ProbeRecord, ...],
    probe_state: str,
) -> tuple[ProbeRecord, ...]:
    return tuple(record for record in records if record.probe_state == probe_state)


def _contributing_control_refs(records: tuple[ProbeRecord, ...]) -> tuple[str, ...]:
    refs: set[str] = set()
    for record in records:
        refs.update(record.contributing_control_refs)
    return tuple(sorted(refs))


def _reason(
    prefix: str,
    *,
    records: tuple[ProbeRecord, ...],
    controls: tuple[str, ...],
) -> str:
    probe_bits = ", ".join(f"{record.probe_id}:{record.probe_state}" for record in records)
    control_bits = ", ".join(controls) if controls else "none"
    return f"{prefix}; probes={probe_bits}; contributing_controls={control_bits}"
