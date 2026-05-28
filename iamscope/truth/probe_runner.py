"""Engagement-scoped producer for probe_overlay.json sidecars.

The runner is intentionally separate from graph production. It joins probe
requests to existing scenario edges, runs optional simulator/runtime checks,
and emits the existing ProbeOverlay schema keyed by edge_id and scenario hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from botocore.exceptions import ClientError

from iamscope.auth.session import get_client, get_session
from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    ACTION_CLASS_VALUES,
    PROBE_KIND_OPERATOR,
    PROBE_KIND_RUNTIME,
    PROBE_KIND_SIMULATOR,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
    PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
    PROBE_STATE_SIMULATOR_ONLY_DENIED,
    SIMULATOR_STATE_ALLOWED,
    SIMULATOR_STATE_DENIED,
    SIMULATOR_STATE_NOT_RUN,
    VALIDATED_STATE_ALLOWED,
    VALIDATED_STATE_DENIED,
    VALIDATED_STATE_NOT_PROBED,
)
from iamscope.truth.confounded import judge_edge_confounding
from iamscope.truth.probe_overlay import (
    PROBE_OVERLAY_SCHEMA_VERSION,
    ProbeOverlay,
    ProbeRecord,
)

PROBE_MODE_SIMULATOR = "simulator"
PROBE_MODE_RUNTIME = "runtime"
PROBE_MODE_BOTH = "both"
PROBE_MODE_CONFOUNDED_SKIP = "confounded_skip"
PROBE_MODE_VALUES: frozenset[str] = frozenset(
    {
        PROBE_MODE_SIMULATOR,
        PROBE_MODE_RUNTIME,
        PROBE_MODE_BOTH,
        PROBE_MODE_CONFOUNDED_SKIP,
    }
)


class AwsClientFactory(Protocol):
    def __call__(self, profile_name: str | None, region_name: str, service_name: str) -> Any:
        """Return an AWS client for service_name."""


@dataclass(frozen=True)
class ProbePlanItem:
    """One requested probe against one scenario edge."""

    mode: str
    source_arn: str | None = None
    target_arn: str | None = None
    edge_id: str | None = None
    action_class: str = ACTION_CLASS_STS_ASSUME_ROLE
    external_id: str | None = None
    simulator_profile: str | None = None
    runtime_profile: str | None = None
    region_name: str | None = None
    confounded_reason: str = ""
    contributing_control_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in PROBE_MODE_VALUES:
            raise ValueError(f"mode must be one of {sorted(PROBE_MODE_VALUES)}, got {self.mode!r}")
        if self.action_class not in ACTION_CLASS_VALUES:
            raise ValueError(f"action_class must be one of {sorted(ACTION_CLASS_VALUES)}, got {self.action_class!r}")
        object.__setattr__(self, "contributing_control_refs", tuple(self.contributing_control_refs))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbePlanItem:
        return cls(
            mode=str(data["mode"]),
            source_arn=data.get("source_arn"),
            target_arn=data.get("target_arn"),
            edge_id=data.get("edge_id"),
            action_class=str(data.get("action_class", ACTION_CLASS_STS_ASSUME_ROLE)),
            external_id=data.get("external_id"),
            simulator_profile=data.get("simulator_profile"),
            runtime_profile=data.get("runtime_profile"),
            region_name=data.get("region_name"),
            confounded_reason=str(data.get("confounded_reason", "")),
            contributing_control_refs=tuple(data.get("contributing_control_refs", ())),
        )


def load_probe_plan(path: str | Path) -> tuple[str | None, tuple[ProbePlanItem, ...]]:
    """Load a probe plan JSON file.

    Accepted shape:
      {"engagement_run_id": "optional", "probes": [{...}]}
    """
    data = json.loads(Path(path).read_bytes())
    probes = tuple(ProbePlanItem.from_dict(item) for item in data.get("probes", []))
    return data.get("engagement_run_id"), probes


def build_probe_overlay_from_plan(
    *,
    scenario: dict[str, Any],
    plan_items: tuple[ProbePlanItem, ...],
    engagement_run_id: str,
    default_profile: str | None = None,
    default_region: str = "us-east-1",
    respect_confounders: bool = False,
    client_factory: AwsClientFactory | None = None,
    generated_at_utc: str | None = None,
) -> ProbeOverlay:
    """Run a probe plan and return a schema-valid ProbeOverlay."""
    if client_factory is None:
        client_factory = _default_client_factory
    generated_at = generated_at_utc or _utc_now()
    scenario_hash = _scenario_hash(scenario)
    records: list[ProbeRecord] = []
    for item in plan_items:
        edge = _resolve_edge(scenario, item)
        if edge is None:
            raise ValueError("probe plan item does not match any scenario edge")
        edge_id = str(edge["edge_id"])
        region = item.region_name or default_region
        profile_for_simulator = item.simulator_profile or default_profile
        profile_for_runtime = item.runtime_profile or default_profile

        confounder = judge_edge_confounding(
            edge=edge,
            constraints=list(scenario.get("constraints", [])),
            edge_constraints=list(scenario.get("edge_constraints", [])),
            action_class=item.action_class,
        )
        if item.mode == PROBE_MODE_CONFOUNDED_SKIP or (respect_confounders and confounder.confounded):
            controls = item.contributing_control_refs or confounder.contributing_scps
            records.append(
                _record(
                    engagement_run_id=engagement_run_id,
                    edge_id=edge_id,
                    action_class=item.action_class,
                    probe_kind=PROBE_KIND_OPERATOR,
                    probe_state=PROBE_STATE_CONFOUNDED_SKIP,
                    probed_at_utc=generated_at,
                    simulator_state=SIMULATOR_STATE_NOT_RUN,
                    runtime_state=VALIDATED_STATE_NOT_PROBED,
                    confounded=True,
                    confounded_reason=item.confounded_reason or confounder.reason or "confounded_probe_surface",
                    contributing_control_refs=controls,
                )
            )
            continue

        simulator_state: str | None = None
        runtime_state: str | None = None
        probe_kind = PROBE_KIND_OPERATOR
        notes_digest: str | None = None
        if item.mode in (PROBE_MODE_SIMULATOR, PROBE_MODE_BOTH):
            simulator_state = _run_simulator(
                client_factory(profile_for_simulator, region, "iam"),
                source_arn=_edge_source(edge),
                target_arn=_edge_target(edge),
                action_class=item.action_class,
            )
            probe_kind = PROBE_KIND_SIMULATOR
        if item.mode in (PROBE_MODE_RUNTIME, PROBE_MODE_BOTH):
            runtime_state, notes_digest = _run_runtime_sts(
                client_factory(profile_for_runtime, region, "sts"),
                target_arn=_edge_target(edge),
                external_id=item.external_id,
                session_name=_session_name(engagement_run_id, edge_id),
            )
            probe_kind = PROBE_KIND_RUNTIME

        probe_state = _probe_state_for_result(
            mode=item.mode,
            simulator_state=simulator_state,
            runtime_state=runtime_state,
        )
        records.append(
            _record(
                engagement_run_id=engagement_run_id,
                edge_id=edge_id,
                action_class=item.action_class,
                probe_kind=probe_kind,
                probe_state=probe_state,
                probed_at_utc=generated_at,
                simulator_state=simulator_state,
                runtime_state=runtime_state,
                confounded=False,
                confounded_reason="",
                contributing_control_refs=item.contributing_control_refs,
                notes_digest=notes_digest,
            )
        )

    return ProbeOverlay(
        schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
        engagement_run_id=engagement_run_id,
        scenario_canonical_hash=scenario_hash,
        generated_at_utc=generated_at,
        probes=tuple(records),
    )


def build_probe_overlay_from_paths(
    *,
    scenario_path: str | Path,
    plan_path: str | Path,
    output_path: str | Path,
    engagement_run_id: str | None = None,
    default_profile: str | None = None,
    default_region: str = "us-east-1",
    respect_confounders: bool = False,
) -> ProbeOverlay:
    """Load scenario/plan, run probes, and write probe_overlay.json."""
    from iamscope.output.probe_overlay_json import write_probe_overlay

    scenario = json.loads(Path(scenario_path).read_bytes())
    plan_run_id, plan_items = load_probe_plan(plan_path)
    run_id = engagement_run_id or plan_run_id or _run_id()
    overlay = build_probe_overlay_from_plan(
        scenario=scenario,
        plan_items=plan_items,
        engagement_run_id=run_id,
        default_profile=default_profile,
        default_region=default_region,
        respect_confounders=respect_confounders,
    )
    write_probe_overlay(output_path, overlay)
    return overlay


def _run_simulator(
    iam_client: Any,
    *,
    source_arn: str,
    target_arn: str,
    action_class: str,
) -> str:
    response = iam_client.simulate_principal_policy(
        PolicySourceArn=source_arn,
        ActionNames=[action_class],
        ResourceArns=[target_arn],
    )
    results = response.get("EvaluationResults", [])
    decision = str(results[0].get("EvalDecision", "")) if results else ""
    if decision == "allowed":
        return SIMULATOR_STATE_ALLOWED
    return SIMULATOR_STATE_DENIED


def _run_runtime_sts(
    sts_client: Any,
    *,
    target_arn: str,
    external_id: str | None,
    session_name: str,
) -> tuple[str, str | None]:
    params: dict[str, str] = {
        "RoleArn": target_arn,
        "RoleSessionName": session_name,
    }
    if external_id:
        params["ExternalId"] = external_id
    try:
        sts_client.assume_role(**params)
    except ClientError as e:
        code = str(e.response.get("Error", {}).get("Code", ""))
        message = str(e.response.get("Error", {}).get("Message", ""))
        if code in {"AccessDenied", "AccessDeniedException"} or "not authorized" in message.lower():
            return VALIDATED_STATE_DENIED, _notes_digest(code, message)
        raise
    return VALIDATED_STATE_ALLOWED, None


def _probe_state_for_result(
    *,
    mode: str,
    simulator_state: str | None,
    runtime_state: str | None,
) -> str:
    if mode == PROBE_MODE_SIMULATOR:
        return (
            PROBE_STATE_SIMULATOR_ONLY_ALLOWED
            if simulator_state == SIMULATOR_STATE_ALLOWED
            else PROBE_STATE_SIMULATOR_ONLY_DENIED
        )
    if mode == PROBE_MODE_RUNTIME:
        return (
            PROBE_STATE_PROBED_CORRELATED_ALLOWED
            if runtime_state == VALIDATED_STATE_ALLOWED
            else PROBE_STATE_PROBED_CORRELATED_DENIED
        )
    if runtime_state == VALIDATED_STATE_ALLOWED and simulator_state == SIMULATOR_STATE_ALLOWED:
        return PROBE_STATE_PROBED_CORRELATED_ALLOWED
    if runtime_state == VALIDATED_STATE_DENIED and simulator_state == SIMULATOR_STATE_DENIED:
        return PROBE_STATE_PROBED_CORRELATED_DENIED
    return PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT


def _record(
    *,
    engagement_run_id: str,
    edge_id: str,
    action_class: str,
    probe_kind: str,
    probe_state: str,
    probed_at_utc: str,
    simulator_state: str | None,
    runtime_state: str | None,
    confounded: bool,
    confounded_reason: str,
    contributing_control_refs: tuple[str, ...],
    notes_digest: str | None = None,
) -> ProbeRecord:
    return ProbeRecord(
        probe_id=_probe_id(engagement_run_id, edge_id, probe_state, probed_at_utc),
        edge_id=edge_id,
        action_class=action_class,
        probe_kind=probe_kind,
        probe_state=probe_state,
        probed_at_utc=probed_at_utc,
        authorization_ref=None,
        confounded=confounded,
        confounded_reason=confounded_reason,
        contributing_control_refs=tuple(contributing_control_refs),
        simulator_state=simulator_state,
        runtime_state=runtime_state,
        cloudtrail_state=None,
        notes_digest=notes_digest,
    )


def _resolve_edge(scenario: dict[str, Any], item: ProbePlanItem) -> dict[str, Any] | None:
    edges = list(scenario.get("edges", []))
    if item.edge_id:
        for edge in edges:
            if str(edge.get("edge_id", "")) == item.edge_id:
                return cast(dict[str, Any], edge)
        return None
    matches = []
    for edge in edges:
        edge_type = str(edge.get("edge_type", ""))
        if not edge_type.lower().startswith(item.action_class.lower()):
            continue
        if item.source_arn and _edge_source(edge) != item.source_arn:
            continue
        if item.target_arn and _edge_target(edge) != item.target_arn:
            continue
        matches.append(edge)
    return cast(dict[str, Any], sorted(matches, key=lambda e: str(e.get("edge_id", "")))[0]) if matches else None


def _edge_source(edge: dict[str, Any]) -> str:
    return str(edge.get("src", {}).get("provider_id", ""))


def _edge_target(edge: dict[str, Any]) -> str:
    return str(edge.get("dst", {}).get("provider_id", ""))


def _scenario_hash(scenario: dict[str, Any]) -> str:
    scenario_hash = scenario.get("metadata", {}).get("canonical_hash")
    if not scenario_hash:
        raise ValueError("scenario metadata.canonical_hash is required")
    return str(scenario_hash)


def _default_client_factory(profile_name: str | None, region_name: str, service_name: str) -> Any:
    session = get_session(profile_name=profile_name, region_name=region_name)
    return get_client(session, service_name, region_name=region_name)


def _probe_id(engagement_run_id: str, edge_id: str, probe_state: str, probed_at_utc: str) -> str:
    digest = hashlib.sha256("\0".join((engagement_run_id, edge_id, probe_state, probed_at_utc)).encode()).hexdigest()[
        :16
    ]
    return f"probe-{digest}"


def _notes_digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _session_name(engagement_run_id: str, edge_id: str) -> str:
    suffix = hashlib.sha256(f"{engagement_run_id}\0{edge_id}".encode()).hexdigest()[:12]
    return f"iamscope-probe-{suffix}"


def _run_id() -> str:
    return f"run-{hashlib.sha256(_utc_now().encode()).hexdigest()[:16]}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
