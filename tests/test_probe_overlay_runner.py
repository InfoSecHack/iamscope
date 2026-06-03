"""Tests for the thin probe_overlay.json producer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from pytest import CaptureFixture

from iamscope.cli import main
from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
    PROBE_STATE_SIMULATOR_ONLY_DENIED,
    SIMULATOR_STATE_ALLOWED,
    SIMULATOR_STATE_DENIED,
    VALIDATED_STATE_ALLOWED,
    VALIDATED_STATE_DENIED,
)
from iamscope.output.probe_overlay_json import load_probe_overlay
from iamscope.truth.probe_overlay import join_probe_overlay_to_scenario
from iamscope.truth.probe_runner import (
    PROBE_MODE_BOTH,
    PROBE_MODE_CONFOUNDED_SKIP,
    PROBE_MODE_RUNTIME,
    PROBE_MODE_SIMULATOR,
    ProbePlanItem,
    build_probe_overlay_from_plan,
)

_SOURCE = "arn:aws:iam::111111\u003111111:role/Source"
_TARGET = "arn:aws:iam::222222\u003222222:role/Target"
_EDGE_ID = "edge-assume-role-1"
_SCENARIO_HASH = "hash-probe-runner"


class _FakeIamClient:
    def __init__(self, decision: str) -> None:
        self.decision = decision
        self.calls: list[dict[str, Any]] = []

    def simulate_principal_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"EvaluationResults": [{"EvalDecision": self.decision}]}


class _FakeStsClient:
    def __init__(self, *, allow: bool) -> None:
        self.allow = allow
        self.calls: list[dict[str, Any]] = []

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if not self.allow:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized to perform sts:AssumeRole"}},
                "AssumeRole",
            )
        return {"Credentials": {"AccessKeyId": "AKIAEXAMPLE"}}


def _scenario() -> dict[str, Any]:
    return {
        "metadata": {"canonical_hash": _SCENARIO_HASH},
        "nodes": [],
        "edges": [
            {
                "edge_id": _EDGE_ID,
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": _SOURCE},
                "dst": {"provider_id": _TARGET},
            }
        ],
        "constraints": [],
        "edge_constraints": [],
        "objectives": [],
        "observations": [],
    }


def _overlay_for(
    item: ProbePlanItem,
    client_factory: Any,
) -> Any:
    return build_probe_overlay_from_plan(
        scenario=_scenario(),
        plan_items=(item,),
        engagement_run_id="run-test",
        default_region="us-east-1",
        client_factory=client_factory,
        generated_at_utc="2026-01-01T00:00:00Z",
    )


def test_simulator_allowed_overlay_joins_by_edge_id_and_scenario_hash() -> None:
    iam = _FakeIamClient("allowed")
    overlay = _overlay_for(
        ProbePlanItem(mode=PROBE_MODE_SIMULATOR, edge_id=_EDGE_ID),
        lambda _profile, _region, service: iam if service == "iam" else None,
    )

    records_by_edge = join_probe_overlay_to_scenario(_scenario(), overlay)
    record = records_by_edge[_EDGE_ID][0]

    assert overlay.scenario_canonical_hash == _SCENARIO_HASH
    assert record.probe_state == PROBE_STATE_SIMULATOR_ONLY_ALLOWED
    assert record.simulator_state == SIMULATOR_STATE_ALLOWED
    assert record.runtime_state is None
    assert iam.calls[0]["PolicySourceArn"] == _SOURCE
    assert iam.calls[0]["ResourceArns"] == [_TARGET]


def test_simulator_denied_maps_to_simulator_only_denied() -> None:
    iam = _FakeIamClient("implicitDeny")
    overlay = _overlay_for(
        ProbePlanItem(mode=PROBE_MODE_SIMULATOR, source_arn=_SOURCE, target_arn=_TARGET),
        lambda _profile, _region, service: iam if service == "iam" else None,
    )

    record = overlay.probes[0]

    assert record.probe_state == PROBE_STATE_SIMULATOR_ONLY_DENIED
    assert record.simulator_state == SIMULATOR_STATE_DENIED


def test_runtime_allowed_maps_to_correlated_allowed() -> None:
    sts = _FakeStsClient(allow=True)
    overlay = _overlay_for(
        ProbePlanItem(mode=PROBE_MODE_RUNTIME, edge_id=_EDGE_ID, external_id="external-1"),
        lambda _profile, _region, service: sts if service == "sts" else None,
    )

    record = overlay.probes[0]

    assert record.probe_state == PROBE_STATE_PROBED_CORRELATED_ALLOWED
    assert record.runtime_state == VALIDATED_STATE_ALLOWED
    assert sts.calls[0]["RoleArn"] == _TARGET
    assert sts.calls[0]["ExternalId"] == "external-1"


def test_runtime_denied_maps_to_correlated_denied_with_error_digest() -> None:
    sts = _FakeStsClient(allow=False)
    overlay = _overlay_for(
        ProbePlanItem(mode=PROBE_MODE_RUNTIME, edge_id=_EDGE_ID),
        lambda _profile, _region, service: sts if service == "sts" else None,
    )

    record = overlay.probes[0]

    assert record.probe_state == PROBE_STATE_PROBED_CORRELATED_DENIED
    assert record.runtime_state == VALIDATED_STATE_DENIED
    assert record.notes_digest is not None


def test_both_simulator_and_runtime_denied_maps_to_correlated_denied() -> None:
    iam = _FakeIamClient("explicitDeny")
    sts = _FakeStsClient(allow=False)

    def factory(_profile: str | None, _region: str, service: str) -> Any:
        return iam if service == "iam" else sts

    overlay = _overlay_for(
        ProbePlanItem(mode=PROBE_MODE_BOTH, edge_id=_EDGE_ID),
        factory,
    )

    record = overlay.probes[0]

    assert record.probe_state == PROBE_STATE_PROBED_CORRELATED_DENIED
    assert record.simulator_state == SIMULATOR_STATE_DENIED
    assert record.runtime_state == VALIDATED_STATE_DENIED


def test_confounded_skip_never_constructs_aws_client() -> None:
    def factory(_profile: str | None, _region: str, service: str) -> Any:
        raise AssertionError(f"unexpected AWS client for {service}")

    overlay = _overlay_for(
        ProbePlanItem(
            mode=PROBE_MODE_CONFOUNDED_SKIP,
            edge_id=_EDGE_ID,
            confounded_reason="inherited_org_control",
            contributing_control_refs=("p-inherited",),
        ),
        factory,
    )

    record = overlay.probes[0]

    assert record.probe_state == PROBE_STATE_CONFOUNDED_SKIP
    assert record.confounded is True
    assert record.confounded_reason == "inherited_org_control"
    assert record.contributing_control_refs == ("p-inherited",)


def test_probe_overlay_cli_writes_valid_overlay_for_confounded_plan(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(_scenario()), encoding="utf-8")
    plan_path = tmp_path / "probe_plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "engagement_run_id": "run-cli-probe",
                "probes": [
                    {
                        "mode": PROBE_MODE_CONFOUNDED_SKIP,
                        "edge_id": _EDGE_ID,
                        "action_class": ACTION_CLASS_STS_ASSUME_ROLE,
                        "confounded_reason": "cli_confounded",
                        "contributing_control_refs": ["p-cli"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "probe_overlay.json"

    exit_code = main(
        [
            "probe-overlay",
            "--scenario",
            str(scenario_path),
            "--plan",
            str(plan_path),
            "--output",
            str(output_path),
        ]
    )

    out = capsys.readouterr().out
    overlay = load_probe_overlay(output_path)
    records_by_edge = join_probe_overlay_to_scenario(_scenario(), overlay)

    assert exit_code == 0
    assert "Wrote" in out
    assert overlay.engagement_run_id == "run-cli-probe"
    assert records_by_edge[_EDGE_ID][0].probe_state == PROBE_STATE_CONFOUNDED_SKIP


def test_mocked_example_artifact_loads() -> None:
    overlay = load_probe_overlay("tests/fixtures/truth_contract/probe_overlay_producer_example.json")

    assert overlay.engagement_run_id == "run-producer-example"
    assert overlay.probes[0].probe_state == PROBE_STATE_PROBED_CORRELATED_ALLOWED
