"""Confounded environment judgments for Phase 2 truth contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    ACTION_CLASS_VALUES,
    CONSTRAINT_TYPE_SCP,
    EVIDENCE_LEVEL_HEURISTIC,
    EVIDENCE_LEVEL_VALUES,
)
from iamscope.truth.org_controls import has_broad_action_scope, is_action_relevant


@dataclass(frozen=True)
class ConfoundedJudgment:
    account_id: str
    action_class: str
    confounded: bool
    reason: str
    contributing_scps: tuple[str, ...]
    evidence_level: str

    def __post_init__(self) -> None:
        if self.action_class not in ACTION_CLASS_VALUES:
            raise ValueError(f"action_class must be one of {sorted(ACTION_CLASS_VALUES)}, got {self.action_class!r}")
        if self.evidence_level not in EVIDENCE_LEVEL_VALUES:
            raise ValueError(
                f"evidence_level must be one of {sorted(EVIDENCE_LEVEL_VALUES)}, got {self.evidence_level!r}"
            )
        object.__setattr__(self, "contributing_scps", tuple(self.contributing_scps))


def judge_account_confounding(
    account_id: str,
    effective_controls: dict[str, list[dict[str, Any]]],
    action_class: str = ACTION_CLASS_STS_ASSUME_ROLE,
) -> ConfoundedJudgment:
    """Judge whether an account has inherited effective controls for an action."""
    _require_supported_action(action_class)
    controls = effective_controls.get(account_id, [])
    contributing = tuple(
        sorted(
            str(control.get("policy_id") or control.get("constraint_id") or "")
            for control in controls
            if control.get("inherited")
            and control.get("relevant_to_sts_assume_role")
            and control.get("broad_assume_role_scope")
        )
    )
    contributing = tuple(policy_id for policy_id in contributing if policy_id)
    if contributing:
        return ConfoundedJudgment(
            account_id=account_id,
            action_class=action_class,
            confounded=True,
            reason="inherited_org_control_governs_sts_assumerole",
            contributing_scps=contributing,
            evidence_level=EVIDENCE_LEVEL_HEURISTIC,
        )
    return ConfoundedJudgment(
        account_id=account_id,
        action_class=action_class,
        confounded=False,
        reason="no_inherited_org_control_governs_sts_assumerole",
        contributing_scps=(),
        evidence_level=EVIDENCE_LEVEL_HEURISTIC,
    )


def judge_edge_confounding(
    edge: dict[str, Any],
    constraints: list[dict[str, Any]],
    edge_constraints: list[dict[str, Any]],
    action_class: str = ACTION_CLASS_STS_ASSUME_ROLE,
) -> ConfoundedJudgment:
    """Judge edge-level confounding from scenario constraints and bindings."""
    _require_supported_action(action_class)
    account_id = _account_from_provider_id(edge.get("dst", {}).get("provider_id", ""))
    edge_id = str(edge.get("edge_id", ""))
    constraint_by_id = {str(c.get("constraint_id", "")): c for c in constraints}
    bound_constraint_ids = {
        str(ec.get("constraint_id", "")) for ec in edge_constraints if str(ec.get("edge_id", "")) == edge_id
    }
    contributing: list[str] = []
    for constraint_id in sorted(bound_constraint_ids):
        constraint = constraint_by_id.get(constraint_id)
        if not constraint:
            continue
        if constraint.get("constraint_type") != CONSTRAINT_TYPE_SCP:
            continue
        if constraint.get("scope_type") not in {"ROOT", "OU"}:
            continue
        props = constraint.get("properties", {})
        if not isinstance(props, dict):
            continue
        if not is_action_relevant(props, action_class):
            continue
        if not has_broad_action_scope(props, action_class):
            continue
        contributing.append(str(constraint.get("policy_id") or constraint_id))

    if contributing:
        return ConfoundedJudgment(
            account_id=account_id,
            action_class=action_class,
            confounded=True,
            reason="inherited_org_control_governs_sts_assumerole",
            contributing_scps=tuple(sorted(set(contributing))),
            evidence_level=EVIDENCE_LEVEL_HEURISTIC,
        )
    return ConfoundedJudgment(
        account_id=account_id,
        action_class=action_class,
        confounded=False,
        reason="no_inherited_org_control_governs_sts_assumerole",
        contributing_scps=(),
        evidence_level=EVIDENCE_LEVEL_HEURISTIC,
    )


def _require_supported_action(action_class: str) -> None:
    if action_class != ACTION_CLASS_STS_ASSUME_ROLE:
        raise ValueError("Phase 2 confounded detection supports only sts:AssumeRole")


def _account_from_provider_id(provider_id: str) -> str:
    parts = provider_id.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return ""
