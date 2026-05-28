"""Closed action-class helpers for truth-contract sidecars."""

from __future__ import annotations

from iamscope.constants import ACTION_CLASS_VALUES


def validate_action_class(action_class: str) -> str:
    """Return a valid action class or raise ValueError."""
    if action_class not in ACTION_CLASS_VALUES:
        raise ValueError(f"action_class must be one of {sorted(ACTION_CLASS_VALUES)}, got {action_class!r}")
    return action_class
