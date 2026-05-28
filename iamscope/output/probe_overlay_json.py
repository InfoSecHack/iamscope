"""Canonical JSON load/save for probe overlay sidecars."""

from __future__ import annotations

import json
from pathlib import Path

from iamscope.identity.canonical import canonical_json_bytes
from iamscope.truth.probe_overlay import ProbeOverlay


def emit_probe_overlay(overlay: ProbeOverlay) -> bytes:
    """Emit a probe overlay using IAMScope canonical JSON settings."""
    return canonical_json_bytes(overlay.to_dict())


def load_probe_overlay(path: str | Path) -> ProbeOverlay:
    """Load and validate a probe overlay sidecar."""
    data = json.loads(Path(path).read_bytes())
    return ProbeOverlay.from_dict(data)


def write_probe_overlay(path: str | Path, overlay: ProbeOverlay) -> None:
    """Write a canonical probe overlay sidecar."""
    Path(path).write_bytes(emit_probe_overlay(overlay))
