"""Deterministic statement digest computation.

Produces a canonical SHA-256 hash of an IAM policy statement dict.
Two statements that are semantically equivalent (same keys, same values
modulo casing) produce the same digest.

Matches ARF-RT Decision 6 conventions:
- Keys are lowercased and sorted
- String values are lowercased (AWS policy evaluation is case-insensitive for actions)
- Lists preserve order (significant for Condition operators)
- Deterministic JSON serialization (sorted keys, no whitespace)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def statement_digest(statement: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 of a policy statement.

    The statement dict is serialized with sorted keys, no whitespace,
    all string values lowercased. This ensures the same statement
    always produces the same digest regardless of key ordering in
    the original policy document.

    Args:
        statement: A single IAM policy statement dict.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    canonical = _canonicalize(statement)
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonicalize(obj: Any) -> Any:
    """Recursively sort keys and lowercase string values."""
    if isinstance(obj, dict):
        return {k.lower(): _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_canonicalize(item) for item in obj]
    if isinstance(obj, str):
        return obj.lower()
    return obj
