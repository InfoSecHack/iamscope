"""Canonical JSON serialization and SHA-256 digest primitives.

This module lives in `iamscope.identity` because canonical byte
serialization is infrastructure shared across the **identity layer**
(deterministic ID computation: node_id, edge_id, constraint_id,
finding_id, and any future algorithm-version-pinned hash) and the
**output layer** (scenario.json canonical emission and canonical_hash
metadata field).

It does NOT live in `iamscope.output.scenario_json` — which is where
`_canonical_json_bytes` and `_compute_hash` originally lived as
private helpers — because that location couples canonicalization to
scenario emission and creates a circular dependency the moment any
module outside `output/` needs canonical bytes. Session 1's Fix A
already had to reach across that boundary (validate.py's Session 1
hoisted import from `iamscope.output.scenario_json`), and Session 2's
edge-identity redesign needs the same primitives inside `models.py`
— a top-level import from `models.py` → `output.scenario_json`
would cycle through `output.scenario_json` → `iamscope.models` at
line 28 of that module.

Having ONE canonicalization path in the codebase is load-bearing for
a security tool. Two paths (a separate features-canonicalizer in
models.py, say) would create a drift-landmine class of bug where a
future change to one path silently diverges from the other, breaking
the `emit_scenario → validate_scenario` byte-stability contract in a
way that no single test catches at commit time. Extracting to
`iamscope.identity.canonical` makes that class of bug structurally
impossible: every consumer imports from the same module.

The primitives are named WITHOUT underscore prefixes
(`canonical_json_bytes`, `compute_hash`) because they are now public
API. Consumers outside this module import them directly.

Dependencies: hashlib, json, and `iamscope.constants` for the pinned
JSON dumping rules. NO imports from other iamscope modules — that's
the rule that keeps this module dependency-free and usable from
anywhere in the package, including from `iamscope.models`.

Pinned JSON canonicalization contract (matches the pre-v0.2.37
`_canonical_json_bytes` in `iamscope.output.scenario_json` verbatim,
re-homed here as public API):
- Keys sorted lexicographically (`sort_keys=True`)
- Compact separators: `(",", ":")`
- ASCII-safe (`ensure_ascii=True`)
- No trailing newline
- UTF-8 encoded

These rules come from `iamscope.constants` (`JSON_SORT_KEYS`,
`JSON_SEPARATORS`, `JSON_ENSURE_ASCII`) and must NOT be changed
without bumping the `id_algorithm` version string in
`iamscope.identity.deterministic_ids` and regenerating every
fixture with a canonical_hash or embedded edge_id.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from iamscope.constants import (
    JSON_ENSURE_ASCII,
    JSON_SEPARATORS,
    JSON_SORT_KEYS,
)


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize any JSON-native Python object to canonical JSON bytes.

    Canonical JSON rules (pinned, see module docstring):
    - Keys sorted lexicographically
    - Compact separators: (',', ':')
    - ASCII-safe (ensure_ascii=True)
    - No trailing newline
    - UTF-8 encoded

    Args:
        obj: A JSON-serializable Python object. Accepted types:
            str, int, float, bool, None, list, dict (with str keys),
            and arbitrarily nested combinations of the above. Types
            outside this set will raise `TypeError` from `json.dumps`.

    Returns:
        UTF-8 encoded bytes of the canonical JSON representation.
    """
    json_str = json.dumps(
        obj,
        sort_keys=JSON_SORT_KEYS,
        separators=JSON_SEPARATORS,
        ensure_ascii=JSON_ENSURE_ASCII,
    )
    return json_str.encode("utf-8")


def compute_hash(canonical_bytes: bytes) -> str:
    """Compute the SHA-256 hex digest of a byte string.

    Used for `metadata.canonical_hash` (over the canonical scenario
    payload) and — as of v0.2.37 — as a building block for
    `Edge.edge_id` when hashing the `features` dict.

    Args:
        canonical_bytes: The bytes to hash. Typically the output of
            `canonical_json_bytes(obj)`.

    Returns:
        64-character lowercase hex string (SHA-256 digest).
    """
    return hashlib.sha256(canonical_bytes).hexdigest()
