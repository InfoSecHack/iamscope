"""Deterministic ID generation for IAMScope.

Algorithm: sha256_null_separated_v2 (bumped from v1 in v0.2.37)
- Fields are stripped and lowercased
- Joined with NULL byte separator (\\x00)
- SHA-256 hashed
- Full hex digest (64 chars)

This algorithm is PINNED. Changing it breaks ARF-RT references,
observation logs, and cross-run comparisons. The algorithm version
is recorded in output metadata as `id_algorithm` (see
`iamscope.constants.ID_ALGORITHM`).

### v1 → v2 migration (v0.2.37, reviewer Top 10 #2)

v1 `edge_id` was computed from only
    (edge_type, src_provider_id, dst_provider_id, region)
which meant two semantically different edges between the same
principals — e.g., an MFA-conditioned trust and an unconditioned
trust — collided on a single edge_id. The pipeline's
`seen_edge_ids` dedup then silently dropped one of them (the
second by statement-index order), producing a fact graph that
lost the MFA protection signal entirely and corrupted every
downstream evidence path that keyed on edge_id.

v2 adds the canonical-JSON-encoded `features` dict as a fifth
field to the `edge_id` formula. Two edges with identical
(edge_type, src, dst, region) but differing features are now
assigned distinct edge_ids — including the MFA-vs-naked trust
case, permission edges with vs without conditions, and wildcard
vs literal-ARN resource references that happen to share the
permission shape.

**Migration contract for downstream consumers:**
- v1 and v2 scenarios are NOT edge-id-comparable. A v1 scenario's
  edge_ids cannot be correlated to a v2 scenario's edge_ids for
  the same logical edges — the hash inputs differ, so the hex
  values differ.
- v1 and v2 findings from `findings_diff` should be treated as
  separate ID spaces. Bumping the `id_algorithm` metadata field
  from v1 to v2 IS the signal that downstream correlators should
  not attempt cross-version edge-id matching.
- The `id_algorithm` metadata field documents which formula
  produced the edge_ids in a given scenario. Consumers should
  read that field and gate any edge-id comparison on equality.

Pinned formulas (v2):
- node_id       = canonical_id(provider, node_type, provider_id)
- edge_id       = canonical_id(edge_type, src_provider_id,
                                dst_provider_id, region,
                                features_digest)
                  where features_digest is
                  canonical_json_bytes(features).decode("utf-8")
- constraint_id = canonical_id(provider, constraint_type,
                                scope_type, scope_id, policy_id,
                                statement_id)

`node_id` and `constraint_id` formulas are UNCHANGED between
v1 and v2 — only `edge_id` gained the features_digest field.
A pure v1→v2 re-emit on the same inputs produces identical node
and constraint IDs, and v2-only-different edge IDs for edges
whose features participated in the v1 collision.
"""

import hashlib
import json
from typing import Any


def canonical_id(*fields: str) -> str:
    """Compute deterministic ID from ordered fields.

    All strings are stripped and lowercased before hashing.
    Fields are joined with NULL byte (\\x00) separator.
    Returns SHA-256 full hex digest (64 characters).

    Args:
        *fields: Ordered string fields to hash. Each field is
                 stripped of leading/trailing whitespace and
                 lowercased before joining.

    Returns:
        64-character lowercase hex string (SHA-256 digest).

    Raises:
        ValueError: If any field is not a string or is empty after stripping.
    """
    if not fields:
        raise ValueError("canonical_id requires at least one field")

    processed: list[str] = []
    for i, field in enumerate(fields):
        if not isinstance(field, str):
            raise ValueError(f"canonical_id field {i} must be a string, got {type(field).__name__}: {field!r}")
        stripped = field.strip().lower()
        if not stripped:
            raise ValueError(f"canonical_id field {i} is empty after stripping: {field!r}")
        processed.append(stripped)

    canonical = "\x00".join(processed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def node_id(provider: str, node_type: str, provider_id: str) -> str:
    """Compute deterministic node ID.

    Formula: canonical_id(provider, node_type, provider_id)

    Args:
        provider: Provider string (e.g., "aws").
        node_type: Node type string (e.g., "IAMRole").
        provider_id: Provider-specific ID (e.g., full ARN).

    Returns:
        64-character hex string.
    """
    return canonical_id(provider, node_type, provider_id)


def edge_id(
    edge_type: str,
    src_provider_id: str,
    dst_provider_id: str,
    region: str,
    features_digest: str,
) -> str:
    """Compute deterministic edge ID (sha256_null_separated_v2).

    Formula: canonical_id(edge_type, src_provider_id, dst_provider_id,
                          region, features_digest)

    v2 (v0.2.37+) adds `features_digest` as a required fifth field —
    see module docstring for the v1→v2 migration rationale (reviewer
    Top 10 #2: MFA-vs-naked trust edge collision).

    Args:
        edge_type: Edge type string (e.g., "sts:AssumeRole_trust").
        src_provider_id: Source principal ARN or synthetic ID.
        dst_provider_id: Destination principal ARN or synthetic ID.
        region: Region string ("-" for global/non-regional).
        features_digest: Canonical JSON bytes of the Edge's features
            dict, decoded as a UTF-8 string — produced by
            `canonical_json_bytes(features).decode("utf-8")` at the
            call site, NOT pre-hashed separately. The caller passes
            the raw canonical-JSON string and this function feeds it
            into the same null-separated SHA-256 as the other
            fields, so the whole edge_id computation is one hash
            pass, not two. An empty features dict canonicalizes to
            the two-character string `"{}"` which is distinct from
            any non-empty features canonicalization, so no-features
            edges hash consistently.

    Returns:
        64-character hex string.
    """
    return canonical_id(edge_type, src_provider_id, dst_provider_id, region, features_digest)


def constraint_id(
    provider: str,
    constraint_type: str,
    scope_type: str,
    scope_id: str,
    policy_id: str,
    statement_id: str,
) -> str:
    """Compute deterministic constraint ID.

    Formula: canonical_id(provider, constraint_type, scope_type,
                          scope_id, policy_id, statement_id)

    Per Phase A R14: statement_id is included to avoid collisions
    when multiple statements from the same SCP produce separate
    constraint objects.

    Args:
        provider: Provider string (e.g., "aws").
        constraint_type: Constraint type (e.g., "SCP").
        scope_type: Scope type (e.g., "OU", "ACCOUNT").
        scope_id: Scope identifier (e.g., OU ID or account ID).
        policy_id: Policy identifier (e.g., SCP policy ID).
        statement_id: Statement Sid or index string (e.g., "DenyAssumeRole" or "stmt_0").

    Returns:
        64-character hex string.
    """
    return canonical_id(provider, constraint_type, scope_type, scope_id, policy_id, statement_id)


def edge_constraint_sort_key(ec_edge_id: str, ec_constraint_id: str) -> tuple[str, str]:
    """Compute sort key for edge_constraint entries.

    Sort order: (edge_id, constraint_id) lexicographic tuple.

    Args:
        ec_edge_id: The edge_id this binding references.
        ec_constraint_id: The constraint_id this binding references.

    Returns:
        Tuple of (edge_id, constraint_id) for sorting.
    """
    return (ec_edge_id, ec_constraint_id)


def finding_id(
    pattern_id: str,
    pattern_version: str,
    source_provider_id: str,
    target_provider_id: str,
    evidence_bundle_digest: str,
) -> str:
    """Compute deterministic finding ID — S09 reasoner layer.

    Formula: canonical_id(pattern_id, pattern_version, source_provider_id,
                          target_provider_id, evidence_bundle_digest)

    Two runs against the same scenario with the same reasoner version must
    produce identical finding_ids. Bumping `pattern_version` forces a new ID
    even against unchanged scenario data — this is how reasoner logic
    changes are tracked through findings_diff: a "we fixed a bug in the
    reasoner" change shows up as old_id deleted + new_id added rather than
    silently changing the verdict on the same ID.

    Including `evidence_bundle_digest` in the formula means two findings
    with identical (pattern, source, target) but different evidence
    (different statements cited, different edges examined) get different
    IDs — preventing collision when a reasoner re-analyzes the same source/
    target pair under expanded evidence (e.g., a new constraint that wasn't
    examined in the prior run).

    Args:
        pattern_id: Stable lowercase snake_case reasoner identifier
                    (e.g., "passrole_lambda", "cross_account_trust").
        pattern_version: Semver string; bump on logic change.
        source_provider_id: Source principal's full ARN or synthetic ID.
        target_provider_id: Target principal/resource's full ARN or synthetic ID.
        evidence_bundle_digest: SHA-256 digest from EvidenceBundle.bundle_digest.

    Returns:
        64-character lowercase hex string (SHA-256 digest).

    Raises:
        ValueError: If any field is empty after stripping (per canonical_id rules).
    """
    return canonical_id(
        pattern_id,
        pattern_version,
        source_provider_id,
        target_provider_id,
        evidence_bundle_digest,
    )


def finding_key(
    pattern_id: str,
    source: dict[str, Any],
    target: dict[str, Any],
    scenario_hash: str,
) -> str:
    """Compute stable semantic finding key for findings_diff joins.

    Formula: sha256(canonical_json({
        "pattern_id": pattern_id,
        "scenario_hash": scenario_hash,
        "source": source,
        "target": target,
    }))

    Unlike `finding_id`, this deliberately excludes `pattern_version`,
    verdict fields, and evidence bundle digest. Runtime proof overlays or
    evidence changes can therefore produce a new `finding_id` while keeping
    the same semantic `finding_key` for diffing and replay joins.
    """
    material = json.dumps(
        {
            "pattern_id": pattern_id,
            "scenario_hash": scenario_hash,
            "source": source,
            "target": target,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()
