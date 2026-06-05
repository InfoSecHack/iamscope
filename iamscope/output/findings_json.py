"""Findings JSON emitter — canonical, deterministic, byte-stable.

Emits `findings.json` in the §3.6 sidecar schema. Output is canonical
JSON: sorted keys, compact separators, ASCII-safe, no trailing newline.
A SHA-256 self-hash is stored in `metadata.canonical_hash` and computed
over a hash payload that excludes `canonical_hash` itself plus the two
non-deterministic timestamp fields (`reasoning_timestamp`,
`reasoning_duration_seconds`). This means the same scenario + same
reasoners + same versions always produces the same `canonical_hash`,
even across runs separated by hours.

Determinism contract:
    Two `emit_findings` calls with the same Findings + same metadata
    inputs (excluding the two timestamp fields) → byte-identical output
    AND identical canonical_hash.

Sort order (pinned, all order-insensitive collections):
- `findings[]` sorted by `finding_id` (stable across registration order)
- `findings[].evidence.statement_digests[]` sorted lexicographically
- `findings[].evidence.edge_refs[]` sorted lexicographically
- `findings[].evidence.constraint_refs[]` sorted lexicographically
- `findings[].evidence.edge_constraint_refs[]` sorted lexicographically
- `findings[].evidence.node_refs[]` sorted lexicographically
- `findings[].evidence.condition_context_assumed[]` sorted by (key, explanation)
- All dicts (statement_sources, reasoner_versions, etc.) sorted via
  `json.dumps(sort_keys=True)` automatically
- `metadata.reasoners_run[]` sorted lexicographically

Sort order EXCEPTIONS (order is meaningful):
- `findings[].required_checks[]` — reasoner emits in narrative order
  (matches the reasoning_trace step ordering)
- `findings[].blockers_observed[]` — reasoner emits in detection order
- `findings[].assumptions[]` — reasoner emits in detection order
- `findings[].evidence.reasoning_trace[]` — STRICTLY ordered by step,
  reflects the reasoner's decision sequence. Reordering would corrupt
  the audit trail.

The reasoner is responsible for emitting these ordered fields
deterministically; S10's `TestDeterminism` class verifies this for
`cross_account_trust`. Future reasoners must do the same.
"""

from __future__ import annotations

import json
import re
from typing import Any

from iamscope.constants import ID_ALGORITHM, JSON_TRAILING_NEWLINE
from iamscope.identity.canonical import canonical_json_bytes, compute_hash
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.verdict import (
    Assumption,
    Blocker,
    Check,
    Finding,
    Verdict,
)

# Schema version for the findings.json file format. Bump on breaking
# schema changes (field removal, type changes); new optional fields do
# not require a version bump but should be flagged in the changelog.
SCHEMA_VERSION: str = "1.0"

# Constant identifying the source tool. Matches scenario.json metadata.
SOURCE_TOOL: str = "iamscope"

# Default source tool version. Caller can override via the
# `source_tool_version` parameter.
DEFAULT_SOURCE_TOOL_VERSION: str = "0.2.0"

# Hash scope documentation string written to metadata.hash_scope.
# Static string per §3.6 — describes which fields are excluded from the
# canonical hash computation.
_HASH_SCOPE_DOC: str = "canonical_hash excludes canonical_hash, reasoning_timestamp, reasoning_duration_seconds"

# All four Verdict enum values, used to populate verdict_breakdown
# with zero entries for verdicts that don't appear in the findings list.
# Per §3.6 design note 2, the breakdown is part of the canonical_hash
# so a change in counts breaks the hash — that requires the breakdown
# to always have all four keys present (otherwise removing a verdict
# would silently change the dict shape and confuse diffs).
_ALL_VERDICT_KEYS: tuple[str, ...] = tuple(v.value for v in Verdict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit_findings(
    findings: list[Finding],
    *,
    scenario_hash: str,
    reasoners_used: dict[str, dict[str, str]],
    reasoners_skipped: dict[str, str] | None = None,
    reasoning_timestamp: str = "",
    reasoning_duration_seconds: float = 0.0,
    source_tool_version: str = DEFAULT_SOURCE_TOOL_VERSION,
    collection_context_source: dict[str, Any] | None = None,
) -> tuple[bytes, str]:
    """Emit findings.json as canonical bytes with deterministic hash.

    Args:
        findings: List of Finding objects from `Registry.run_all()`.
            May be empty (no findings is a valid output).
        scenario_hash: The canonical hash of the scenario.json this
            reasoning run was computed against. Stored at top level
            and on each finding for self-containment per §3.6 design
            note 1.
        reasoners_used: A dict mapping `pattern_id` to `{"version":
            "x.y.z", "title": "Human Readable"}`. The CLI layer (S14)
            builds this from the registered reasoners before calling.
            Used to populate the top-level `reasoner_versions` field
            and the per-finding `pattern_title` field.
        reasoners_skipped: Optional dict mapping `pattern_id` to a
            reason string for reasoners whose `preconditions_met`
            returned False. Empty dict (or None) is the common case.
            Per §3.6 design note 3, this is how FindingsForge knows
            "absence of findings" means "we ran and found nothing"
            vs "we didn't run."
        reasoning_timestamp: ISO 8601 timestamp of when the reasoning
            ran (e.g., "2026-04-08T14:30:00Z"). Empty string by default.
            **Excluded from canonical_hash** so two runs separated by
            hours over the same data still produce the same hash.
        reasoning_duration_seconds: Duration in seconds. **Excluded
            from canonical_hash** for the same reason.
        source_tool_version: Override for the iamscope version string
            written to top-level `source_tool_version` and
            `metadata.collector_version`.
        collection_context_source: Optional scenario/PipelineResult metadata
            carrying `collection_failures` and `policy_parse_failures`.
            The emitter maps these records onto each finding without
            changing verdict semantics.

    Returns:
        Tuple of (findings_json_bytes, canonical_hash_hex). The bytes
        are the canonical JSON UTF-8 representation; the hash is the
        SHA-256 hex digest written into the bytes' `metadata.canonical_hash`.

    Raises:
        TypeError: If `findings` contains a non-Finding object.
        KeyError: If a finding's `pattern_id` is not in `reasoners_used`.
    """
    if reasoners_skipped is None:
        reasoners_skipped = {}

    # Validate input types up front so the error message points at
    # the bad input rather than at a stack frame inside _finding_to_dict.
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(f"emit_findings: findings[{i}] must be a Finding, got {type(f).__name__}")

    # Sort findings by finding_id for deterministic order regardless of
    # how the caller (Registry, CLI, test) ordered them. Ties are
    # impossible (finding_id is a SHA-256 hash) but we use a stable sort
    # anyway as a defensive measure.
    sorted_findings = sorted(findings, key=lambda f: f.finding_id)

    # Build per-finding dicts. This triggers the lazy `finding_id`
    # property compute on each Finding, populating the cache. Subsequent
    # calls to `f.finding_id` (e.g., for the verdict breakdown) hit the
    # cache.
    finding_dicts = [_finding_to_dict(f, reasoners_used, collection_context_source) for f in sorted_findings]

    # Verdict breakdown — always populated with all four enum values,
    # zero entries for verdicts not present. This makes the field shape
    # stable across emits with different verdict mixes, which matters
    # because verdict_breakdown is part of the canonical_hash.
    verdict_breakdown = _compute_verdict_breakdown(sorted_findings)

    # Reasoner versions — pull from reasoners_used. Sorted via
    # JSON_SORT_KEYS at emit time, but we build a fresh dict to avoid
    # accidental mutation of the caller's input.
    reasoner_versions = {pid: meta["version"] for pid, meta in reasoners_used.items()}

    # Build the metadata block sans the three excluded fields.
    metadata_for_hash: dict[str, Any] = {
        "collector": SOURCE_TOOL,
        "collector_version": source_tool_version,
        "findings_count": len(sorted_findings),
        "hash_scope": _HASH_SCOPE_DOC,
        "id_algorithm": ID_ALGORITHM,
        "reasoners_run": sorted(reasoners_used.keys()),
        "reasoners_skipped": dict(reasoners_skipped),
        "verdict_breakdown": verdict_breakdown,
    }

    # Build the hash payload. Per §3.6, the canonical_hash covers the
    # full document EXCEPT canonical_hash, reasoning_timestamp, and
    # reasoning_duration_seconds. The first is excluded because it's
    # the field we're computing; the latter two because they're
    # non-deterministic and would break byte-stability across runs.
    hash_payload: dict[str, Any] = {
        "findings": finding_dicts,
        "metadata": metadata_for_hash,
        "reasoner_versions": reasoner_versions,
        "scenario_hash": scenario_hash,
        "schema_version": SCHEMA_VERSION,
        "source_tool": SOURCE_TOOL,
        "source_tool_version": source_tool_version,
    }
    canonical_bytes = canonical_json_bytes(hash_payload)
    canonical_hash = compute_hash(canonical_bytes)

    # Build the full document with the three excluded fields restored.
    # The metadata block now carries canonical_hash, reasoning_timestamp,
    # and reasoning_duration_seconds in addition to the hashed fields.
    full_metadata: dict[str, Any] = dict(metadata_for_hash)
    full_metadata["canonical_hash"] = canonical_hash
    full_metadata["reasoning_timestamp"] = reasoning_timestamp
    full_metadata["reasoning_duration_seconds"] = reasoning_duration_seconds

    full_document: dict[str, Any] = {
        "findings": finding_dicts,
        "metadata": full_metadata,
        "reasoner_versions": reasoner_versions,
        "scenario_hash": scenario_hash,
        "schema_version": SCHEMA_VERSION,
        "source_tool": SOURCE_TOOL,
        "source_tool_version": source_tool_version,
    }

    output_bytes = canonical_json_bytes(full_document)
    if JSON_TRAILING_NEWLINE:
        output_bytes += b"\n"
    return output_bytes, canonical_hash


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _compute_verdict_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Count findings by verdict, ensuring all four keys are present.

    Returns a dict with all four Verdict enum values as keys, and the
    count of findings whose verdict matches each key. Verdicts not
    present in the findings list get 0 (not omitted) so the dict shape
    is stable across emits — see the `_ALL_VERDICT_KEYS` rationale.
    """
    breakdown: dict[str, int] = {key: 0 for key in _ALL_VERDICT_KEYS}
    for f in findings:
        breakdown[f.verdict.value] += 1
    return breakdown


def _finding_to_dict(
    finding: Finding,
    reasoners_used: dict[str, dict[str, str]],
    collection_context_source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a Finding to its §3.6 JSON dict shape.

    The `pattern_title` field comes from the `reasoners_used` mapping
    because the Finding dataclass doesn't carry it (S08 design choice
    to keep Finding lean — title is a reasoner-class attribute, not
    finding data).
    """
    pattern_id = finding.pattern_id
    if pattern_id not in reasoners_used:
        raise KeyError(
            f"emit_findings: finding pattern_id={pattern_id!r} is not "
            f"in reasoners_used. Every reasoner that emitted findings "
            f"must be present in reasoners_used so the emitter can "
            f"populate pattern_title. The CLI layer (S14) builds this "
            f"mapping from the registry before calling emit_findings."
        )
    pattern_title = reasoners_used[pattern_id]["title"]

    return {
        "assumptions": [_assumption_to_dict(a) for a in finding.assumptions],
        "blockers_observed": [_blocker_to_dict(b) for b in finding.blockers_observed],
        "collection_context": _collection_context_for_finding(finding, collection_context_source),
        "evidence": _evidence_to_dict(finding.evidence),
        "finding_id": finding.finding_id,
        "finding_key": finding.finding_key,
        "pattern_id": pattern_id,
        "pattern_title": pattern_title,
        "pattern_version": finding.pattern_version,
        "reasoner_exit_reason": finding.reasoner_exit_reason,
        "required_checks": [_check_to_dict(c) for c in finding.required_checks],
        "scenario_hash": finding.scenario_hash,
        "severity": finding.severity,
        "source": finding.source.to_dict(),
        "target": finding.target.to_dict(),
        "title": finding.title,
        "verdict": finding.verdict.value,
    }


def _collection_context_for_finding(
    finding: Finding,
    collection_context_source: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build deterministic per-finding partial-collection context.

    Reasoners should not know about collection coverage. The emitter has
    enough presentation context to attach scenario-level collection and
    parse failures to each finding by source/target account or exact
    source/target ARN while preserving verdict semantics.
    """
    source = collection_context_source or {}
    collection_failures = _normalise_failure_records(source.get("collection_failures", []))
    policy_parse_failures = _normalise_failure_records(source.get("policy_parse_failures", []))
    finding_accounts = sorted(
        {
            account
            for account in (
                _extract_aws_account_id(finding.source.provider_id),
                _extract_aws_account_id(finding.target.provider_id),
            )
            if account
        }
    )
    finding_provider_ids = {finding.source.provider_id, finding.target.provider_id}

    related_collection_failures = [
        failure for failure in collection_failures if str(failure.get("account_id", "")) in finding_accounts
    ]
    related_policy_parse_failures: list[dict[str, Any]] = []
    account_level_policy_match = False
    for failure in policy_parse_failures:
        source_arn = str(failure.get("source_arn", ""))
        failure_account = _extract_aws_account_id(source_arn) or _extract_aws_account_id(
            str(failure.get("policy_arn", ""))
        )
        if source_arn in finding_provider_ids:
            related_policy_parse_failures.append(failure)
        elif failure_account and failure_account in finding_accounts:
            related_policy_parse_failures.append(failure)
            account_level_policy_match = True

    related_collection_failures = _sort_failure_records(related_collection_failures)
    related_policy_parse_failures = _sort_failure_records(related_policy_parse_failures)

    coverage_notes: list[str] = []
    if collection_failures and not related_collection_failures:
        coverage_notes.append("collection was partial; no direct account match found for this finding")
    if policy_parse_failures and not related_policy_parse_failures:
        coverage_notes.append(
            "policy parsing was partial; no direct source/target account match found for this finding"
        )
    if account_level_policy_match:
        coverage_notes.append("policy parse failure related by account, not exact source/target ARN")

    affected_accounts = sorted(
        {
            str(failure.get("account_id", ""))
            for failure in related_collection_failures
            if str(failure.get("account_id", ""))
        }
        | {
            account
            for failure in related_policy_parse_failures
            for account in (
                _extract_aws_account_id(str(failure.get("source_arn", ""))),
                _extract_aws_account_id(str(failure.get("policy_arn", ""))),
            )
            if account
        }
    )

    has_collection_failures = bool(collection_failures)
    has_policy_parse_failures = bool(policy_parse_failures)
    return {
        "affected_accounts": affected_accounts,
        "coverage_notes": sorted(set(coverage_notes)),
        "graph_collection_complete": not (has_collection_failures or has_policy_parse_failures),
        "has_collection_failures": has_collection_failures,
        "has_policy_parse_failures": has_policy_parse_failures,
        "related_collection_failures": related_collection_failures,
        "related_policy_parse_failures": related_policy_parse_failures,
    }


def _normalise_failure_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    records: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            records.append({str(key): _safe_context_value(val) for key, val in item.items()})
    return _sort_failure_records(records)


def _sort_failure_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda record: json.dumps(record, sort_keys=True, separators=(",", ":")))


def _safe_context_value(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\r", " ").replace("\n", " ")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value).replace("\r", " ").replace("\n", " ")


def _extract_aws_account_id(provider_id: str) -> str:
    match = re.match(r"^arn:[^:]*:[^:]*::([0-9]{12}):", provider_id)
    return match.group(1) if match else ""


def _check_to_dict(check: Check) -> dict[str, Any]:
    """Convert a Check to its §3.6 dict shape.

    `evidence_refs` is sorted lexicographically — Check refs are
    order-insensitive (the reasoner cites the set of evidence the
    check inspected). Sort gives byte-stable output.
    """
    return {
        "description": check.description,
        "evidence_refs": sorted(check.evidence_refs),
        "name": check.name,
        "reason": check.reason,
        "state": check.state.value,
    }


def _blocker_to_dict(blocker: Blocker) -> dict[str, Any]:
    """Convert a Blocker to its §3.6 dict shape."""
    return {
        "constraint_id": blocker.constraint_id,
        "edge_id": blocker.edge_id if blocker.edge_id is not None else "",
        "kind": blocker.kind,
        "reason": blocker.reason,
    }


def _assumption_to_dict(assumption: Assumption) -> dict[str, Any]:
    """Convert an Assumption to its §3.6 dict shape."""
    return {
        "detail": assumption.detail,
        "kind": assumption.kind,
    }


def _evidence_to_dict(evidence: EvidenceBundle) -> dict[str, Any]:
    """Convert an EvidenceBundle to its §3.6 dict shape.

    All order-insensitive collections are sorted; the reasoning_trace
    is preserved in step order because the trace IS the reasoner's
    narrative — reordering it corrupts the audit story.

    `statement_sources` is a dict whose values are tuples; the JSON
    representation must serialize the tuples as lists. We do this
    explicitly here rather than relying on `json.dumps` so the dict
    shape is unambiguous and round-trippable.

    `condition_context_assumed` is a tuple of (key, explanation) tuples;
    we serialize as a sorted list of two-element lists.
    """
    return {
        "condition_context_assumed": sorted([list(pair) for pair in evidence.condition_context_assumed]),
        "constraint_refs": sorted(evidence.constraint_refs),
        "edge_constraint_refs": sorted(evidence.edge_constraint_refs),
        "edge_refs": sorted(evidence.edge_refs),
        "node_refs": sorted(evidence.node_refs),
        "reasoning_trace": [_trace_entry_to_dict(t) for t in evidence.reasoning_trace],
        "statement_digests": sorted(evidence.statement_digests),
        "statement_sources": {digest: list(source) for digest, source in evidence.statement_sources.items()},
    }


def _trace_entry_to_dict(entry: TraceEntry) -> dict[str, Any]:
    """Convert a TraceEntry to its §3.6 dict shape.

    Per §3.6 design note (and S09 evidence.py rationale), the `inputs`
    field is sorted within the entry — inputs are an unordered set,
    not a sequence. The `reason` field IS included in the JSON output
    even though it's excluded from the bundle_digest (because it's
    presentation-only for the audit trail, not part of the finding's
    identity).
    """
    return {
        "action": entry.action,
        "inputs": sorted(entry.inputs),
        "reason": entry.reason,
        "result": entry.result,
        "step": entry.step,
    }
