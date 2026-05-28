"""IAMScope data models.

Dataclasses representing nodes, edges, constraints, edge_constraints,
and metadata for the scenario.json output format.

All models are designed for deterministic serialization:
- No mutable default factories that depend on insertion order
- All dict fields are sorted during to_dict()
- All list fields maintain insertion order (sorted externally by the emitter)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from iamscope.constants import (
    CONSTRAINT_STATUS_ACTIVE,
    GOVERNANCE_CONFIDENCE_VALUES,
    ID_ALGORITHM,
    REGION_GLOBAL,
    VALIDATION_STATUS_UNVALIDATED,
)
from iamscope.identity.canonical import canonical_json_bytes
from iamscope.identity.deterministic_ids import (
    constraint_id as compute_constraint_id,
)
from iamscope.identity.deterministic_ids import (
    edge_id as compute_edge_id,
)
from iamscope.identity.deterministic_ids import (
    node_id as compute_node_id,
)


def _canonicalize_raw_json(raw: str | dict | None) -> str | None:
    """Re-serialize raw JSON/dict to canonical form for determinism.

    Per Phase A R16: embedded raw JSON must be re-serialized through
    canonical JSON (sorted keys, compact separators) to ensure
    byte-level stability regardless of AWS API response key ordering.

    Args:
        raw: A JSON string, a dict, or None.

    Returns:
        Canonical JSON string, or None if input is None.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            # Not valid JSON — store as-is but warn
            return raw
    else:
        parsed = raw
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sorted_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with keys sorted lexicographically.

    Recursively sorts nested dicts. Lists are NOT sorted here —
    list sorting is the emitter's responsibility using canonical sort keys.
    """
    result: dict[str, Any] = {}
    for key in sorted(d.keys()):
        value = d[key]
        if isinstance(value, dict):
            result[key] = _sorted_dict(value)
        elif isinstance(value, list):
            result[key] = [_sorted_dict(item) if isinstance(item, dict) else item for item in value]
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# ControlRef — edge-to-control attribution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlRef:
    """Deterministic pointer to a specific policy statement.

    Every edge carries ControlRefs in its features dict to attribute
    the edge to the specific policy statements that create or block it.
    IAMScope emits raw ControlRefs; ARF-RT clusters and reasons about them.

    Three categories on edges:
    - allow_controls: statements that make the edge possible
    - deny_controls: statements that block the edge
    - condition_controls: conditions that gate the edge
    """

    control_type: str
    # One of: TRUST, IDENTITY_POLICY, SCP, RESOURCE_POLICY,
    #         PERMISSIONS_BOUNDARY, SESSION_POLICY,
    #         TAG_CONDITION, EXTERNAL_ID_REQUIREMENT,
    #         MFA_REQUIREMENT, SOURCE_ACCOUNT_CONDITION

    # Policy identification (at least one should be set)
    policy_arn: str | None = None  # For IAM policies, trust policies (role ARN)
    policy_id: str | None = None  # For SCPs (org policy ID like p-750k87br)

    # Statement identification within the policy
    statement_index: int = 0  # Position in Statement array (0-indexed)
    statement_sid: str | None = None  # Sid field if present

    # Deterministic content hash
    digest: str = ""  # SHA-256 of canonical statement JSON

    # Human-readable context (not used for matching — just for reports)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a sorted dict for deterministic JSON output."""
        d: dict[str, Any] = {
            "control_type": self.control_type,
            "digest": self.digest,
            "statement_index": self.statement_index,
            "summary": self.summary,
        }
        if self.policy_arn is not None:
            d["policy_arn"] = self.policy_arn
        if self.policy_id is not None:
            d["policy_id"] = self.policy_id
        if self.statement_sid is not None:
            d["statement_sid"] = self.statement_sid
        return _sorted_dict(d)


# ---------------------------------------------------------------------------
# Node Reference (embedded in edges)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeRef:
    """Minimal node reference embedded in edge src/dst fields."""

    provider: str
    node_type: str
    provider_id: str
    region: str = REGION_GLOBAL

    def to_dict(self) -> dict[str, Any]:
        return _sorted_dict(
            {
                "node_type": self.node_type,
                "provider": self.provider,
                "provider_id": self.provider_id,
                "region": self.region,
            }
        )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@dataclass
class Node:
    """A node in the identity graph.

    Represents an IAM principal, synthetic account root, service,
    federation provider, or cross-service resource (Lambda, EC2).
    """

    provider: str
    node_type: str
    provider_id: str
    region: str = REGION_GLOBAL
    properties: dict[str, Any] = field(default_factory=dict)

    # Computed in Phase 5 (ID assignment)
    _node_id: str | None = field(default=None, repr=False, compare=False)

    @property
    def node_id(self) -> str:
        """Deterministic node ID. Computed lazily and cached."""
        if self._node_id is None:
            self._node_id = compute_node_id(self.provider, self.node_type, self.provider_id)
        return self._node_id

    def to_ref(self) -> NodeRef:
        """Create a NodeRef for embedding in edges."""
        return NodeRef(
            provider=self.provider,
            node_type=self.node_type,
            provider_id=self.provider_id,
            region=self.region,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict with sorted keys for canonical JSON."""
        d: dict[str, Any] = {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "properties": self.properties,
            "provider": self.provider,
            "provider_id": self.provider_id,
            "region": self.region,
        }
        return _sorted_dict(d)


# ---------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------


@dataclass
class Edge:
    """A directed edge in the identity graph.

    Represents a trust, permission, or service relationship
    between two principals or resources.
    """

    edge_type: str
    src: NodeRef
    dst: NodeRef
    region: str = REGION_GLOBAL
    features: dict[str, Any] = field(default_factory=dict)

    # Computed in Phase 5 (ID assignment)
    _edge_id: str | None = field(default=None, repr=False, compare=False)

    @property
    def edge_id(self) -> str:
        """Deterministic edge ID. Computed lazily and cached.

        v0.2.37 (sha256_null_separated_v2): the features dict is now
        included in the hash via its canonical JSON encoding. See
        `iamscope.identity.deterministic_ids.edge_id` for the formula
        and the v1→v2 migration rationale. The features digest is
        computed lazily on first property access, same as the rest of
        the edge_id memoization — no extra work at Edge instantiation.

        `self.features` is guaranteed to be a dict by the dataclass
        `default_factory=dict`, so no defensive None handling is
        needed. An empty features dict canonicalizes to `"{}"` and
        produces a stable edge_id for featureless edges.
        """
        if self._edge_id is None:
            features_digest = canonical_json_bytes(self.features).decode("utf-8")
            self._edge_id = compute_edge_id(
                self.edge_type,
                self.src.provider_id,
                self.dst.provider_id,
                self.region,
                features_digest,
            )
        return self._edge_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict with sorted keys for canonical JSON."""
        d: dict[str, Any] = {
            "dst": self.dst.to_dict(),
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "features": self.features,
            "region": self.region,
            "src": self.src.to_dict(),
        }
        return _sorted_dict(d)


# ---------------------------------------------------------------------------
# Constraint
# ---------------------------------------------------------------------------


@dataclass
class Constraint:
    """A governance constraint (SCP, trust condition, permission boundary).

    Represents parsed policy data with confidence metadata.
    """

    provider: str
    constraint_type: str
    scope_type: str
    scope_id: str
    policy_id: str
    statement_id: str  # Per R14: included in constraint_id
    region: str = REGION_GLOBAL
    properties: dict[str, Any] = field(default_factory=dict)
    status: str = CONSTRAINT_STATUS_ACTIVE
    validation_status: str = VALIDATION_STATUS_UNVALIDATED
    confidence_q: int = 500

    # Computed in Phase 5 (ID assignment)
    _constraint_id: str | None = field(default=None, repr=False, compare=False)

    @property
    def constraint_id(self) -> str:
        """Deterministic constraint ID. Computed lazily and cached."""
        if self._constraint_id is None:
            self._constraint_id = compute_constraint_id(
                self.provider,
                self.constraint_type,
                self.scope_type,
                self.scope_id,
                self.policy_id,
                self.statement_id,
            )
        return self._constraint_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict with sorted keys for canonical JSON."""
        d: dict[str, Any] = {
            "confidence_q": self.confidence_q,
            "constraint_id": self.constraint_id,
            "constraint_type": self.constraint_type,
            "policy_id": self.policy_id,
            "properties": self.properties,
            "provider": self.provider,
            "region": self.region,
            "scope_id": self.scope_id,
            "scope_type": self.scope_type,
            "statement_id": self.statement_id,
            "status": self.status,
            "validation_status": self.validation_status,
        }
        return _sorted_dict(d)


# ---------------------------------------------------------------------------
# Edge Constraint (binding)
# ---------------------------------------------------------------------------


@dataclass
class EdgeConstraint:
    """Binding between an edge and a constraint with governance metadata.

    Per Phase A R15: references edges and constraints by ID only,
    not by embedding full objects. The full data lives in edges[]
    and constraints[] arrays.

    IMPORTANT — ARF-RT compatibility (extra="forbid"):
    ARF-RT's EdgeConstraintInput only accepts edge_ref, constraint_ref,
    and relation_type. Any extra fields (like binding_metadata) cause
    a hard Pydantic validation error.

    Therefore:
    - to_dict()         → scenario.json (edge_id + constraint_id ONLY)
    - to_binding_dict() → binding_metadata.json sidecar (full governance data)

    The governance_confidence, likely_blocking, and binding_reason fields
    are computed internally for the standalone report and sidecar file.
    They are NOT emitted in scenario.json until ARF-RT adds support.
    """

    edge_id: str
    constraint_id: str
    governance_confidence: str
    likely_blocking: bool
    binding_reason: str = ""

    def __post_init__(self) -> None:
        """Validate governance_confidence against the closed enum.

        GC-1 (S07): pre-S07 the field was an open string, which let
        ghostgates leak its enrichment-specific values ("compromised",
        "externally_validated") into the same key the SCP/boundary binders
        wrote ("complete", "partial", "needs_review"). Any reasoner that
        depended on this field had to handle 5+ values from a non-central
        registry. Post-S07 EdgeConstraint enforces the 3-value set at
        construction; ghostgates writes its own field instead.
        """
        if self.governance_confidence not in GOVERNANCE_CONFIDENCE_VALUES:
            raise ValueError(
                f"EdgeConstraint.governance_confidence must be one of "
                f"{sorted(GOVERNANCE_CONFIDENCE_VALUES)}, got "
                f"{self.governance_confidence!r}. Ghostgates enrichment "
                f"values belong on EnrichmentResult.enrichment_confidence, "
                f"not here."
            )

    @property
    def sort_key(self) -> tuple[str, str]:
        """Sort key: (edge_id, constraint_id) lexicographic tuple."""
        return (self.edge_id, self.constraint_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to ARF-RT-compatible dict for scenario.json.

        ONLY emits edge_id and constraint_id. No binding_metadata.
        ARF-RT uses extra="forbid" — any unknown fields cause rejection.
        """
        d: dict[str, Any] = {
            "constraint_id": self.constraint_id,
            "edge_id": self.edge_id,
        }
        return _sorted_dict(d)

    def to_binding_dict(self) -> dict[str, Any]:
        """Serialize to sidecar dict with full governance metadata.

        Used for binding_metadata.json and standalone report.
        This data is per-edge-per-constraint (not per-constraint),
        so it cannot live in constraint properties.
        """
        d: dict[str, Any] = {
            "binding_metadata": {
                "binding_reason": self.binding_reason,
                "governance_confidence": self.governance_confidence,
                "likely_blocking": self.likely_blocking,
            },
            "constraint_id": self.constraint_id,
            "edge_id": self.edge_id,
        }
        return _sorted_dict(d)


# ---------------------------------------------------------------------------
# SCP Parse Result (intermediate — used during collection, stored in constraint properties)
# ---------------------------------------------------------------------------


@dataclass
class SCPParseResult:
    """Structured parse output for one SCP statement.

    This is an intermediate representation used during SCP parsing.
    It gets stored inside a Constraint's properties dict for output.
    """

    statement_id: str
    effect: str  # Always "Deny" for SCPs we process

    # Action model — exactly one set is populated
    deny_actions: list[str] = field(default_factory=list)
    deny_not_actions: list[str] = field(default_factory=list)

    # Resource scope
    resource_patterns: list[str] = field(default_factory=lambda: ["*"])

    # Exception patterns
    exception_principal_patterns: list[str] = field(default_factory=list)
    exception_org_ids: list[str] = field(default_factory=list)
    exception_account_ids: list[str] = field(default_factory=list)
    applicable_principal_patterns: list[str] = field(default_factory=list)

    # Raw conditions (canonicalized)
    raw_conditions: dict[str, Any] = field(default_factory=dict)

    # Parse confidence
    parse_status: str = "complete"
    parse_warnings: list[str] = field(default_factory=list)

    def to_properties_dict(self) -> dict[str, Any]:
        """Convert to a dict suitable for Constraint.properties.

        All lists are sorted for determinism.
        Raw conditions are canonicalized.
        """
        props = {
            "deny_actions": sorted(self.deny_actions),
            "deny_not_actions": sorted(self.deny_not_actions),
            "effect": self.effect,
            "exception_account_ids": sorted(self.exception_account_ids),
            "exception_org_ids": sorted(self.exception_org_ids),
            "exception_principal_patterns": sorted(self.exception_principal_patterns),
            "parse_status": self.parse_status,
            "parse_warnings": sorted(self.parse_warnings),
            "raw_conditions": self.raw_conditions,  # Already canonical from parser
            "resource_patterns": sorted(self.resource_patterns),
            "statement_id": self.statement_id,
        }
        if self.applicable_principal_patterns:
            props["applicable_principal_patterns"] = sorted(self.applicable_principal_patterns)
        return _sorted_dict(props)


# ---------------------------------------------------------------------------
# Trust Parse Result (intermediate — used during trust policy parsing)
# ---------------------------------------------------------------------------


@dataclass
class TrustParseResult:
    """Structured parse output for one trust policy statement.

    Produces one or more _trust edges depending on the principal field.
    """

    statement_index: int
    effect: str  # "Allow" for trust statements we care about
    action: str  # "sts:AssumeRole", "sts:AssumeRoleWithSAML", etc.

    # Principal resolution
    principal_type: str  # "AWS", "Service", "Federated"
    principal_value: str  # ARN, service name, or "*"
    resolved_node_type: str  # IAMRole, AccountPrincipalSet, WildcardPrincipal, etc.
    trust_scope: str  # account_root, specific_role, any_aws_principal, service, federated

    # Condition extraction
    has_external_id: bool = False
    has_source_account_condition: bool = False
    has_source_ip_condition: bool = False
    has_source_vpc_condition: bool = False
    has_org_id_condition: bool = False
    has_mfa_condition: bool = False
    condition_keys: list[str] = field(default_factory=list)
    raw_conditions: dict[str, Any] = field(default_factory=dict)

    # OIDC subject claim extraction
    # Populated for OIDC federated principals when a :sub condition is present.
    # e.g. "repo:MyOrg/MyRepo:ref:refs/heads/main" for GitHub Actions.
    # None means no sub claim found; "*" means wildcard sub.
    oidc_subject_pattern: str | None = None

    # Cross-account (set during resolution)
    cross_account: bool = False

    # Naked trust classification (set during resolution)
    naked_trust_classification: str = ""

    # DIG-1 (S05): SHA-256 digest of the canonical statement dict. Populated by
    # the parser at parse time from the raw statement JSON, so the digest is
    # stable against the source policy bytes (not IAMScope's parsed interpretation).
    # Used by resolvers to attach ControlRef evidence attribution to the edge.
    statement_digest: str = ""


# ---------------------------------------------------------------------------
# Permission Parse Result
# ---------------------------------------------------------------------------


@dataclass
class PermissionParseResult:
    """Structured parse output for one permission policy statement grant.

    Produces one _permission edge per (action, resource) pair.
    Multiple resources in one statement produce multiple results.
    """

    statement_index: int
    effect: str  # "Allow" — only Allow statements produce permission edges
    action: str  # "sts:AssumeRole", "iam:PassRole", etc.

    # Resource targeting
    resource_pattern: str  # Specific ARN or "*"
    is_wildcard_resource: bool  # True if resource is "*" or "arn:aws:iam::*:role/*"

    # Source principal info (who has this permission)
    source_arn: str  # ARN of the principal (user/role/group)
    source_node_type: str  # IAMRole, IAMUser, IAMGroup
    source_account_id: str  # Account ID of the source principal

    # Policy source tracking
    policy_source: str = ""  # "inline", "managed", "group_inline", "group_managed"
    policy_name: str = ""  # Policy name or ARN
    policy_arn: str = ""  # For managed policies

    # Condition extraction (permission-side conditions are uncommon but exist)
    has_conditions: bool = False
    raw_conditions: dict[str, Any] = field(default_factory=dict)

    # Action matching metadata
    action_matched_via: str = ""  # "exact", "wildcard_sts", "wildcard_iam", "wildcard_star"

    # DIG-1 (S05): SHA-256 digest of the canonical statement dict. Populated by
    # the parser at parse time from the raw statement JSON. See TrustParseResult
    # for rationale and ControlRef evidence-attribution semantics.
    statement_digest: str = ""


# ---------------------------------------------------------------------------
# Permission Deny Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionDenyResult:
    """Structured parse output for one identity-policy Deny statement."""

    principal_arn: str
    policy_arn: str
    statement_id: str
    deny_actions: list[str]
    resource_patterns: list[str]
    has_conditions: bool
    raw_conditions: dict[str, Any]
    parse_status: str


# ---------------------------------------------------------------------------
# Resource Policy Collection / Parse Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourcePolicyDocument:
    """Raw resource policy collected from a service-owned resource."""

    target_arn: str
    policy_document: str | dict[str, Any]
    policy_source: str
    account_id: str
    region: str
    resource_type: str
    policy_name: str = ""


@dataclass(frozen=True)
class ResourcePolicyParseResult:
    """Structured parse output for one resource-policy Allow grant."""

    target_arn: str
    target_node_type: str
    policy_source: str
    policy_name: str
    account_id: str
    region: str
    statement_index: int
    statement_sid: str | None
    effect: str
    principal_type: str
    principal_value: str
    resolved_node_type: str
    action: str
    resource_pattern: str
    has_conditions: bool
    raw_conditions: dict[str, Any]
    parse_status: str
    statement_digest: str


# ---------------------------------------------------------------------------
# Organization Collection Models
# ---------------------------------------------------------------------------


@dataclass
class OUInfo:
    """Organizational Unit metadata collected from AWS Organizations."""

    ou_id: str
    name: str
    parent_id: str
    ou_path: str  # e.g. "/Root/Production/Workloads"
    account_ids: list[str] = field(default_factory=list)  # Direct children only
    child_ou_ids: list[str] = field(default_factory=list)


@dataclass
class AccountInfo:
    """AWS account metadata collected from AWS Organizations."""

    account_id: str
    name: str
    email: str
    status: str  # ACTIVE, SUSPENDED
    parent_id: str  # OU or root ID
    ou_path: str = ""


@dataclass
class OrgData:
    """Complete organization discovery output from Phase 1 collection.

    Contains the OU tree, account listing, SCP policies and their
    scope bindings, plus the computed ou_account_map for SCP inheritance.
    """

    org_id: str
    root_id: str
    accounts: list[AccountInfo] = field(default_factory=list)
    ous: list[OUInfo] = field(default_factory=list)
    scp_constraints: list[Any] = field(default_factory=list)  # Constraint objects
    ou_account_map: dict[str, set[str]] = field(default_factory=dict)
    # Maps scope_id → set of account IDs governed (recursive)

    @property
    def account_ids(self) -> set[str]:
        """All collected account IDs."""
        return {a.account_id for a in self.accounts}

    @property
    def active_account_ids(self) -> set[str]:
        """Active account IDs only."""
        return {a.account_id for a in self.accounts if a.status == "ACTIVE"}


# ---------------------------------------------------------------------------
# Scenario Metadata
# ---------------------------------------------------------------------------


@dataclass
class ScenarioMetadata:
    """Metadata block for scenario.json.

    Per Phase A R02/R03: metadata is included in scenario.json but
    EXCLUDED from the canonical hash computation. The hash covers
    only nodes, edges, constraints, edge_constraints, objectives,
    observations.
    """

    collector: str = "iamscope"
    collector_version: str = "0.2.0"
    id_algorithm: str = ID_ALGORITHM
    org_id: str = ""
    accounts_collected: int = 0
    accounts_skipped: int = 0
    collection_timestamp: str = ""  # ISO format, non-deterministic
    collection_duration_seconds: float = 0.0
    noise_filter: dict[str, Any] = field(default_factory=dict)
    graph_stats: dict[str, Any] = field(default_factory=dict)
    # BUG-013 fix: structured record of every per-region / per-global
    # collector call that raised during this run. Empty in the happy
    # path; any non-empty value means the fact graph is partial and
    # downstream findings may be incomplete. Each entry is a dict
    # produced by `CollectionFailure.to_dict()`. Safe to embed here
    # because `canonical_hash` excludes metadata — the non-deterministic
    # failure content will never perturb the hash.
    collection_failures: list[dict[str, Any]] = field(default_factory=list)
    hash_scope: str = "canonical_hash excludes metadata block"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict with sorted keys."""
        d: dict[str, Any] = {
            "accounts_collected": self.accounts_collected,
            "accounts_skipped": self.accounts_skipped,
            "collection_duration_seconds": self.collection_duration_seconds,
            "collection_failures": self.collection_failures,
            "collection_timestamp": self.collection_timestamp,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "graph_stats": self.graph_stats,
            "hash_scope": self.hash_scope,
            "id_algorithm": self.id_algorithm,
            "noise_filter": self.noise_filter,
            "org_id": self.org_id,
        }
        return _sorted_dict(d)
