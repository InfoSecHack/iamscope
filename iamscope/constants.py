"""IAMScope constants — hard limits, confidence mappings, enums.

All values in this module are pinned and must not change without
a full review of downstream impacts (ARF-RT integration, ID stability).
"""

# ---------------------------------------------------------------------------
# Graph explosion hard limits (non-overridable)
# ---------------------------------------------------------------------------
MAX_EDGES_PER_EXPANSION: int = 500
MAX_TOTAL_EDGES: int = 100_000

# ---------------------------------------------------------------------------
# Deterministic ID algorithm version
# ---------------------------------------------------------------------------
ID_ALGORITHM: str = "sha256_null_separated_v3_case_sensitive_provider_ids"

# ---------------------------------------------------------------------------
# confidence_q mapping (int 0..1000)
#
# Maps (parse_status, likely_blocking) → confidence_q for SCP constraints.
# [ASSUMPTION] per Phase A R05 — pinned mapping, ARF-RT uses these as priors.
# ---------------------------------------------------------------------------
CONFIDENCE_Q_COMPLETE_BLOCKING: int = 800
CONFIDENCE_Q_COMPLETE_NOT_BLOCKING: int = 500
CONFIDENCE_Q_PARTIAL: int = 300
CONFIDENCE_Q_UNSUPPORTED: int = 100
CONFIDENCE_Q_PERMISSION_BOUNDARY: int = 100  # Prior only; per-edge binding carries evaluated confidence

# ---------------------------------------------------------------------------
# Parse status enum values
# ---------------------------------------------------------------------------
PARSE_STATUS_COMPLETE: str = "complete"
PARSE_STATUS_PARTIAL: str = "partial"
PARSE_STATUS_UNSUPPORTED: str = "unsupported"

# ---------------------------------------------------------------------------
# Constraint status / validation_status enum values
# [ASSUMPTION] per Phase A Section C — verify against ARF-RT v0.3.9 enums.
# ---------------------------------------------------------------------------
CONSTRAINT_STATUS_ACTIVE: str = "ACTIVE"
CONSTRAINT_STATUS_INVALIDATED: str = "INVALIDATED"

VALIDATION_STATUS_UNVALIDATED: str = "UNVALIDATED"
# S08: VALIDATION_STATUS_VALIDATED was a zombie constant (zero external
# references in the fact-layer code). Its semantic replacement lives in
# `iamscope.reasoner.verdict.Verdict.VALIDATED` — the reasoner layer owns
# the validated/blocked/inconclusive/precondition_only taxonomy, not the
# fact-layer constraint status field. `validation_status` on Constraint
# stays scoped to the narrower UNVALIDATED/ASSUMED/NEEDS_REVIEW set.
VALIDATION_STATUS_ASSUMED: str = "ASSUMED"
VALIDATION_STATUS_NEEDS_REVIEW: str = "NEEDS_REVIEW"

# ---------------------------------------------------------------------------
# Finding severity enum values (reasoner layer, S08+)
# ---------------------------------------------------------------------------
# Closed-set severity strings used by reasoner `Finding` objects. Validated
# at Finding construction time via `reasoner.verdict.Finding.__post_init__`.
# Closed-set pattern matches existing fact-layer enums (EXPANSION_MODE_*,
# PARSE_STATUS_*, GOVERNANCE_CONFIDENCE_*).
SEVERITY_CRITICAL: str = "critical"
SEVERITY_HIGH: str = "high"
SEVERITY_MEDIUM: str = "medium"
SEVERITY_LOW: str = "low"
SEVERITY_INFO: str = "info"
SEVERITY_VALUES: frozenset[str] = frozenset(
    {
        SEVERITY_CRITICAL,
        SEVERITY_HIGH,
        SEVERITY_MEDIUM,
        SEVERITY_LOW,
        SEVERITY_INFO,
    }
)

# ---------------------------------------------------------------------------
# Governance confidence enum values (binding metadata)
# ---------------------------------------------------------------------------
# GC-1 fix (S07): the original `governance_confidence` field was an open
# string. The SCP binder and permission boundary resolver wrote the three
# values below, while the ghostgates enrichment module wrote two ADDITIONAL
# values ("compromised", "externally_validated") to the same field, creating
# an effective 5+ value open enum with no central registry. After GC-1:
# - `governance_confidence` is a closed 3-value enum used by SCP/boundary
#   binders, validated at EdgeConstraint construction time.
# - `enrichment_confidence` is a separate closed 2-value enum used only by
#   ghostgates, written into binding_metadata.json under its own key alongside
#   (not overwriting) governance_confidence.
GOVERNANCE_CONFIDENCE_COMPLETE: str = "complete"
GOVERNANCE_CONFIDENCE_PARTIAL: str = "partial"
GOVERNANCE_CONFIDENCE_NEEDS_REVIEW: str = "needs_review"
GOVERNANCE_CONFIDENCE_VALUES: frozenset[str] = frozenset(
    {
        GOVERNANCE_CONFIDENCE_COMPLETE,
        GOVERNANCE_CONFIDENCE_PARTIAL,
        GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    }
)

# Enrichment confidence enum values (ghostgates-only, sidecar key)
ENRICHMENT_CONFIDENCE_COMPROMISED: str = "compromised"
ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED: str = "externally_validated"
ENRICHMENT_CONFIDENCE_VALUES: frozenset[str] = frozenset(
    {
        ENRICHMENT_CONFIDENCE_COMPROMISED,
        ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED,
    }
)

# ---------------------------------------------------------------------------
# Naked trust classification
# ---------------------------------------------------------------------------
NAKED_CRITICAL: str = "CRITICAL_NAKED"
NAKED_BROAD: str = "BROAD_NAKED"
NAKED_NARROW: str = "NARROW_NAKED"
NAKED_CONDITIONED: str = "CONDITIONED"
NAKED_INTRA_ACCOUNT: str = "INTRA_ACCOUNT"

# ---------------------------------------------------------------------------
# Trust scope values
# ---------------------------------------------------------------------------
TRUST_SCOPE_ACCOUNT_ROOT: str = "account_root"
TRUST_SCOPE_SPECIFIC_ROLE: str = "specific_role"
TRUST_SCOPE_SPECIFIC_USER: str = "specific_user"
TRUST_SCOPE_ANY_AWS_PRINCIPAL: str = "any_aws_principal"
TRUST_SCOPE_SERVICE: str = "service"
TRUST_SCOPE_FEDERATED: str = "federated"

# ---------------------------------------------------------------------------
# Node types
# [ASSUMPTION] per Phase A Section C — __hyperedge__ accepted by ARF-RT.
# ---------------------------------------------------------------------------
NODE_TYPE_IAM_ROLE: str = "IAMRole"
NODE_TYPE_IAM_USER: str = "IAMUser"
NODE_TYPE_IAM_GROUP: str = "IAMGroup"
NODE_TYPE_ACCOUNT_ROOT: str = "AccountPrincipalSet"
NODE_TYPE_WILDCARD_PRINCIPAL: str = "WildcardPrincipal"
NODE_TYPE_AWS_SERVICE: str = "AWSService"
NODE_TYPE_SAML_PROVIDER: str = "SAMLProvider"
NODE_TYPE_OIDC_PROVIDER: str = "OIDCProvider"
NODE_TYPE_LAMBDA_FUNCTION: str = "LambdaFunction"
NODE_TYPE_EC2_INSTANCE_PROFILE: str = "EC2InstanceProfile"
NODE_TYPE_EXTERNAL_ACCOUNT: str = "ExternalAccount"
NODE_TYPE_HYPEREDGE: str = "__hyperedge__"
# TYP-1 additions (S04): resource node types that PassRole / permission edges
# may target. NODE_TYPE_EC2_INSTANCE is distinct from NODE_TYPE_EC2_INSTANCE_PROFILE
# (the latter is an IAM instance profile; this is an actual EC2 instance).
NODE_TYPE_ECS_CLUSTER: str = "ECSCluster"
NODE_TYPE_EC2_INSTANCE: str = "EC2Instance"
NODE_TYPE_SECRETS_MANAGER_SECRET: str = "SecretsManagerSecret"
NODE_TYPE_KMS_KEY: str = "KMSKey"
NODE_TYPE_S3_BUCKET: str = "S3Bucket"

# ---------------------------------------------------------------------------
# Edge type suffixes
# ---------------------------------------------------------------------------
EDGE_LAYER_TRUST: str = "trust"
EDGE_LAYER_PERMISSION: str = "permission"
EDGE_LAYER_SERVICE: str = "service"
EDGE_LAYER_RESOURCE_POLICY: str = "resource_policy"
EDGE_LAYER_RESOLVED: str = "resolved"

# ---------------------------------------------------------------------------
# Constraint types
# [ASSUMPTION] per Phase A Section C — verify exact strings against ARF-RT.
# ---------------------------------------------------------------------------
CONSTRAINT_TYPE_SCP: str = "SCP"
CONSTRAINT_TYPE_TRUST_CONDITION: str = "TRUST_CONDITION"
CONSTRAINT_TYPE_PERMISSION_BOUNDARY: str = "PERMISSION_BOUNDARY"
CONSTRAINT_TYPE_IDENTITY_DENY: str = "IDENTITY_DENY"
CONSTRAINT_TYPE_RESOURCE_POLICY_CONDITION: str = "RESOURCE_POLICY_CONDITION"
CONSTRAINT_TYPE_RESOURCE_POLICY_DENY: str = "RESOURCE_POLICY_DENY"
CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT: str = "STALE_PRINCIPAL_DRIFT"

# ---------------------------------------------------------------------------
# Truth contract closed enums (Phase 0-2)
# ---------------------------------------------------------------------------
ACTION_CLASS_STS_ASSUME_ROLE: str = "sts:AssumeRole"
ACTION_CLASS_VALUES: frozenset[str] = frozenset(
    {
        ACTION_CLASS_STS_ASSUME_ROLE,
    }
)

PROBE_KIND_SIMULATOR: str = "simulator"
PROBE_KIND_RUNTIME: str = "runtime"
PROBE_KIND_CLOUDTRAIL: str = "cloudtrail"
PROBE_KIND_OPERATOR: str = "operator_annotation"
PROBE_KIND_VALUES: frozenset[str] = frozenset(
    {
        PROBE_KIND_SIMULATOR,
        PROBE_KIND_RUNTIME,
        PROBE_KIND_CLOUDTRAIL,
        PROBE_KIND_OPERATOR,
    }
)

PROBE_STATE_NOT_PROBED: str = "not_probed"
PROBE_STATE_SIMULATOR_ONLY_ALLOWED: str = "simulator_only_allowed"
PROBE_STATE_SIMULATOR_ONLY_DENIED: str = "simulator_only_denied"
PROBE_STATE_SIMULATOR_ONLY_ERROR: str = "simulator_only_error"
PROBE_STATE_PROBED_UNCORRELATED_ALLOWED: str = "probed_uncorrelated_allowed"
PROBE_STATE_PROBED_UNCORRELATED_DENIED: str = "probed_uncorrelated_denied"
PROBE_STATE_PROBED_CORRELATED_ALLOWED: str = "probed_correlated_allowed"
PROBE_STATE_PROBED_CORRELATED_DENIED: str = "probed_correlated_denied"
PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT: str = "probed_correlated_disagreement"
PROBE_STATE_CONFOUNDED_SKIP: str = "confounded_skip"
PROBE_STATE_VALUES: frozenset[str] = frozenset(
    {
        PROBE_STATE_NOT_PROBED,
        PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
        PROBE_STATE_SIMULATOR_ONLY_DENIED,
        PROBE_STATE_SIMULATOR_ONLY_ERROR,
        PROBE_STATE_PROBED_UNCORRELATED_ALLOWED,
        PROBE_STATE_PROBED_UNCORRELATED_DENIED,
        PROBE_STATE_PROBED_CORRELATED_ALLOWED,
        PROBE_STATE_PROBED_CORRELATED_DENIED,
        PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
        PROBE_STATE_CONFOUNDED_SKIP,
    }
)

DECLARED_STATE_ALLOW: str = "allow"
DECLARED_STATE_DENY: str = "deny"
DECLARED_STATE_UNKNOWN: str = "unknown"
DECLARED_STATE_VALUES: frozenset[str] = frozenset(
    {
        DECLARED_STATE_ALLOW,
        DECLARED_STATE_DENY,
        DECLARED_STATE_UNKNOWN,
    }
)

SIMULATOR_STATE_NOT_RUN: str = "not_run"
SIMULATOR_STATE_ALLOWED: str = "allowed"
SIMULATOR_STATE_DENIED: str = "denied"
SIMULATOR_STATE_ERROR: str = "error"
SIMULATOR_STATE_VALUES: frozenset[str] = frozenset(
    {
        SIMULATOR_STATE_NOT_RUN,
        SIMULATOR_STATE_ALLOWED,
        SIMULATOR_STATE_DENIED,
        SIMULATOR_STATE_ERROR,
    }
)

VALIDATED_STATE_NOT_PROBED: str = "not_probed"
VALIDATED_STATE_ALLOWED: str = "allowed"
VALIDATED_STATE_DENIED: str = "denied"
VALIDATED_STATE_ERROR: str = "error"
VALIDATED_STATE_VALUES: frozenset[str] = frozenset(
    {
        VALIDATED_STATE_NOT_PROBED,
        VALIDATED_STATE_ALLOWED,
        VALIDATED_STATE_DENIED,
        VALIDATED_STATE_ERROR,
    }
)

EVIDENCE_LEVEL_DECLARED: str = "declared"
EVIDENCE_LEVEL_SIMULATOR_ADVISORY: str = "simulator_advisory"
EVIDENCE_LEVEL_LIVE_VALIDATED: str = "live_validated"
EVIDENCE_LEVEL_HEURISTIC: str = "heuristic"
EVIDENCE_LEVEL_PARTIAL: str = "partial"
EVIDENCE_LEVEL_VALUES: frozenset[str] = frozenset(
    {
        EVIDENCE_LEVEL_DECLARED,
        EVIDENCE_LEVEL_SIMULATOR_ADVISORY,
        EVIDENCE_LEVEL_LIVE_VALIDATED,
        EVIDENCE_LEVEL_HEURISTIC,
        EVIDENCE_LEVEL_PARTIAL,
    }
)

# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
PROVIDER_AWS: str = "aws"

# ---------------------------------------------------------------------------
# Region placeholder for non-regional resources (IAM is global)
# ---------------------------------------------------------------------------
REGION_GLOBAL: str = "-"

# ---------------------------------------------------------------------------
# Known condition keys for trust policy parsing
# ---------------------------------------------------------------------------
KNOWN_CONDITION_KEYS: set[str] = {
    "sts:ExternalId",
    "aws:SourceAccount",
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:PrincipalOrgID",
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
    "sts:RoleSessionName",
    "aws:PrincipalArn",
    "aws:PrincipalTag",
    "aws:RequestedRegion",
    "aws:TokenIssueTime",
}

# ---------------------------------------------------------------------------
# Known SCP exception condition operators → field mapping
# ---------------------------------------------------------------------------
SCP_EXCEPTION_OPERATORS: dict[str, str] = {
    "ArnNotLike": "exception_principal_patterns",
    "StringNotLike": "exception_principal_patterns",
    "StringNotEquals": "exception_org_ids",  # for aws:PrincipalOrgID
}

SCP_EXCEPTION_CONDITION_KEYS: dict[str, str] = {
    "aws:PrincipalArn": "exception_principal_patterns",
    "aws:PrincipalOrgID": "exception_org_ids",
    "aws:SourceAccount": "exception_account_ids",
}

# ---------------------------------------------------------------------------
# Expansion mode values
# ---------------------------------------------------------------------------
EXPANSION_MODE_WARN: str = "warn"
EXPANSION_MODE_SKIP: str = "skip"
EXPANSION_MODE_EXPAND: str = "expand"

# ---------------------------------------------------------------------------
# Default noise filter settings
# ---------------------------------------------------------------------------
DEFAULT_EXCLUDE_SERVICE_LINKED: bool = True
DEFAULT_EXCLUDE_AWS_MANAGED: bool = True
DEFAULT_INCLUDE_SSO_ROLES: bool = True
DEFAULT_EXCLUDE_SELF_TRUST: bool = True
DEFAULT_EXCLUDE_SERVICE_PRINCIPALS: bool = False

# ---------------------------------------------------------------------------
# Rate limiting defaults
# ---------------------------------------------------------------------------
DEFAULT_ACCOUNT_DELAY_MS: int = 500
DEFAULT_MAX_RETRY_ATTEMPTS: int = 10

# ---------------------------------------------------------------------------
# Canonical JSON output settings (pinned)
# ---------------------------------------------------------------------------
JSON_SEPARATORS: tuple[str, str] = (",", ":")
JSON_ENSURE_ASCII: bool = True
JSON_SORT_KEYS: bool = True
JSON_TRAILING_NEWLINE: bool = False  # Pinned: NO trailing newline
