"""IAMScope reasoner layer — pluggable pattern evaluators that emit
deterministic `Finding` objects with a closed 4-value verdict taxonomy.

S08 shipped the verdict taxonomy and Finding scaffolding. S09 added the
reasoner Protocol, FactGraph wrapper, evidence bundle, and registry.
S10–S12 will add individual reasoners.

The reasoner layer is sidecar-only: it consumes `scenario.json` plus
`binding_metadata.json` and emits `findings.json`. It does not modify
the fact graph.
"""

from iamscope.reasoner.admin_reachability import AdminReachabilityReasoner
from iamscope.reasoner.assume_role_chain import AssumeRoleChainReasoner
from iamscope.reasoner.base import Reasoner, ReasonerError
from iamscope.reasoner.cross_account_trust import CrossAccountTrustReasoner
from iamscope.reasoner.evidence import (
    EvidenceBundle,
    InvalidEvidenceError,
    TraceEntry,
)
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.iam_group_membership_escalation import (
    IAMGroupMembershipEscalationReasoner,
)
from iamscope.reasoner.passrole_ecs import PassRoleEcsReasoner
from iamscope.reasoner.passrole_lambda import PassRoleLambdaReasoner
from iamscope.reasoner.registry import Registry
from iamscope.reasoner.s3_bucket_takeover import S3BucketTakeoverReasoner
from iamscope.reasoner.secrets_blast_radius import SecretsBlastRadiusReasoner
from iamscope.reasoner.verdict import (
    ASSUMPTION_KIND_CONDITION_CONTEXT,
    Assumption,
    Blocker,
    Check,
    CheckState,
    Finding,
    InvalidFindingError,
    Verdict,
)

__all__ = [
    "ASSUMPTION_KIND_CONDITION_CONTEXT",
    "AdminReachabilityReasoner",
    "Assumption",
    "AssumeRoleChainReasoner",
    "Blocker",
    "Check",
    "CheckState",
    "CrossAccountTrustReasoner",
    "EvidenceBundle",
    "FactGraph",
    "Finding",
    "IAMGroupMembershipEscalationReasoner",
    "InvalidEvidenceError",
    "InvalidFindingError",
    "PassRoleEcsReasoner",
    "PassRoleLambdaReasoner",
    "Reasoner",
    "ReasonerError",
    "Registry",
    "S3BucketTakeoverReasoner",
    "SecretsBlastRadiusReasoner",
    "TraceEntry",
    "Verdict",
]
