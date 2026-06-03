"""S13 golden findings fixtures — byte-pinned canonical findings.json files.

Each test rebuilds a known FactGraph, runs the matching reasoner, emits
findings.json via S11's `emit_findings` with timestamp-stable parameters,
and asserts byte-equality against a fixture file checked into the repo
under `tests/fixtures/expected_output/findings/`.

**Why this matters:** the pinned hashes are the ARF-RT contract proof.
Any silent change in:
- reasoner verdict logic
- evidence bundle structure
- finding_id formula
- emitter sort order
- emitter hash scope
- canonical JSON conventions

…breaks the canonical_hash and surfaces immediately on the next test
run. The hash diff tells you a format change happened; the structural
assertions in each test (verdict, severity, finding count) tell you
WHICH layer changed.

**Regen procedure:** if a fixture needs to be regenerated after a
deliberate format change:
1. Set `_REGEN = True` at the top of this module
2. Run `pytest tests/test_golden_findings.py` — fixtures are written
3. Set `_REGEN = False`
4. Re-run `pytest tests/test_golden_findings.py` — verifies byte-equality
5. Commit both the test module change AND the regenerated fixture files

The two-step regen is deliberate: it forces the developer to inspect
the diff between the old and new fixture files before committing,
catching any unintended format changes.

**Builders are inlined** rather than imported from `test_cross_account_reasoner.py`
or `test_passrole_lambda_reasoner.py` because golden tests should be
self-contained and not depend on other test modules' internal helpers.
A change in the other test module's helpers would silently invalidate
the goldens; inline duplication keeps the contract explicit.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NAKED_NARROW,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.output.findings_json import emit_findings
from iamscope.reasoner import (
    AdminReachabilityReasoner,
    AssumeRoleChainReasoner,
    CrossAccountTrustReasoner,
    FactGraph,
    IAMGroupMembershipEscalationReasoner,
    PassRoleEcsReasoner,
    PassRoleLambdaReasoner,
    Reasoner,
    S3BucketTakeoverReasoner,
    SecretsBlastRadiusReasoner,
)

# ---------------------------------------------------------------------------
# Regen toggle. Set to True to (re)write fixture files; False to verify.
# ---------------------------------------------------------------------------

_REGEN: bool = False


# ---------------------------------------------------------------------------
# Stable emission parameters
# ---------------------------------------------------------------------------

# Fixed nominal timestamp — clearly a fixture marker, never a real run time.
# These two fields are EXCLUDED from canonical_hash so technically any value
# would work, but a fixed marker makes the fixture files easier to read and
# the diff churn predictable if the format ever changes.
_FIXTURE_TIMESTAMP: str = "2026-01-01T00:00:00Z"
_FIXTURE_DURATION: float = 0.0
_FIXTURE_SOURCE_VERSION: str = "0.2.0"

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "expected_output" / "findings"


# ---------------------------------------------------------------------------
# Fixture constants
# ---------------------------------------------------------------------------

_TARGET_ACCOUNT = "111111\u003111111"
_EXTERNAL_ACCOUNT = "999999\u003999999"

# Cross-account trust fixture ARNs (mirrors test_cross_account_reasoner.py)
_CAT_TARGET_ROLE_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:role/ProdAdmin"
_CAT_EXTERNAL_ROOT_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:root"
_CAT_EXTERNAL_ROLE_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:role/Specific"
_CAT_INTRA_USER_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:user/Bob"
_CAT_OIDC_PROVIDER_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
_CAT_WILDCARD_PRINCIPAL = "arn:aws:iam:::*"

# PassRole-Lambda fixture ARNs (mirrors test_passrole_lambda_reasoner.py)
_PRL_ALICE_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:user/Alice"
_PRL_ADMIN_ROLE_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:role/AdminRole"
_LAMBDA_SERVICE = "lambda.amazonaws.com"
_EC2_SERVICE = "ec2.amazonaws.com"
_HYPEREDGE_PROVIDER_ID = "__hyperedge__:passrole_wildcard:abc123"


# ---------------------------------------------------------------------------
# Reasoners-used dicts
# ---------------------------------------------------------------------------


def _cat_reasoners_used() -> dict[str, dict[str, str]]:
    r = CrossAccountTrustReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _prl_reasoners_used() -> dict[str, dict[str, str]]:
    r = PassRoleLambdaReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


# ---------------------------------------------------------------------------
# Cross-account trust fixture builders
# ---------------------------------------------------------------------------


def _cat_target_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_CAT_TARGET_ROLE_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "path": "/",
        },
    )


def _cat_account_root_node(
    account_id: str,
    *,
    org_member: bool = False,
) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=f"arn:aws:iam::{account_id}:root",
        region=REGION_GLOBAL,
        properties={
            "account_id": account_id,
            "is_synthetic": True,
            "org_member": org_member,
            "principal_count": 50,
        },
    )


def _cat_wildcard_principal_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=_CAT_WILDCARD_PRINCIPAL,
        region=REGION_GLOBAL,
        properties={
            "is_synthetic": True,
            "org_member": False,
            "wildcard": True,
        },
    )


def _cat_external_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_CAT_EXTERNAL_ROLE_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _EXTERNAL_ACCOUNT,
            "is_synthetic": True,
            "org_member": False,
        },
    )


def _cat_intra_user_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=_CAT_INTRA_USER_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "org_member": True,
        },
    )


def _cat_oidc_provider_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type="OIDCProvider",
        provider_id=_CAT_OIDC_PROVIDER_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "org_member": False,
        },
    )


def _cat_trust_edge(
    *,
    src: Node,
    dst: Node,
    naked_trust: str | None,
    cross_account: bool,
    has_external_id: bool = False,
    has_mfa_condition: bool = False,
    has_org_id_condition: bool = False,
    digest: str = "deadbeef" * 8,
    statement_index: int = 0,
) -> Edge:
    features: dict[str, Any] = {
        "allow_controls": [
            {
                "control_type": "TRUST",
                "policy_arn": dst.provider_id,
                "statement_index": statement_index,
                "digest": digest,
                "summary": f"trust policy for {dst.provider_id}",
            }
        ],
        "cross_account": cross_account,
        "effect": "Allow",
        "has_external_id": has_external_id,
        "has_mfa_condition": has_mfa_condition,
        "has_org_id_condition": has_org_id_condition,
        "has_source_account_condition": False,
        "has_source_ip_condition": False,
        "has_source_vpc_condition": False,
        "is_wildcard_principal": (src.provider_id == _CAT_WILDCARD_PRINCIPAL),
        "layer": "trust",
        "principal_type": "AWS",
        "raw_conditions": {},
        "source_policy": "TrustPolicy",
        "statement_index": statement_index,
        "trust_scope": "account_root",
    }
    if naked_trust is not None:
        features["naked_trust"] = naked_trust
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features=features,
    )


def _cat_make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    edge_constraints: tuple[EdgeConstraint, ...] = (),
    constraints: tuple[Constraint, ...] = (),
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=False,
    )


# Per-fixture FactGraph constructors


def _cat_fixture_a_facts() -> FactGraph:
    """Critical naked wildcard principal — validated/critical."""
    target = _cat_target_role_node()
    wildcard_src = _cat_wildcard_principal_node()
    edge = _cat_trust_edge(
        src=wildcard_src,
        dst=target,
        naked_trust=NAKED_CRITICAL,
        cross_account=True,
    )
    return _cat_make_facts(nodes=(target, wildcard_src), edges=(edge,))


def _cat_fixture_b_facts() -> FactGraph:
    """Broad naked blocked by SCP — blocked/info."""
    target = _cat_target_role_node()
    external = _cat_account_root_node(_EXTERNAL_ACCOUNT)
    edge = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_BROAD,
        cross_account=True,
    )
    scp_constraint = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-assume",
        statement_id="DenyAssumeRoleProd",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "complete",
            "policy_name": "DenyAssumeRoleProd",
            "resource_patterns": ["*"],
        },
    )
    ec = EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=scp_constraint.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason="SCP DenyAssumeRoleProd at OU ou-prod denies sts:AssumeRole",
    )
    return _cat_make_facts(
        nodes=(target, external),
        edges=(edge,),
        constraints=(scp_constraint,),
        edge_constraints=(ec,),
    )


def _cat_fixture_c_facts() -> FactGraph:
    """Narrow naked weak conditions — validated/medium."""
    target = _cat_target_role_node()
    external = _cat_external_role_node()
    edge = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_NARROW,
        cross_account=True,
        has_external_id=True,
    )
    return _cat_make_facts(nodes=(target, external), edges=(edge,))


def _cat_fixture_d_facts() -> FactGraph:
    """Conditioned (OrgID + MFA) — no finding emitted."""
    target = _cat_target_role_node()
    external = _cat_external_role_node()
    edge = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_CONDITIONED,
        cross_account=True,
        has_org_id_condition=True,
        has_mfa_condition=True,
    )
    return _cat_make_facts(nodes=(target, external), edges=(edge,))


def _cat_fixture_e_facts() -> FactGraph:
    """SCP partial → inconclusive/high."""
    target = _cat_target_role_node()
    external = _cat_account_root_node(_EXTERNAL_ACCOUNT)
    edge = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_CRITICAL,
        cross_account=True,
    )
    scp_constraint = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-partial",
        statement_id="PartialDenyAssume",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "partial",
            "policy_name": "PartialPolicy",
            "resource_patterns": ["*"],
        },
    )
    ec = EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=scp_constraint.constraint_id,
        governance_confidence="partial",
        likely_blocking=False,
        binding_reason="SCP parse partial — could not evaluate fully",
    )
    return _cat_make_facts(
        nodes=(target, external),
        edges=(edge,),
        constraints=(scp_constraint,),
        edge_constraints=(ec,),
    )


def _cat_fixture_f_facts() -> FactGraph:
    """OIDC broad no :sub — validated/high."""
    target = _cat_target_role_node()
    oidc = _cat_oidc_provider_node()
    edge = _cat_trust_edge(
        src=oidc,
        dst=target,
        naked_trust=NAKED_BROAD,
        cross_account=True,
    )
    return _cat_make_facts(nodes=(target, oidc), edges=(edge,))


def _cat_fixture_g_facts() -> FactGraph:
    """Unsupported SCP (needs_review) → inconclusive/high."""
    target = _cat_target_role_node()
    external = _cat_account_root_node(_EXTERNAL_ACCOUNT)
    edge = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_CRITICAL,
        cross_account=True,
    )
    scp_constraint = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-unsupported",
        statement_id="UnsupportedSyntax",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "unsupported",
            "policy_name": "UnsupportedPolicy",
            "resource_patterns": ["*"],
        },
    )
    ec = EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=scp_constraint.constraint_id,
        governance_confidence="needs_review",
        likely_blocking=False,
        binding_reason="SCP uses unsupported syntax — manual review required",
    )
    return _cat_make_facts(
        nodes=(target, external),
        edges=(edge,),
        constraints=(scp_constraint,),
        edge_constraints=(ec,),
    )


def _cat_fixture_h_facts() -> FactGraph:
    """Multi-statement dedup — exactly one finding from cross-account statement."""
    target = _cat_target_role_node()
    intra_user = _cat_intra_user_node()
    external = _cat_account_root_node(_EXTERNAL_ACCOUNT)
    edge_intra = _cat_trust_edge(
        src=intra_user,
        dst=target,
        naked_trust=NAKED_INTRA_ACCOUNT,
        cross_account=False,
        statement_index=0,
        digest="0123456789abcdef" * 4,
    )
    edge_cross = _cat_trust_edge(
        src=external,
        dst=target,
        naked_trust=NAKED_BROAD,
        cross_account=True,
        statement_index=1,
        digest="fedcba9876543210" * 4,
    )
    return _cat_make_facts(
        nodes=(target, intra_user, external),
        edges=(edge_intra, edge_cross),
    )


def _cat_fixture_z_facts() -> FactGraph:
    """Same-org cross-account → severity downgrade critical→high."""
    target = _cat_target_role_node()
    external_in_org = _cat_account_root_node(
        _EXTERNAL_ACCOUNT,
        org_member=True,
    )
    edge = _cat_trust_edge(
        src=external_in_org,
        dst=target,
        naked_trust=NAKED_CRITICAL,
        cross_account=True,
    )
    return _cat_make_facts(
        nodes=(target, external_in_org),
        edges=(edge,),
    )


# ---------------------------------------------------------------------------
# PassRole-Lambda fixture builders
# ---------------------------------------------------------------------------


def _prl_alice_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=_PRL_ALICE_ARN,
        properties={"account_id": _TARGET_ACCOUNT},
    )


def _prl_admin_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_PRL_ADMIN_ROLE_ARN,
        properties={"account_id": _TARGET_ACCOUNT},
    )


def _prl_lambda_service_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id=_LAMBDA_SERVICE,
        properties={},
    )


def _prl_ec2_service_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id=_EC2_SERVICE,
        properties={},
    )


def _prl_hyperedge_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type="__hyperedge__",
        provider_id=_HYPEREDGE_PROVIDER_ID,
        properties={"would_expand_to": 50, "expansion_type": "iam:PassRole"},
    )


def _prl_perm_edge(
    *,
    src: Node,
    dst: Node,
    action: str,
    raw_conditions: dict[str, Any] | None = None,
    has_conditions: bool = False,
    digest: str = "deadbeef" * 8,
    statement_index: int = 0,
) -> Edge:
    if raw_conditions is None:
        raw_conditions = {}
    return Edge(
        edge_type=f"{action}_permission",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_TARGET_ACCOUNT}:policy/AlicePerms",
                    "statement_index": statement_index,
                    "digest": digest,
                    "summary": f"{action} grant",
                }
            ],
            "action_matched_via": "exact",
            "effect": "Allow",
            "has_conditions": has_conditions,
            "is_wildcard_resource": False,
            "layer": "permission",
            "policy_arn": f"arn:aws:iam::{_TARGET_ACCOUNT}:policy/AlicePerms",
            "policy_name": "AlicePerms",
            "raw_conditions": raw_conditions,
            "resource_pattern": dst.provider_id,
            "statement_index": statement_index,
        },
    )


def _prl_lambda_trust_edge(target: Node) -> Edge:
    lambda_svc = _prl_lambda_service_node()
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=lambda_svc.to_ref(),
        dst=target.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": target.provider_id,
                    "statement_index": 0,
                    "digest": "cafebabe" * 8,
                    "summary": "trust lambda",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "principal_type": "Service",
            "raw_conditions": {},
            "statement_index": 0,
        },
    )


def _prl_admin_grant_edge(target: Node) -> Edge:
    return Edge(
        edge_type="iam:*_permission",
        src=target.to_ref(),
        dst=target.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "statement_index": 0,
                    "digest": "cccccccc" * 8,
                    "summary": "iam:*",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )


def _prl_make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...] = (),
    edge_constraints: tuple[EdgeConstraint, ...] = (),
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=False,
    )


def _prl_build_admin_chain(
    *,
    raw_conditions: dict[str, Any] | None = None,
) -> tuple[FactGraph, Edge, Edge]:
    """Canonical Lambda PassRole admin chain — fixture A baseline."""
    alice = _prl_alice_node()
    target = _prl_admin_role_node()
    lambda_svc = _prl_lambda_service_node()

    lambda_create = _prl_perm_edge(
        src=alice,
        dst=target,
        action="lambda:CreateFunction",
        digest="aaaaaaaa" * 8,
        statement_index=0,
    )
    passrole = _prl_perm_edge(
        src=alice,
        dst=target,
        action="iam:PassRole",
        digest="bbbbbbbb" * 8,
        statement_index=1,
        raw_conditions=raw_conditions,
        has_conditions=bool(raw_conditions),
    )
    lambda_trust = _prl_lambda_trust_edge(target)
    admin_grant = _prl_admin_grant_edge(target)

    return (
        _prl_make_facts(
            nodes=(alice, target, lambda_svc),
            edges=(lambda_create, passrole, lambda_trust, admin_grant),
        ),
        lambda_create,
        passrole,
    )


def _prl_fixture_a_facts() -> FactGraph:
    """Validated admin (happy path) — validated/critical."""
    facts, _, _ = _prl_build_admin_chain()
    return facts


def _prl_fixture_b_facts() -> FactGraph:
    """Trust missing — target trusts EC2 only.

    Under target-first enumeration this produces no findings (the EC2-only
    role is never enumerated as a candidate). The fixture pins this empty
    output as documentation that the reasoner correctly emits zero findings
    for non-Lambda-trusting roles.
    """
    alice = _prl_alice_node()
    ec2_svc = _prl_ec2_service_node()
    ec2_only_role = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=f"arn:aws:iam::{_TARGET_ACCOUNT}:role/Ec2Only",
        properties={"account_id": _TARGET_ACCOUNT},
    )
    lambda_create = _prl_perm_edge(
        src=alice,
        dst=ec2_only_role,
        action="lambda:CreateFunction",
    )
    passrole = _prl_perm_edge(
        src=alice,
        dst=ec2_only_role,
        action="iam:PassRole",
    )
    ec2_trust = Edge(
        edge_type="sts:AssumeRole_trust",
        src=ec2_svc.to_ref(),
        dst=ec2_only_role.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": ec2_only_role.provider_id,
                    "statement_index": 0,
                    "digest": "ec2trust0" * 7 + "_pad",
                    "summary": "trust ec2",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "principal_type": "Service",
            "raw_conditions": {},
            "statement_index": 0,
        },
    )
    return _prl_make_facts(
        nodes=(alice, ec2_only_role, ec2_svc),
        edges=(lambda_create, passrole, ec2_trust),
    )


def _prl_fixture_c_facts() -> FactGraph:
    """Blocked by SCP on lambda:CreateFunction — blocked/info."""
    facts, lambda_create_edge, _ = _prl_build_admin_chain()
    scp = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-lambda",
        statement_id="DenyLambdaCreate",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["lambda:CreateFunction"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "complete",
            "policy_name": "DenyLambdaProd",
            "resource_patterns": ["*"],
        },
    )
    binding = EdgeConstraint(
        edge_id=lambda_create_edge.edge_id,
        constraint_id=scp.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason="SCP DenyLambdaCreate at OU ou-prod denies lambda:CreateFunction",
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _prl_fixture_d_facts() -> FactGraph:
    """Blocked by permission boundary post-BND-1 — blocked/info."""
    facts, lambda_create_edge, _ = _prl_build_admin_chain()
    boundary = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        scope_type="USER",
        scope_id=_PRL_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_TARGET_ACCOUNT}:policy/AliceBoundary",
        statement_id="BoundaryDeniesLambda",
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["s3:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
        },
    )
    binding = EdgeConstraint(
        edge_id=lambda_create_edge.edge_id,
        constraint_id=boundary.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason=(
            "permission boundary allowed_actions={s3:*, dynamodb:*} does not include lambda:CreateFunction (post-BND-1)"
        ),
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(boundary,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _prl_fixture_e_facts() -> FactGraph:
    """Inconclusive partial SCP — inconclusive/high."""
    facts, lambda_create_edge, _ = _prl_build_admin_chain()
    scp = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-lambda",
        statement_id="PartialDenyLambda",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["lambda:CreateFunction"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "partial",
            "policy_name": "PartialPolicy",
            "resource_patterns": ["*"],
        },
    )
    binding = EdgeConstraint(
        edge_id=lambda_create_edge.edge_id,
        constraint_id=scp.constraint_id,
        governance_confidence="partial",
        likely_blocking=False,
        binding_reason="SCP parse partial — could not evaluate fully",
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _prl_fixture_f_facts() -> FactGraph:
    """Hyperedge wildcard PassRole — inconclusive/high. THE CRITICAL FIXTURE."""
    alice = _prl_alice_node()
    target = _prl_admin_role_node()
    lambda_svc = _prl_lambda_service_node()
    hyper = _prl_hyperedge_node()

    lambda_create = _prl_perm_edge(
        src=alice,
        dst=target,
        action="lambda:CreateFunction",
    )
    wildcard_passrole = Edge(
        edge_type="iam:PassRole_permission",
        src=alice.to_ref(),
        dst=hyper.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_TARGET_ACCOUNT}:policy/AlicePerms",
                    "statement_index": 0,
                    "digest": "feedface" * 8,
                    "summary": "wildcard PassRole",
                }
            ],
            "action_matched_via": "exact",
            "effect": "Allow",
            "expansion_mode": "warn",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "policy_arn": f"arn:aws:iam::{_TARGET_ACCOUNT}:policy/AlicePerms",
            "policy_name": "AlicePerms",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
            "suppressed": True,
            "would_expand_to": 50,
        },
    )
    lambda_trust = _prl_lambda_trust_edge(target)
    admin_grant = _prl_admin_grant_edge(target)
    return _prl_make_facts(
        nodes=(alice, target, lambda_svc, hyper),
        edges=(lambda_create, wildcard_passrole, lambda_trust, admin_grant),
    )


def _prl_fixture_g_facts() -> FactGraph:
    """PassedToService scoped to EC2 → precondition_only/medium."""
    facts, _, _ = _prl_build_admin_chain(
        raw_conditions={
            "StringEquals": {
                "iam:PassedToService": "ec2.amazonaws.com",
            },
        },
    )
    return facts


# ---------------------------------------------------------------------------
# Emit + read helpers
# ---------------------------------------------------------------------------


def _emit_for_fixture(
    *,
    facts: FactGraph,
    reasoner: Reasoner,
    reasoners_used: dict[str, dict[str, str]],
) -> tuple[bytes, str]:
    """Emit findings.json with timestamp-stable parameters."""
    findings = reasoner.run(facts)
    return emit_findings(
        findings,
        scenario_hash=facts.scenario_hash,
        reasoners_used=reasoners_used,
        reasoning_timestamp=_FIXTURE_TIMESTAMP,
        reasoning_duration_seconds=_FIXTURE_DURATION,
        source_tool_version=_FIXTURE_SOURCE_VERSION,
    )


def _verify_or_regen(
    *,
    fixture_path: Path,
    facts: FactGraph,
    reasoner: Reasoner,
    reasoners_used: dict[str, dict[str, str]],
    expected_finding_count: int,
    expected_verdict: str | None,
    expected_severity: str | None,
) -> None:
    """The unified verification/regen workhorse.

    When _REGEN is True, writes the fixture file to disk. When False,
    asserts byte-equality against the on-disk fixture, plus structural
    assertions (finding count, verdict, severity for the first finding).
    """
    bytes_now, hash_now = _emit_for_fixture(
        facts=facts,
        reasoner=reasoner,
        reasoners_used=reasoners_used,
    )

    if _REGEN:
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_bytes(bytes_now)
        return

    assert fixture_path.exists(), (
        f"golden fixture missing: {fixture_path}. "
        f"Set _REGEN=True at the top of test_golden_findings.py "
        f"and re-run to regenerate, then set back to False."
    )
    fixture_bytes = fixture_path.read_bytes()
    fixture_doc = json.loads(fixture_bytes)
    parsed = json.loads(bytes_now)
    assert parsed == fixture_doc, (
        f"golden fixture semantic mismatch: {fixture_path}\n"
        f"  fixture hash: {hashlib.sha256(fixture_bytes).hexdigest()}\n"
        f"  actual hash:  {hashlib.sha256(bytes_now).hexdigest()}\n"
        f"  fixture canonical_hash: {fixture_doc['metadata']['canonical_hash']}\n"
        f"  actual canonical_hash:  {hash_now}\n"
        f"Public fixtures may use JSON escapes to avoid raw account IDs; "
        f"the parsed JSON contract must still match."
    )
    assert hash_now == fixture_doc["metadata"]["canonical_hash"]

    # Structural assertions for diagnostic value.
    assert parsed["metadata"]["findings_count"] == expected_finding_count
    if expected_finding_count > 0 and expected_verdict is not None:
        assert parsed["findings"][0]["verdict"] == expected_verdict
    if expected_finding_count > 0 and expected_severity is not None:
        assert parsed["findings"][0]["severity"] == expected_severity


# ---------------------------------------------------------------------------
# Cross-account trust golden tests
# ---------------------------------------------------------------------------


_CAT_DIR = GOLDEN_DIR / "cross_account_trust"


@pytest.mark.golden
class TestCrossAccountTrustGoldens:
    """Pinned canonical findings.json for §4A.5 fixtures."""

    def test_fixture_a(self) -> None:
        """A: critical_naked_wildcard_principal → validated/critical"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_a_critical_naked_wildcard.json",
            facts=_cat_fixture_a_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_b(self) -> None:
        """B: broad_naked_blocked_by_scp → blocked/info"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_b_broad_naked_blocked_scp.json",
            facts=_cat_fixture_b_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_c(self) -> None:
        """C: narrow_naked_weak_conditions → validated/medium"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_c_narrow_naked_weak.json",
            facts=_cat_fixture_c_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="medium",
        )

    def test_fixture_d(self) -> None:
        """D: conditioned_no_finding → empty findings list"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_d_conditioned_no_finding.json",
            facts=_cat_fixture_d_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=0,
            expected_verdict=None,
            expected_severity=None,
        )

    def test_fixture_e(self) -> None:
        """E: scp_partial_forces_inconclusive → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_e_scp_partial_inconclusive.json",
            facts=_cat_fixture_e_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_f(self) -> None:
        """F: oidc_broad_no_sub → validated/high"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_f_oidc_broad_no_sub.json",
            facts=_cat_fixture_f_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="high",
        )

    def test_fixture_g(self) -> None:
        """G: unsupported_scp_forces_inconclusive → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_g_unsupported_scp_inconclusive.json",
            facts=_cat_fixture_g_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_h(self) -> None:
        """H: multi_statement_dedup → exactly one finding (cross-account only)"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_h_multi_statement_dedup.json",
            facts=_cat_fixture_h_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="high",
        )

    def test_fixture_z(self) -> None:
        """Z: same_org_downgrade → validated/high (downgraded from critical)"""
        _verify_or_regen(
            fixture_path=_CAT_DIR / "fixture_z_same_org_downgrade.json",
            facts=_cat_fixture_z_facts(),
            reasoner=CrossAccountTrustReasoner(),
            reasoners_used=_cat_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="high",
        )


# ---------------------------------------------------------------------------
# PassRole-Lambda golden tests
# ---------------------------------------------------------------------------


_PRL_DIR = GOLDEN_DIR / "passrole_lambda"


@pytest.mark.golden
class TestPassRoleLambdaGoldens:
    """Pinned canonical findings.json for §4B.5 fixtures."""

    def test_fixture_a(self) -> None:
        """A: validated_admin → validated/critical"""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_a_validated_admin.json",
            facts=_prl_fixture_a_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_b(self) -> None:
        """B: precondition_only_trust_missing → empty findings (target-first scope decision)."""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_b_trust_missing_no_finding.json",
            facts=_prl_fixture_b_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=0,
            expected_verdict=None,
            expected_severity=None,
        )

    def test_fixture_c(self) -> None:
        """C: blocked_by_scp → blocked/info"""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_c_blocked_by_scp.json",
            facts=_prl_fixture_c_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_d(self) -> None:
        """D: blocked_by_boundary_post_bnd1 → blocked/info"""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_d_blocked_by_boundary_post_bnd1.json",
            facts=_prl_fixture_d_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_e(self) -> None:
        """E: inconclusive_partial_scp → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_e_inconclusive_partial_scp.json",
            facts=_prl_fixture_e_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_f(self) -> None:
        """F: inconclusive_wildcard_passrole_hyperedge → inconclusive/high.

        THE HIGHEST-PRIORITY CORRECTNESS TEST IN THE REBUILD. The pinned
        canonical_hash here catches a regression in any of the
        false-positive guards: hyperedge handling, target-first
        enumeration, check 2 state classification.
        """
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_f_hyperedge_inconclusive.json",
            facts=_prl_fixture_f_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_g(self) -> None:
        """G: precondition_only_passedtoservice_ec2 → precondition_only/medium"""
        _verify_or_regen(
            fixture_path=_PRL_DIR / "fixture_g_passedtoservice_ec2.json",
            facts=_prl_fixture_g_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="precondition_only",
            expected_severity="medium",
        )


# ---------------------------------------------------------------------------
# PassRole-ECS golden tests (priority 3a)
# ---------------------------------------------------------------------------
#
# Imports helpers from test_passrole_ecs_reasoner.py rather than cloning the
# ~400 lines of `_prl_*` scaffolding. This is a deliberate departure from
# the cross-account-trust and passrole_lambda golden sections, which both
# self-contain their builders. The justification: the ECS reasoner's
# fixture builders are mechanically derived from the Lambda ones (same
# Alice → AdminRole shape, same SCP/boundary patterns), so duplicating the
# scaffolding would copy 400 lines for zero additional clarity. Cross-test
# imports are legal pytest behavior — pytest treats sibling test modules
# as ordinary Python modules.
#
# Initial golden set ships 3 fixtures: A (validated/critical), C (blocked
# by SCP), F (hyperedge inconclusive — the §4B.6 row 1 false-positive
# guard). Fixtures B/D/E/G are deferred to a follow-up.

from tests.test_passrole_ecs_reasoner import (  # noqa: E402, I001
    _ACCOUNT as _PRE_ACCOUNT,
    _ALICE_ARN as _PRE_ALICE_ARN,
    _admin_role_node as _pre_admin_role_node,
    _alice_node as _pre_alice_node,
    _build_admin_chain as _pre_build_admin_chain,
    _ecs_tasks_service_node as _pre_ecs_tasks_service_node,
    _hyperedge_node as _pre_hyperedge_node,
    _make_facts as _pre_make_facts,
    _permission_edge as _pre_permission_edge,
    _trust_edge_from_service as _pre_trust_edge_from_service,
    _wildcard_passrole_to_hyperedge as _pre_wildcard_passrole_to_hyperedge,
)

_PRE_DIR = GOLDEN_DIR / "passrole_ecs"


def _pre_reasoners_used() -> dict[str, dict[str, str]]:
    r = PassRoleEcsReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _pre_fixture_a_facts() -> FactGraph:
    """Canonical ECS PassRole admin chain → validated/critical."""
    facts, _, _, _ = _pre_build_admin_chain()
    return facts


def _pre_fixture_c_facts() -> FactGraph:
    """Blocked by SCP on ecs:RegisterTaskDefinition → blocked/info.

    Bind an SCP that explicitly denies ecs:RegisterTaskDefinition with
    complete confidence to the register witness edge. Check 4a returns
    FAIL; check 4b PASSes (no blocker on the run edge); _and_tristate
    yields FAIL → check 4 fails → verdict = blocked.

    Tests that the two-witness check 4 logic correctly catches an SCP
    blocking only ONE of the two required ECS actions.
    """
    facts, register_witness, _, _ = _pre_build_admin_chain()
    scp = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-ecs",
        statement_id="DenyEcsRegister",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["ecs:RegisterTaskDefinition"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "complete",
            "policy_name": "DenyEcsProd",
            "resource_patterns": ["*"],
        },
    )
    binding = EdgeConstraint(
        edge_id=register_witness.edge_id,
        constraint_id=scp.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason="SCP DenyEcsRegister at OU ou-prod denies ecs:RegisterTaskDefinition",
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _pre_fixture_f_facts() -> FactGraph:
    """Wildcard PassRole → hyperedge dst → inconclusive/high.

    The §4B.6 row 1 false-positive guard for the ECS reasoner. Mirrors
    test_passrole_ecs_reasoner.py::TestFixtureFInconclusiveWildcardPassroleHyperedgeEcs.
    Alice has clean ecs:RegisterTaskDefinition + ecs:RunTask + a wildcard
    PassRole that produces a hyperedge dst. Target-first enumeration
    finds the AdminRole (ECS-trusting), pairs with Alice, computes
    check 1 = PASS, check 2 = UNKNOWN (hyperedge witness), verdict =
    inconclusive.

    If has_action() is mutated to accept hyperedges as PASS witnesses,
    this fixture's canonical_hash will change → byte-lock break →
    test failure. The most valuable byte-lock canary in the ECS suite.
    """
    alice = _pre_alice_node()
    target = _pre_admin_role_node()
    ecs_svc = _pre_ecs_tasks_service_node()
    hyper = _pre_hyperedge_node()

    register_edge = _pre_permission_edge(
        src=alice,
        dst=target,
        action="ecs:RegisterTaskDefinition",
    )
    run_edge = _pre_permission_edge(
        src=alice,
        dst=target,
        action="ecs:RunTask",
        digest="eeeeeeee" * 8,
        statement_index=3,
    )
    wildcard_passrole = _pre_wildcard_passrole_to_hyperedge(src=alice)
    ecs_trust = _pre_trust_edge_from_service(service=ecs_svc, target=target)
    admin_grant = Edge(
        edge_type="iam:*_permission",
        src=target.to_ref(),
        dst=target.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "statement_index": 0,
                    "digest": "dddddddd" * 8,
                    "summary": "iam:*",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )
    return _pre_make_facts(
        nodes=(alice, target, ecs_svc, hyper),
        edges=(register_edge, run_edge, wildcard_passrole, ecs_trust, admin_grant),
    )


def _pre_fixture_b_facts() -> FactGraph:
    """B: Trust missing — target trusts EC2 only (not ecs-tasks).

    Mirrors the Lambda B fixture: under target-first enumeration the
    EC2-only role is never enumerated as a passrole_ecs candidate
    because its trust policy doesn't admit ecs-tasks.amazonaws.com.
    The fixture pins this empty output as documentation that the
    reasoner correctly emits zero findings for non-ECS-trusting roles.
    """
    facts, _, _, _ = _pre_build_admin_chain(target_trusts_ecs_tasks=False)
    return facts


def _pre_fixture_d_facts() -> FactGraph:
    """D: Permission boundary post-BND-1 blocks ecs:RegisterTaskDefinition → blocked/info.

    Mirrors Lambda D. Bind a permission boundary with allowed_actions
    not including ecs:RegisterTaskDefinition to the register_task_def
    edge with governance_confidence=complete. Check 6a (boundary on
    register witness) returns FAIL; check 6b (boundary on run witness)
    returns PASS; the and_tristate combiner yields FAIL → check 6 fails
    → verdict = blocked.

    Tests that the per-witness boundary check correctly catches a
    boundary blocking only ONE of the two ECS witness actions, and
    that the priority-3a two-witness combinator properly propagates
    the FAIL.
    """
    facts, register_witness, _, _ = _pre_build_admin_chain()
    boundary = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        scope_type="USER",
        scope_id=_PRE_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_PRE_ACCOUNT}:policy/AliceBoundary",
        statement_id="BoundaryDeniesEcsRegister",
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["s3:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
        },
    )
    binding = EdgeConstraint(
        edge_id=register_witness.edge_id,
        constraint_id=boundary.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason=(
            "permission boundary allowed_actions={s3:*, dynamodb:*} "
            "does not include ecs:RegisterTaskDefinition (post-BND-1)"
        ),
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(boundary,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _pre_fixture_e_facts() -> FactGraph:
    """E: Inconclusive partial SCP → inconclusive/high.

    Mirrors Lambda E. Bind an SCP with parse_status=partial and
    governance_confidence=partial to the register_task_def edge.
    Check 4a returns UNKNOWN (partial parse can't prove blocking);
    check 4b returns PASS; the and_tristate combiner yields UNKNOWN
    → check 4 unknown → verdict = inconclusive.
    """
    facts, register_witness, _, _ = _pre_build_admin_chain()
    scp = Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-ecs",
        statement_id="PartialDenyEcs",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["ecs:RegisterTaskDefinition"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "partial",
            "policy_name": "PartialPolicy",
            "resource_patterns": ["*"],
        },
    )
    binding = EdgeConstraint(
        edge_id=register_witness.edge_id,
        constraint_id=scp.constraint_id,
        governance_confidence="partial",
        likely_blocking=False,
        binding_reason="SCP parse partial — could not evaluate fully",
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _pre_fixture_g_facts() -> FactGraph:
    """G: PassedToService scoped to ec2 → precondition_only/medium.

    Mirrors Lambda G. The passrole edge has an iam:PassedToService
    condition scoped to ec2.amazonaws.com (not ecs-tasks). Check 8
    (`passrole_condition_scoped_to_ecs_or_absent`) returns FAIL → the
    passrole is scoped to a service the role can't be assumed by
    via ECS task launch → precondition_only/medium.
    """
    facts, _, _, _ = _pre_build_admin_chain(
        raw_conditions={
            "StringEquals": {
                "iam:PassedToService": "ec2.amazonaws.com",
            },
        },
    )
    return facts


@pytest.mark.golden
class TestPassRoleEcsGoldens:
    """Pinned canonical findings.json for the passrole_ecs reasoner.

    Complete set: 7 fixtures covering all the canonical verdict shapes,
    matching passrole_lambda's coverage. A (validated/critical),
    B (no findings on non-ECS-trusting role), C (blocked by SCP),
    D (blocked by boundary), E (inconclusive partial SCP),
    F (hyperedge inconclusive — false-positive guard), G (precondition_only
    PassedToService scoped to ec2).
    """

    def test_fixture_a_validated_admin(self) -> None:
        """A: canonical admin chain → validated/critical"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_a_validated_admin.json",
            facts=_pre_fixture_a_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_b_trust_missing_no_findings(self) -> None:
        """B: target trusts EC2 only → no findings emitted"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_b_trust_missing_no_findings.json",
            facts=_pre_fixture_b_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=0,
            expected_verdict=None,
            expected_severity=None,
        )

    def test_fixture_c_blocked_by_scp(self) -> None:
        """C: SCP denies ecs:RegisterTaskDefinition → blocked/info"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_c_blocked_by_scp.json",
            facts=_pre_fixture_c_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_d_blocked_by_boundary(self) -> None:
        """D: permission boundary blocks ecs:RegisterTaskDefinition → blocked/info"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_d_blocked_by_boundary.json",
            facts=_pre_fixture_d_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_e_inconclusive_partial_scp(self) -> None:
        """E: SCP with partial parse → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_e_inconclusive_partial_scp.json",
            facts=_pre_fixture_e_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_f_hyperedge_inconclusive(self) -> None:
        """F: wildcard PassRole → hyperedge → inconclusive/high

        The §4B.6 row 1 false-positive guard. If has_action() is ever
        mutated to accept hyperedges as PASS witnesses, this fixture
        will fail.
        """
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_f_hyperedge_inconclusive.json",
            facts=_pre_fixture_f_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_g_passrole_scoped_to_ec2(self) -> None:
        """G: iam:PassedToService=ec2.amazonaws.com → precondition_only/medium"""
        _verify_or_regen(
            fixture_path=_PRE_DIR / "fixture_g_passrole_scoped_to_ec2.json",
            facts=_pre_fixture_g_facts(),
            reasoner=PassRoleEcsReasoner(),
            reasoners_used=_pre_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="precondition_only",
            expected_severity="medium",
        )


# ---------------------------------------------------------------------------
# Assume role chain golden tests (priority 3b)
# ---------------------------------------------------------------------------
#
# 3 fixtures covering the canonical verdict shapes for the BFS chain walker:
# A (validated 2-hop), B (blocked by SCP on first hop), C (inconclusive
# hyperedge on a hop). Reuses the fact-graph builders from the assume_role_chain
# unit test file via direct import.

from tests.test_assume_role_chain_reasoner import (  # noqa: E402, I001
    _ADMIN_ARN as _ARC_ADMIN_ARN,
    _ALICE_ARN as _ARC_ALICE_ARN,
    _DEVOPS_ARN as _ARC_DEVOPS_ARN,
    _admin_grant_edge as _arc_admin_grant_edge,
    _assume_perm_edge as _arc_assume_perm_edge,
    _binding as _arc_binding,
    _build_two_hop_chain as _arc_build_two_hop_chain,
    _make_facts as _arc_make_facts,
    _role as _arc_role,
    _scp as _arc_scp,
    _trust_edge as _arc_trust_edge,
    _user as _arc_user,
)

_ARC_DIR = GOLDEN_DIR / "assume_role_chain"


def _arc_reasoners_used() -> dict[str, dict[str, str]]:
    r = AssumeRoleChainReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _arc_fixture_a_facts() -> FactGraph:
    """A: canonical 2-hop chain Alice → DevOps → Admin → validated/high."""
    return _arc_build_two_hop_chain()


def _arc_fixture_b_facts() -> FactGraph:
    """B: SCP blocks the Alice→DevOps hop with complete confidence → blocked/info.

    Tests that per-hop SCP blocking via and_tristate_many correctly
    propagates a single-hop block into the chain-level verdict. If the
    `_check_scp_blockers_on_edge` helper is ever mutated to skip the
    confidence check, this fixture will fail.
    """
    facts = _arc_build_two_hop_chain()
    first_hop = next(
        e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ARC_ALICE_ARN
    )
    scp = _arc_scp(statement_id="DenyAliceAssumeRole")
    binding = _arc_binding(edge_id=first_hop.edge_id, constraint_id=scp.constraint_id)
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _arc_fixture_c_facts() -> FactGraph:
    """C: wildcard resource on first hop's permission edge → inconclusive/high.

    The §4B.6 row 1 false-positive guard for the chain reasoner. If
    check 6 (`no_hop_traverses_hyperedge`) is ever mutated to accept
    wildcard resources as PASS witnesses, this fixture will fail.
    """
    alice = _arc_user(_ARC_ALICE_ARN)
    devops = _arc_role(_ARC_DEVOPS_ARN)
    admin = _arc_role(_ARC_ADMIN_ARN)
    perm_1 = _arc_assume_perm_edge(
        src_arn=_ARC_ALICE_ARN,
        dst_arn=_ARC_DEVOPS_ARN,
        is_wildcard_resource=True,
    )
    trust_1 = _arc_trust_edge(principal_arn=_ARC_ALICE_ARN, target_arn=_ARC_DEVOPS_ARN)
    perm_2 = _arc_assume_perm_edge(src_arn=_ARC_DEVOPS_ARN, dst_arn=_ARC_ADMIN_ARN)
    trust_2 = _arc_trust_edge(principal_arn=_ARC_DEVOPS_ARN, target_arn=_ARC_ADMIN_ARN)
    admin_grant = _arc_admin_grant_edge(_ARC_ADMIN_ARN)
    return _arc_make_facts(
        nodes=(alice, devops, admin),
        edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
    )


class TestAssumeRoleChainGoldens:
    """Pinned canonical findings.json for the assume_role_chain reasoner."""

    def test_fixture_a_validated_two_hop(self) -> None:
        """A: 2-hop chain to admin → validated/high"""
        _verify_or_regen(
            fixture_path=_ARC_DIR / "fixture_a_validated_two_hop.json",
            facts=_arc_fixture_a_facts(),
            reasoner=AssumeRoleChainReasoner(),
            reasoners_used=_arc_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="high",
        )

    def test_fixture_b_blocked_by_scp_first_hop(self) -> None:
        """B: SCP blocks Alice→DevOps hop → blocked/info"""
        _verify_or_regen(
            fixture_path=_ARC_DIR / "fixture_b_blocked_by_scp_first_hop.json",
            facts=_arc_fixture_b_facts(),
            reasoner=AssumeRoleChainReasoner(),
            reasoners_used=_arc_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_c_hyperedge_inconclusive(self) -> None:
        """C: wildcard resource on first hop → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_ARC_DIR / "fixture_c_hyperedge_inconclusive.json",
            facts=_arc_fixture_c_facts(),
            reasoner=AssumeRoleChainReasoner(),
            reasoners_used=_arc_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )


# ---------------------------------------------------------------------------
# Admin reachability golden tests (priority 3c)
# ---------------------------------------------------------------------------
#
# 3 fixtures covering the canonical verdict shapes for the per-principal
# blast-forward reachability walker: A (1 admin reach validated/high),
# B (2 admins reach validated/critical), C (hyperedge inconclusive).
# Reuses the same fact-graph builders as the assume_role_chain goldens
# (fact graphs are identical; only the reasoner differs).

_ARR_DIR = GOLDEN_DIR / "admin_reachability"


def _arr_reasoners_used() -> dict[str, dict[str, str]]:
    r = AdminReachabilityReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _arr_fixture_a_facts() -> FactGraph:
    """A: 1 admin reachable via 2-hop chain → validated/high.

    Same fact graph as the assume_role_chain fixture A, but produces a
    different finding shape: one finding per principal (Alice and DevOps
    both reach Admin), each with a single reachable admin in the set.
    """
    return _arc_build_two_hop_chain()


def _arr_fixture_b_facts() -> FactGraph:
    """B: 2 admins reachable from Alice → validated/critical.

    Alice → DevOps → AdminRole AND Alice → DevOps → ProdAdmin. DevOps
    can assume both Admin and Prod, both of which are admin-equivalent.
    Critical severity because the count of reachable admins crosses
    the threshold (2+).
    """
    _prod_arn_local = "arn:aws:iam::111111\u003111111:role/Prod"
    alice = _arc_user(_ARC_ALICE_ARN)
    devops = _arc_role(_ARC_DEVOPS_ARN)
    admin = _arc_role(_ARC_ADMIN_ARN)
    prod = _arc_role(_prod_arn_local)
    perm_a_d = _arc_assume_perm_edge(
        src_arn=_ARC_ALICE_ARN,
        dst_arn=_ARC_DEVOPS_ARN,
        digest="1" * 64,
    )
    trust_a_d = _arc_trust_edge(
        principal_arn=_ARC_ALICE_ARN,
        target_arn=_ARC_DEVOPS_ARN,
        digest="2" * 64,
    )
    perm_d_a = _arc_assume_perm_edge(
        src_arn=_ARC_DEVOPS_ARN,
        dst_arn=_ARC_ADMIN_ARN,
        digest="3" * 64,
    )
    trust_d_a = _arc_trust_edge(
        principal_arn=_ARC_DEVOPS_ARN,
        target_arn=_ARC_ADMIN_ARN,
        digest="4" * 64,
    )
    perm_d_p = _arc_assume_perm_edge(
        src_arn=_ARC_DEVOPS_ARN,
        dst_arn=_prod_arn_local,
        digest="5" * 64,
    )
    trust_d_p = _arc_trust_edge(
        principal_arn=_ARC_DEVOPS_ARN,
        target_arn=_prod_arn_local,
        digest="6" * 64,
    )
    admin_grant_1 = _arc_admin_grant_edge(_ARC_ADMIN_ARN)
    admin_grant_2 = _arc_admin_grant_edge(_prod_arn_local)
    return _arc_make_facts(
        nodes=(alice, devops, admin, prod),
        edges=(
            perm_a_d,
            trust_a_d,
            perm_d_a,
            trust_d_a,
            perm_d_p,
            trust_d_p,
            admin_grant_1,
            admin_grant_2,
        ),
    )


def _arr_fixture_c_facts() -> FactGraph:
    """C: wildcard resource on the DevOps→Admin hop → inconclusive.

    The wildcard is placed on the second hop so that BOTH Alice's walk
    (which crosses it via Alice→DevOps→Admin) AND DevOps's walk (which
    crosses it directly via DevOps→Admin) traverse the ambiguous edge.
    Both findings end up with check 3 (`at_least_one_reachable_chain_uses_clean_witnesses`)
    flipped to UNKNOWN, producing inconclusive verdicts for both.

    The §4B.6 row 1 false-positive guard for the reachability reasoner.
    """
    alice = _arc_user(_ARC_ALICE_ARN)
    devops = _arc_role(_ARC_DEVOPS_ARN)
    admin = _arc_role(_ARC_ADMIN_ARN)
    perm_1 = _arc_assume_perm_edge(src_arn=_ARC_ALICE_ARN, dst_arn=_ARC_DEVOPS_ARN)
    trust_1 = _arc_trust_edge(principal_arn=_ARC_ALICE_ARN, target_arn=_ARC_DEVOPS_ARN)
    perm_2 = _arc_assume_perm_edge(
        src_arn=_ARC_DEVOPS_ARN,
        dst_arn=_ARC_ADMIN_ARN,
        is_wildcard_resource=True,
    )
    trust_2 = _arc_trust_edge(principal_arn=_ARC_DEVOPS_ARN, target_arn=_ARC_ADMIN_ARN)
    admin_grant = _arc_admin_grant_edge(_ARC_ADMIN_ARN)
    return _arc_make_facts(
        nodes=(alice, devops, admin),
        edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
    )


class TestAdminReachabilityGoldens:
    """Pinned canonical findings.json for the admin_reachability reasoner."""

    def test_fixture_a_validated_one_admin(self) -> None:
        """A: 1 reachable admin via 2-hop chain → validated/high"""
        _verify_or_regen(
            fixture_path=_ARR_DIR / "fixture_a_validated_one_admin.json",
            facts=_arr_fixture_a_facts(),
            reasoner=AdminReachabilityReasoner(),
            reasoners_used=_arr_reasoners_used(),
            expected_finding_count=2,  # Alice + DevOps both reach Admin
            expected_verdict="validated",
            expected_severity="high",
        )

    def test_fixture_b_validated_two_admins_critical(self) -> None:
        """B: 2 reachable admins from Alice → validated/critical"""
        _verify_or_regen(
            fixture_path=_ARR_DIR / "fixture_b_validated_two_admins_critical.json",
            facts=_arr_fixture_b_facts(),
            reasoner=AdminReachabilityReasoner(),
            reasoners_used=_arr_reasoners_used(),
            expected_finding_count=2,  # Alice (2 admins) + DevOps (2 admins)
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_c_hyperedge_inconclusive(self) -> None:
        """C: wildcard hop → inconclusive"""
        _verify_or_regen(
            fixture_path=_ARR_DIR / "fixture_c_hyperedge_inconclusive.json",
            facts=_arr_fixture_c_facts(),
            reasoner=AdminReachabilityReasoner(),
            reasoners_used=_arr_reasoners_used(),
            expected_finding_count=2,  # Alice + DevOps both flagged
            expected_verdict="inconclusive",
            expected_severity="high",
        )


# ---------------------------------------------------------------------------
# Secrets blast radius golden tests (priority 3d)
# ---------------------------------------------------------------------------
#
# 3 fixtures covering the canonical verdict shapes for the per-secret
# IAM-layer blast radius reasoner: A (validated/high for non-admin
# reader), B (blocked by SCP), C (inconclusive wildcard resource).

from tests.test_secrets_blast_radius_reasoner import (  # noqa: E402, I001
    _ACCOUNT as _SBR_ACCOUNT,
    _ALICE_ARN as _SBR_ALICE_ARN,
    _KEY_ARN as _SBR_KEY_ARN,
    _SECRET_1_ARN as _SBR_SECRET_1_ARN,
    _binding as _sbr_binding,
    _build_alice_reads_secret as _sbr_build_alice_reads_secret,
    _get_secret_edge as _sbr_get_secret_edge,
    _kms_key_node as _sbr_kms_key_node,
    _make_facts as _sbr_make_facts,
    _scp as _sbr_scp,
    _secret as _sbr_secret,
    _secret_with_kms as _sbr_secret_with_kms,
    _user as _sbr_user,
)

_SBR_DIR = GOLDEN_DIR / "secrets_blast_radius"


def _sbr_reasoners_used() -> dict[str, dict[str, str]]:
    r = SecretsBlastRadiusReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _sbr_fixture_a_facts() -> FactGraph:
    """A: non-admin Alice reads Secret1 → validated/high.

    The canonical single-finding shape. Alice is a plain IAM user
    with no admin-equivalent permissions, holding a specific
    `secretsmanager:GetSecretValue` grant on Secret1. All 4 substantive
    checks PASS (principal has permission, clean witness, no SCP, no
    boundary); check 5 (principal filter) PASSes because Alice is an
    IAMUser. Verdict: validated. Severity: high (non-admin).
    """
    return _sbr_build_alice_reads_secret()


def _sbr_fixture_b_facts() -> FactGraph:
    """B: SCP blocks GetSecretValue with complete confidence → blocked/info.

    Bind an SCP with complete governance confidence to the Alice→Secret1
    permission edge. Check 3 returns FAIL → verdict = blocked. Tests
    that the per-edge SCP blocker detection correctly propagates into
    the secrets-layer verdict mapping.
    """
    facts = _sbr_build_alice_reads_secret()
    edge = next(e for e in facts.edges if e.edge_type == "secretsmanager:GetSecretValue_permission")
    scp = _sbr_scp()
    binding = _sbr_binding(edge_id=edge.edge_id, constraint_id=scp.constraint_id)
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


def _sbr_fixture_c_facts() -> FactGraph:
    """C: wildcard resource → inconclusive/medium.

    Alice's GetSecretValue permission edge has `is_wildcard_resource=True`,
    simulating a policy like `Resource: "arn:aws:secretsmanager:*:*:secret:*"`.
    Check 2 returns UNKNOWN → verdict = inconclusive, severity = medium.
    The §4B.6 row 1 false-positive guard for the secrets reasoner.
    """
    alice = _sbr_user(_SBR_ALICE_ARN)
    secret = _sbr_secret(_SBR_SECRET_1_ARN)
    edge = _sbr_get_secret_edge(
        src=alice,
        dst_arn=_SBR_SECRET_1_ARN,
        is_wildcard_resource=True,
    )
    return _sbr_make_facts(nodes=(alice, secret), edges=(edge,))


def _sbr_fixture_d_facts() -> FactGraph:
    """D (v2 KMS): CMK blocks principal → precondition_only/medium.

    Alice has GetSecretValue permission targeting Secret1, which is
    encrypted with a customer-managed KMS key whose policy only
    grants kms:Decrypt to Bob. Check 6 returns FAIL → verdict =
    precondition_only, severity = medium. The KMS layer blocks the
    exfil path even though IAM allows it — semantically identical
    to "principal has lambda:CreateFunction but target role doesn't
    trust Lambda" in passrole_lambda.
    """
    alice = _sbr_user(_SBR_ALICE_ARN)
    secret = _sbr_secret_with_kms(_SBR_KEY_ARN)
    kms = _sbr_kms_key_node(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_SBR_ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
    )
    edge = _sbr_get_secret_edge(src=alice, dst_arn=_SBR_SECRET_1_ARN)
    return _sbr_make_facts(nodes=(alice, secret, kms), edges=(edge,))


def _sbr_fixture_e_facts() -> FactGraph:
    """E (v2 KMS): CMK policy has Condition → inconclusive/medium.

    Alice has GetSecretValue permission targeting Secret1, which is
    encrypted with a customer-managed KMS key whose policy grants
    account-root delegation BUT only under a Condition block
    (aws:SourceVpc). The reasoner cannot evaluate runtime conditions
    from the static graph, so check 6 returns UNKNOWN → verdict =
    inconclusive, severity = medium. Demonstrates that KMS conditions
    trigger the refuses-to-lie default at the KMS layer just like
    IAM conditions do at the permission-edge layer.
    """
    alice = _sbr_user(_SBR_ALICE_ARN)
    secret = _sbr_secret_with_kms(_SBR_KEY_ARN)
    kms = _sbr_kms_key_node(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_SBR_ACCOUNT}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                }
            ],
        }
    )
    edge = _sbr_get_secret_edge(src=alice, dst_arn=_SBR_SECRET_1_ARN)
    return _sbr_make_facts(nodes=(alice, secret, kms), edges=(edge,))


@pytest.mark.golden
class TestSecretsBlastRadiusGoldens:
    """Pinned canonical findings.json for the secrets_blast_radius reasoner."""

    def test_fixture_a_validated_non_admin(self) -> None:
        """A: Alice reads Secret1 → validated/high"""
        _verify_or_regen(
            fixture_path=_SBR_DIR / "fixture_a_validated_non_admin.json",
            facts=_sbr_fixture_a_facts(),
            reasoner=SecretsBlastRadiusReasoner(),
            reasoners_used=_sbr_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="high",
        )

    def test_fixture_b_blocked_by_scp(self) -> None:
        """B: SCP blocks GetSecretValue → blocked/info"""
        _verify_or_regen(
            fixture_path=_SBR_DIR / "fixture_b_blocked_by_scp.json",
            facts=_sbr_fixture_b_facts(),
            reasoner=SecretsBlastRadiusReasoner(),
            reasoners_used=_sbr_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )

    def test_fixture_c_wildcard_inconclusive(self) -> None:
        """C: wildcard resource → inconclusive/medium"""
        _verify_or_regen(
            fixture_path=_SBR_DIR / "fixture_c_wildcard_inconclusive.json",
            facts=_sbr_fixture_c_facts(),
            reasoner=SecretsBlastRadiusReasoner(),
            reasoners_used=_sbr_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="medium",
        )

    def test_fixture_d_kms_blocks_precondition_only(self) -> None:
        """D (v2 KMS): CMK blocks principal → precondition_only/medium"""
        _verify_or_regen(
            fixture_path=_SBR_DIR / "fixture_d_kms_blocks_precondition_only.json",
            facts=_sbr_fixture_d_facts(),
            reasoner=SecretsBlastRadiusReasoner(),
            reasoners_used=_sbr_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="precondition_only",
            expected_severity="medium",
        )

    def test_fixture_e_kms_conditions_inconclusive(self) -> None:
        """E (v2 KMS): CMK policy has Condition → inconclusive/medium"""
        _verify_or_regen(
            fixture_path=_SBR_DIR / "fixture_e_kms_conditions_inconclusive.json",
            facts=_sbr_fixture_e_facts(),
            reasoner=SecretsBlastRadiusReasoner(),
            reasoners_used=_sbr_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="medium",
        )


# ---------------------------------------------------------------------------
# IAM group membership escalation golden tests (v0.2.25)
# ---------------------------------------------------------------------------
#
# 3 fixtures covering the canonical verdict shapes for the group
# membership escalation reasoner: A (validated/critical user adds
# themselves to admin group), B (wildcard inconclusive), C (blocked
# by SCP).

from tests.test_iam_group_membership_escalation_reasoner import (  # noqa: E402, I001
    _ADMIN_GROUP_ARN as _IGME_ADMIN_GROUP_ARN,
    _ALICE_ARN as _IGME_ALICE_ARN,
    _add_user_to_group_edge as _igme_aug_edge,
    _admin_grant_edge_for_group as _igme_admin_grant_edge,
    _binding as _igme_binding,
    _build_alice_to_admin_group as _igme_build_alice_to_admin,
    _group as _igme_group,
    _make_facts as _igme_make_facts,
    _scp as _igme_scp,
    _user as _igme_user,
)

_IGME_DIR = GOLDEN_DIR / "iam_group_membership_escalation"


def _igme_reasoners_used() -> dict[str, dict[str, str]]:
    r = IAMGroupMembershipEscalationReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _igme_fixture_a_facts() -> FactGraph:
    """A: Alice adds herself to admin group → validated/critical."""
    return _igme_build_alice_to_admin()


def _igme_fixture_b_facts() -> FactGraph:
    """B: wildcard resource witness → inconclusive/high."""
    alice = _igme_user(_IGME_ALICE_ARN)
    admin = _igme_group(_IGME_ADMIN_GROUP_ARN)
    aug_edge = _igme_aug_edge(
        src=alice,
        group_arn=_IGME_ADMIN_GROUP_ARN,
        is_wildcard_resource=True,
    )
    admin_grant = _igme_admin_grant_edge(_IGME_ADMIN_GROUP_ARN)
    return _igme_make_facts(
        nodes=(alice, admin),
        edges=(aug_edge, admin_grant),
    )


def _igme_fixture_c_facts() -> FactGraph:
    """C: SCP blocks AddUserToGroup → blocked/info."""
    facts = _igme_build_alice_to_admin()
    aug_edge = next(e for e in facts.edges if e.edge_type == "iam:AddUserToGroup_permission")
    scp = _igme_scp()
    binding = _igme_binding(
        edge_id=aug_edge.edge_id,
        constraint_id=scp.constraint_id,
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


@pytest.mark.golden
class TestIAMGroupMembershipEscalationGoldens:
    """Pinned canonical findings.json for the group membership reasoner."""

    def test_fixture_a_validated_critical(self) -> None:
        """A: Alice → admin group → validated/critical"""
        _verify_or_regen(
            fixture_path=_IGME_DIR / "fixture_a_validated_critical.json",
            facts=_igme_fixture_a_facts(),
            reasoner=IAMGroupMembershipEscalationReasoner(),
            reasoners_used=_igme_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_b_wildcard_inconclusive(self) -> None:
        """B: wildcard resource → inconclusive/high"""
        _verify_or_regen(
            fixture_path=_IGME_DIR / "fixture_b_wildcard_inconclusive.json",
            facts=_igme_fixture_b_facts(),
            reasoner=IAMGroupMembershipEscalationReasoner(),
            reasoners_used=_igme_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_c_blocked_by_scp(self) -> None:
        """C: SCP blocks AddUserToGroup → blocked/info"""
        _verify_or_regen(
            fixture_path=_IGME_DIR / "fixture_c_blocked_by_scp.json",
            facts=_igme_fixture_c_facts(),
            reasoner=IAMGroupMembershipEscalationReasoner(),
            reasoners_used=_igme_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )


# ---------------------------------------------------------------------------
# S3 bucket takeover golden tests (v0.2.26)
# ---------------------------------------------------------------------------
#
# 3 fixtures for the S3 bucket takeover reasoner: A (validated/critical
# user rewrites bucket policy), B (wildcard resource inconclusive),
# C (SCP blocks, blocked/info).

from tests.test_s3_bucket_takeover_reasoner import (  # noqa: E402, I001
    _ALICE_ARN as _S3_ALICE_ARN,
    _BUCKET_A as _S3_BUCKET_A,
    _binding as _s3_binding,
    _bucket as _s3_bucket,
    _build_alice_to_bucket_a as _s3_build_alice_to_bucket_a,
    _make_facts as _s3_make_facts,
    _pbp_edge as _s3_pbp_edge,
    _scp as _s3_scp,
    _user as _s3_user,
)

_S3_DIR = GOLDEN_DIR / "s3_bucket_takeover"


def _s3_reasoners_used() -> dict[str, dict[str, str]]:
    r = S3BucketTakeoverReasoner()
    return {r.pattern_id: {"version": r.pattern_version, "title": r.pattern_title}}


def _s3_fixture_a_facts() -> FactGraph:
    """A: Alice rewrites bucket policy → validated/critical."""
    return _s3_build_alice_to_bucket_a()


def _s3_fixture_b_facts() -> FactGraph:
    """B: wildcard resource witness → inconclusive/high."""
    alice = _s3_user(_S3_ALICE_ARN)
    bucket = _s3_bucket(_S3_BUCKET_A)
    edge = _s3_pbp_edge(
        src=alice,
        bucket_arn=_S3_BUCKET_A,
        is_wildcard_resource=True,
    )
    return _s3_make_facts(nodes=(alice, bucket), edges=(edge,))


def _s3_fixture_c_facts() -> FactGraph:
    """C: SCP blocks PutBucketPolicy → blocked/info."""
    facts = _s3_build_alice_to_bucket_a()
    edge = next(e for e in facts.edges if e.edge_type == "s3:PutBucketPolicy_permission")
    scp = _s3_scp()
    binding = _s3_binding(
        edge_id=edge.edge_id,
        constraint_id=scp.constraint_id,
    )
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=(scp,),
        edge_constraints=(binding,),
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=False,
    )


@pytest.mark.golden
class TestS3BucketTakeoverGoldens:
    """Pinned canonical findings.json for the S3 bucket takeover reasoner."""

    def test_fixture_a_validated_critical(self) -> None:
        _verify_or_regen(
            fixture_path=_S3_DIR / "fixture_a_validated_critical.json",
            facts=_s3_fixture_a_facts(),
            reasoner=S3BucketTakeoverReasoner(),
            reasoners_used=_s3_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="validated",
            expected_severity="critical",
        )

    def test_fixture_b_wildcard_inconclusive(self) -> None:
        _verify_or_regen(
            fixture_path=_S3_DIR / "fixture_b_wildcard_inconclusive.json",
            facts=_s3_fixture_b_facts(),
            reasoner=S3BucketTakeoverReasoner(),
            reasoners_used=_s3_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="inconclusive",
            expected_severity="high",
        )

    def test_fixture_c_blocked_by_scp(self) -> None:
        _verify_or_regen(
            fixture_path=_S3_DIR / "fixture_c_blocked_by_scp.json",
            facts=_s3_fixture_c_facts(),
            reasoner=S3BucketTakeoverReasoner(),
            reasoners_used=_s3_reasoners_used(),
            expected_finding_count=1,
            expected_verdict="blocked",
            expected_severity="info",
        )


# ---------------------------------------------------------------------------
# Determinism: fixture H from §4B.5
# ---------------------------------------------------------------------------


class TestDeterminismDoubleEmit:
    """Plan §4B.5 fixture H: byte-identical findings.json across two emits.

    This is a behavioral test, not a fixture file — fixture H produces
    bytes byte-identical to fixture A by definition, so a separate file
    would just be a duplicate. The test below asserts the byte-equality
    property directly: emit fixture A's facts twice and compare the
    resulting bytes.
    """

    def test_double_emit_byte_identical(self) -> None:
        b1, h1 = _emit_for_fixture(
            facts=_prl_fixture_a_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
        )
        b2, h2 = _emit_for_fixture(
            facts=_prl_fixture_a_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
        )
        assert b1 == b2
        assert h1 == h2

    def test_double_emit_canonical_hash_in_file_stable(self) -> None:
        """The in-file canonical_hash is also stable across emits."""
        b1, _ = _emit_for_fixture(
            facts=_prl_fixture_a_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
        )
        b2, _ = _emit_for_fixture(
            facts=_prl_fixture_a_facts(),
            reasoner=PassRoleLambdaReasoner(),
            reasoners_used=_prl_reasoners_used(),
        )
        h1 = json.loads(b1)["metadata"]["canonical_hash"]
        h2 = json.loads(b2)["metadata"]["canonical_hash"]
        assert h1 == h2
