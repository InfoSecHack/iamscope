"""Pipeline orchestrator — ties all IAMScope phases into a single collect run.

Phase 1: Organization collection (OU tree, SCPs, account list)
Phase 2: Per-account IAM collection (roles, users, groups, policies)
Phase 3: Resolution pipeline (trust edges, synthetic nodes, permission edges,
         SCP bindings)
Phase 4: Scenario JSON emission

Per architecture doc §5.3:
- Phase 1 runs once against the management account
- Phase 2 runs per-account (assumes into each via collection role)
- Phase 3 is pure computation (no API calls)
- Phase 4 is pure serialization

All phases are deterministic given the same API responses.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import boto3

from iamscope.auth.assume_role import assume_collection_role, get_caller_identity
from iamscope.collector.account import AccountData, collect_account
from iamscope.collector.ec2_collector import collect_instance_profiles
from iamscope.collector.failures import CollectionFailure
from iamscope.collector.kms_collector import collect_kms_keys
from iamscope.collector.lambda_collector import collect_lambda_functions
from iamscope.collector.organization import collect_organization
from iamscope.collector.passrole import build_permission_edges
from iamscope.collector.s3_collector import collect_s3_buckets
from iamscope.collector.secrets_collector import collect_secrets
from iamscope.constants import EDGE_LAYER_PERMISSION, EDGE_LAYER_TRUST, ID_ALGORITHM, MAX_TOTAL_EDGES
from iamscope.controls.expansion import ExpansionController
from iamscope.controls.noise_filter import NoiseFilter
from iamscope.models import (
    AccountInfo,
    Constraint,
    Edge,
    EdgeConstraint,
    Node,
    NodeRef,
    OrgData,
    ResourcePolicyDocument,
    ScenarioMetadata,
    TrustParseResult,
)
from iamscope.output.scenario_json import emit_binding_metadata, emit_scenario
from iamscope.parser.parse_failures import PolicyParseFailure
from iamscope.parser.resource_policy import parse_resource_policy_documents
from iamscope.resolver.cross_account import build_trust_edges, resolve_synthetic_nodes
from iamscope.resolver.identity_deny_binder import (
    bind_all_identity_denies,
    build_identity_deny_constraints,
)
from iamscope.resolver.permission_boundary import (
    bind_permission_boundaries,
    build_permission_boundary_constraints,
)
from iamscope.resolver.resource_policy_binder import build_resource_policy_graph
from iamscope.resolver.scp_binder import bind_all_scps
from iamscope.resolver.stale_principal_drift import build_stale_principal_drift_constraints
from iamscope.resolver.trust_condition_binder import (
    bind_all_trust_conditions,
    build_trust_condition_constraints,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for a pipeline run."""

    # Auth
    profile_name: str | None = None
    region_name: str = "us-east-1"
    collection_role_name: str = "IAMScopeReader"
    external_id: str | None = None

    # Mode
    standalone: bool = False  # Single-account mode: skip org discovery

    # Scope
    account_filter: set[str] | None = None  # None = all accounts
    skip_accounts: set[str] = field(default_factory=set)

    # Noise filter
    include_service_linked: bool = False
    include_aws_managed: bool = False
    include_service_principals: bool = True

    # Expansion controls
    global_expansion_mode: str = "warn"
    passrole_mode: str | None = None
    lambda_mode: str | None = None
    ec2_mode: str | None = None

    # Output
    output_path: str = "scenario.json"
    binding_metadata_path: str = "binding_metadata.json"

    # Lambda/EC2/Secrets/KMS/S3 collection
    collect_lambda: bool = True
    collect_instance_profiles: bool = True
    collect_secrets: bool = True
    collect_kms: bool = True
    collect_s3: bool = True
    lambda_regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    secrets_regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    kms_regions: list[str] = field(default_factory=lambda: ["us-east-1"])


@dataclass
class PipelineResult:
    """Output of a pipeline run."""

    scenario_bytes: bytes = b""
    canonical_hash: str = ""
    binding_metadata_bytes: bytes = b""
    org_data: OrgData | None = None
    account_data: list[AccountData] = field(default_factory=list)
    accounts_collected: int = 0
    accounts_skipped: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    total_constraints: int = 0
    total_edge_constraints: int = 0
    total_lambda_functions: int = 0
    total_instance_profiles: int = 0
    edge_budget_exhausted: bool = False
    duration_seconds: float = 0.0

    # S14: structured fact-graph data so the CLI layer can construct a
    # `FactGraph` for reasoner runs without re-parsing scenario_bytes.
    # These fields are populated alongside scenario_bytes in run_pipeline
    # so callers don't need to know about the assembly internals. The
    # cost is ~0 — these are the same Python objects emit_scenario
    # consumed, just kept as attribute references rather than dropped.
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    constraints: list[Constraint] = field(default_factory=list)
    edge_constraints: list[EdgeConstraint] = field(default_factory=list)

    # BUG-013 fix: structured record of every per-region / per-global
    # collector call that raised. Populated by run_pipeline threading
    # a shared list into each collector. Empty in the happy path; any
    # non-empty value means the fact graph is partial and downstream
    # findings may be incomplete. CLI callers can choose to fail loud
    # or surface the list in reports. Also mirrored into
    # `ScenarioMetadata.collection_failures` so consumers that only
    # read scenario.json still see the signal.
    collection_failures: list[CollectionFailure] = field(default_factory=list)

    # BUG-024 fix: structured record of per-account IAM policy parse
    # failures aggregated from AccountData.policy_parse_failures. Empty
    # in the happy path; any non-empty value means one or more IAM
    # policies could not be parsed before graph construction.
    policy_parse_failures: list[PolicyParseFailure] = field(default_factory=list)


def run_pipeline(
    session: boto3.Session,
    config: PipelineConfig,
) -> PipelineResult:
    """Run the full IAMScope collection and resolution pipeline.

    Args:
        session: boto3 Session with permissions for the management account.
        config: Pipeline configuration.

    Returns:
        PipelineResult with scenario bytes, stats, and all intermediate data.
    """
    start_time = time.monotonic()
    result = PipelineResult()

    # Get caller identity (needed for both modes)
    caller = get_caller_identity(session)
    caller_account_id = caller["Account"]

    if config.standalone:
        # --- Standalone mode: skip org discovery ---
        logger.info("=== Standalone Mode: Single-Account Collection ===")
        org_data = OrgData(
            org_id="standalone",
            root_id="standalone",
            accounts=[
                AccountInfo(
                    account_id=caller_account_id,
                    name="standalone",
                    email="",
                    status="ACTIVE",
                    parent_id="standalone",
                ),
            ],
        )
        result.org_data = org_data

        # Collect the current account directly
        logger.info("Collecting account %s (standalone)", caller_account_id)
        all_account_data: list[AccountData] = []
        all_service_nodes: list[Node] = []
        all_service_edges: list[Edge] = []
        all_resource_policy_docs: list[ResourcePolicyDocument] = []

        acct_data = collect_account(
            session,
            caller_account_id,
            region_name=config.region_name,
            include_service_linked=config.include_service_linked,
            include_aws_managed=config.include_aws_managed,
        )
        all_account_data.append(acct_data)

        if config.collect_lambda:
            lambda_nodes, lambda_edges = collect_lambda_functions(
                session,
                caller_account_id,
                regions=config.lambda_regions,
                failures=result.collection_failures,
                resource_policies=all_resource_policy_docs,
            )
            all_service_nodes.extend(lambda_nodes)
            all_service_edges.extend(lambda_edges)
            result.total_lambda_functions += len(lambda_nodes)

        if config.collect_secrets:
            secret_nodes = collect_secrets(
                session,
                caller_account_id,
                regions=config.secrets_regions,
                failures=result.collection_failures,
                resource_policies=all_resource_policy_docs,
            )
            all_service_nodes.extend(secret_nodes)

        if config.collect_kms:
            kms_nodes = collect_kms_keys(
                session,
                caller_account_id,
                regions=config.kms_regions,
                failures=result.collection_failures,
                resource_policies=all_resource_policy_docs,
            )
            all_service_nodes.extend(kms_nodes)

        if config.collect_s3:
            s3_nodes = collect_s3_buckets(
                session,
                caller_account_id,
                failures=result.collection_failures,
                resource_policies=all_resource_policy_docs,
            )
            all_service_nodes.extend(s3_nodes)

        if config.collect_instance_profiles:
            ip_nodes, ip_edges = collect_instance_profiles(session, caller_account_id)
            all_service_nodes.extend(ip_nodes)
            all_service_edges.extend(ip_edges)
            result.total_instance_profiles += len(ip_nodes)

        result.account_data = all_account_data
        result.accounts_collected = 1
        result.accounts_skipped = 0

    else:
        # --- Organization mode: full org discovery ---
        # --- Phase 1: Organization ---
        logger.info("=== Phase 1: Organization Collection ===")
        org_data = collect_organization(session, region_name=config.region_name)
        result.org_data = org_data
        logger.info(
            "Org %s: %d accounts, %d OUs, %d SCP constraints",
            org_data.org_id,
            len(org_data.accounts),
            len(org_data.ous),
            len(org_data.scp_constraints),
        )

        # --- Phase 2: Per-Account Collection ---
        logger.info("=== Phase 2: Per-Account Collection ===")
        mgmt_account_id = caller_account_id

        target_accounts = _resolve_target_accounts(org_data, config, mgmt_account_id)
        logger.info("Target accounts: %d", len(target_accounts))

        all_account_data = []
        all_service_nodes = []
        all_service_edges = []
        all_resource_policy_docs = []
        accounts_skipped = 0

        for account_id in sorted(target_accounts):
            acct_session = _get_account_session(session, account_id, mgmt_account_id, config)
            if acct_session is None:
                accounts_skipped += 1
                continue

            acct_data = collect_account(
                acct_session,
                account_id,
                region_name=config.region_name,
                include_service_linked=config.include_service_linked,
                include_aws_managed=config.include_aws_managed,
            )
            all_account_data.append(acct_data)

            if config.collect_lambda:
                lambda_nodes, lambda_edges = collect_lambda_functions(
                    acct_session,
                    account_id,
                    regions=config.lambda_regions,
                    failures=result.collection_failures,
                    resource_policies=all_resource_policy_docs,
                )
                all_service_nodes.extend(lambda_nodes)
                all_service_edges.extend(lambda_edges)
                result.total_lambda_functions += len(lambda_nodes)

            if config.collect_secrets:
                secret_nodes = collect_secrets(
                    acct_session,
                    account_id,
                    regions=config.secrets_regions,
                    failures=result.collection_failures,
                    resource_policies=all_resource_policy_docs,
                )
                all_service_nodes.extend(secret_nodes)

            if config.collect_kms:
                kms_nodes = collect_kms_keys(
                    acct_session,
                    account_id,
                    regions=config.kms_regions,
                    failures=result.collection_failures,
                    resource_policies=all_resource_policy_docs,
                )
                all_service_nodes.extend(kms_nodes)

            if config.collect_s3:
                s3_nodes = collect_s3_buckets(
                    acct_session,
                    account_id,
                    failures=result.collection_failures,
                    resource_policies=all_resource_policy_docs,
                )
                all_service_nodes.extend(s3_nodes)

            if config.collect_instance_profiles:
                ip_nodes, ip_edges = collect_instance_profiles(acct_session, account_id)
                all_service_nodes.extend(ip_nodes)
                all_service_edges.extend(ip_edges)
                result.total_instance_profiles += len(ip_nodes)

        result.account_data = all_account_data
        result.accounts_collected = len(all_account_data)
        result.accounts_skipped = accounts_skipped

    result.policy_parse_failures = _aggregate_policy_parse_failures(result.account_data)

    # --- Phase 3: Resolution ---
    logger.info("=== Phase 3: Resolution Pipeline ===")
    nodes, edges, constraints, edge_constraints, budget_hit = _run_resolution(
        org_data,
        all_account_data,
        config,
        all_service_nodes,
        all_service_edges,
        resource_policy_documents=all_resource_policy_docs,
    )
    result.total_nodes = len(nodes)
    result.total_edges = len(edges)
    result.total_constraints = len(constraints)
    result.total_edge_constraints = len(edge_constraints)
    result.edge_budget_exhausted = budget_hit

    # --- Phase 3.5: Dangling-reference endpoint materialization ---
    # BUG-023 (dst case) + Fix A (src case). Real-world IAM policies
    # routinely reference resources that are not in the collected node
    # set. The canonical dst case is RDS-managed SecretsManager secrets
    # with the `rds!` name prefix: these are owned by the RDS service,
    # not returned by `secretsmanager:ListSecrets` for most principals
    # (even with full read perms), but they ARE referenced by ARN in
    # IAM policies that grant principals access to the database's
    # master credentials. The permission edge builder creates a
    # specific edge pointing at the literal ARN, and the scenario
    # emission validator crashes because no node with that provider_id
    # exists in the fact graph.
    #
    # The symmetric src case: `cross_account.build_trust_edges` creates
    # a trust edge for every parsed principal, and
    # `resolve_synthetic_nodes` materializes a synthetic for every
    # principal type EXCEPT same-account IAMRole/IAMUser — which are
    # assumed to be present in the IAM collector output. When a trust
    # policy references a deleted, renamed, or not-yet-created
    # same-account role (a common drift pattern in real customer
    # environments), that assumption breaks and the trust edge has a
    # src that does not resolve. Pre-Fix-A the validator only checked
    # dst, so these passed silently. Fix A rule 8b checks both, so
    # the pipeline has to materialize the missing src before emission.
    #
    # Other shapes that trigger the dst case:
    # - Lambda functions in regions the collector didn't scan
    # - Deleted resources referenced by stale IAM policies
    # - Cross-account resources the collector has list perms on but
    #   doesn't walk as part of the org scope
    # - KMS keys in other accounts referenced by cross-account grants
    #
    # The fix is to synthesize a placeholder node for every
    # unresolvable edge endpoint (src or dst), flagged with
    # `is_dangling_reference=True` so downstream reasoners can demote
    # verdicts on findings against these endpoints to INCONCLUSIVE
    # (we can confirm the IAM permission grant or trust exists but
    # cannot verify the KMS layer, current reachability, or other
    # endpoint-specific gates).
    #
    # Pre-BUG-023 the validator raised `Edge dst references non-existent
    # node` on these, blocking the entire pipeline. Post-fix the pipeline
    # runs to completion and the findings output clearly marks the
    # synthetic endpoints in both the scenario.json nodes list and the
    # downstream findings.
    synthetic_dangling_nodes = _materialize_dangling_endpoints(nodes, edges)
    if synthetic_dangling_nodes:
        logger.warning(
            "Materialized %d synthetic endpoint node(s) for dangling "
            "IAM references (e.g., rds! secrets, cross-region Lambda, "
            "deleted resources, stale same-account trust principals). "
            "Downstream findings against these endpoints are demoted "
            "to INCONCLUSIVE. See scenario.json nodes list for "
            "is_dangling_reference=True.",
            len(synthetic_dangling_nodes),
        )
        nodes = list(nodes) + synthetic_dangling_nodes
        # Re-count totals so the metadata reflects the materialized set.
        result.total_nodes = len(nodes)

    # --- Phase 4: Emission ---
    logger.info("=== Phase 4: Scenario Emission ===")
    # BUG-013: emit a summary warning if any collectors silently
    # skipped regions/calls during this run. Individual warnings are
    # already logged by each collector at the point of failure; this
    # aggregates them so operators watching the final pipeline log
    # can't miss the signal. The structured list is embedded in both
    # PipelineResult and ScenarioMetadata for programmatic consumers.
    if result.collection_failures:
        logger.warning(
            "Collection was partial: %d failed calls across "
            "lambda/secrets/kms/s3 collectors. Fact graph may be "
            "incomplete and downstream findings may be missing. "
            "See PipelineResult.collection_failures or the "
            "scenario.json metadata.collection_failures field for "
            "the full list.",
            len(result.collection_failures),
        )
    if result.policy_parse_failures:
        logger.warning(
            "IAM policy parsing was partial: %d policy document(s) failed "
            "to parse during account collection. Fact graph may be "
            "incomplete and downstream findings may be missing. "
            "See PipelineResult.policy_parse_failures or the scenario.json "
            "metadata.policy_parse_failures field for the full list.",
            len(result.policy_parse_failures),
        )
    metadata = ScenarioMetadata(
        collector="iamscope",
        collector_version="0.2.0",
        id_algorithm=ID_ALGORITHM,
        org_id=org_data.org_id,
        accounts_collected=result.accounts_collected,
        accounts_skipped=result.accounts_skipped,
        collection_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        noise_filter={
            "include_service_linked": config.include_service_linked,
            "include_aws_managed": config.include_aws_managed,
            "expansion_mode": config.global_expansion_mode,
            "standalone": config.standalone,
        },
        graph_stats={
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_constraints": len(constraints),
            "total_edge_constraints": len(edge_constraints),
        },
        collection_failures=[f.to_dict() for f in result.collection_failures],
        policy_parse_failures=[f.to_dict() for f in result.policy_parse_failures],
    )

    scenario_bytes, canonical_hash = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=metadata,
    )
    result.scenario_bytes = scenario_bytes
    result.canonical_hash = canonical_hash

    # S14: expose structured fact data for the CLI layer's reasoner
    # phase. The lists are the same Python objects emit_scenario
    # consumed, retained as attribute references.
    result.nodes = nodes
    result.edges = edges
    result.constraints = constraints
    result.edge_constraints = edge_constraints

    # Emit binding metadata sidecar
    result.binding_metadata_bytes = emit_binding_metadata(edge_constraints)

    duration = time.monotonic() - start_time
    result.duration_seconds = duration
    metadata.collection_duration_seconds = duration

    logger.info(
        "Pipeline complete: %d nodes, %d edges, %d constraints, %d edge_constraints, hash=%s, duration=%.1fs",
        len(nodes),
        len(edges),
        len(constraints),
        len(edge_constraints),
        canonical_hash[:12],
        duration,
    )

    return result


def _policy_parse_failure_sort_key(failure: PolicyParseFailure) -> tuple[str, str, str, str, str, str, str, str]:
    """Stable ordering for policy parse failures across accounts and AWS pages."""
    return (
        failure.parser,
        failure.source_arn,
        failure.policy_source,
        failure.policy_name,
        failure.policy_arn,
        failure.failure_kind,
        failure.error_class,
        failure.error_message,
    )


def _aggregate_policy_parse_failures(account_data: list[AccountData]) -> list[PolicyParseFailure]:
    """Aggregate per-account IAM policy parse failures deterministically."""
    failures: list[PolicyParseFailure] = []
    for acct in sorted(account_data, key=lambda account: account.account_id):
        failures.extend(sorted(acct.policy_parse_failures, key=_policy_parse_failure_sort_key))
    return failures


def _resolve_target_accounts(
    org_data: OrgData,
    config: PipelineConfig,
    mgmt_account_id: str,
) -> set[str]:
    """Determine which accounts to collect."""
    target = set(config.account_filter) if config.account_filter is not None else set(org_data.active_account_ids)
    target -= config.skip_accounts
    return target


def _get_account_session(
    session: boto3.Session,
    account_id: str,
    mgmt_account_id: str,
    config: PipelineConfig,
) -> boto3.Session | None:
    """Get a boto3 Session for a target account.

    For the management account, use the existing session.
    For member accounts, assume the collection role.
    """
    if account_id == mgmt_account_id:
        return session

    return assume_collection_role(
        session,
        account_id,
        config.collection_role_name,
        region_name=config.region_name,
        external_id=config.external_id,
    )


def _org_membership_resolution_context(
    org_data: OrgData,
    all_account_data: list[AccountData],
    config: PipelineConfig,
) -> tuple[set[str], bool]:
    """Return known accounts and whether absence proves non-membership.

    Trust-policy synthetic principals need a tri-state org-membership signal:
    member, non_member, or unknown. Known active org accounts and directly
    collected account IDs are members. Absence proves non-membership only when
    the run covers the full active org account set. Standalone, account-filtered,
    skipped, or otherwise partial runs leave absent accounts unknown instead of
    silently asserting they are external/non-members.
    """
    active_org_accounts = set(org_data.active_account_ids)
    collected_accounts = {acct.account_id for acct in all_account_data if acct.account_id}
    known_accounts = active_org_accounts | collected_accounts

    org_collection_complete = (
        not config.standalone
        and config.account_filter is None
        and not config.skip_accounts
        and bool(active_org_accounts)
        and active_org_accounts <= collected_accounts
    )
    return known_accounts, org_collection_complete


def _run_resolution(
    org_data: OrgData,
    all_account_data: list[AccountData],
    config: PipelineConfig,
    service_nodes: list[Node] | None = None,
    service_edges: list[Edge] | None = None,
    resource_policy_documents: list[ResourcePolicyDocument] | None = None,
) -> tuple[list[Node], list[Edge], list[Constraint], list[EdgeConstraint], bool]:
    """Run the Phase 3 resolution pipeline.

    Steps:
    1. Collect all IAM nodes from account data
    2. Build trust edges from trust parse results
    3. Resolve synthetic nodes (external accounts, wildcards, services)
    4. Build permission edges with expansion controls
    5. Add Lambda/EC2 service nodes and edges
    6. Bind SCPs to trust edges

    Enforces MAX_TOTAL_EDGES as a hard circuit-breaker. If the budget
    is exhausted mid-collection, remaining edges are dropped and a
    warning is logged.

    Returns:
        Tuple of (nodes, edges, constraints, edge_constraints, budget_exhausted).
    """
    all_nodes: list[Node] = []
    all_edges: list[Edge] = []
    all_constraints: list[Constraint] = list(org_data.scp_constraints)
    edge_budget_exhausted = False

    def _add_edges(new_edges: list[Edge]) -> None:
        """Append edges up to MAX_TOTAL_EDGES, then drop the rest."""
        nonlocal edge_budget_exhausted
        if edge_budget_exhausted:
            return
        remaining = MAX_TOTAL_EDGES - len(all_edges)
        if remaining <= 0:
            edge_budget_exhausted = True
            logger.warning(
                "Edge budget exhausted at %d edges (MAX_TOTAL_EDGES=%d). Dropping %d remaining edges.",
                len(all_edges),
                MAX_TOTAL_EDGES,
                len(new_edges),
            )
            return
        if len(new_edges) > remaining:
            logger.warning(
                "Edge budget nearly exhausted: accepting %d of %d edges (total will be %d/%d).",
                remaining,
                len(new_edges),
                MAX_TOTAL_EDGES,
                MAX_TOTAL_EDGES,
            )
            all_edges.extend(new_edges[:remaining])
            edge_budget_exhausted = True
        else:
            all_edges.extend(new_edges)

    # Aggregate all role ARNs across all accounts for expansion control.
    # Sort/dedupe before wildcard expansion so AWS response ordering cannot
    # perturb expanded permission edge construction across repeat collects.
    all_role_arns: list[str] = []
    for acct in all_account_data:
        all_role_arns.extend(acct.role_arns)
    all_role_arns = sorted(set(all_role_arns))

    # Expansion controller
    ec = ExpansionController(
        global_mode=config.global_expansion_mode,
        passrole_mode=config.passrole_mode,
        lambda_mode=config.lambda_mode,
        ec2_mode=config.ec2_mode,
    )

    # Known account IDs for synthetic node resolution. Absence from this set
    # proves non-membership only when collection covered the full active org;
    # partial/standalone runs keep absent accounts explicitly unknown.
    known_accounts, org_collection_complete = _org_membership_resolution_context(
        org_data,
        all_account_data,
        config,
    )

    # NF-1 fix (S06): construct a real NoiseFilter from config and pass its
    # edge filter function to build_trust_edges. Pre-S06 this was dead code
    # on the hot path — the filter class was tested but never instantiated
    # by the pipeline. Default `exclude_self_trust=True` removes role-trusts-
    # itself noise edges which inflate the graph without adding signal.
    noise_filter = NoiseFilter(
        exclude_service_linked=not config.include_service_linked,
        exclude_aws_managed=not config.include_aws_managed,
        exclude_service_principals=not config.include_service_principals,
        exclude_accounts=frozenset(config.skip_accounts),
        include_accounts=(frozenset(config.account_filter) if config.account_filter else frozenset()),
    )
    noise_filter_fn = noise_filter.to_filter_fn()

    # Collect trust results grouped by role node
    all_trust_results: list[TrustParseResult] = []

    for acct in all_account_data:
        # Add IAM nodes
        all_nodes.extend(acct.nodes)

        # Group trust results by role node
        role_trust_map: dict[str, tuple[Node, list[TrustParseResult]]] = {}
        for role_node, tr in acct.trust_results:
            if role_node.provider_id not in role_trust_map:
                role_trust_map[role_node.provider_id] = (role_node, [])
            role_trust_map[role_node.provider_id][1].append(tr)
            all_trust_results.append(tr)

        # Build trust edges per role — now applying the NoiseFilter callback.
        for _role_arn, (role_node, trust_results) in sorted(role_trust_map.items()):
            trust_edges = build_trust_edges(
                trust_results,
                role_node,
                noise_filter_fn=noise_filter_fn,
            )
            _add_edges(trust_edges)

        # Build permission edges
        perm_edges, hyperedge_nodes = build_permission_edges(acct.permission_results, ec, all_role_arns)
        _add_edges(perm_edges)
        all_nodes.extend(hyperedge_nodes)

    # Resolve synthetic nodes (external accounts, wildcards, services)
    synthetic_nodes = resolve_synthetic_nodes(
        all_trust_results,
        known_account_ids=known_accounts,
        org_collection_complete=org_collection_complete,
    )
    all_nodes.extend(synthetic_nodes)

    # Add Lambda/EC2 service nodes and edges
    if service_nodes:
        all_nodes.extend(service_nodes)
    if service_edges:
        _add_edges(service_edges)

    if resource_policy_documents:
        resource_policy_results = parse_resource_policy_documents(resource_policy_documents)
        rp_nodes, rp_edges, rp_constraints, rp_edge_constraints = build_resource_policy_graph(
            resource_policy_results,
            all_nodes,
        )
        all_nodes.extend(rp_nodes)
        _add_edges(rp_edges)
        all_constraints.extend(rp_constraints)
    else:
        rp_edge_constraints = []

    # Separate trust edges for SCP binding
    trust_edges = [e for e in all_edges if e.edge_type.endswith(f"_{EDGE_LAYER_TRUST}")]

    # Build and bind trust-condition constraints before SCPs so conditioned
    # trust controls are exported as first-class scenario constraints.
    trust_condition_constraints = build_trust_condition_constraints(trust_edges)
    if trust_condition_constraints:
        all_constraints.extend(trust_condition_constraints)

    # Bind SCPs to trust edges
    edge_constraints = bind_all_scps(trust_edges, all_constraints, org_data.ou_account_map)

    if trust_condition_constraints:
        edge_constraints.extend(bind_all_trust_conditions(trust_edges, trust_condition_constraints))

    edge_constraints.extend(rp_edge_constraints)

    # Build and bind permission boundary constraints
    all_boundary_policies: dict[str, dict] = {}
    for acct in all_account_data:
        all_boundary_policies.update(acct.permission_boundary_policies)

    if all_boundary_policies:
        boundary_constraints = build_permission_boundary_constraints(all_boundary_policies)
        all_constraints.extend(boundary_constraints)
        boundary_ecs = bind_permission_boundaries(
            all_edges,
            all_nodes,
            boundary_constraints,
        )
        edge_constraints.extend(boundary_ecs)

    identity_deny_constraints: list[Constraint] = []
    for acct in all_account_data:
        acct.permission_deny_constraints = build_identity_deny_constraints(acct.raw_deny_results)
        identity_deny_constraints.extend(acct.permission_deny_constraints)

    if identity_deny_constraints:
        all_constraints.extend(identity_deny_constraints)
        permission_edges = [e for e in all_edges if e.edge_type.endswith(f"_{EDGE_LAYER_PERMISSION}")]
        identity_deny_ecs = bind_all_identity_denies(
            permission_edges,
            identity_deny_constraints,
        )
        edge_constraints.extend(identity_deny_ecs)

    # Deduplicate nodes by node_id
    seen_node_ids: set[str] = set()
    unique_nodes: list[Node] = []
    for node in all_nodes:
        if node.node_id not in seen_node_ids:
            seen_node_ids.add(node.node_id)
            unique_nodes.append(node)

    # Deduplicate edges by edge_id
    seen_edge_ids: set[str] = set()
    unique_edges: list[Edge] = []
    for edge in all_edges:
        if edge.edge_id not in seen_edge_ids:
            seen_edge_ids.add(edge.edge_id)
            unique_edges.append(edge)

    stale_drift_constraints, stale_drift_edge_constraints = build_stale_principal_drift_constraints(unique_edges)
    if stale_drift_constraints:
        existing_constraint_ids = {constraint.constraint_id for constraint in all_constraints}
        for constraint in stale_drift_constraints:
            if constraint.constraint_id not in existing_constraint_ids:
                all_constraints.append(constraint)
                existing_constraint_ids.add(constraint.constraint_id)
        edge_constraints.extend(stale_drift_edge_constraints)

    return unique_nodes, unique_edges, all_constraints, edge_constraints, edge_budget_exhausted


# ---------------------------------------------------------------------------
# BUG-023 / Fix A — dangling-reference endpoint materialization
# ---------------------------------------------------------------------------


_DANGLING_REASON_DST = (
    "referenced by IAM policy but not returned by collection — may be "
    "a restricted resource (e.g. rds! SecretsManager secrets), in an "
    "unscanned region, in another account, or deleted"
)
_DANGLING_REASON_SRC = (
    "principal named in a trust policy but not resolvable — may be a "
    "deleted or renamed same-account IAM role/user, a not-yet-created "
    "principal mid-Terraform-apply, or eventual-consistency drift "
    "between Organizations and IAM"
)


def _materialize_dangling_endpoints(
    nodes: list[Node],
    edges: list[Edge],
) -> list[Node]:
    """Synthesize placeholder nodes for edges with unresolvable endpoints.

    BUG-023 (dst case): real-world IAM policies routinely reference
    resources that the collector couldn't or didn't collect. The
    canonical case is RDS-managed SecretsManager secrets (name prefix
    `rds!`) which are owned by the RDS service and hidden from
    `ListSecrets` for most principals, but ARE referenced by literal
    ARN in IAM policies that grant database credential access. Pre-fix
    the edge builder would create a permission edge targeting the
    literal ARN and the scenario validator would crash with "Edge dst
    references non-existent node".

    Fix A (src case): same architectural gap exists on the edge src
    side for trust edges. `cross_account.build_trust_edges` constructs
    one edge per parsed trust policy principal and
    `resolve_synthetic_nodes` materializes a synthetic for every
    principal EXCEPT same-account `IAMRole`/`IAMUser` (see
    `cross_account._create_synthetic_node`). The assumption is that
    same-account roles are present in the IAM collector output. That
    assumption breaks when a trust policy references a deleted,
    renamed, or not-yet-created same-account principal — a common
    drift pattern in customer environments. Pre-Fix-A the validator
    only checked edge dst, so these dangling srcs passed silently.
    Fix A's validate.py rule 8b checks src as well, so the pipeline
    has to materialize the missing src before emission.

    This function scans the edges after resolution and, for each
    unique (provider, node_type, provider_id) src OR dst that isn't
    in the collected node set, emits a synthetic Node with:
    - `is_synthetic=True` — marks as not directly collected
    - `is_dangling_reference=True` — marks as the specific "referenced
      by policy but not collected" case, distinguishing it from other
      synthetic nodes (hyperedges, external-account placeholders, etc.)
    - `collection_status="not_collected"` — human-readable reason
    - `dangling_reason` — src case and dst case carry distinct strings
      so operators can tell which drift pattern they hit
    - `account_id` extracted from ARN when present — needed for the
      reasoner's scope filters

    Downstream reasoners SHOULD check `is_dangling_reference` on
    endpoint nodes and demote verdicts to INCONCLUSIVE when set — we
    can confirm the IAM permission grant or trust exists but cannot
    verify KMS/boundary/current-existence gates on an endpoint we
    never collected. Reasoner-side integration is a separate
    incremental change; this function alone unblocks the pipeline
    and preserves the signal in scenario.json.

    Returns the list of synthetic Node objects to append to the graph's
    node list. The edges list is NOT modified — the caller simply adds
    the returned nodes and proceeds to emission.
    """
    # Build lookup of already-present (provider, node_type, provider_id)
    # triples. This matches the key shape the scenario_json validator
    # uses, so any key NOT in this set is exactly what the validator
    # would have rejected.
    known: set[tuple[str, str, str]] = set()
    for n in nodes:
        known.add((n.provider, n.node_type, n.provider_id))

    # Accumulate unique synthetic endpoints. Multiple edges may point
    # at the same dangling ARN — we only emit one synthetic node per
    # unique (provider, node_type, provider_id) triple, matching the
    # validator's uniqueness contract. First-insertion wins on the
    # dangling_reason string when a key appears as both a dangling
    # src in one edge and a dangling dst in another; edges are already
    # deduped and ordered upstream so the outcome is deterministic.
    synthetic: dict[tuple[str, str, str], Node] = {}

    def _emit(ref: NodeRef, reason: str) -> None:
        key = (ref.provider, ref.node_type, ref.provider_id)
        if key in known or key in synthetic:
            return
        synthetic[key] = Node(
            provider=ref.provider,
            node_type=ref.node_type,
            provider_id=ref.provider_id,
            region=ref.region,
            properties={
                "account_id": _extract_account_id_from_arn(ref.provider_id),
                "is_synthetic": True,
                "is_dangling_reference": True,
                "collection_status": "not_collected",
                "dangling_reason": reason,
            },
        )

    for e in edges:
        _emit(e.src, _DANGLING_REASON_SRC)
        _emit(e.dst, _DANGLING_REASON_DST)

    # Sort for determinism so the canonical hash is stable across runs
    # with the same inputs.
    return sorted(synthetic.values(), key=lambda n: n.node_id)


def _extract_account_id_from_arn(arn: str) -> str:
    """Extract the 12-digit account ID from an AWS ARN.

    Handles standard ARN shapes:
        arn:aws:<service>:<region>:<account>:<resource>

    Returns the account ID if found, empty string otherwise. Used by
    `_materialize_dangling_endpoints` to populate the `account_id`
    property on synthetic nodes — the reasoners' scope filters and
    SCP binding paths both expect this property to be set for
    account-scoped resources.
    """
    # Split on `:` — ARN format is
    # arn : partition : service : region : account : resource...
    # ...so the account is field 4 (zero-indexed).
    if not arn.startswith("arn:"):
        return ""
    parts = arn.split(":", 5)
    if len(parts) < 5:
        return ""
    account = parts[4]
    # Some ARNs omit the account (e.g. S3 bucket ARNs:
    # `arn:aws:s3:::my-bucket`). Return empty for those.
    if not account or len(account) != 12 or not account.isdigit():
        return ""
    return account
