"""S3 bucket takeover reasoner.

Pattern: a principal (user or role) with `s3:PutBucketPolicy`
permission on an S3 bucket can rewrite the bucket policy and grant
themselves full control of the bucket's contents. This is the most
direct S3 data-exfiltration primitive — whatever is in the bucket
(credentials, source code, backups, customer data, infrastructure
templates) becomes accessible to the attacker after one API call.

The reasoner does NOT evaluate the CURRENT bucket policy content — it
only cares that the principal CAN rewrite it. A future v2 could pull
the current policy for defense-in-depth analysis, but v1 is pure
IAM-layer reasoning: "who holds the pen" rather than "what's written
on the page right now."

Source scoping: users + roles. Both are realistic attackers. A
compromised role session can rewrite a bucket policy just as
effectively as a user; the differentiator (user has stable identity,
role requires ongoing session) doesn't matter once the policy is
rewritten. The fifth check filters service principals and root
because those represent infrastructure, not attacker-controlled
entities — a Lambda execution role with `s3:PutBucketPolicy` IS a
realistic finding, but the AWS service principal `s3.amazonaws.com`
itself is not.

Target scoping: all S3Bucket nodes in the graph. For each (principal,
bucket) pair where the principal holds a clean or wildcard
`s3:PutBucketPolicy` permission edge, emit a finding. One finding per
pair — deduplicated across multiple witness statements.

Fact-layer dependency: this reasoner requires S3Bucket nodes in the
graph. The v0.2.26 S3 collector (`iamscope/collector/s3_collector.py`)
creates these nodes via `list_buckets`. Before v0.2.26, S3 bucket
ARNs were classified as IAMRole via the legacy fallback in
`_classify_resource_arn` and no S3-aware reasoner was possible.

Verdict mapping:
    Check 3 FAIL (SCP blocks)           → blocked / info
    Check 4 FAIL (boundary blocks)      → blocked / info
    Check 5 FAIL (service/root)         → no finding (filtered)
    Check 2 UNKNOWN (wildcard witness)  → inconclusive / high
    Any check UNKNOWN                   → inconclusive / high
    All checks PASS                     → validated / critical

Severity rationale: validated → critical always. Rewriting a bucket
policy gives the attacker unrestricted read/write on all objects in
the bucket. There's no "partial control" — the attacker controls
what the policy says next, which is the same as controlling the
bucket. An inconclusive variant is `high` because wildcard cases are
common and would flood reports if classified critical.
"""

from __future__ import annotations

import logging

from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_S3_BUCKET,
)
from iamscope.models import Edge, Node
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph, _is_unknown_witness
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


_PUT_BUCKET_POLICY_ACTION: str = "s3:PutBucketPolicy"
_PUT_BUCKET_POLICY_EDGE_TYPE: str = f"{_PUT_BUCKET_POLICY_ACTION}_permission"


class S3BucketTakeoverReasoner:
    """Detect principals who can take over an S3 bucket via PutBucketPolicy."""

    pattern_id: str = "s3_bucket_takeover"
    pattern_version: str = "1.0.0"
    pattern_title: str = "S3 Bucket Takeover"
    severity_default: str = "critical"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Run only if there's at least one S3 bucket AND one principal."""
        has_bucket = any(n.node_type == NODE_TYPE_S3_BUCKET for n in facts.nodes)
        if not has_bucket:
            return (False, "no S3Bucket nodes in graph")
        has_principal = any(n.node_type in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE) for n in facts.nodes)
        if not has_principal:
            return (False, "no IAMUser or IAMRole nodes in graph")
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Enumerate (principal, bucket) pairs with PutBucketPolicy."""
        findings: list[Finding] = []
        all_buckets: list[Node] = [n for n in facts.nodes if n.node_type == NODE_TYPE_S3_BUCKET]

        for node in facts.nodes:
            if node.node_type not in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE):
                continue
            witnesses: list[Edge] = [
                e for e in facts.edges_from(node.provider_id) if e.edge_type == _PUT_BUCKET_POLICY_EDGE_TYPE
            ]
            if not witnesses:
                continue

            # Dedupe by bucket provider_id so we emit at most one
            # finding per (principal, bucket) pair.
            targets: dict[str, tuple[Node, Edge, bool]] = {}
            for edge in witnesses:
                dst_provider_id = edge.dst.provider_id
                is_unknown = _is_unknown_witness(edge)
                if is_unknown:
                    # Hyperedge or wildcard resource → iterate all
                    # buckets as potential targets, mark check 2 UNKNOWN.
                    for b in all_buckets:
                        if b.provider_id not in targets:
                            targets[b.provider_id] = (b, edge, False)
                else:
                    # Clean witness → try to match a specific bucket
                    # node via O(1) provider_id lookup. If the dst ARN
                    # doesn't match any bucket node directly (possible
                    # for object-level grants), fall back to iterating
                    # all buckets as UNKNOWN.
                    candidate = facts.node_by_provider_id(dst_provider_id)
                    if candidate is not None and candidate.node_type == NODE_TYPE_S3_BUCKET:
                        targets[dst_provider_id] = (candidate, edge, True)
                    else:
                        for b in all_buckets:
                            if b.provider_id not in targets:
                                targets[b.provider_id] = (b, edge, False)

            for bucket_provider_id in sorted(targets.keys()):
                bucket, witness_edge, is_clean = targets[bucket_provider_id]
                finding = self._build_finding(
                    facts=facts,
                    principal=node,
                    bucket=bucket,
                    witness_edge=witness_edge,
                    is_clean_witness=is_clean,
                )
                if finding is not None:
                    findings.append(finding)

        findings.sort(
            key=lambda f: (f.source.provider_id, f.target.provider_id),
        )
        return findings

    # ---------------------------------------------------------------
    # Finding construction
    # ---------------------------------------------------------------

    def _build_finding(
        self,
        *,
        facts: FactGraph,
        principal: Node,
        bucket: Node,
        witness_edge: Edge,
        is_clean_witness: bool,
    ) -> Finding | None:
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        edge_refs: list[str] = [witness_edge.edge_id]
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        node_refs_set: set[str] = {principal.node_id, bucket.node_id}
        trace: list[TraceEntry] = []

        self._absorb_digests(witness_edge, statement_digests, statement_sources)

        # ---- Check 1: principal_has_put_bucket_policy_permission
        check_results.append(
            Check(
                name="principal_has_put_bucket_policy_permission",
                description=("Principal has a permission edge for s3:PutBucketPolicy (enumeration invariant)"),
                state=CheckState.PASS,
                evidence_refs=(witness_edge.edge_id,),
                reason="permission edge witnessed",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_principal_has_put_bucket_policy_permission",
                inputs=(principal.provider_id,),
                result="PASS",
                reason="permission edge witnessed",
            )
        )

        # ---- Check 2: witness_edge_is_clean
        check_2_state = CheckState.PASS if is_clean_witness else CheckState.UNKNOWN
        check_2_reason = (
            "witness edge resolves to specific target bucket"
            if is_clean_witness
            else "witness edge is wildcard-expansion hyperedge or "
            "wildcard-resource (target bucket iterated from all "
            "buckets)"
        )
        check_results.append(
            Check(
                name="witness_edge_is_clean",
                description=(
                    "Permission edge for s3:PutBucketPolicy resolves to a "
                    "specific target bucket (clean witness proves the edge's "
                    "target)"
                ),
                state=check_2_state,
                evidence_refs=(witness_edge.edge_id,),
                reason=check_2_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_witness_edge_is_clean",
                inputs=(witness_edge.edge_id,),
                result=check_2_state.value.upper(),
                reason=check_2_reason,
            )
        )

        # ---- Check 3: no_scp_blocks_put_bucket_policy
        # Each check gets its own constraint_refs accumulator so the
        # evidence_refs attributed to check 3 are ONLY the SCPs it
        # evaluated, not a contaminated mix of SCPs and boundaries.
        check_3_constraint_refs: set[str] = set()
        check_3_state, check_3_reason, check_3_blockers = self._check_scp_blockers(
            facts,
            witness_edge,
            check_3_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_3_blockers)
        check_results.append(
            Check(
                name="no_scp_blocks_put_bucket_policy",
                description=("No SCP blocks s3:PutBucketPolicy on this edge with complete governance confidence"),
                state=check_3_state,
                evidence_refs=(
                    tuple(sorted(check_3_constraint_refs)) if check_3_constraint_refs else (witness_edge.edge_id,)
                ),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_no_scp_blocks_put_bucket_policy",
                inputs=(witness_edge.edge_id,),
                result=check_3_state.value.upper(),
                reason=check_3_reason,
            )
        )
        constraint_refs.update(check_3_constraint_refs)

        # ---- Check 4: no_boundary_blocks_put_bucket_policy
        check_4_constraint_refs: set[str] = set()
        check_4_state, check_4_reason, check_4_blockers = self._check_boundary_blockers(
            facts,
            witness_edge,
            check_4_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_4_blockers)
        check_results.append(
            Check(
                name="no_boundary_blocks_put_bucket_policy",
                description=("No permission boundary blocks s3:PutBucketPolicy on this edge"),
                state=check_4_state,
                evidence_refs=(
                    tuple(sorted(check_4_constraint_refs)) if check_4_constraint_refs else (witness_edge.edge_id,)
                ),
                reason=check_4_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_no_boundary_blocks_put_bucket_policy",
                inputs=(witness_edge.edge_id,),
                result=check_4_state.value.upper(),
                reason=check_4_reason,
            )
        )
        constraint_refs.update(check_4_constraint_refs)

        # ---- Check 5: principal_is_actionable
        # Filter out service principals and root. Service principals
        # (*.amazonaws.com) represent infrastructure, not attacker-
        # controlled entities. Root accounts are always "admin" and
        # bucket policy rewrites are a non-finding for root because
        # root already has full access to all buckets it owns.
        is_actionable, actionable_reason = self._is_actionable_principal(
            principal,
        )
        if not is_actionable:
            return None
        check_results.append(
            Check(
                name="principal_is_actionable",
                description=("Principal is an attacker-controllable user or role (not a service principal or root)"),
                state=CheckState.PASS,
                evidence_refs=(witness_edge.edge_id,),
                reason=actionable_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_principal_is_actionable",
                inputs=(principal.provider_id,),
                result="PASS",
                reason=actionable_reason,
            )
        )

        # ---- Verdict + severity
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results,
        )
        if verdict is None:
            return None

        title = self._compose_title(principal, bucket, verdict)

        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=dict(statement_sources),
            edge_refs=tuple(edge_refs),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(sorted(node_refs_set)),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=principal.to_ref(),
            target=bucket.to_ref(),
            verdict=verdict,
            severity=severity,
            title=title,
            required_checks=tuple(check_results),
            blockers_observed=tuple(blockers),
            assumptions=(),
            evidence=evidence,
            scenario_hash=facts.scenario_hash,
            reasoner_exit_reason=exit_reason,
        )

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    def _is_actionable_principal(self, principal: Node) -> tuple[bool, str]:
        """Return (is_actionable, reason).

        Filters out service principals (*.amazonaws.com) and root.
        """
        arn = principal.provider_id
        if ":root" in arn:
            return (False, "principal is account root")
        if ".amazonaws.com" in arn:
            return (False, "principal is an AWS service principal")
        return (True, "principal is an attacker-controllable user or role")

    def _check_scp_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no SCP bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "SCP":
                continue
            edge_constraint_refs.add(
                f"{binding.edge_id}:{binding.constraint_id}",
            )
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="scp",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=(binding.binding_reason or "SCP denies s3:PutBucketPolicy"),
                    )
                )
                state = CheckState.FAIL
                reason = f"SCP {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"SCP {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _check_boundary_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no permission boundary bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "PERMISSION_BOUNDARY":
                continue
            edge_constraint_refs.add(
                f"{binding.edge_id}:{binding.constraint_id}",
            )
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="permission_boundary",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=(binding.binding_reason or "boundary blocks s3:PutBucketPolicy"),
                    )
                )
                state = CheckState.FAIL
                reason = f"boundary {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"boundary {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
    ) -> tuple[Verdict | None, str, str]:
        check_by_name = {c.name: c for c in check_results}
        check_3 = check_by_name["no_scp_blocks_put_bucket_policy"]
        check_4 = check_by_name["no_boundary_blocks_put_bucket_policy"]

        if check_3.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "SCP blocks s3:PutBucketPolicy",
            )

        if check_4.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "permission boundary blocks s3:PutBucketPolicy",
            )

        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                "high",
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}",
            )

        return (
            Verdict.VALIDATED,
            "critical",
            "all checks PASS; principal can rewrite bucket policy and take full control of bucket contents",
        )

    def _compose_title(
        self,
        principal: Node,
        bucket: Node,
        verdict: Verdict,
    ) -> str:
        verdict_label = {
            Verdict.VALIDATED: "Validated",
            Verdict.BLOCKED: "Blocked",
            Verdict.INCONCLUSIVE: "Inconclusive",
            Verdict.PRECONDITION_ONLY: "Precondition-only",
        }.get(verdict, "Unknown")
        return (
            f"{verdict_label} S3 bucket takeover: "
            f"{principal.provider_id} can call s3:PutBucketPolicy on "
            f"{bucket.provider_id}"
        )

    def _absorb_digests(
        self,
        edge: Edge,
        digests: set[str],
        sources: dict[str, tuple[str, int, str]],
    ) -> None:
        for ref in (edge.features or {}).get("allow_controls", []) or []:
            if isinstance(ref, dict):
                digest = ref.get("digest", "")
                if digest:
                    digests.add(digest)
                    sources[digest] = (
                        ref.get("policy_arn", ""),
                        int(ref.get("statement_index", 0)),
                        ref.get("summary", ""),
                    )
