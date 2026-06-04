"""PassRole-to-Lambda privilege escalation reasoner — S12 (flagship).

The flagship reasoner of the rebuild. Implements the full 8-check logic
from plan §4B for the canonical Lambda privilege escalation pattern:

    A principal with `lambda:CreateFunction` AND `iam:PassRole`
    targeting a role that trusts `lambda.amazonaws.com` can:
        1. create a Lambda function
        2. assign the target role as the function's execution role
        3. cause the function to execute arbitrary code with that
           role's permissions

The pattern is the canonical IAM privilege escalation chain in AWS.
This reasoner emits one Finding per (source_principal, target_role)
pair where the chain is reachable, with verdict + severity per the
§4B.3 mapping table.

**Why this reasoner is the highest-stakes session in the rebuild:**

1. **It exercises BND-1 + PR-1 + COND-1 fact-layer fixes end-to-end.**
   The plan's fixture D verdict flips on BND-1 (boundary action
   intersection); fixture G's verdict flips on PR-1 + COND-1
   (`raw_conditions` propagation + iam:PassedToService flag).

2. **Fixture F is the highest-priority correctness test.** Per §4B.6
   row 1, a reasoner that breaks the tristate `has_action` so it
   returns PASS for hyperedges produces silent false positives. The
   negative-test pattern in fixture F mutates `has_action` to return
   PASS on hyperedges and verifies the fixture fails — catching the
   single most common false-positive production path documented in
   the entire plan.

3. **It is the reasoner FindingsForge will consume on day one** for
   the flagship Lambda privilege escalation pattern.

The reasoner follows the cross_account_trust template directly: same
Reasoner Protocol pattern, same EvidenceBundle population pattern,
same verdict mapping structure — but with 8 checks instead of 6 and
more complex multi-edge synthesis.

**Candidate enumeration is target-first** (find Lambda-trusting roles,
then find principals with lambda:CreateFunction, then pair them) rather
than source-first. The plan describes source-first ("for each
IAMUser/IAMRole, look at their PassRole permission edges"), but
source-first would skip fixture F entirely: Alice's wildcard PassRole
becomes a hyperedge whose dst is a synthetic node, so there's no
extractable target_role_arn to enumerate against. Target-first catches
fixture F because the target role IS in the graph (it trusts Lambda)
and Alice IS in the graph (she has lambda:CreateFunction); the
PassRole linkage between them gets evaluated by `has_action(...)`
which correctly returns UNKNOWN for hyperedges. This is documented
inline as a deliberate scope decision, not a deviation.

**`condition_context_assumed` handling per §4B.4:** IAMScope cannot
see AWS session policies at collection time. Per the plan's design
choice, the reasoner accepts the assumption "no session policy
restricts this chain" by default and emits VALIDATED findings, but
documents the assumption in `condition_context_assumed` with kind
`session_policy` so a pedantic reviewer can audit it. The reasoner
does NOT add this to the EvidenceBundle's `condition_context_assumed`
tuple (which would force inconclusive per §3.4 invariant), but rather
adds an `Assumption` to the Finding's `assumptions` list with
`kind="session_policy"`. The §3.4 invariant only forces inconclusive
on `kind="condition_context"` assumptions, not session-policy ones.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from iamscope.models import Edge, Node, NodeRef
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.identity_deny import check_identity_deny_blockers
from iamscope.reasoner.verdict import (
    Assumption,
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


# Service principal for Lambda execution. Hardcoded as the canonical
# AWS service principal name; will not change.
_LAMBDA_SERVICE_PRINCIPAL: str = "lambda.amazonaws.com"

# The two actions whose presence on the source principal defines the
# Lambda PassRole pattern.
_LAMBDA_CREATE_ACTION: str = "lambda:CreateFunction"
_PASSROLE_ACTION: str = "iam:PassRole"

# Operators on `iam:PassedToService` conditions that the reasoner can
# evaluate cleanly. StringEquals and StringLike are the supported set;
# anything else (StringNotEquals, ForAllValues:..., Bool, Numeric, etc.)
# yields UNKNOWN because the semantics are too varied to evaluate
# correctly without an actual policy engine.
_SUPPORTED_PASSEDTOSERVICE_OPERATORS: frozenset[str] = frozenset(
    {
        "StringEquals",
        "StringLike",
    }
)


class PassRoleLambdaReasoner:
    """Reasoner for the Lambda PassRole privilege escalation chain (§4B).

    Identity attributes per Reasoner Protocol:
    """

    pattern_id: str = "passrole_lambda"
    pattern_version: str = "1.0.0"
    pattern_title: str = "Lambda PassRole Privilege Chain"
    severity_default: str = SEVERITY_HIGH

    # ---------------------------------------------------------------
    # Reasoner Protocol methods
    # ---------------------------------------------------------------

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Three hard gates per plan §4B.1.

        - No IAM roles → cannot reason about a PassRole chain.
        - PR-1 not applied → permission edges lack `raw_conditions` →
          check 8 cannot evaluate iam:PassedToService scoping → would
          produce wrong answers. Refuse to run.
        - edge_budget_exhausted → a dropped edge could invalidate any
          `validated` verdict. Refuse to run rather than emit degraded
          findings.
        """
        if not any(n.node_type == NODE_TYPE_IAM_ROLE for n in facts.nodes):
            return (False, "no IAM roles in graph")

        # Sample the first permission edge to check the PR-1 invariant.
        sample = next(
            (e for e in facts.edges if e.edge_type.endswith("_permission")),
            None,
        )
        if sample is not None and "raw_conditions" not in sample.features:
            return (
                False,
                "PR-1 not applied: permission edges lack raw_conditions; "
                "passrole_lambda refuses to run against pre-fix collector",
            )

        if facts.edge_budget_exhausted:
            return (
                False,
                "edge_budget_exhausted — cannot guarantee completeness",
            )

        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Enumerate (source, target) candidates and evaluate each.

        Target-first enumeration (see module docstring for rationale).
        Returns findings in deterministic order (sorted by
        source.provider_id, then target.provider_id) so two runs over
        the same graph produce byte-identical output.
        """
        candidates = self._enumerate_candidates(facts)
        findings: list[Finding] = []
        for source, target in candidates:
            finding = self._evaluate_candidate(facts, source, target)
            if finding is not None:
                findings.append(finding)
        # Stable sort to guarantee deterministic emit order regardless
        # of dict iteration order in the candidate enumeration.
        findings.sort(key=lambda f: (f.source.provider_id, f.target.provider_id))
        return findings

    # ---------------------------------------------------------------
    # Candidate enumeration
    # ---------------------------------------------------------------

    def _enumerate_candidates(
        self,
        facts: FactGraph,
    ) -> list[tuple[Node, Node]]:
        """Enumerate (source_principal, target_role) candidates.

        Target-first: for each IAMRole that trusts Lambda, find every
        IAMUser / IAMRole in the graph that has lambda:CreateFunction
        (`has_action(...)` returning anything other than FAIL).
        Pair them. Pairs where the source is the target itself are
        skipped (a role passing itself to Lambda is not the standard
        privilege escalation chain).
        """
        lambda_trusting_roles: list[Node] = []
        for node in facts.nodes:
            if node.node_type != NODE_TYPE_IAM_ROLE:
                continue
            if self._role_trusts_lambda(facts, node.provider_id):
                lambda_trusting_roles.append(node)

        if not lambda_trusting_roles:
            return []

        # Find every principal with any lambda:CreateFunction permission.
        # `has_action` is the tristate API; we accept PASS or UNKNOWN
        # (UNKNOWN means there IS a matching edge but with ambiguity
        # flags — still a candidate worth evaluating, will produce an
        # inconclusive finding).
        principals_with_lambda_create: list[Node] = []
        for node in facts.nodes:
            if node.node_type not in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE):
                continue
            state = facts.has_action(node.provider_id, _LAMBDA_CREATE_ACTION)
            if state is not CheckState.FAIL:
                principals_with_lambda_create.append(node)

        # Cartesian product, deduplicated, with self-pairs filtered.
        candidates: list[tuple[Node, Node]] = []
        seen: set[tuple[str, str]] = set()
        for source in principals_with_lambda_create:
            for target in lambda_trusting_roles:
                if source.provider_id == target.provider_id:
                    continue  # role passing itself — not the pattern
                key = (source.provider_id, target.provider_id)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((source, target))
        return candidates

    def _role_trusts_lambda(self, facts: FactGraph, role_arn: str) -> bool:
        """Does this role's trust policy trust lambda.amazonaws.com?

        Walks `trust_policy_of(role_arn)` (which returns trust edges TO
        the role) and looks for any edge whose src is an AWSService
        node with provider_id == "lambda.amazonaws.com" and effect
        == "Allow" (the parser only emits Allow trust edges, but we
        belt-and-suspenders the check).
        """
        for edge in facts.trust_policy_of(role_arn):
            if (
                edge.src.node_type == NODE_TYPE_AWS_SERVICE
                and edge.src.provider_id == _LAMBDA_SERVICE_PRINCIPAL
                and (edge.features or {}).get("effect", "Allow") == "Allow"
            ):
                return True
        return False

    # ---------------------------------------------------------------
    # Per-candidate evaluation
    # ---------------------------------------------------------------

    def _evaluate_candidate(
        self,
        facts: FactGraph,
        source: Node,
        target: Node,
    ) -> Finding | None:
        """Run the 8-check pipeline against one (source, target) pair.

        Returns None for early-exit cases (check 1 or 2 FAIL).
        Otherwise builds a Finding with the appropriate verdict and
        severity per the §4B.3 mapping.
        """
        source_arn = source.provider_id
        target_arn = target.provider_id

        # ---- Check 1: source has lambda:CreateFunction
        check_1_state = facts.has_action(source_arn, _LAMBDA_CREATE_ACTION)
        if check_1_state is CheckState.FAIL:
            return None  # early exit, no overpermission

        # ---- Check 2: source has PassRole targeting target.
        # NOTE: per plan §4B.2 check 2 row, UNKNOWN is "wildcard
        # expansion edge OR hyperedge match" — explicitly NOT
        # has_conditions=True. The has_conditions case is delegated
        # entirely to check 8, which evaluates iam:PassedToService
        # scoping. If we used has_action() here, the has_conditions
        # trigger would force UNKNOWN whenever a condition exists,
        # short-circuiting check 8 entirely and forcing inconclusive
        # on the very fixtures (G and variants) that PR-1 + COND-1
        # were built to handle.
        #
        # So we compute check 2's state via _find_witness_edge directly,
        # checking only for hyperedge / wildcard-resource flags. The
        # condition handling is owned by check 8.
        check_2_witness = self._find_witness_edge(
            facts,
            source_arn,
            _PASSROLE_ACTION,
            resource_pattern=target_arn,
        )
        if check_2_witness is None:
            return None  # no PassRole link to this target — early exit
        check_2_state = self._classify_check_2_witness(check_2_witness)

        # Find check 1's witness edge for evidence purposes. Check 2's
        # witness was already found above (it's needed before computing
        # check_2_state, so the order is reversed compared to how the
        # checks read in the trace).
        check_1_witness = self._find_witness_edge(
            facts,
            source_arn,
            _LAMBDA_CREATE_ACTION,
            resource_pattern=None,
        )

        # If we couldn't find a witness edge despite has_action not
        # returning FAIL, something is wrong with the fact graph
        # internal consistency — bail to inconclusive via UNKNOWN.
        if check_1_witness is None:
            check_1_state = CheckState.UNKNOWN

        # ---- Build evidence accumulators.
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        node_refs: set[str] = {source.node_id, target.node_id}
        edge_refs: list[str] = []
        trace: list[TraceEntry] = []

        # Pull statement digests from witness edges' allow_controls
        # (DIG-1 post-S05).
        for witness in (check_1_witness, check_2_witness):
            if witness is None:
                continue
            edge_refs.append(witness.edge_id)
            for ref in (witness.features or {}).get("allow_controls", []) or []:
                if isinstance(ref, dict):
                    digest = ref.get("digest", "")
                    if digest:
                        statement_digests.add(digest)
                        statement_sources[digest] = (
                            ref.get("policy_arn", ""),
                            int(ref.get("statement_index", 0)),
                            ref.get("summary", ""),
                        )

        # ---- Check 1 result row.
        check_results.append(
            Check(
                name="source_has_lambda_create_function",
                description="Source principal has lambda:CreateFunction",
                state=check_1_state,
                evidence_refs=((check_1_witness.edge_id,) if check_1_witness is not None else ()),
                reason=self._explain_check_state(check_1_state, "lambda:CreateFunction"),
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_source_has_lambda_create_function",
                inputs=(source_arn, _LAMBDA_CREATE_ACTION),
                result=check_1_state.value.upper(),
                reason=self._explain_check_state(check_1_state, _LAMBDA_CREATE_ACTION),
            )
        )

        # ---- Check 2 result row.
        check_results.append(
            Check(
                name="source_has_passrole_to_target",
                description="Source can PassRole to the target role",
                state=check_2_state,
                evidence_refs=((check_2_witness.edge_id,) if check_2_witness is not None else ()),
                reason=self._explain_check_state(check_2_state, "iam:PassRole"),
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_source_has_passrole_to_target",
                inputs=(source_arn, _PASSROLE_ACTION, target_arn),
                result=check_2_state.value.upper(),
                reason=self._explain_check_state(check_2_state, _PASSROLE_ACTION),
            )
        )

        # ---- Check 3: target trusts Lambda.
        # We already know this is true from candidate enumeration, but
        # we re-check here to capture the witness trust edge for evidence.
        lambda_trust_edge = self._find_lambda_trust_edge(facts, target_arn)
        if lambda_trust_edge is not None:
            check_3_state = CheckState.PASS
            check_3_reason = (
                f"target role {target_arn} trusts lambda.amazonaws.com via trust edge {lambda_trust_edge.edge_id}"
            )
            edge_refs.append(lambda_trust_edge.edge_id)
            # Pull trust statement digests too.
            for ref in (lambda_trust_edge.features or {}).get("allow_controls", []) or []:
                if isinstance(ref, dict):
                    digest = ref.get("digest", "")
                    if digest:
                        statement_digests.add(digest)
                        statement_sources[digest] = (
                            ref.get("policy_arn", ""),
                            int(ref.get("statement_index", 0)),
                            ref.get("summary", ""),
                        )
        else:
            check_3_state = CheckState.FAIL
            check_3_reason = f"target role {target_arn} does not trust lambda.amazonaws.com"
        check_results.append(
            Check(
                name="target_trusts_lambda_service",
                description="Target role's trust policy trusts Lambda",
                state=check_3_state,
                evidence_refs=((lambda_trust_edge.edge_id,) if lambda_trust_edge is not None else ()),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_target_trusts_lambda_service",
                inputs=(target_arn, _LAMBDA_SERVICE_PRINCIPAL),
                result=check_3_state.value.upper(),
                reason=check_3_reason,
            )
        )

        # ---- Check 4: no SCP blocks lambda:CreateFunction.
        check_4_state, check_4_reason, check_4_blockers = self._check_scp_blockers(
            facts,
            check_1_witness,
            constraint_refs,
            edge_constraint_refs,
            action_label="lambda:CreateFunction",
        )
        blockers.extend(check_4_blockers)
        check_results.append(
            Check(
                name="no_scp_blocks_lambda_create_function",
                description="No SCP blocks lambda:CreateFunction with full confidence",
                state=check_4_state,
                evidence_refs=tuple(sorted(constraint_refs))
                if constraint_refs
                else ((check_1_witness.edge_id,) if check_1_witness else ()),
                reason=check_4_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_no_scp_blocks_lambda_create_function",
                inputs=(check_1_witness.edge_id if check_1_witness else "",),
                result=check_4_state.value.upper(),
                reason=check_4_reason,
            )
        )

        # ---- Check 5: no SCP blocks iam:PassRole.
        scp_5_constraint_refs: set[str] = set()
        check_5_state, check_5_reason, check_5_blockers = self._check_scp_blockers(
            facts,
            check_2_witness,
            scp_5_constraint_refs,
            edge_constraint_refs,
            action_label="iam:PassRole",
        )
        constraint_refs.update(scp_5_constraint_refs)
        blockers.extend(check_5_blockers)
        check_results.append(
            Check(
                name="no_scp_blocks_passrole",
                description="No SCP blocks iam:PassRole with full confidence",
                state=check_5_state,
                evidence_refs=tuple(sorted(scp_5_constraint_refs))
                if scp_5_constraint_refs
                else ((check_2_witness.edge_id,) if check_2_witness else ()),
                reason=check_5_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_no_scp_blocks_passrole",
                inputs=(check_2_witness.edge_id if check_2_witness else "",),
                result=check_5_state.value.upper(),
                reason=check_5_reason,
            )
        )

        # ---- Check 6: no boundary blocks lambda:CreateFunction.
        bnd_6_constraint_refs: set[str] = set()
        check_6_state, check_6_reason, check_6_blockers = self._check_boundary_blockers(
            facts,
            check_1_witness,
            bnd_6_constraint_refs,
            edge_constraint_refs,
            action_label="lambda:CreateFunction",
        )
        constraint_refs.update(bnd_6_constraint_refs)
        blockers.extend(check_6_blockers)
        check_results.append(
            Check(
                name="no_boundary_blocks_lambda_create_function",
                description="Permission boundary on source allows lambda:CreateFunction",
                state=check_6_state,
                evidence_refs=tuple(sorted(bnd_6_constraint_refs))
                if bnd_6_constraint_refs
                else ((check_1_witness.edge_id,) if check_1_witness else ()),
                reason=check_6_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=6,
                action="check_no_boundary_blocks_lambda_create_function",
                inputs=(check_1_witness.edge_id if check_1_witness else "",),
                result=check_6_state.value.upper(),
                reason=check_6_reason,
            )
        )

        # ---- Check 7: no boundary blocks iam:PassRole.
        bnd_7_constraint_refs: set[str] = set()
        check_7_state, check_7_reason, check_7_blockers = self._check_boundary_blockers(
            facts,
            check_2_witness,
            bnd_7_constraint_refs,
            edge_constraint_refs,
            action_label="iam:PassRole",
        )
        constraint_refs.update(bnd_7_constraint_refs)
        blockers.extend(check_7_blockers)
        check_results.append(
            Check(
                name="no_boundary_blocks_passrole",
                description="Permission boundary on source allows iam:PassRole",
                state=check_7_state,
                evidence_refs=tuple(sorted(bnd_7_constraint_refs))
                if bnd_7_constraint_refs
                else ((check_2_witness.edge_id,) if check_2_witness else ()),
                reason=check_7_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=7,
                action="check_no_boundary_blocks_passrole",
                inputs=(check_2_witness.edge_id if check_2_witness else "",),
                result=check_7_state.value.upper(),
                reason=check_7_reason,
            )
        )

        # ---- Check 8: no identity-policy Deny blocks lambda:CreateFunction.
        deny_8_constraint_refs: set[str] = set()
        check_8_state, check_8_reason, check_8_blockers = check_identity_deny_blockers(
            facts,
            check_1_witness,
            deny_8_constraint_refs,
            edge_constraint_refs,
            action_label="lambda:CreateFunction",
            edge_constraint_ref_separator="|",
        )
        constraint_refs.update(deny_8_constraint_refs)
        blockers.extend(check_8_blockers)
        check_results.append(
            Check(
                name="no_identity_deny_blocks_lambda_create_function",
                description="No identity-policy Deny blocks lambda:CreateFunction",
                state=check_8_state,
                evidence_refs=tuple(sorted(deny_8_constraint_refs))
                if deny_8_constraint_refs
                else ((check_1_witness.edge_id,) if check_1_witness else ()),
                reason=check_8_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=8,
                action="check_no_identity_deny_blocks_lambda_create_function",
                inputs=(check_1_witness.edge_id if check_1_witness else "",),
                result=check_8_state.value.upper(),
                reason=check_8_reason,
            )
        )

        # ---- Check 9: no identity-policy Deny blocks iam:PassRole.
        deny_9_constraint_refs: set[str] = set()
        check_9_state, check_9_reason, check_9_blockers = check_identity_deny_blockers(
            facts,
            check_2_witness,
            deny_9_constraint_refs,
            edge_constraint_refs,
            action_label="iam:PassRole",
            edge_constraint_ref_separator="|",
        )
        constraint_refs.update(deny_9_constraint_refs)
        blockers.extend(check_9_blockers)
        check_results.append(
            Check(
                name="no_identity_deny_blocks_passrole",
                description="No identity-policy Deny blocks iam:PassRole",
                state=check_9_state,
                evidence_refs=tuple(sorted(deny_9_constraint_refs))
                if deny_9_constraint_refs
                else ((check_2_witness.edge_id,) if check_2_witness else ()),
                reason=check_9_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=9,
                action="check_no_identity_deny_blocks_passrole",
                inputs=(check_2_witness.edge_id if check_2_witness else "",),
                result=check_9_state.value.upper(),
                reason=check_9_reason,
            )
        )

        # ---- Check 10: PassedToService scoping.
        check_10_state, check_10_reason = self._check_passed_to_service(
            check_2_witness,
        )
        check_results.append(
            Check(
                name="passrole_condition_scoped_to_lambda_or_absent",
                description=("iam:PassRole condition iam:PassedToService is absent or scoped to Lambda"),
                state=check_10_state,
                evidence_refs=((check_2_witness.edge_id,) if check_2_witness is not None else ()),
                reason=check_10_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=10,
                action="check_passrole_condition_scoped_to_lambda_or_absent",
                inputs=(check_2_witness.edge_id if check_2_witness else "",),
                result=check_10_state.value.upper(),
                reason=check_10_reason,
            )
        )

        # ---- Admin-equivalence read (separate from the checks).
        is_admin = self._is_admin_equivalent(facts, target)
        trace.append(
            TraceEntry(
                step=11,
                action="evaluate_admin_equivalence",
                inputs=(target_arn,),
                result="ADMIN_EQUIVALENT" if is_admin else "NON_ADMIN",
                reason=(
                    f"target role {target_arn} has wildcard permission edges"
                    if is_admin
                    else f"target role {target_arn} has no wildcard permission edges"
                ),
            )
        )

        # ---- Verdict mapping per §4B.3.
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results=check_results,
            is_admin=is_admin,
        )

        # If verdict is "no finding" (early exits already returned None
        # above, but a check 1/2 UNKNOWN with everything else clean
        # could still produce a verdict), bail.
        if verdict is None:
            return None

        # Add the trust_missing blocker if check 3 failed (the
        # precondition_only path requires at least one blocker per
        # §3.4 invariant).
        if check_3_state is CheckState.FAIL:
            blockers.append(
                Blocker(
                    kind="trust_missing",
                    constraint_id=None,
                    edge_id=None,
                    reason=check_3_reason,
                )
            )
        # Same for check 8 FAIL — the PassedToService scoping
        # precondition_only path needs a blocker.
        if check_10_state is CheckState.FAIL:
            blockers.append(
                Blocker(
                    kind="passed_to_service",
                    constraint_id=None,
                    edge_id=check_2_witness.edge_id if check_2_witness else None,
                    reason=check_10_reason,
                )
            )

        # ---- Final trace entry: verdict emission.
        trace.append(
            TraceEntry(
                step=12,
                action="emit_verdict",
                inputs=(verdict.value, severity),
                result=verdict.value.upper(),
                reason=exit_reason,
            )
        )

        # ---- Build assumptions list.
        # Per §4B.4: VALIDATED findings carry the session-policy
        # assumption explicitly so a reviewer can audit it. Per the
        # design choice, this is kind="session_policy" NOT
        # kind="condition_context" — the latter would force inconclusive
        # via §3.4 invariant 5, which we don't want for the default
        # validated case.
        assumptions: list[Assumption] = []
        if verdict is Verdict.VALIDATED:
            assumptions.append(
                Assumption(
                    kind="session_policy",
                    detail=(
                        "no session policy restricts lambda:CreateFunction "
                        "or iam:PassRole; session policies are not visible "
                        "to IAMScope collectors at collection time"
                    ),
                )
            )

        # ---- Build the EvidenceBundle.
        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=statement_sources,
            edge_refs=tuple(sorted(set(edge_refs))),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(sorted(node_refs)),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        # ---- Compose title and build Finding.
        title = self._compose_title(
            source_arn=source_arn,
            target_arn=target_arn,
            verdict=verdict,
            is_admin=is_admin,
        )
        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=NodeRef(
                provider=source.provider,
                node_type=source.node_type,
                provider_id=source_arn,
                region=source.region,
            ),
            target=NodeRef(
                provider=target.provider,
                node_type=target.node_type,
                provider_id=target_arn,
                region=target.region,
            ),
            verdict=verdict,
            severity=severity,
            title=title,
            required_checks=tuple(check_results),
            blockers_observed=tuple(blockers),
            assumptions=tuple(assumptions),
            evidence=evidence,
            scenario_hash=facts.scenario_hash,
            reasoner_exit_reason=exit_reason,
        )

    # ---------------------------------------------------------------
    # Witness edge lookups
    # ---------------------------------------------------------------

    def _find_witness_edge(
        self,
        facts: FactGraph,
        source_arn: str,
        action: str,
        resource_pattern: str | None,
    ) -> Edge | None:
        """Find the first matching permission edge for evidence purposes.

        Returns the FIRST clean (non-hyperedge, non-conditioned,
        non-wildcard) matching edge if one exists, else the first
        ambiguous matching edge, else None. This mirrors the
        priority order of `has_action` but returns the witness Edge
        instead of the CheckState.
        """
        expected_edge_type = f"{action}_permission"
        clean_witness: Edge | None = None
        ambiguous_witness: Edge | None = None
        for edge in facts.edges_from(source_arn):
            if edge.edge_type != expected_edge_type:
                continue
            if resource_pattern is not None:
                from iamscope.reasoner.fact_graph import _resource_matches

                if not _resource_matches(edge, resource_pattern):
                    continue
            from iamscope.reasoner.fact_graph import _is_unknown_witness

            if _is_unknown_witness(edge):
                if ambiguous_witness is None:
                    ambiguous_witness = edge
            else:
                if clean_witness is None:
                    clean_witness = edge
        return clean_witness or ambiguous_witness

    def _classify_check_2_witness(self, witness: Edge) -> CheckState:
        """Classify a PassRole witness edge per plan §4B.2 row 2.

        Per the plan, check 2's UNKNOWN trigger is "wildcard expansion
        edge OR hyperedge match" — explicitly NOT has_conditions=True.
        The has_conditions case is delegated entirely to check 8, which
        evaluates iam:PassedToService scoping. This helper exists so
        check 2 can compute its state directly from the witness edge
        without going through has_action (which would collapse the
        has_conditions case into UNKNOWN and short-circuit check 8).

        Returns:
            CheckState.UNKNOWN if the witness has the hyperedge dst flag
                or is_wildcard_resource flag (the two conditions named
                in the plan §4B.2 check 2 row).
            CheckState.PASS otherwise.

        Note that has_conditions=True does NOT trigger UNKNOWN here.
        That's the behavior difference from `has_action` and the reason
        this helper exists at all.
        """
        from iamscope.constants import NODE_TYPE_HYPEREDGE

        if witness.dst.node_type == NODE_TYPE_HYPEREDGE:
            return CheckState.UNKNOWN
        features: dict[str, Any] = witness.features or {}
        if features.get("is_wildcard_resource", False):
            return CheckState.UNKNOWN
        return CheckState.PASS

    def _find_lambda_trust_edge(
        self,
        facts: FactGraph,
        role_arn: str,
    ) -> Edge | None:
        """Find the trust edge proving the role trusts Lambda."""
        for edge in facts.trust_policy_of(role_arn):
            if (
                edge.src.node_type == NODE_TYPE_AWS_SERVICE
                and edge.src.provider_id == _LAMBDA_SERVICE_PRINCIPAL
                and (edge.features or {}).get("effect", "Allow") == "Allow"
            ):
                return edge
        return None

    # ---------------------------------------------------------------
    # SCP / boundary blocker checks
    # ---------------------------------------------------------------

    def _check_scp_blockers(
        self,
        facts: FactGraph,
        witness_edge: Edge | None,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
        action_label: str,
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Walk SCP bindings on a witness edge.

        Returns (state, reason, blockers). The constraint_refs and
        edge_constraint_refs sets are mutated in-place to add every
        binding examined (pass or fail) so the evidence bundle shows
        the full check set per §4B.4.
        """
        if witness_edge is None:
            return (
                CheckState.UNKNOWN,
                f"no witness edge available for {action_label} SCP check",
                [],
            )

        bindings = facts.bindings_for_edge(witness_edge.edge_id)
        # Filter to SCP-typed bindings via constraint_by_id lookup.
        scp_bindings = []
        for b in bindings:
            constraint = facts.constraint_by_id(b.constraint_id)
            if constraint is None:
                continue
            if constraint.constraint_type == "SCP":
                scp_bindings.append(b)

        if not scp_bindings:
            return (
                CheckState.PASS,
                f"no SCP bindings observed on {action_label} witness edge",
                [],
            )

        # Add every examined binding to the evidence accumulators.
        for b in scp_bindings:
            constraint_refs.add(b.constraint_id)
            edge_constraint_refs.add(f"{b.edge_id}|{b.constraint_id}")

        blocking_complete: list = []
        ambiguous: list = []
        for binding in scp_bindings:
            if binding.likely_blocking and binding.governance_confidence == "complete":
                blocking_complete.append(binding)
            elif binding.governance_confidence in ("partial", "needs_review"):
                ambiguous.append(binding)

        if blocking_complete:
            blockers = [
                Blocker(
                    kind="scp",
                    constraint_id=b.constraint_id,
                    edge_id=witness_edge.edge_id,
                    reason=b.binding_reason or f"SCP denies {action_label}",
                )
                for b in blocking_complete
            ]
            return (
                CheckState.FAIL,
                f"{len(blocking_complete)} SCP binding(s) likely_blocking "
                f"with governance_confidence=complete on {action_label}",
                blockers,
            )

        if ambiguous:
            return (
                CheckState.UNKNOWN,
                f"{len(ambiguous)} SCP binding(s) with governance_confidence "
                f"∈ partial/needs_review on {action_label} — cannot confirm",
                [],
            )

        return (
            CheckState.PASS,
            f"{len(scp_bindings)} SCP binding(s) all non-blocking with "
            f"governance_confidence=complete on {action_label}",
            [],
        )

    def _check_boundary_blockers(
        self,
        facts: FactGraph,
        witness_edge: Edge | None,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
        action_label: str,
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Walk PERMISSION_BOUNDARY bindings on a witness edge (post-BND-1).

        Per plan §4B.6 row 3 (the BND-1 dependency): a binding with
        `likely_blocking=True, governance_confidence=complete` means
        the boundary's allowed_actions does NOT include the action of
        the bound edge. Pre-BND-1 the field was always False; post-BND-1
        it correctly reflects the action intersection. The reasoner
        defers to the binder's `likely_blocking` flag rather than
        re-implementing boundary evaluation.
        """
        if witness_edge is None:
            return (
                CheckState.UNKNOWN,
                f"no witness edge available for {action_label} boundary check",
                [],
            )

        bindings = facts.bindings_for_edge(witness_edge.edge_id)
        boundary_bindings = []
        for b in bindings:
            constraint = facts.constraint_by_id(b.constraint_id)
            if constraint is None:
                continue
            if constraint.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY:
                boundary_bindings.append(b)

        if not boundary_bindings:
            return (
                CheckState.PASS,
                f"no permission boundary bindings observed on {action_label} witness edge",
                [],
            )

        for b in boundary_bindings:
            constraint_refs.add(b.constraint_id)
            edge_constraint_refs.add(f"{b.edge_id}|{b.constraint_id}")

        blocking_complete: list = []
        ambiguous: list = []
        for binding in boundary_bindings:
            if binding.likely_blocking and binding.governance_confidence == "complete":
                blocking_complete.append(binding)
            elif binding.governance_confidence in ("partial", "needs_review"):
                ambiguous.append(binding)

        if blocking_complete:
            blockers = [
                Blocker(
                    kind="boundary",
                    constraint_id=b.constraint_id,
                    edge_id=witness_edge.edge_id,
                    reason=b.binding_reason or (f"permission boundary does not allow {action_label}"),
                )
                for b in blocking_complete
            ]
            return (
                CheckState.FAIL,
                f"{len(blocking_complete)} permission boundary binding(s) "
                f"likely_blocking with governance_confidence=complete on "
                f"{action_label}",
                blockers,
            )

        if ambiguous:
            return (
                CheckState.UNKNOWN,
                f"{len(ambiguous)} permission boundary binding(s) with "
                f"governance_confidence ∈ partial/needs_review on "
                f"{action_label}",
                [],
            )

        return (
            CheckState.PASS,
            f"{len(boundary_bindings)} permission boundary binding(s) "
            f"all non-blocking with governance_confidence=complete on "
            f"{action_label}",
            [],
        )

    # ---------------------------------------------------------------
    # Check 8: PassedToService scoping
    # ---------------------------------------------------------------

    def _check_passed_to_service(
        self,
        witness_edge: Edge | None,
    ) -> tuple[CheckState, str]:
        """Evaluate iam:PassedToService scoping on the PassRole witness edge.

        Per plan §4B.2 row 8:
        - PASS: condition absent OR present and value includes lambda.amazonaws.com
        - FAIL: condition present and value does NOT include Lambda (e.g. ec2)
        - UNKNOWN: raw_conditions present but operator not in
                   StringEquals / StringLike

        Reads `features.raw_conditions` (post-PR-1) and walks the
        condition operator → key → value tree.
        """
        if witness_edge is None:
            return (
                CheckState.UNKNOWN,
                "no PassRole witness edge available",
            )

        features: dict[str, Any] = witness_edge.features or {}
        raw_conditions: dict[str, Any] = features.get("raw_conditions", {}) or {}

        if not raw_conditions:
            return (
                CheckState.PASS,
                "no condition block on PassRole statement (unrestricted)",
            )

        # Walk the condition operator → key → value structure looking
        # for iam:PassedToService.
        found_in_supported_op = False
        found_in_unsupported_op = False
        scoped_to_lambda = False
        other_services: list[str] = []

        for operator, op_body in raw_conditions.items():
            if not isinstance(op_body, dict):
                continue
            for key, value in op_body.items():
                # AWS condition keys are case-insensitive on the key.
                if key.lower() != "iam:passedtoservice":
                    continue
                if operator in _SUPPORTED_PASSEDTOSERVICE_OPERATORS:
                    found_in_supported_op = True
                    values = value if isinstance(value, list) else [value]
                    for v in values:
                        if self._passed_to_service_matches(operator, str(v), _LAMBDA_SERVICE_PRINCIPAL):
                            scoped_to_lambda = True
                        else:
                            other_services.append(str(v))
                else:
                    found_in_unsupported_op = True

        # No iam:PassedToService key found anywhere → unrestricted.
        if not (found_in_supported_op or found_in_unsupported_op):
            return (
                CheckState.PASS,
                "iam:PassedToService not present in PassRole condition block",
            )

        # Found in unsupported operator only → UNKNOWN.
        if found_in_unsupported_op and not found_in_supported_op:
            return (
                CheckState.UNKNOWN,
                "iam:PassedToService present but operator not in {StringEquals, StringLike} — cannot evaluate scoping",
            )

        # Found in supported operator. Decision rules:
        # - scoped to Lambda (with or without other services) → PASS
        # - scoped to other services only → FAIL
        if scoped_to_lambda:
            return (
                CheckState.PASS,
                f"iam:PassedToService includes {_LAMBDA_SERVICE_PRINCIPAL}",
            )
        return (
            CheckState.FAIL,
            f"iam:PassedToService scoped to {sorted(set(other_services))} "
            f"(not Lambda) — PassRole cannot pass to a Lambda execution role",
        )

    def _passed_to_service_matches(
        self,
        operator: str,
        condition_value: str,
        service_principal: str,
    ) -> bool:
        """Evaluate supported iam:PassedToService operators.

        StringEquals preserves exact string semantics. StringLike uses
        AWS-style glob matching, case-insensitively, so values such as
        `lambda.*`, `*.amazonaws.com`, and `*` match Lambda.
        """
        condition_value_lower = condition_value.lower()
        service_principal_lower = service_principal.lower()
        if operator == "StringEquals":
            return condition_value_lower == service_principal_lower
        if operator == "StringLike":
            return fnmatch.fnmatchcase(service_principal_lower, condition_value_lower)
        return False

    # ---------------------------------------------------------------
    # Admin-equivalence read
    # ---------------------------------------------------------------

    def _is_admin_equivalent(
        self,
        facts: FactGraph,
        target_role: Node,
    ) -> bool:
        """Delegate to the shared admin detection module (3c-refactor).

        Originally inlined here in S12. The two-tier detection logic
        was duplicated across passrole_lambda, passrole_ecs,
        assume_role_chain, and admin_reachability — promoted to
        `iamscope.reasoner.admin_detection` as the canonical source
        of truth. This method survives as a thin delegate to keep
        call sites stable.
        """
        from iamscope.reasoner.admin_detection import is_admin_equivalent

        return is_admin_equivalent(facts, target_role)

    # ---------------------------------------------------------------
    # Verdict mapping
    # ---------------------------------------------------------------

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
        is_admin: bool,
    ) -> tuple[Verdict | None, str, str]:
        """Apply the §4B.3 verdict mapping table top-down.

        Returns (verdict, severity, exit_reason). verdict can be None
        if all rules say "no finding" (currently only the early-exit
        cases on check 1/2 FAIL, which are handled before this method
        is called — included as defensive None handling).
        """
        check_by_name = {c.name: c for c in check_results}
        check_3 = check_by_name.get("target_trusts_lambda_service")
        check_4 = check_by_name.get("no_scp_blocks_lambda_create_function")
        check_5 = check_by_name.get("no_scp_blocks_passrole")
        check_6 = check_by_name.get("no_boundary_blocks_lambda_create_function")
        check_7 = check_by_name.get("no_boundary_blocks_passrole")
        check_8 = check_by_name.get("no_identity_deny_blocks_lambda_create_function")
        check_9 = check_by_name.get("no_identity_deny_blocks_passrole")
        check_10 = check_by_name.get("passrole_condition_scoped_to_lambda_or_absent")

        # Rule 3: Check 3 FAIL → precondition_only / medium.
        if check_3 is not None and check_3.state is CheckState.FAIL:
            return (
                Verdict.PRECONDITION_ONLY,
                SEVERITY_MEDIUM,
                "target role does not trust Lambda — chain not exploitable as written",
            )

        # Rule 4: Check 10 FAIL -> precondition_only / medium.
        if check_10 is not None and check_10.state is CheckState.FAIL:
            return (
                Verdict.PRECONDITION_ONLY,
                SEVERITY_MEDIUM,
                "iam:PassedToService scoped away from Lambda — chain not exploitable",
            )

        # Rule 5: Check 4/5 FAIL → blocked / info (SCP).
        if check_4 is not None and check_4.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "SCP blocks lambda:CreateFunction with complete confidence",
            )
        if check_5 is not None and check_5.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "SCP blocks iam:PassRole with complete confidence",
            )

        # Rule 6: Check 6/7 FAIL → blocked / info (boundary, post-BND-1).
        if check_6 is not None and check_6.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "permission boundary blocks lambda:CreateFunction (post-BND-1)",
            )
        if check_7 is not None and check_7.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "permission boundary blocks iam:PassRole (post-BND-1)",
            )

        # Rule 7: identity-policy Deny blocks with complete confidence.
        if check_8 is not None and check_8.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "identity policy Deny blocks lambda:CreateFunction with complete confidence",
            )
        if check_9 is not None and check_9.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                SEVERITY_INFO,
                "identity policy Deny blocks iam:PassRole with complete confidence",
            )

        # Rule 8: Any check UNKNOWN -> inconclusive / high.
        unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown_checks:
            return (
                Verdict.INCONCLUSIVE,
                SEVERITY_HIGH,
                f"check(s) UNKNOWN: {', '.join(unknown_checks)}",
            )

        # Rule 9: All PASS -> validated.
        if is_admin:
            return (
                Verdict.VALIDATED,
                SEVERITY_CRITICAL,
                "all checks PASS; target role has admin-equivalent permissions",
            )
        return (
            Verdict.VALIDATED,
            SEVERITY_HIGH,
            "all checks PASS; non-admin target role",
        )

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    def _explain_check_state(self, state: CheckState, action: str) -> str:
        """Build a human-readable reason string for a has_action result."""
        if state is CheckState.PASS:
            return f"explicit non-conditioned permission edge for {action}"
        if state is CheckState.UNKNOWN:
            return f"matching {action} edge has ambiguity flag (hyperedge, wildcard resource, or conditions)"
        return f"no matching {action} edge"

    def _compose_title(
        self,
        source_arn: str,
        target_arn: str,
        verdict: Verdict,
        is_admin: bool,
    ) -> str:
        """Build a human-readable one-line title for the finding."""
        admin_qualifier = " admin-equivalent" if is_admin else ""
        if verdict is Verdict.VALIDATED:
            return f"{source_arn} can assume{admin_qualifier} role {target_arn} via Lambda PassRole chain"
        if verdict is Verdict.BLOCKED:
            return f"Blocked Lambda PassRole chain from {source_arn} to {target_arn}"
        if verdict is Verdict.PRECONDITION_ONLY:
            return f"Precondition-only Lambda PassRole chain from {source_arn} to {target_arn}"
        return f"Inconclusive Lambda PassRole chain from {source_arn} to {target_arn}"
