"""Reasoner pipeline benchmark — generates a synthetic fact graph and
measures where the reasoner layer spends its time.

Generates ~200 nodes / ~1000 edges of representative AWS org shape:
- 100 IAMRole nodes (20 admin-equivalent, 80 regular)
- 50 IAMUser nodes
- 10 IAMGroup nodes (3 admin-equivalent)
- 20 S3Bucket nodes
- 10 SecretsManagerSecret nodes
- 5 KMSKey nodes
- 5 LambdaFunction nodes

Permission edges connect principals to resources with realistic
density. The graph is deterministic (seeded RNG) so benchmark
numbers are reproducible across runs.

Usage:
    python3 tests/benchmark_reasoners.py [--profile]

Without --profile, prints a summary table of per-reasoner runtime.
With --profile, runs cProfile and prints the top 30 hot spots by
cumulative time.
"""

from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import sys
import time

from iamscope.models import Edge, Node
from iamscope.reasoner import (
    AdminReachabilityReasoner,
    AssumeRoleChainReasoner,
    CrossAccountTrustReasoner,
    FactGraph,
    IAMGroupMembershipEscalationReasoner,
    PassRoleEcsReasoner,
    PassRoleLambdaReasoner,
    S3BucketTakeoverReasoner,
    SecretsBlastRadiusReasoner,
)

ACCOUNT = "111111\u003111111"


def _node(node_type: str, provider_id: str, **props) -> Node:
    return Node(
        provider="aws",
        node_type=node_type,
        provider_id=provider_id,
        properties={"account_id": ACCOUNT, **props},
    )


def _perm_edge(
    *,
    src: Node,
    dst: Node,
    action: str,
    edge_idx: int,
) -> Edge:
    """Create a permission edge from src to dst for a given action."""
    digest = f"{edge_idx:064x}"
    return Edge(
        edge_type=f"{action}_permission",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region="aws-global",
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/P{edge_idx}",
                    "statement_index": 0,
                    "digest": digest,
                    "summary": f"{action} grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": False,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": dst.provider_id,
            "statement_index": 0,
        },
    )


def build_large_fact_graph() -> FactGraph:
    """Build a synthetic ~200-node / ~1000-edge fact graph."""
    nodes: list[Node] = []
    edges: list[Edge] = []
    edge_idx = 0

    # Principals
    roles: list[Node] = []
    for i in range(100):
        r = _node("IAMRole", f"arn:aws:iam::{ACCOUNT}:role/Role{i:03d}")
        roles.append(r)
        nodes.append(r)

    users: list[Node] = []
    for i in range(50):
        u = _node("IAMUser", f"arn:aws:iam::{ACCOUNT}:user/User{i:03d}")
        users.append(u)
        nodes.append(u)

    groups: list[Node] = []
    for i in range(10):
        g = _node("IAMGroup", f"arn:aws:iam::{ACCOUNT}:group/Group{i:02d}")
        groups.append(g)
        nodes.append(g)

    # Resources
    buckets: list[Node] = []
    for i in range(20):
        b = _node("S3Bucket", f"arn:aws:s3:::bucket-{i:03d}")
        buckets.append(b)
        nodes.append(b)

    secrets: list[Node] = []
    for i in range(10):
        s = _node(
            "SecretsManagerSecret",
            f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:prod/s{i:03d}",
        )
        secrets.append(s)
        nodes.append(s)

    kms_keys: list[Node] = []
    for i in range(5):
        k = _node(
            "KMSKey",
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/key-{i:04d}",
        )
        kms_keys.append(k)
        nodes.append(k)

    lambdas: list[Node] = []
    for i in range(5):
        fn = _node(
            "LambdaFunction",
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn-{i:03d}",
        )
        lambdas.append(fn)
        nodes.append(fn)

    # Admin-equivalent self-edges for 20 of the roles and 3 of the groups
    for r in roles[:20]:
        edges.append(
            Edge(
                edge_type="iam:*_permission",
                src=r.to_ref(),
                dst=r.to_ref(),
                region="aws-global",
                features={
                    "allow_controls": [
                        {
                            "control_type": "PERMISSION",
                            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                            "statement_index": 0,
                            "digest": f"{edge_idx:064x}",
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
        )
        edge_idx += 1

    for g in groups[:3]:
        edges.append(
            Edge(
                edge_type="iam:*_permission",
                src=g.to_ref(),
                dst=g.to_ref(),
                region="aws-global",
                features={
                    "allow_controls": [
                        {
                            "control_type": "PERMISSION",
                            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                            "statement_index": 0,
                            "digest": f"{edge_idx:064x}",
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
        )
        edge_idx += 1

    # S3 PutBucketPolicy: 30 principals × 2 buckets each
    for i, principal in enumerate(roles[20:50] + users[:10]):
        for b in buckets[i % 10 : i % 10 + 2]:
            edges.append(
                _perm_edge(
                    src=principal,
                    dst=b,
                    action="s3:PutBucketPolicy",
                    edge_idx=edge_idx,
                )
            )
            edge_idx += 1

    # Secrets GetSecretValue: 40 principals × 2 secrets each
    for i, principal in enumerate(roles[20:50] + users[:20]):
        for s in secrets[i % 5 : i % 5 + 2]:
            edges.append(
                _perm_edge(
                    src=principal,
                    dst=s,
                    action="secretsmanager:GetSecretValue",
                    edge_idx=edge_idx,
                )
            )
            edge_idx += 1

    # IAM AddUserToGroup: 20 users × 2 groups each
    for i, u in enumerate(users[:20]):
        for g in groups[i % 8 : i % 8 + 2]:
            edges.append(
                _perm_edge(
                    src=u,
                    dst=g,
                    action="iam:AddUserToGroup",
                    edge_idx=edge_idx,
                )
            )
            edge_idx += 1

    # PassRole edges: 30 roles × 1 target role each
    for i, src_role in enumerate(roles[30:60]):
        tgt_role = roles[60 + i]
        edges.append(
            _perm_edge(
                src=src_role,
                dst=tgt_role,
                action="iam:PassRole",
                edge_idx=edge_idx,
            )
        )
        edge_idx += 1

    # AssumeRole trust edges: 40 principals trust each other
    for i in range(40):
        src_r = roles[i]
        dst_r = roles[(i + 1) % 40]
        edges.append(
            Edge(
                edge_type="sts:AssumeRole_trust",
                src=src_r.to_ref(),
                dst=dst_r.to_ref(),
                region="aws-global",
                features={
                    "allow_controls": [
                        {
                            "control_type": "TRUST",
                            "policy_arn": f"trust/{dst_r.provider_id}",
                            "statement_index": 0,
                            "digest": f"{edge_idx:064x}",
                            "summary": "trust",
                        }
                    ],
                    "effect": "Allow",
                    "has_conditions": False,
                    "is_wildcard_resource": False,
                    "layer": "trust",
                    "naked_trust": True,
                    "raw_conditions": {},
                    "resource_pattern": "*",
                    "statement_index": 0,
                    "trusted_principal_type": "AWS",
                },
            )
        )
        edge_idx += 1

    return FactGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        constraints=(),
        edge_constraints=(),
        scenario_hash="b" * 64,
        edge_budget_exhausted=False,
    )


def run_all_reasoners(facts: FactGraph) -> dict[str, tuple[int, float]]:
    """Run all 8 reasoners and return (finding_count, wall_time_sec) per reasoner."""
    reasoners = [
        ("cross_account_trust", CrossAccountTrustReasoner()),
        ("passrole_lambda", PassRoleLambdaReasoner()),
        ("passrole_ecs", PassRoleEcsReasoner()),
        ("assume_role_chain", AssumeRoleChainReasoner()),
        ("admin_reachability", AdminReachabilityReasoner()),
        ("secrets_blast_radius", SecretsBlastRadiusReasoner()),
        ("iam_group_membership_escalation", IAMGroupMembershipEscalationReasoner()),
        ("s3_bucket_takeover", S3BucketTakeoverReasoner()),
    ]
    results: dict[str, tuple[int, float]] = {}
    for name, r in reasoners:
        ok, _ = r.preconditions_met(facts)
        if not ok:
            results[name] = (0, 0.0)
            continue
        start = time.perf_counter()
        findings = r.run(facts)
        elapsed = time.perf_counter() - start
        results[name] = (len(findings), elapsed)
    return results


def summarize(results: dict[str, tuple[int, float]]) -> None:
    total_time = sum(t for _, t in results.values())
    total_findings = sum(c for c, _ in results.values())
    print("=" * 70)
    print(f"{'Reasoner':<40} {'Findings':>10} {'Wall (ms)':>12}")
    print("-" * 70)
    for name, (count, elapsed) in sorted(
        results.items(),
        key=lambda kv: kv[1][1],
        reverse=True,
    ):
        print(f"{name:<40} {count:>10} {elapsed * 1000:>12.2f}")
    print("-" * 70)
    print(f"{'TOTAL':<40} {total_findings:>10} {total_time * 1000:>12.2f}")
    print("=" * 70)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Run under cProfile and print top 30 hot spots",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of benchmark runs (median reported)",
    )
    args = parser.parse_args()

    print("Building synthetic fact graph...")
    facts = build_large_fact_graph()
    print(f"  nodes: {len(facts.nodes)}, edges: {len(facts.edges)}")
    print()

    if args.profile:
        profiler = cProfile.Profile()
        profiler.enable()
        results = run_all_reasoners(facts)
        profiler.disable()
        summarize(results)
        print()
        print("Top 30 hot spots by cumulative time:")
        print("-" * 70)
        stream = io.StringIO()
        ps = pstats.Stats(profiler, stream=stream).sort_stats("cumulative")
        ps.print_stats(30)
        print(stream.getvalue())
    else:
        print(f"Running {args.runs} iteration(s)...")
        print()
        all_results = []
        for _i in range(args.runs):
            results = run_all_reasoners(facts)
            all_results.append(results)
        # Report median
        median_results: dict[str, tuple[int, float]] = {}
        for name in all_results[0]:
            counts = [r[name][0] for r in all_results]
            times = sorted([r[name][1] for r in all_results])
            median_results[name] = (counts[0], times[len(times) // 2])
        summarize(median_results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
