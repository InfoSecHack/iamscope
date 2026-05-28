from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json

SCHEMA_VERSION = "0.1"
REPORT_TYPE = "synthetic_scalability_benchmark"
EVIDENCE_BOUNDARY = (
    "Synthetic scalability metrics only; this does not prove broad IAMScope correctness, "
    "production readiness, live AWS behavior, or arbitrary enterprise graph correctness."
)


@dataclass(frozen=True)
class FixtureConfig:
    name: str
    fixture_class: str
    seed: int
    account_count: int
    principals_per_account: int
    roles_per_account: int
    path_depth: int
    branching_factor: int
    constraint_count: int
    resource_policy_edge_count: int
    extra_trust_edges_per_principal: int = 0
    disjoint_path_roles: bool = False
    omit_terminal_assume_role_pair: bool = False
    expected_valid_synthetic_paths: int | None = None


FIXTURE_CONFIGS: dict[str, FixtureConfig] = {
    "small": FixtureConfig(
        name="small",
        fixture_class="small_regression_fixture",
        seed=20260509,
        account_count=1,
        principals_per_account=1,
        roles_per_account=3,
        path_depth=2,
        branching_factor=1,
        constraint_count=0,
        resource_policy_edge_count=0,
    ),
    "medium": FixtureConfig(
        name="medium",
        fixture_class="medium_synthetic_org_graph",
        seed=20260509,
        account_count=2,
        principals_per_account=4,
        roles_per_account=10,
        path_depth=3,
        branching_factor=2,
        constraint_count=6,
        resource_policy_edge_count=4,
    ),
    "constraint_heavy": FixtureConfig(
        name="constraint_heavy",
        fixture_class="constraint_heavy_synthetic_fixture",
        seed=20260509,
        account_count=2,
        principals_per_account=5,
        roles_per_account=12,
        path_depth=3,
        branching_factor=2,
        constraint_count=32,
        resource_policy_edge_count=6,
    ),
    "dense_trust": FixtureConfig(
        name="dense_trust",
        fixture_class="dense_trust_synthetic_fixture",
        seed=20260509,
        account_count=2,
        principals_per_account=4,
        roles_per_account=12,
        path_depth=3,
        branching_factor=3,
        constraint_count=4,
        resource_policy_edge_count=4,
        extra_trust_edges_per_principal=4,
    ),
    "multihop_stress": FixtureConfig(
        name="multihop_stress",
        fixture_class="multihop_stress_synthetic_fixture",
        seed=20260509,
        account_count=2,
        principals_per_account=3,
        roles_per_account=18,
        path_depth=6,
        branching_factor=2,
        constraint_count=4,
        resource_policy_edge_count=4,
    ),
    "negative_no_valid_path": FixtureConfig(
        name="negative_no_valid_path",
        fixture_class="negative_no_valid_path_synthetic_fixture",
        seed=20260509,
        account_count=2,
        principals_per_account=4,
        roles_per_account=12,
        path_depth=4,
        branching_factor=2,
        constraint_count=4,
        resource_policy_edge_count=4,
        disjoint_path_roles=True,
        omit_terminal_assume_role_pair=True,
        expected_valid_synthetic_paths=0,
    ),
}

DEFAULT_FIXTURES = (
    "small",
    "medium",
    "constraint_heavy",
    "dense_trust",
    "multihop_stress",
    "negative_no_valid_path",
)


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _account_id(config: FixtureConfig, index: int) -> str:
    return f"{config.seed % 1000000:06d}{index + 1:06d}"


def _role_id(config: FixtureConfig, account_index: int, role_index: int) -> str:
    return f"{config.name}:account:{account_index}:role:{role_index}"


def _user_id(config: FixtureConfig, account_index: int, principal_index: int) -> str:
    return f"{config.name}:account:{account_index}:user:{principal_index}"


def _add_edge(edges: dict[str, dict[str, Any]], *, source: str, target: str, edge_type: str, action: str) -> None:
    edge_id = _stable_digest({"action": action, "edge_type": edge_type, "source": source, "target": target})[:20]
    edges[edge_id] = {
        "edge_id": edge_id,
        "source": source,
        "target": target,
        "type": edge_type,
        "action": action,
    }


def generate_fixture(name: str) -> dict[str, Any]:
    config = _fixture_config(name)
    nodes: dict[str, dict[str, Any]] = {}
    permission_edges: dict[str, dict[str, Any]] = {}
    trust_edges: dict[str, dict[str, Any]] = {}
    resource_policy_edges: dict[str, dict[str, Any]] = {}

    for account_index in range(config.account_count):
        account_id = _account_id(config, account_index)
        nodes[f"{config.name}:account:{account_index}"] = {
            "node_id": f"{config.name}:account:{account_index}",
            "kind": "AWSAccount",
            "account_id": account_id,
        }
        for principal_index in range(config.principals_per_account):
            node_id = _user_id(config, account_index, principal_index)
            nodes[node_id] = {
                "node_id": node_id,
                "kind": "IAMUser",
                "account_id": account_id,
                "arn": f"arn:aws:iam::{account_id}:user/{config.name}-user-{principal_index}",
            }
        for role_index in range(config.roles_per_account):
            node_id = _role_id(config, account_index, role_index)
            nodes[node_id] = {
                "node_id": node_id,
                "kind": "IAMRole",
                "account_id": account_id,
                "arn": f"arn:aws:iam::{account_id}:role/{config.name}-role-{role_index}",
            }

    for account_index in range(config.account_count):
        for principal_index in range(config.principals_per_account):
            source = _user_id(config, account_index, principal_index)
            for branch_index in range(config.branching_factor):
                if config.disjoint_path_roles:
                    first_role_index = _disjoint_path_role_index(
                        config, principal_index=principal_index, branch_index=branch_index, depth_index=0
                    )
                else:
                    first_role_index = (principal_index * config.branching_factor + branch_index) % (
                        config.roles_per_account
                    )
                current_target = _role_id(config, account_index, first_role_index)
                _add_assume_role_pair(permission_edges, trust_edges, source=source, target=current_target)
                current_source = current_target
                for depth_index in range(1, config.path_depth):
                    if config.disjoint_path_roles:
                        next_role_index = _disjoint_path_role_index(
                            config, principal_index=principal_index, branch_index=branch_index, depth_index=depth_index
                        )
                    else:
                        next_role_index = (
                            first_role_index + depth_index * config.branching_factor + branch_index
                        ) % config.roles_per_account
                    if next_role_index == first_role_index:
                        next_role_index = (next_role_index + 1) % config.roles_per_account
                    next_target = _role_id(config, account_index, next_role_index)
                    if config.omit_terminal_assume_role_pair and depth_index == config.path_depth - 1:
                        _add_terminal_gap_edges(
                            permission_edges,
                            trust_edges,
                            source=current_source,
                            target=next_target,
                        )
                        continue
                    _add_assume_role_pair(permission_edges, trust_edges, source=current_source, target=next_target)
                    current_source = next_target

    _add_extra_trust_edges(trust_edges, config=config)

    for edge_index in range(config.resource_policy_edge_count):
        account_index = edge_index % config.account_count
        principal_index = edge_index % config.principals_per_account
        source = _user_id(config, account_index, principal_index)
        target = f"{config.name}:account:{account_index}:synthetic-resource:{edge_index}"
        nodes[target] = {
            "node_id": target,
            "kind": "SyntheticResource",
            "account_id": _account_id(config, account_index),
        }
        _add_edge(
            resource_policy_edges,
            source=source,
            target=target,
            edge_type="synthetic_resource_policy_allow",
            action="synthetic:GetObject",
        )

    constraints = [
        {
            "constraint_id": _stable_digest(
                {
                    "fixture": config.name,
                    "index": index,
                    "seed": config.seed,
                    "type": "synthetic_condition",
                }
            )[:20],
            "type": "synthetic_condition",
            "scope": config.name,
        }
        for index in range(config.constraint_count)
    ]

    fixture = {
        "fixture_name": config.name,
        "fixture_class": config.fixture_class,
        "seed": config.seed,
        "config": _config_payload(config),
        "nodes": sorted(nodes.values(), key=lambda item: item["node_id"]),
        "permission_edges": sorted(permission_edges.values(), key=lambda item: item["edge_id"]),
        "trust_edges": sorted(trust_edges.values(), key=lambda item: item["edge_id"]),
        "resource_policy_edges": sorted(resource_policy_edges.values(), key=lambda item: item["edge_id"]),
        "constraints": constraints,
    }
    return fixture


def _add_assume_role_pair(
    permission_edges: dict[str, dict[str, Any]],
    trust_edges: dict[str, dict[str, Any]],
    *,
    source: str,
    target: str,
) -> None:
    _add_edge(
        permission_edges, source=source, target=target, edge_type="sts:AssumeRole_permission", action="sts:AssumeRole"
    )
    _add_edge(trust_edges, source=source, target=target, edge_type="sts:AssumeRole_trust", action="sts:AssumeRole")


def _config_payload(config: FixtureConfig) -> dict[str, bool | int | str]:
    payload: dict[str, bool | int | str] = {
        "name": config.name,
        "fixture_class": config.fixture_class,
        "seed": config.seed,
        "account_count": config.account_count,
        "principals_per_account": config.principals_per_account,
        "roles_per_account": config.roles_per_account,
        "path_depth": config.path_depth,
        "branching_factor": config.branching_factor,
        "constraint_count": config.constraint_count,
        "resource_policy_edge_count": config.resource_policy_edge_count,
    }
    if config.extra_trust_edges_per_principal:
        payload["extra_trust_edges_per_principal"] = config.extra_trust_edges_per_principal
    if config.disjoint_path_roles:
        payload["disjoint_path_roles"] = True
    if config.omit_terminal_assume_role_pair:
        payload["omit_terminal_assume_role_pair"] = True
    if config.expected_valid_synthetic_paths is not None:
        payload["expected_valid_synthetic_paths"] = config.expected_valid_synthetic_paths
    return payload


def _disjoint_path_role_index(
    config: FixtureConfig, *, principal_index: int, branch_index: int, depth_index: int
) -> int:
    return (
        principal_index * config.branching_factor * config.path_depth
        + branch_index * config.path_depth
        + depth_index
    ) % config.roles_per_account


def _add_terminal_gap_edges(
    permission_edges: dict[str, dict[str, Any]],
    trust_edges: dict[str, dict[str, Any]],
    *,
    source: str,
    target: str,
) -> None:
    # Add deterministic but nonmatching evidence so search work exists without a full valid path.
    decoy_source = target
    _add_edge(
        permission_edges,
        source=source,
        target=target,
        edge_type="sts:AssumeRole_permission",
        action="sts:AssumeRole",
    )
    _add_edge(
        trust_edges,
        source=decoy_source,
        target=target,
        edge_type="sts:AssumeRole_trust",
        action="sts:AssumeRole",
    )


def _add_extra_trust_edges(trust_edges: dict[str, dict[str, Any]], *, config: FixtureConfig) -> None:
    for account_index in range(config.account_count):
        for principal_index in range(config.principals_per_account):
            source = _user_id(config, account_index, principal_index)
            for offset in range(config.extra_trust_edges_per_principal):
                role_index = (
                    principal_index * config.branching_factor + config.path_depth * config.branching_factor + offset
                ) % config.roles_per_account
                target = _role_id(config, account_index, role_index)
                _add_edge(
                    trust_edges,
                    source=source,
                    target=target,
                    edge_type="sts:AssumeRole_trust",
                    action="sts:AssumeRole",
                )


def _fixture_config(name: str) -> FixtureConfig:
    try:
        return FIXTURE_CONFIGS[name]
    except KeyError as exc:
        choices = ", ".join(sorted(FIXTURE_CONFIGS))
        raise ValueError(f"unknown fixture {name!r}; expected one of: {choices}") from exc


def _fixture_size_summary(fixture: dict[str, Any]) -> dict[str, int]:
    nodes = fixture["nodes"]
    return {
        "accounts": sum(1 for node in nodes if node["kind"] == "AWSAccount"),
        "principals": sum(1 for node in nodes if node["kind"] == "IAMUser"),
        "roles": sum(1 for node in nodes if node["kind"] == "IAMRole"),
        "resources": sum(1 for node in nodes if node["kind"] == "SyntheticResource"),
        "nodes": len(nodes),
        "trust_edges": len(fixture["trust_edges"]),
        "permission_edges": len(fixture["permission_edges"]),
        "resource_policy_edges": len(fixture["resource_policy_edges"]),
        "constraints": len(fixture["constraints"]),
        "path_depth": int(fixture["config"]["path_depth"]),
        "branching_factor": int(fixture["config"]["branching_factor"]),
    }


def _candidate_paths(fixture: dict[str, Any]) -> list[list[str]]:
    max_depth = int(fixture["config"]["path_depth"])
    node_by_id = {node["node_id"]: node for node in fixture["nodes"]}
    trust_pairs = {(edge["source"], edge["target"]) for edge in fixture["trust_edges"]}
    permission_by_source: dict[str, list[dict[str, Any]]] = {}
    for edge in fixture["permission_edges"]:
        permission_by_source.setdefault(str(edge["source"]), []).append(edge)
    for edges in permission_by_source.values():
        edges.sort(key=lambda item: str(item["edge_id"]))

    paths: list[list[str]] = []
    start_nodes = sorted(node["node_id"] for node in fixture["nodes"] if node["kind"] == "IAMUser")
    for start_node in start_nodes:
        _walk_paths(
            current_node=start_node,
            permission_by_source=permission_by_source,
            trust_pairs=trust_pairs,
            node_by_id=node_by_id,
            max_depth=max_depth,
            current_path=[],
            visited={start_node},
            paths=paths,
        )
    return paths


def _walk_paths(
    *,
    current_node: str,
    permission_by_source: dict[str, list[dict[str, Any]]],
    trust_pairs: set[tuple[str, str]],
    node_by_id: dict[str, dict[str, Any]],
    max_depth: int,
    current_path: list[str],
    visited: set[str],
    paths: list[list[str]],
) -> None:
    if len(current_path) >= max_depth:
        return
    for edge in permission_by_source.get(current_node, []):
        target = str(edge["target"])
        if (current_node, target) not in trust_pairs:
            continue
        if target in visited:
            continue
        if node_by_id[target]["kind"] != "IAMRole":
            continue
        next_path = [*current_path, str(edge["edge_id"])]
        paths.append(next_path)
        _walk_paths(
            current_node=target,
            permission_by_source=permission_by_source,
            trust_pairs=trust_pairs,
            node_by_id=node_by_id,
            max_depth=max_depth,
            current_path=next_path,
            visited={*visited, target},
            paths=paths,
        )


def run_fixture(name: str) -> dict[str, Any]:
    started = time.perf_counter_ns()
    load_started = time.perf_counter_ns()
    fixture = generate_fixture(name)
    artifact_load_time_ms = _elapsed_ms(load_started)
    candidate_paths = _candidate_paths(fixture)
    fixture_digest = _stable_digest(fixture)
    stable_metrics = {
        "candidate_paths_considered": len(candidate_paths),
        "constraint_evaluations": len(candidate_paths) * len(fixture["constraints"]),
        "fixture_digest": fixture_digest,
        "fixture_size": _fixture_size_summary(fixture),
    }
    wall_clock_runtime_ms = _elapsed_ms(started)
    result = {
        "fixture_name": fixture["fixture_name"],
        "fixture_class": fixture["fixture_class"],
        "seed": fixture["seed"],
        "fixture_size": stable_metrics["fixture_size"],
        "metrics": {
            "wall_clock_runtime_ms": wall_clock_runtime_ms,
            "peak_memory_bytes": "not_collected",
            "candidate_paths_considered": stable_metrics["candidate_paths_considered"],
            "paths_validated": "not_collected",
            "paths_rejected": "not_collected",
            "constraint_evaluations": stable_metrics["constraint_evaluations"],
            "artifact_load_time_ms": artifact_load_time_ms,
            "report_generation_time_ms": "not_collected",
            "deterministic_output_stability": {
                "fixture_digest": fixture_digest,
                "stable_metric_digest": _stable_digest(stable_metrics),
            },
            "failure_mode_classification": "none",
        },
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }
    if "expected_valid_synthetic_paths" in fixture["config"]:
        result["synthetic_path_expectation"] = {
            "expected_valid_synthetic_paths": fixture["config"]["expected_valid_synthetic_paths"],
            "representation": "full_depth_candidate_paths",
        }
    return result


def _elapsed_ms(started_ns: int) -> float:
    return round((time.perf_counter_ns() - started_ns) / 1_000_000, 3)


def build_report(fixture_names: list[str] | None = None) -> dict[str, Any]:
    selected = fixture_names or list(DEFAULT_FIXTURES)
    invalid = sorted(set(selected) - set(FIXTURE_CONFIGS))
    if invalid:
        choices = ", ".join(sorted(FIXTURE_CONFIGS))
        raise ValueError(f"unknown fixture(s): {', '.join(invalid)}; expected one of: {choices}")

    report_started = time.perf_counter_ns()
    fixture_results = [run_fixture(name) for name in selected]
    report_generation_time_ms = _elapsed_ms(report_started)
    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "fixture_count": len(fixture_results),
        "fixture_names": selected,
        "available_fixture_sizes": list(DEFAULT_FIXTURES),
        "fixtures": fixture_results,
        "report_metrics": {
            "report_generation_time_ms": report_generation_time_ms,
            "deterministic_output_stability": {
                "stable_report_digest": _stable_digest(
                    [
                        {
                            "fixture_name": item["fixture_name"],
                            "fixture_size": item["fixture_size"],
                            "stable_metric_digest": item["metrics"]["deterministic_output_stability"][
                                "stable_metric_digest"
                            ],
                        }
                        for item in fixture_results
                    ]
                )
            },
        },
        "evidence_boundary": EVIDENCE_BOUNDARY,
        "non_goals": [
            "no live AWS benchmark",
            "no production-readiness proof",
            "no broad IAMScope correctness proof",
            "no arbitrary enterprise graph correctness proof",
            "no composite score",
            "no semantic mutation-pair replacement",
        ],
    }


def write_report(report: dict[str, Any], json_out: Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope Synthetic Scalability Report",
        "",
        "Synthetic-only scalability report for the bounded scalability harness.",
        "",
        "No composite score is emitted. Metrics remain separate and per fixture.",
        "",
        "This report does not prove real-world scalability or correctness, live AWS correctness, deployment readiness, "
        "or arbitrary enterprise graph correctness.",
        "",
        "## Harness Config",
        "",
        f"- Report type: `{report['report_type']}`.",
        f"- Schema version: `{report['schema_version']}`.",
        f"- Fixture count: `{report['fixture_count']}`.",
        f"- Fixture names: `{', '.join(str(name) for name in report['fixture_names'])}`.",
        "",
        "## Fixture Summary",
        "",
        "| Fixture | Class | Seed | Accounts | Principals | Roles | Nodes | Permission edges | Trust edges | Resource-policy edges | Constraints | Path depth | Branching factor |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for fixture in report["fixtures"]:
        size = fixture["fixture_size"]
        lines.append(
            "| {fixture_name} | {fixture_class} | {seed} | {accounts} | {principals} | {roles} | {nodes} | "
            "{permission_edges} | {trust_edges} | {resource_policy_edges} | {constraints} | {path_depth} | "
            "{branching_factor} |".format(
                fixture_name=fixture["fixture_name"],
                fixture_class=fixture["fixture_class"],
                seed=fixture["seed"],
                accounts=size["accounts"],
                principals=size["principals"],
                roles=size["roles"],
                nodes=size["nodes"],
                permission_edges=size["permission_edges"],
                trust_edges=size["trust_edges"],
                resource_policy_edges=size["resource_policy_edges"],
                constraints=size["constraints"],
                path_depth=size["path_depth"],
                branching_factor=size["branching_factor"],
            )
        )

    lines.extend(
        [
            "",
            "## Per-Fixture Metrics",
            "",
            "| Fixture | wall_clock_runtime_ms | candidate_paths_considered | constraint_evaluations | artifact_load_time_ms | paths_validated | paths_rejected | peak_memory_bytes | deterministic_output_stability | failure_mode_classification |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for fixture in report["fixtures"]:
        metrics = fixture["metrics"]
        stability = metrics["deterministic_output_stability"]
        lines.append(
            "| {fixture_name} | {wall_clock_runtime_ms} | {candidate_paths_considered} | "
            "{constraint_evaluations} | {artifact_load_time_ms} | {paths_validated} | {paths_rejected} | "
            "{peak_memory_bytes} | fixture_digest=`{fixture_digest}`; stable_metric_digest=`{stable_metric_digest}` | "
            "{failure_mode_classification} |".format(
                fixture_name=fixture["fixture_name"],
                wall_clock_runtime_ms=metrics["wall_clock_runtime_ms"],
                candidate_paths_considered=metrics["candidate_paths_considered"],
                constraint_evaluations=metrics["constraint_evaluations"],
                artifact_load_time_ms=metrics["artifact_load_time_ms"],
                paths_validated=metrics["paths_validated"],
                paths_rejected=metrics["paths_rejected"],
                peak_memory_bytes=metrics["peak_memory_bytes"],
                fixture_digest=stability["fixture_digest"],
                stable_metric_digest=stability["stable_metric_digest"],
                failure_mode_classification=metrics["failure_mode_classification"],
            )
        )

    report_stability = report["report_metrics"]["deterministic_output_stability"]
    lines.extend(
        [
            "",
            "## Report Stability",
            "",
            f"- Stable report digest: `{report_stability['stable_report_digest']}`.",
            "- Runtime fields such as `wall_clock_runtime_ms` and `artifact_load_time_ms` are measured values, not stability markers.",
            "",
            "## Caveats",
            "",
            "- Synthetic-only: this report is generated from deterministic synthetic fixtures, not live AWS.",
            "- No composite score: metrics remain separate and per fixture.",
            "- Does not prove real-world scalability or correctness.",
            "- Does not prove deployment readiness, runtime exploitability, broad IAMScope correctness, or arbitrary enterprise graph correctness.",
            "- Does not claim generic resource-policy Deny support or finding-level resource-policy reachability.",
            "- The only implemented scalability fixtures are `small`, `medium`, `constraint_heavy`, `dense_trust`, `multihop_stress`, and `negative_no_valid_path`.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run minimal synthetic IAMScope scalability benchmarks.")
    parser.add_argument(
        "--fixture",
        action="append",
        choices=sorted(FIXTURE_CONFIGS),
        help="Fixture size to run. May be passed multiple times. Defaults to small and medium.",
    )
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON summary.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown summary.")
    args = parser.parse_args(argv)

    report = build_report(args.fixture)
    if args.json_out:
        write_report(report, args.json_out)
        print(f"scalability_report_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"scalability_report_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
