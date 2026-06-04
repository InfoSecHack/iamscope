"""IAMScope CLI — command-line interface for collection and analysis.

Usage:
    iamscope collect [options]
    iamscope collect --profile myprofile --output ./results/
    iamscope collect --accounts <account-id-1>,<account-id-2>
    iamscope collect --expansion-mode expand --include-service-linked

The CLI wraps the pipeline orchestrator and handles:
- Argument parsing
- Logging configuration
- File output
- Exit codes
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Callable
from pathlib import Path

from iamscope.auth.session import get_session
from iamscope.constants import SEVERITY_MEDIUM
from iamscope.output.findings_json import emit_findings
from iamscope.pipeline import PipelineConfig, PipelineResult, run_pipeline
from iamscope.reasoner import (
    ASSUMPTION_KIND_CONDITION_CONTEXT,
    AdminReachabilityReasoner,
    AssumeRoleChainReasoner,
    Assumption,
    CrossAccountTrustReasoner,
    FactGraph,
    Finding,
    IAMGroupMembershipEscalationReasoner,
    PassRoleEcsReasoner,
    PassRoleLambdaReasoner,
    Reasoner,
    Registry,
    S3BucketTakeoverReasoner,
    SecretsBlastRadiusReasoner,
    Verdict,
)
from iamscope.reasoner.cross_reasoner_consistency import (
    apply_cross_reasoner_demotions,
)
from iamscope.truth.probe_overlay import ProbeRecord

logger = logging.getLogger(__name__)


# S14: registry of all reasoners shipped with IAMScope. Order is the
# default registration order when --reasoners is not specified. Adding
# a new reasoner here is the only place the CLI needs to be touched
# when a new pattern lands; the rest of the wiring is generic.
#
# Type hint is `Callable[[], Reasoner]` rather than `type[Reasoner]`
# because Reasoner is a `@runtime_checkable Protocol` and using
# `type[Protocol]` produces strict-checker complaints about Protocol
# instantiation. The factories below are concrete classes, but the
# constraint is "callable that returns a Reasoner instance," not
# "subclass of the Reasoner Protocol."
_AVAILABLE_REASONER_FACTORIES: dict[str, Callable[[], Reasoner]] = {
    CrossAccountTrustReasoner.pattern_id: CrossAccountTrustReasoner,
    PassRoleLambdaReasoner.pattern_id: PassRoleLambdaReasoner,
    PassRoleEcsReasoner.pattern_id: PassRoleEcsReasoner,
    AssumeRoleChainReasoner.pattern_id: AssumeRoleChainReasoner,
    AdminReachabilityReasoner.pattern_id: AdminReachabilityReasoner,
    SecretsBlastRadiusReasoner.pattern_id: SecretsBlastRadiusReasoner,
    IAMGroupMembershipEscalationReasoner.pattern_id: IAMGroupMembershipEscalationReasoner,
    S3BucketTakeoverReasoner.pattern_id: S3BucketTakeoverReasoner,
}


def _log_cli_error(message: str, exception: BaseException) -> None:
    """Log a CLI-level exception with visibility-tier-aware detail.

    BUG-011/12 fix: every CLI command handler used to catch
    `Exception` and log only `logger.error("... failed: %s", e)`, with
    NO escape hatch for users who wanted to see the underlying
    traceback. A user running `iamscope report -vv broken.json` got
    the same one-line output as `iamscope report broken.json`, making
    any bug in a downstream module nearly impossible to debug without
    editing the source. The only handler with a debug-traceback
    escape was the `pipeline` handler (cli.py:428-429, pre-fix).

    This helper centralizes the pattern:

    1. Always log the one-line error at WARNING/ERROR level, so
       even quiet operators see SOMETHING went wrong.
    2. When the logger is at DEBUG level (user passed `-vv`),
       also emit the full traceback via `logger.exception` so
       the operator can diagnose the failure without re-running
       under `python -X dev` or editing the source.

    All CLI command handlers that catch a broad `Exception` should
    use this helper instead of writing the pattern inline, so the
    escape hatch is consistent across subcommands.
    """
    logger.error("%s: %s", message, exception)
    if logger.isEnabledFor(logging.DEBUG):
        logger.exception("Full traceback:")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments. None uses sys.argv.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose, args.quiet)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    result: int = args.func(args)
    return result


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    from iamscope import __version__

    parser = argparse.ArgumentParser(
        prog="iamscope",
        description="IAMScope — AWS IAM trust and permission graph collector",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"iamscope {__version__}",
        help="Show iamscope release version and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    subparsers = parser.add_subparsers(title="commands")

    # --- collect ---
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect IAM data from an AWS Organization",
        description="Run the full IAMScope collection pipeline: "
        "organization discovery, per-account IAM collection, "
        "trust/permission resolution, scenario.json emission.",
    )
    _add_collect_args(collect_parser)
    collect_parser.set_defaults(func=_cmd_collect)

    # --- report ---
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a security assessment report from scenario.json + findings.json",
    )
    report_parser.add_argument(
        "scenario",
        help="Path to scenario.json",
    )
    report_parser.add_argument(
        "--findings",
        dest="findings",
        default=None,
        help=(
            "Path to findings.json. If not provided, the CLI auto-discovers "
            "`findings.json` as a sibling of the scenario file. Pass "
            "--no-auto-findings to suppress auto-discovery (for back-compat "
            "graph-only reports). When findings.json is present, the report "
            "leads with a findings-first section grouped by pattern_id."
        ),
    )
    report_parser.add_argument(
        "--no-auto-findings",
        action="store_true",
        help=(
            "Disable auto-discovery of sibling findings.json. Produces a "
            "graph-only report matching the pre-priority-2 format."
        ),
    )
    report_parser.add_argument(
        "--binding-metadata",
        dest="binding_metadata",
        default=None,
        help="Path to binding_metadata.json",
    )
    report_parser.add_argument(
        "--enrichment",
        default=None,
        help="Path to GhostGates enrichment.json",
    )
    report_parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        default=None,
        help="Output file path (default: stdout)",
    )
    report_parser.set_defaults(func=_cmd_report)

    # --- enrich ---
    enrich_parser = subparsers.add_parser(
        "enrich",
        help="Enrich scenario with GhostGates CI/CD gate bypass data",
    )
    enrich_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario.json",
    )
    enrich_parser.add_argument(
        "--ghostgates",
        required=True,
        help="Path to GhostGates report.json",
    )
    enrich_parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        default="enrichment.json",
        help="Output path for enrichment results (default: enrichment.json)",
    )
    enrich_parser.set_defaults(func=_cmd_enrich)

    # --- diff ---
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two scenario.json files and show changes",
    )
    diff_parser.add_argument(
        "before",
        help="Path to the earlier scenario.json",
    )
    diff_parser.add_argument(
        "after",
        help="Path to the later scenario.json",
    )
    diff_parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        default=None,
        help="Output path for diff JSON (default: stdout Markdown)",
    )
    diff_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Output raw JSON instead of Markdown",
    )
    diff_parser.set_defaults(func=_cmd_diff)

    # --- diff-findings ---
    findings_diff_parser = subparsers.add_parser(
        "diff-findings",
        help="Compare two findings.json files by stable finding_key",
        description=(
            "Compare baseline and candidate findings.json files using "
            "stable semantic finding_key identity instead of mutable "
            "finding_id or list position."
        ),
    )
    findings_diff_parser.add_argument(
        "baseline",
        help="Path to baseline findings.json",
    )
    findings_diff_parser.add_argument(
        "candidate",
        help="Path to candidate findings.json",
    )
    findings_diff_parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Output format (default: human)",
    )
    findings_diff_parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        default=None,
        help="Output path (default: stdout)",
    )
    findings_diff_parser.set_defaults(func=_cmd_diff_findings)

    # --- edge-truth ---
    edge_truth_parser = subparsers.add_parser(
        "edge-truth",
        help="Show declared/simulated/validated/confounded truth for one edge",
        description=(
            "Join scenario.json with optional binding_metadata.json and "
            "probe_overlay.json sidecars for one source/target/action edge."
        ),
    )
    edge_truth_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario.json",
    )
    edge_truth_parser.add_argument(
        "--binding-metadata",
        default=None,
        help="Path to binding_metadata.json",
    )
    edge_truth_parser.add_argument(
        "--probe-overlay",
        default=None,
        help="Path to probe_overlay.json",
    )
    edge_truth_parser.add_argument(
        "--source-arn",
        required=True,
        help="Source principal ARN",
    )
    edge_truth_parser.add_argument(
        "--target-arn",
        required=True,
        help="Target role ARN",
    )
    edge_truth_parser.add_argument(
        "--action-class",
        required=True,
        help="Action class, e.g. sts:AssumeRole",
    )
    edge_truth_parser.set_defaults(func=_cmd_edge_truth)

    # --- stale-drift ---
    stale_drift_parser = subparsers.add_parser(
        "stale-drift",
        help="Inspect stale principal drift evidence for one edge or finding",
        description=(
            "Inspect STALE_PRINCIPAL_DRIFT constraint evidence from a frozen "
            "scenario.json, optionally anchored by finding_key from findings.json."
        ),
    )
    stale_drift_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario.json",
    )
    stale_drift_parser.add_argument(
        "--edge-id",
        default=None,
        help="Specific edge_id to inspect",
    )
    stale_drift_parser.add_argument(
        "--findings",
        default=None,
        help="Optional findings.json used with --finding-key",
    )
    stale_drift_parser.add_argument(
        "--finding-key",
        default=None,
        help="Stable finding_key to inspect via findings.json evidence",
    )
    stale_drift_parser.set_defaults(func=_cmd_stale_drift)

    # --- probe-overlay ---
    probe_overlay_parser = subparsers.add_parser(
        "probe-overlay",
        help="Run simulator/runtime probes and emit probe_overlay.json",
        description=(
            "Run an explicit engagement probe plan against an existing "
            "scenario.json and emit the probe overlay sidecar consumed by "
            "overlay-aware reasoners."
        ),
    )
    probe_overlay_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to scenario.json",
    )
    probe_overlay_parser.add_argument(
        "--plan",
        required=True,
        help="Path to probe plan JSON",
    )
    probe_overlay_parser.add_argument(
        "--output",
        "-o",
        default="probe_overlay.json",
        help="Output path for probe_overlay.json (default: probe_overlay.json)",
    )
    probe_overlay_parser.add_argument(
        "--engagement-run-id",
        default=None,
        help="Optional run identifier. Defaults to engagement_run_id in the plan or a generated id.",
    )
    probe_overlay_parser.add_argument(
        "--profile",
        dest="profile_name",
        default=None,
        help="Default AWS profile for simulator/runtime clients when a plan item omits a profile.",
    )
    probe_overlay_parser.add_argument(
        "--region",
        dest="region_name",
        default="us-east-1",
        help="Default AWS region (default: us-east-1)",
    )
    probe_overlay_parser.add_argument(
        "--respect-confounders",
        action="store_true",
        default=False,
        help="Emit confounded_skip instead of running AWS calls when scenario sidecars mark the edge confounded.",
    )
    probe_overlay_parser.set_defaults(func=_cmd_probe_overlay)

    # --- replay-findings ---
    replay_parser = subparsers.add_parser(
        "replay-findings",
        help="Run reasoners over frozen scenario/binding/probe artifacts",
        description=(
            "Replay IAMScope reasoners over an existing scenario.json and "
            "binding_metadata.json, with optional probe_overlay.json, without "
            "recollecting AWS."
        ),
    )
    replay_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to frozen scenario.json",
    )
    replay_parser.add_argument(
        "--binding-metadata",
        required=True,
        help="Path to binding_metadata.json",
    )
    replay_parser.add_argument(
        "--probe-overlay",
        default=None,
        help="Optional probe_overlay.json",
    )
    replay_parser.add_argument(
        "--reasoners",
        default=None,
        help=(
            "Comma-separated reasoner pattern_ids to run "
            f"(available: {','.join(sorted(_AVAILABLE_REASONER_FACTORIES))}). "
            "Defaults to all reasoners."
        ),
    )
    replay_parser.add_argument(
        "--output",
        "-o",
        default="findings.json",
        help="Output findings.json path (default: findings.json)",
    )
    replay_parser.set_defaults(func=_cmd_replay_findings)

    # --- demo-pack ---
    demo_pack_parser = subparsers.add_parser(
        "demo-pack",
        help="Build a frozen replay/probe/diff demo pack",
        description=(
            "Copy frozen artifacts, replay baseline and optional overlay "
            "findings, and write semantic diff outputs for handoff or demo."
        ),
    )
    demo_pack_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to frozen scenario.json",
    )
    demo_pack_parser.add_argument(
        "--binding-metadata",
        required=True,
        help="Path to binding_metadata.json",
    )
    demo_pack_parser.add_argument(
        "--probe-overlay",
        default=None,
        help="Optional probe_overlay.json",
    )
    demo_pack_parser.add_argument(
        "--reasoners",
        default=None,
        help=(
            "Comma-separated reasoner pattern_ids to run "
            f"(available: {','.join(sorted(_AVAILABLE_REASONER_FACTORIES))}). "
            "Defaults to all reasoners."
        ),
    )
    demo_pack_parser.add_argument(
        "--output-dir",
        "-o",
        default="iamscope-demo-pack",
        help="Output directory for the demo pack (default: iamscope-demo-pack)",
    )
    demo_pack_parser.set_defaults(func=_cmd_demo_pack)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Cross-check validated findings against AWS IAM Policy Simulator (ground truth verification)",
        description="Runs iam:SimulatePrincipalPolicy for each "
        "validated secrets_blast_radius finding and compares "
        "AWS's own decision against iamscope's verdict. Exit 0 "
        "if all agreed, 1 if any disagreed. v1 supports "
        "secretsmanager:GetSecretValue only.",
    )
    verify_parser.add_argument(
        "--findings",
        required=True,
        help="Path to findings.json from iamscope collect",
    )
    verify_parser.add_argument(
        "--profile",
        required=True,
        help="AWS profile name for the simulator API calls",
    )
    verify_parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write detailed JSON verification report",
    )
    verify_parser.add_argument(
        "--check-target-state",
        action="store_true",
        help="For each validated finding, call the target's describe "
        "API at verify time to confirm the target is live. "
        "Demotes findings where the target is missing, pending "
        "deletion, or inaccessible. Catches scan-to-verify drift "
        "that would otherwise leave stale findings in the report.",
    )

    def _cmd_verify(args: argparse.Namespace) -> int:
        from iamscope.verify import cmd_verify

        return cmd_verify(args)

    verify_parser.set_defaults(func=_cmd_verify)

    # --- validate ---
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a scenario.json for structural integrity",
    )
    validate_parser.add_argument(
        "scenario",
        help="Path to scenario.json",
    )
    validate_parser.set_defaults(func=_cmd_validate)

    # --- why ---
    why_parser = subparsers.add_parser(
        "why",
        help=(
            "Explain why a specific finding was emitted with the "
            "verdict it got. Walks the finding's check results, "
            "evidence, and trace to show the exact reasoning path."
        ),
    )
    why_parser.add_argument(
        "--findings",
        dest="findings_path",
        default="findings.json",
        help="Path to findings.json (default: findings.json in cwd)",
    )
    why_parser.add_argument(
        "--finding-id",
        dest="finding_id",
        default=None,
        help=(
            "Specific finding_id to explain (prefix match — so a short "
            "prefix like 'abc123' is enough as long as it's unique)"
        ),
    )
    why_parser.add_argument(
        "--pattern",
        dest="pattern_id",
        default=None,
        help=(
            "Pattern ID filter (e.g., secrets_blast_radius). Combined "
            "with --source and/or --target to locate a finding."
        ),
    )
    why_parser.add_argument(
        "--source",
        dest="source_arn",
        default=None,
        help="Source principal ARN filter (substring match)",
    )
    why_parser.add_argument(
        "--target",
        dest="target_arn",
        default=None,
        help="Target resource ARN filter (substring match)",
    )
    why_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Include the full reasoning trace (step-by-step evaluation)",
    )
    why_parser.add_argument(
        "--no-color",
        action="store_true",
        help=("Disable ANSI color output (useful for piping to less/grep, auto-disabled when stdout is not a TTY)"),
    )
    why_parser.set_defaults(func=_cmd_why)

    return parser


def _add_collect_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the collect command."""
    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "--profile",
        dest="profile_name",
        default=None,
        help="AWS CLI profile name (default: env/default)",
    )
    auth.add_argument(
        "--region",
        dest="region_name",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    auth.add_argument(
        "--role-name",
        dest="role_name",
        default="IAMScopeReader",
        help="Collection role name to assume in member accounts (default: IAMScopeReader)",
    )
    auth.add_argument(
        "--external-id",
        dest="external_id",
        default=None,
        help="ExternalId for cross-account AssumeRole",
    )

    # Scope
    scope = parser.add_argument_group("Scope")
    scope.add_argument(
        "--standalone",
        action="store_true",
        default=False,
        help="Single-account mode: collect the current account without "
        "requiring AWS Organizations access. Skips SCP collection.",
    )
    scope.add_argument(
        "--accounts",
        dest="account_filter",
        default=None,
        help="Comma-separated account IDs to collect (default: all active)",
    )
    scope.add_argument(
        "--skip-accounts",
        dest="skip_accounts",
        default=None,
        help="Comma-separated account IDs to skip",
    )

    # Noise filter
    noise = parser.add_argument_group("Noise Filter")
    noise.add_argument(
        "--include-service-linked",
        action="store_true",
        default=False,
        help="Include AWS service-linked roles",
    )
    noise.add_argument(
        "--include-aws-managed",
        action="store_true",
        default=False,
        help="Include AWS-managed service roles",
    )

    # Expansion
    expansion = parser.add_argument_group("Expansion Controls")
    expansion.add_argument(
        "--expansion-mode",
        dest="expansion_mode",
        default="warn",
        choices=["expand", "warn", "skip"],
        help="Wildcard expansion mode (default: warn)",
    )
    expansion.add_argument(
        "--passrole-mode",
        dest="passrole_mode",
        default=None,
        choices=["expand", "warn", "skip"],
        help="Override expansion mode for PassRole (default: use global)",
    )
    expansion.add_argument(
        "--lambda-mode",
        dest="lambda_mode",
        default=None,
        choices=["expand", "warn", "skip"],
        help="Override expansion mode for Lambda (default: use global)",
    )
    expansion.add_argument(
        "--ec2-mode",
        dest="ec2_mode",
        default=None,
        choices=["expand", "warn", "skip"],
        help="Override expansion mode for EC2 (default: use global)",
    )

    # Output
    output = parser.add_argument_group("Output")
    output.add_argument(
        "--output",
        "-o",
        dest="output_dir",
        default=".",
        help="Output directory (default: current directory)",
    )

    # Reasoning (S14)
    reasoning = parser.add_argument_group("Reasoning")
    reasoning.add_argument(
        "--no-findings",
        dest="no_findings",
        action="store_true",
        help=(
            "Skip findings.json emission. Reasoners are not run; "
            "only scenario.json and binding_metadata.json are written. "
            "Use this for back-compat with callers that expect the "
            "pre-S14 output set."
        ),
    )
    reasoning.add_argument(
        "--reasoners",
        dest="reasoners",
        default=None,
        help=(
            "Comma-separated list of reasoner pattern_ids to run "
            f"(available: {','.join(sorted(_AVAILABLE_REASONER_FACTORIES))}). "
            "If not specified, all available reasoners run. Pass an "
            "unknown pattern_id to fail fast."
        ),
    )
    reasoning.add_argument(
        "--probe-overlay",
        dest="probe_overlay",
        default=None,
        help=(
            "Optional probe_overlay.json sidecar. When supplied, supported "
            "reasoners may use live probe truth without changing scenario.json."
        ),
    )
    reasoning.add_argument(
        "--assume-no-session-policies",
        dest="assume_no_session_policies",
        action="store_true",
        help=(
            "Pedantic-reviewer mode for passrole_lambda. Demotes every "
            "VALIDATED finding to INCONCLUSIVE by adding a "
            "condition_context assumption. Per plan §4B.4: IAMScope "
            "cannot see AWS session policies at collection time, so "
            "VALIDATED findings implicitly assume no session policy "
            "restricts the chain. This flag forces that assumption "
            "to be visible in the verdict."
        ),
    )


def _cmd_diff_findings(args: argparse.Namespace) -> int:
    """Execute the diff-findings command."""
    import json as _json

    try:
        from iamscope.findings_diff import (
            diff_findings_from_files,
            format_findings_diff,
        )

        result = diff_findings_from_files(args.baseline, args.candidate)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 1
    except Exception as e:
        _log_cli_error("diff-findings failed", e)
        return 1

    output = (
        _json.dumps(result.to_dict(), indent=2, sort_keys=True)
        if args.format == "json"
        else format_findings_diff(result)
    )
    if args.output_path:
        Path(args.output_path).write_text(output, encoding="utf-8")
        logger.info("Wrote findings diff to %s", args.output_path)
    else:
        print(output)
    return 0


def _cmd_demo_pack(args: argparse.Namespace) -> int:
    """Execute the demo-pack command."""
    try:
        from iamscope.demo_pack import build_demo_pack

        pattern_ids, error = _resolve_reasoner_set(args.reasoners)
        if error is not None:
            logger.error("--reasoners: %s", error)
            return 1
        instances = tuple(_AVAILABLE_REASONER_FACTORIES[pid]() for pid in pattern_ids)
        result = build_demo_pack(
            scenario_path=args.scenario,
            binding_metadata_path=args.binding_metadata,
            probe_overlay_path=args.probe_overlay,
            output_dir=args.output_dir,
            reasoner_instances=instances,
            reasoner_ids=tuple(pattern_ids),
        )
    except Exception as e:
        _log_cli_error("demo-pack failed", e)
        return 1

    print(f"Wrote demo pack: {result.output_dir}")
    print(f"Baseline findings: {result.baseline_findings_path}")
    if result.overlay_findings_path is not None:
        print(f"Overlay findings: {result.overlay_findings_path}")
    if result.diff_markdown_path is not None:
        print(f"Findings diff: {result.diff_markdown_path}")
    print(f"Manifest: {result.manifest_path}")
    return 0


def _cmd_edge_truth(args: argparse.Namespace) -> int:
    """Execute the edge-truth command."""
    try:
        from iamscope.truth.edge_truth import (
            render_edge_truth_summary,
            summarize_from_paths,
        )

        summary = summarize_from_paths(
            scenario_path=args.scenario,
            binding_metadata_path=args.binding_metadata,
            probe_overlay_path=args.probe_overlay,
            source_arn=args.source_arn,
            target_arn=args.target_arn,
            action_class=args.action_class,
        )
    except Exception as e:
        _log_cli_error("edge-truth failed", e)
        return 1

    print(render_edge_truth_summary(summary))
    return 0


def _cmd_stale_drift(args: argparse.Namespace) -> int:
    """Execute the stale-drift command."""
    if not args.edge_id and not args.finding_key:
        logger.error("stale-drift requires --edge-id or --finding-key")
        return 1
    if args.finding_key and not args.findings:
        logger.error("--findings is required when --finding-key is used")
        return 1

    try:
        from iamscope.truth.stale_principal_drift import (
            render_stale_drift_summary,
            summarize_stale_drift_from_paths,
        )

        summary = summarize_stale_drift_from_paths(
            scenario_path=args.scenario,
            edge_id=args.edge_id,
            findings_path=args.findings,
            finding_key=args.finding_key,
        )
    except Exception as e:
        _log_cli_error("stale-drift failed", e)
        return 1

    print(render_stale_drift_summary(summary))
    return 0


def _cmd_replay_findings(args: argparse.Namespace) -> int:
    """Execute the replay-findings command."""
    try:
        from iamscope.reasoner.replay import run_reasoners_on_frozen_artifacts

        pattern_ids, error = _resolve_reasoner_set(args.reasoners)
        if error is not None:
            logger.error("--reasoners: %s", error)
            return 1
        instances = tuple(_AVAILABLE_REASONER_FACTORIES[pid]() for pid in pattern_ids)
        result = run_reasoners_on_frozen_artifacts(
            scenario_path=args.scenario,
            binding_metadata_path=args.binding_metadata,
            probe_overlay_path=args.probe_overlay,
            reasoner_instances=instances,
            reasoning_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        Path(args.output).write_bytes(result.findings_bytes)
    except Exception as e:
        _log_cli_error("replay-findings failed", e)
        return 1

    print(f"Wrote {args.output}")
    print(f"Scenario hash: {result.scenario_hash}")
    print(f"Findings: {len(result.findings)}")
    print(f"Findings hash: {result.findings_hash}")
    return 0


def _cmd_probe_overlay(args: argparse.Namespace) -> int:
    """Execute the probe-overlay command."""
    try:
        from iamscope.truth.probe_runner import build_probe_overlay_from_paths

        overlay = build_probe_overlay_from_paths(
            scenario_path=args.scenario,
            plan_path=args.plan,
            output_path=args.output,
            engagement_run_id=args.engagement_run_id,
            default_profile=args.profile_name,
            default_region=args.region_name,
            respect_confounders=args.respect_confounders,
        )
    except Exception as e:
        _log_cli_error("probe-overlay failed", e)
        return 1

    print(f"Wrote {args.output}")
    print(f"Engagement run: {overlay.engagement_run_id}")
    print(f"Probes: {len(overlay.probes)}")
    return 0


def _cmd_collect(args: argparse.Namespace) -> int:
    """Execute the collect command."""
    config = PipelineConfig(
        profile_name=args.profile_name,
        region_name=args.region_name,
        collection_role_name=args.role_name,
        external_id=args.external_id,
        standalone=args.standalone,
        include_service_linked=args.include_service_linked,
        include_aws_managed=args.include_aws_managed,
        global_expansion_mode=args.expansion_mode,
        passrole_mode=args.passrole_mode,
        lambda_mode=args.lambda_mode,
        ec2_mode=args.ec2_mode,
    )

    # Parse and validate account filters
    if args.account_filter:
        config.account_filter = set()
        for a in args.account_filter.split(","):
            a = a.strip()
            if not a:
                continue
            if not (len(a) == 12 and a.isdigit()):
                logger.error("Invalid account ID: %r (must be 12 digits)", a)
                return 1
            config.account_filter.add(a)
    if args.skip_accounts:
        config.skip_accounts = set()
        for a in args.skip_accounts.split(","):
            a = a.strip()
            if not a:
                continue
            if not (len(a) == 12 and a.isdigit()):
                logger.error("Invalid account ID: %r (must be 12 digits)", a)
                return 1
            config.skip_accounts.add(a)

    # Create session
    try:
        session = get_session(
            profile_name=config.profile_name,
            region_name=config.region_name,
        )
    except Exception as e:
        _log_cli_error("Failed to create AWS session", e)
        return 1

    # Run pipeline
    try:
        result = run_pipeline(session, config)
    except Exception as e:
        _log_cli_error("Pipeline failed", e)
        return 1

    # Write outputs
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_outputs(output_dir, result)

    # S14: reasoner phase. Constructs a FactGraph from the pipeline's
    # structured outputs, runs the requested reasoners, applies any
    # post-processors, and emits findings.json. Returns None if
    # --no-findings was set or a fatal arg-validation error occurred.
    findings_result = _run_reasoners_and_emit(result, args)
    if findings_result is not None:
        findings_bytes, findings_hash, _count, _ran, _skipped = findings_result
        _write_findings(output_dir, findings_bytes, findings_hash)
    elif args.reasoners is not None and not args.no_findings:
        # An invalid --reasoners value was passed; the helper logged
        # the error. Exit non-zero.
        return 1

    _print_summary(result, findings_result)

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Execute the report command."""
    from iamscope.report.generator import generate_report_from_files

    # Resolve the findings path: explicit --findings wins; otherwise
    # auto-discover a sibling findings.json in the scenario's directory
    # (unless --no-auto-findings was set). This matches the default
    # `iamscope collect` output layout, which writes all three sidecar
    # files to the same directory.
    findings_path: str | None = None
    if args.findings:
        findings_path = args.findings
    elif not args.no_auto_findings:
        sibling = Path(args.scenario).parent / "findings.json"
        if sibling.exists():
            findings_path = str(sibling)
            logger.info("Auto-discovered findings.json at %s", sibling)

    try:
        report = generate_report_from_files(
            scenario_path=args.scenario,
            binding_metadata_path=args.binding_metadata,
            enrichment_path=args.enrichment,
            findings_path=findings_path,
        )
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 1
    except Exception as e:
        _log_cli_error("Report generation failed", e)
        return 1

    if args.output_path:
        Path(args.output_path).write_text(report)
        logger.info("Wrote report to %s", args.output_path)
    else:
        print(report)

    return 0


def _cmd_enrich(args: argparse.Namespace) -> int:
    """Execute the enrich command."""
    import json as _json

    from iamscope.constants import (
        ENRICHMENT_CONFIDENCE_COMPROMISED,
        ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED,
    )
    from iamscope.enrichment.ghostgates import (
        enrich_scenario,
        enrichment_to_binding_metadata,
        load_ghostgates_report,
    )

    try:
        with open(args.scenario) as f:
            scenario = _json.load(f)
        ghostgates_report = load_ghostgates_report(args.ghostgates)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 1

    results = enrich_scenario(scenario, ghostgates_report)
    entries = enrichment_to_binding_metadata(results)

    output_path = Path(args.output_path)
    output_path.write_text(_json.dumps(entries, indent=2, sort_keys=True))
    logger.info(
        "Wrote %d enrichment entries to %s",
        len(entries),
        output_path,
    )

    compromised = sum(1 for r in results if r.enrichment_confidence == ENRICHMENT_CONFIDENCE_COMPROMISED)
    validated = sum(1 for r in results if r.enrichment_confidence == ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED)
    print(f"GhostGates enrichment: {len(results)} edges enriched ({compromised} compromised, {validated} validated)")

    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """Execute the diff command."""
    import json as _json

    from iamscope.diff import diff_scenarios_from_files, format_diff_report

    try:
        result = diff_scenarios_from_files(args.before, args.after)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 1
    except Exception as e:
        _log_cli_error("Diff failed", e)
        return 1

    output = _json.dumps(result.to_dict(), indent=2, sort_keys=True) if args.json_output else format_diff_report(result)

    if args.output_path:
        Path(args.output_path).write_text(output)
        logger.info("Wrote diff to %s", args.output_path)
    else:
        print(output)

    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    """Execute the validate command."""
    import json as _json

    from iamscope.validate import validate_scenario

    try:
        with open(args.scenario) as f:
            scenario = _json.load(f)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 1
    except _json.JSONDecodeError as e:
        logger.error("Invalid JSON: %s", e)
        return 1

    errors = validate_scenario(scenario)
    if errors:
        print(f"Validation FAILED — {len(errors)} error(s):")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Validation PASSED — scenario.json is structurally valid.")
    return 0


def _cmd_why(args: argparse.Namespace) -> int:
    """Explain why a specific finding was emitted with the verdict it got."""
    import json as _json

    from iamscope.why import (
        explain_finding,
        format_disambiguation_list,
        locate_finding,
        should_use_color,
    )

    # Load findings.json
    try:
        with open(args.findings_path) as f:
            data = _json.load(f)
    except FileNotFoundError:
        logger.error(
            "findings.json not found at %s. Run `iamscope collect` first or pass --findings <path>.",
            args.findings_path,
        )
        return 1
    except _json.JSONDecodeError as e:
        logger.error("Invalid JSON in %s: %s", args.findings_path, e)
        return 1

    findings = data.get("findings", [])
    if not findings:
        print(f"No findings in {args.findings_path}.")
        return 0

    # Locate the finding
    matches, error = locate_finding(
        findings,
        finding_id=args.finding_id,
        pattern_id=args.pattern_id,
        source_arn=args.source_arn,
        target_arn=args.target_arn,
    )
    use_color = should_use_color(args.no_color)

    if error is not None:
        print(error)
        if args.finding_id is None and args.pattern_id is None:
            print()
            print("Available findings:")
            print(format_disambiguation_list(findings[:10], use_color=use_color))
        return 1

    if len(matches) > 1:
        print(format_disambiguation_list(matches, use_color=use_color))
        return 1

    # Exactly one match — render the explanation
    explanation = explain_finding(
        matches[0],
        verbose=args.verbose,
        use_color=use_color,
    )
    print(explanation)
    return 0


def _resolve_reasoner_set(
    reasoners_arg: str | None,
) -> tuple[list[str], str | None]:
    """Parse the --reasoners CLI flag into a validated list of pattern_ids.

    Returns (pattern_ids, error_message). If error_message is non-None,
    the caller should log it and exit 1. The pattern_ids list preserves
    insertion order so registry registration order is predictable.

    Behavior:
    - None (flag not specified) → all available reasoners, in factory dict order
    - "" (empty string) → empty list (no reasoners run, empty findings.json)
    - "a,b" → validated subset preserving comma order
    - any unknown pattern_id → returns error message
    """
    if reasoners_arg is None:
        return list(_AVAILABLE_REASONER_FACTORIES.keys()), None
    if reasoners_arg == "":
        return [], None
    requested = [s.strip() for s in reasoners_arg.split(",") if s.strip()]
    unknown = [r for r in requested if r not in _AVAILABLE_REASONER_FACTORIES]
    if unknown:
        return [], (
            f"unknown reasoner pattern_id(s): {sorted(unknown)}. Available: {sorted(_AVAILABLE_REASONER_FACTORIES)}"
        )
    return requested, None


def _demote_validated_findings(findings: list[Finding]) -> list[Finding]:
    """Apply --assume-no-session-policies post-processor.

    Per plan §4B.4: IAMScope cannot see AWS session policies at
    collection time. By default, passrole_lambda VALIDATED findings
    carry an `Assumption(kind="session_policy", ...)` for audit
    visibility but remain VALIDATED. This post-processor converts the
    session-policy assumption into a `condition_context` assumption,
    which forces the verdict to INCONCLUSIVE per the §3.4 invariant
    on the Finding dataclass.

    Severity is dropped to medium per the plan's design intent for
    pedantic-mode demotion: "the chain MIGHT work but we cannot
    confirm without inspecting session policies the collector cannot
    see."

    Implementation note: Finding is a frozen dataclass, so demotion
    rebuilds the Finding via the constructor with the new verdict,
    severity, assumptions tuple, and exit reason. All other fields
    pass through unchanged. The new finding gets a new finding_id
    because the verdict and assumptions are part of the canonical
    finding identity.

    Only applies to passrole_lambda findings; other reasoners are
    passed through unchanged.
    """
    out: list[Finding] = []
    pedantic_assumption = Assumption(
        kind=ASSUMPTION_KIND_CONDITION_CONTEXT,
        detail=(
            "--assume-no-session-policies flag set; session policies "
            "cannot be verified at collection time, so any chain that "
            "relies on the absence of a session-policy block is "
            "treated as inconclusive"
        ),
    )
    for f in findings:
        if f.pattern_id != PassRoleLambdaReasoner.pattern_id or f.verdict is not Verdict.VALIDATED:
            out.append(f)
            continue
        # Drop the existing session_policy assumption (it's redundant
        # now that we're adding the stricter condition_context one)
        # and add the pedantic assumption.
        kept_assumptions = tuple(a for a in f.assumptions if a.kind != "session_policy")
        new_assumptions = kept_assumptions + (pedantic_assumption,)
        demoted = Finding(
            pattern_id=f.pattern_id,
            pattern_version=f.pattern_version,
            source=f.source,
            target=f.target,
            verdict=Verdict.INCONCLUSIVE,
            severity=SEVERITY_MEDIUM,
            title=f.title,
            required_checks=f.required_checks,
            blockers_observed=f.blockers_observed,
            assumptions=new_assumptions,
            evidence=f.evidence,
            scenario_hash=f.scenario_hash,
            reasoner_exit_reason=("demoted to inconclusive by --assume-no-session-policies"),
        )
        out.append(demoted)
    return out


def _run_reasoners_and_emit(
    result: PipelineResult,
    args: argparse.Namespace,
) -> tuple[bytes, str, int, list[str], dict[str, str]] | None:
    """Run reasoners against the assembled fact graph and emit findings.json bytes.

    Returns None if `--no-findings` was set OR if a fatal error occurred
    (caller should still treat None as "no findings file"). On success,
    returns a tuple of (bytes, canonical_hash, count, run_pattern_ids,
    skipped_dict) for downstream summary printing.

    The five steps:
    1. Resolve `--reasoners` into a validated pattern_id list
    2. Construct a `FactGraph` from the structured pipeline data
    3. Build a Registry, register each reasoner, introspect preconditions
       to compute reasoners_skipped, then run_all
    4. Optionally post-process for --assume-no-session-policies
    5. Build reasoners_used dict, emit findings.json bytes
    """
    if args.no_findings:
        return None

    pattern_ids, error = _resolve_reasoner_set(args.reasoners)
    if error is not None:
        logger.error("--reasoners: %s", error)
        return None

    probe_records_by_edge: dict[str, tuple[ProbeRecord, ...]] = {}
    probe_overlay_path = getattr(args, "probe_overlay", None)
    if probe_overlay_path:
        from iamscope.output.probe_overlay_json import load_probe_overlay

        overlay = load_probe_overlay(probe_overlay_path)
        if overlay.scenario_canonical_hash != result.canonical_hash:
            logger.error("--probe-overlay scenario_canonical_hash does not match the collected scenario canonical hash")
            return None
        known_edge_ids = {edge.edge_id for edge in result.edges}
        tmp_probe_records: dict[str, list[ProbeRecord]] = {}
        for probe in overlay.probes:
            if probe.edge_id not in known_edge_ids:
                logger.error(
                    "--probe-overlay references unknown edge_id %s",
                    probe.edge_id,
                )
                return None
            tmp_probe_records.setdefault(probe.edge_id, []).append(probe)
        probe_records_by_edge = {
            edge_id: tuple(sorted(records, key=lambda p: (p.probed_at_utc, p.probe_id)))
            for edge_id, records in tmp_probe_records.items()
        }

    # Build the FactGraph from the pipeline's structured outputs.
    facts = FactGraph(
        nodes=tuple(result.nodes),
        edges=tuple(result.edges),
        constraints=tuple(result.constraints),
        edge_constraints=tuple(result.edge_constraints),
        scenario_hash=result.canonical_hash,
        edge_budget_exhausted=result.edge_budget_exhausted,
        probe_records_by_edge=probe_records_by_edge,
    )

    # Build the registry and instantiate each requested reasoner.
    registry = Registry()
    instances: list[Reasoner] = []
    for pid in pattern_ids:
        instance = _AVAILABLE_REASONER_FACTORIES[pid]()
        registry.register(instance)
        instances.append(instance)

    # Introspect preconditions BEFORE run_all so we can build the
    # reasoners_skipped dict for the metadata block. Registry.run_all
    # silently skips reasoners whose preconditions_met returns False;
    # we duplicate the check here so the skip reasons can be surfaced
    # in findings.json metadata for the rebuttal-meeting workflow.
    reasoners_skipped: dict[str, str] = {}
    for instance in instances:
        try:
            ran, reason = instance.preconditions_met(facts)
            if not ran:
                reasoners_skipped[instance.pattern_id] = f"preconditions_not_met: {reason}"
        except Exception as e:  # noqa: BLE001
            reasoners_skipped[instance.pattern_id] = f"precondition_check_error: {type(e).__name__}: {e}"

    reasoning_start = time.monotonic()
    findings = registry.run_all(facts)
    reasoning_duration = time.monotonic() - reasoning_start

    findings = apply_cross_reasoner_demotions(findings)

    if args.assume_no_session_policies:
        findings = _demote_validated_findings(findings)

    reasoners_used: dict[str, dict[str, str]] = {
        instance.pattern_id: {
            "version": instance.pattern_version,
            "title": instance.pattern_title,
        }
        for instance in instances
    }

    findings_bytes, findings_hash = emit_findings(
        findings,
        scenario_hash=result.canonical_hash,
        reasoners_used=reasoners_used,
        reasoners_skipped=reasoners_skipped or None,
        reasoning_timestamp=time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        reasoning_duration_seconds=reasoning_duration,
    )

    return (
        findings_bytes,
        findings_hash,
        len(findings),
        pattern_ids,
        reasoners_skipped,
    )


def _write_findings(
    output_dir: Path,
    findings_bytes: bytes,
    findings_hash: str,
) -> None:
    """Write findings.json sidecar to the output directory."""
    findings_path = output_dir / "findings.json"
    findings_path.write_bytes(findings_bytes)
    logger.info(
        "Wrote %s (%d bytes, hash=%s)",
        findings_path,
        len(findings_bytes),
        findings_hash[:12],
    )


def _write_outputs(output_dir: Path, result: PipelineResult) -> None:
    """Write scenario.json and binding_metadata.json to output directory."""
    scenario_path = output_dir / "scenario.json"
    scenario_path.write_bytes(result.scenario_bytes)
    logger.info("Wrote %s (%d bytes)", scenario_path, len(result.scenario_bytes))

    if result.binding_metadata_bytes and result.binding_metadata_bytes != b"[]":
        binding_path = output_dir / "binding_metadata.json"
        binding_path.write_bytes(result.binding_metadata_bytes)
        logger.info("Wrote %s", binding_path)


def _print_summary(
    result: PipelineResult,
    findings_result: tuple[bytes, str, int, list[str], dict[str, str]] | None = None,
) -> None:
    """Print collection summary to stdout."""
    print(f"\n{'=' * 60}")
    print("IAMScope Collection Complete")
    print(f"{'=' * 60}")
    print(f"Accounts collected: {result.accounts_collected}")
    print(f"Accounts skipped:   {result.accounts_skipped}")
    print(f"Nodes:              {result.total_nodes}")
    print(f"Edges:              {result.total_edges}")
    print(f"Constraints:        {result.total_constraints}")
    print(f"Edge constraints:   {result.total_edge_constraints}")
    print(f"Canonical hash:     {result.canonical_hash}")
    print(f"Duration:           {result.duration_seconds:.1f}s")
    if findings_result is not None:
        _, findings_hash, count, ran, skipped = findings_result
        print(f"{'-' * 60}")
        print(f"Findings:           {count}")
        print(f"Reasoners run:      {','.join(ran) if ran else '(none)'}")
        if skipped:
            for pid, reason in sorted(skipped.items()):
                print(f"  skipped: {pid}: {reason}")
        print(f"Findings hash:      {findings_hash}")
    print(f"{'=' * 60}")


def _setup_logging(verbose: int, quiet: bool) -> None:
    """Configure logging based on verbosity flags."""
    if quiet:
        level = logging.ERROR
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy boto3/botocore logging
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def cli_entry() -> None:
    """Console script entry point (called by setuptools)."""
    sys.exit(main())


if __name__ == "__main__":
    cli_entry()
