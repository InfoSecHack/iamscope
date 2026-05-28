"""Small demo-pack builder for truth-aware replay artifacts."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iamscope.findings_diff import diff_findings, format_findings_diff
from iamscope.reasoner.base import Reasoner
from iamscope.reasoner.replay import run_reasoners_on_frozen_artifacts


@dataclass(frozen=True)
class DemoPackResult:
    """Paths produced by build_demo_pack."""

    output_dir: Path
    baseline_findings_path: Path
    overlay_findings_path: Path | None
    diff_json_path: Path | None
    diff_markdown_path: Path | None
    readme_path: Path
    manifest_path: Path


def build_demo_pack(
    *,
    scenario_path: str | Path,
    binding_metadata_path: str | Path,
    probe_overlay_path: str | Path | None,
    output_dir: str | Path,
    reasoner_instances: tuple[Reasoner, ...],
    reasoner_ids: tuple[str, ...],
) -> DemoPackResult:
    """Build a reproducible folder for frozen replay plus semantic diff."""
    out = Path(output_dir)
    inputs = out / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)

    scenario_src = Path(scenario_path)
    binding_src = Path(binding_metadata_path)
    overlay_src = Path(probe_overlay_path) if probe_overlay_path is not None else None

    scenario_dst = inputs / "scenario.json"
    binding_dst = inputs / "binding_metadata.json"
    overlay_dst = inputs / "probe_overlay.json" if overlay_src is not None else None
    shutil.copyfile(scenario_src, scenario_dst)
    shutil.copyfile(binding_src, binding_dst)
    if overlay_src is not None and overlay_dst is not None:
        shutil.copyfile(overlay_src, overlay_dst)

    baseline_result = run_reasoners_on_frozen_artifacts(
        scenario_path=scenario_dst,
        binding_metadata_path=binding_dst,
        probe_overlay_path=None,
        reasoner_instances=reasoner_instances,
    )
    baseline_path = out / "findings.baseline.json"
    baseline_path.write_bytes(baseline_result.findings_bytes)

    overlay_path: Path | None = None
    diff_json_path: Path | None = None
    diff_markdown_path: Path | None = None
    diff_summary: dict[str, Any] | None = None
    if overlay_dst is not None:
        overlay_result = run_reasoners_on_frozen_artifacts(
            scenario_path=scenario_dst,
            binding_metadata_path=binding_dst,
            probe_overlay_path=overlay_dst,
            reasoner_instances=reasoner_instances,
        )
        overlay_path = out / "findings.overlay.json"
        overlay_path.write_bytes(overlay_result.findings_bytes)

        baseline_doc = json.loads(baseline_path.read_text(encoding="utf-8"))
        overlay_doc = json.loads(overlay_path.read_text(encoding="utf-8"))
        diff_result = diff_findings(baseline_doc, overlay_doc)
        diff_summary = diff_result.summary
        diff_json_path = out / "findings.diff.json"
        diff_json_path.write_text(
            json.dumps(diff_result.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        diff_markdown_path = out / "findings.diff.md"
        diff_markdown_path.write_text(
            format_findings_diff(diff_result),
            encoding="utf-8",
        )

    manifest = {
        "artifacts": {
            "baseline_findings": str(baseline_path.name),
            "binding_metadata": "inputs/binding_metadata.json",
            "diff_json": str(diff_json_path.name) if diff_json_path else None,
            "diff_markdown": str(diff_markdown_path.name) if diff_markdown_path else None,
            "overlay_findings": str(overlay_path.name) if overlay_path else None,
            "probe_overlay": "inputs/probe_overlay.json" if overlay_dst else None,
            "scenario": "inputs/scenario.json",
        },
        "claim": (
            "Frozen scenario plus probe overlay can mutate replayed findings "
            "while preserving stable semantic finding_key identity."
        ),
        "diff_summary": diff_summary,
        "reasoners": list(reasoner_ids),
        "scenario_hash": baseline_result.scenario_hash,
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    readme_path = out / "README.md"
    readme_path.write_text(_render_readme(has_overlay=overlay_dst is not None), encoding="utf-8")

    return DemoPackResult(
        output_dir=out,
        baseline_findings_path=baseline_path,
        overlay_findings_path=overlay_path,
        diff_json_path=diff_json_path,
        diff_markdown_path=diff_markdown_path,
        readme_path=readme_path,
        manifest_path=manifest_path,
    )


def _render_readme(*, has_overlay: bool) -> str:
    lines = [
        "# IAMScope Truth-Aware Replay Demo Pack",
        "",
        "This folder is a frozen-artifact proof pack. It does not recollect AWS.",
        (
            "It demonstrates the loop: frozen scenario -> optional probe "
            "overlay -> replay -> semantic diff by finding_key."
        ),
        "",
        "## Contents",
        "",
        "- `inputs/scenario.json`: frozen scenario graph",
        "- `inputs/binding_metadata.json`: frozen governance binding sidecar",
        "- `findings.baseline.json`: replayed findings without probe overlay",
    ]
    if has_overlay:
        lines.extend(
            [
                "- `inputs/probe_overlay.json`: runtime/simulator truth overlay",
                "- `findings.overlay.json`: replayed findings with probe overlay",
                "- `findings.diff.json`: machine-readable semantic diff",
                "- `findings.diff.md`: human-readable semantic diff",
            ]
        )
    lines.extend(
        [
            "- `manifest.json`: paths, reasoners, scenario hash, and diff counts",
            "",
            "## Reproduce",
            "",
            "```bash",
            "source .venv/bin/activate && iamscope replay-findings \\",
            "  --scenario inputs/scenario.json \\",
            "  --binding-metadata inputs/binding_metadata.json \\",
            "  --output findings.baseline.json",
            "```",
        ]
    )
    if has_overlay:
        lines.extend(
            [
                "",
                "```bash",
                "source .venv/bin/activate && iamscope replay-findings \\",
                "  --scenario inputs/scenario.json \\",
                "  --binding-metadata inputs/binding_metadata.json \\",
                "  --probe-overlay inputs/probe_overlay.json \\",
                "  --output findings.overlay.json",
                "```",
                "",
                "```bash",
                "source .venv/bin/activate && iamscope diff-findings \\",
                "  findings.baseline.json findings.overlay.json \\",
                "  --output findings.diff.md",
                "```",
                "",
                "Inspect a changed finding by opening `findings.diff.md`,"
                " copying the candidate finding_id, and running:",
                "",
                "```bash",
                (
                    "source .venv/bin/activate && iamscope why "
                    "--findings findings.overlay.json "
                    "--finding-id <candidate-finding-id-prefix>"
                ),
                "```",
            ]
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            (
                "Use `finding_key` for semantic diffs. `finding_id` may change "
                "when probe evidence, trace entries, or blockers are added."
            ),
        ]
    )
    return "\n".join(lines) + "\n"
