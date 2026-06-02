#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_path_overcounting_shared_uncertainty_demo.sh [--out PATH]

Run the local-only IAMScope path-overcounting demo summary.

Default output: /tmp/iamscope-path-overcounting-demo
EOF
}

OUT_DIR=/tmp/iamscope-path-overcounting-demo
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      if [[ $# -lt 2 ]]; then
        echo "error: --out requires a path" >&2
        exit 2
      fi
      OUT_DIR=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/demo/path_overcounting_shared_uncertainty"
OUT_ABS=$(python -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUT_DIR")
REPO_ABS=$(python -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$REPO_ROOT")

case "$OUT_ABS" in
  "$REPO_ABS"|"$REPO_ABS"/*)
    echo "error: refusing to write demo outputs inside the repository tree: $OUT_ABS" >&2
    echo "choose /tmp or another scratch directory" >&2
    exit 2
    ;;
esac

mkdir -p "$OUT_ABS"

python - "$FIXTURE_DIR" "$OUT_ABS" <<'PY'
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

fixture_dir = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

naive = json.loads((fixture_dir / "naive_candidates.json").read_text())
findings_doc = json.loads((fixture_dir / "findings.json").read_text())
groups_doc = json.loads((fixture_dir / "expected_uncertainty_groups.json").read_text())
binding = json.loads((fixture_dir / "binding_metadata.json").read_text())

candidate_count = len(naive["candidate_paths"])
findings = findings_doc["findings"]
verdicts = Counter(finding["verdict"] for finding in findings)
ordered_verdicts = {
    "validated": verdicts.get("validated", 0),
    "blocked": verdicts.get("blocked", 0),
    "precondition_only": verdicts.get("precondition_only", 0),
    "inconclusive": verdicts.get("inconclusive", 0),
}
groups = {
    group["uncertainty_class"]: len(group["finding_ids"])
    for group in groups_doc["groups"]
}
primary_class = "shared_passrole_target_resource_scope_unknown"
replay_status = findings_doc["replay_equivalence_status"]
replay_status_human = replay_status.replace("_", " ")
replay_reason = binding["findings_generation"]["replay_equivalence_gap"]
findings_mode = findings_doc["generation_mode"].replace("_", " ")
generated_or_replayed = bool(findings_doc["metadata"].get("generated_or_replayed_by_iamscope", False))
stronger_claims_allowed = bool(findings_doc["metadata"].get("stronger_demo_claims_allowed", False))
aws_calls_made = int(bool(findings_doc["metadata"].get("aws_calls_made", False)))
live_aws_used = bool(findings_doc["metadata"].get("live_aws_used", False))

verdict_summary = {
    "fixture_id": findings_doc["fixture_id"],
    "local_only": True,
    "naive_candidate_count": candidate_count,
    "verdict_breakdown": ordered_verdicts,
    "findings_mode": findings_doc["generation_mode"],
    "source_tool": findings_doc["source_tool"],
    "generated_or_replayed_by_iamscope": generated_or_replayed,
    "replay_equivalence_status": replay_status,
    "stronger_demo_claims_allowed": stronger_claims_allowed,
    "aws_calls_made": aws_calls_made,
    "live_aws_used": live_aws_used,
}
uncertainty_summary = {
    "fixture_id": groups_doc["fixture_id"],
    "groups": groups,
    "top_uncertainty_class": primary_class,
    "top_uncertainty_count": groups[primary_class],
    "reviewer_decision": "Do not treat all 23 as independent validated risks. Resolve the primary evidence gap first.",
}

summary = f"""# IAMScope Path Overcounting Demo Summary

IAMScope path-overcounting demo (local only)
Output: {out_dir}

## Naive interpretation

possible escalation paths: {candidate_count}

## IAMScope fixture verdicts

validated: {ordered_verdicts['validated']}
blocked: {ordered_verdicts['blocked']}
precondition_only: {ordered_verdicts['precondition_only']}
inconclusive: {ordered_verdicts['inconclusive']}

## Top uncertainty class

{primary_class}: {groups[primary_class]} inconclusive paths

## Reviewer decision

Do not treat all 23 as independent validated risks.
Resolve the primary evidence gap first.

## Replay equivalence

{replay_status_human}

reason: {replay_reason}

## Safety

AWS calls made: {aws_calls_made}
Live AWS used: {str(live_aws_used).lower()}
Findings mode: {findings_mode}
Generated/replayed by IAMScope: {str(generated_or_replayed).lower()}
Stronger demo claims allowed: {str(stronger_claims_allowed).lower()}

This is a local-only synthetic fixture summary. It is not live AWS validation, not runtime exploitability evidence, not production readiness evidence, not broad correctness evidence, and not replay-proven IAMScope reasoner output.
"""

(out_dir / "verdict-summary.json").write_text(json.dumps(verdict_summary, indent=2, sort_keys=True) + "\n")
(out_dir / "uncertainty-groups.json").write_text(json.dumps(uncertainty_summary, indent=2, sort_keys=True) + "\n")
(out_dir / "summary.md").write_text(summary)

print("IAMScope path-overcounting demo (local only)")
print(f"Output: {out_dir}")
print()
print("Naive interpretation:")
print(f"possible escalation paths: {candidate_count}")
print()
print("IAMScope fixture verdicts:")
for verdict, count in ordered_verdicts.items():
    print(f"{verdict}: {count}")
print()
print("Top uncertainty class:")
print(f"{primary_class}: {groups[primary_class]} inconclusive paths")
print()
print("Reviewer decision:")
print("Do not treat all 23 as independent validated risks.")
print("Resolve the primary evidence gap first.")
print()
print("Replay equivalence:")
print(replay_status_human)
print(f"reason: {replay_reason}")
print()
print("Safety:")
print(f"AWS calls made: {aws_calls_made}")
print(f"Live AWS used: {str(live_aws_used).lower()}")
print(f"Findings mode: {findings_mode}")
print(f"Generated/replayed by IAMScope: {str(generated_or_replayed).lower()}")
print(f"Stronger demo claims allowed: {str(stronger_claims_allowed).lower()}")
PY
