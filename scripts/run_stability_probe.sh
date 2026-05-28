#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate

CASE=""
RUNS=""
OUT_DIR=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_stability_probe.sh --case env03 --runs 3 --out-dir /tmp/iamscope-stability-env03

Supported cases:
  env03  Identity-deny blocked group escalation
  env05  Permission-boundary blocked assume-role/admin chain
  env06  Positive admin reachability
  env07  Non-admin structural/no-false-admin
  env18  Lambda PassRole validated
  env19  Lambda PassRole PassedToService scoped away
  env20  ECS PassRole validated
  env21  ECS PassRole PassedToService scoped away
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case)
      CASE="$2"
      shift 2
      ;;
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$CASE" != "env03" && "$CASE" != "env05" && "$CASE" != "env06" && "$CASE" != "env07" && "$CASE" != "env18" && "$CASE" != "env19" && "$CASE" != "env20" && "$CASE" != "env21" ]]; then
  echo "ERROR: --case must be env03, env05, env06, env07, env18, env19, env20, or env21" >&2
  usage >&2
  exit 2
fi
if [[ ! "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: --runs must be a positive integer" >&2
  usage >&2
  exit 2
fi
if [[ -z "$OUT_DIR" ]]; then
  echo "ERROR: --out-dir is required" >&2
  usage >&2
  exit 2
fi

case "$CASE" in
  env03)
    RUNNER="scripts/run_env03_second_benchmark.sh"
    CASE_ID="env03_identity_deny_group_escalation"
    ;;
  env05)
    RUNNER="scripts/run_env05_first_benchmark.sh"
    CASE_ID="env05_permission_boundary_blocked_chain"
    ;;
  env06)
    RUNNER="scripts/run_env06_third_benchmark.sh"
    CASE_ID="env06_validated_admin_reachability"
    ;;
  env07)
    RUNNER="scripts/run_env07_fourth_benchmark.sh"
    CASE_ID="env07_validated_non_admin_reachability"
    ;;
  env18)
    RUNNER="scripts/run_env18_lambda_passrole_benchmark.sh"
    CASE_ID="env18_lambda_passrole_validated"
    ;;
  env19)
    RUNNER="scripts/run_env19_passedtoservice_scoped_away_benchmark.sh"
    CASE_ID="env19_passedtoservice_scoped_away_nonvalidated"
    ;;
  env20)
    RUNNER="scripts/run_env20_ecs_passrole_benchmark.sh"
    CASE_ID="env20_ecs_passrole_validated"
    ;;
  env21)
    RUNNER="scripts/run_env21_ecs_passedtoservice_scoped_away_benchmark.sh"
    CASE_ID="env21_ecs_passedtoservice_scoped_away_nonvalidated"
    ;;
esac

mkdir -p "$OUT_DIR/archives" "$OUT_DIR/evaluations"
RESULTS_JSONL="$OUT_DIR/stability_runs.jsonl"
SUMMARY_JSON="$OUT_DIR/stability_summary.json"
REPORT_MD="$OUT_DIR/stability_report.md"
: >"$RESULTS_JSONL"

classify_setup_failure() {
  local run_log="$1"
  if [[ ! -f "$run_log" ]]; then
    return 1
  fi
  grep -Eiq 'terraform (init|apply)|NoCredential|ExpiredToken|RequestLimit|Throttl|could not be found|InvalidClientTokenId' "$run_log"
}

for run_index in $(seq 1 "$RUNS"); do
  RUN_LABEL="$(printf "%02d" "$run_index")"
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-stability-${RUN_LABEL}"
  ARCHIVE_DIR="$OUT_DIR/archives/${CASE}-${RUN_ID}"
  EVAL_DIR="$OUT_DIR/evaluations/${CASE}-${RUN_ID}"
  RUN_LOG="$ARCHIVE_DIR/run.log"
  SCENARIO_JSON="$ARCHIVE_DIR/collect/scenario.json"
  FINDINGS_JSON="$ARCHIVE_DIR/collect/findings.json"
  VALIDATE_LOG="$ARCHIVE_DIR/scenario_validate.txt"

  echo "=== stability run ${run_index}/${RUNS}: case=${CASE} archive=${ARCHIVE_DIR} ==="
  set +e
  RUN_ID="$RUN_ID" IAMSCOPE_BENCHMARK_OUT="$ARCHIVE_DIR" bash "$RUNNER"
  RUN_RC="$?"
  set -e

  EVAL_RC="not_run"
  EVALUATED="false"
  if [[ -f "$RUN_LOG" && -f "$SCENARIO_JSON" && -f "$FINDINGS_JSON" && -f "$VALIDATE_LOG" ]]; then
    set +e
    bash scripts/evaluate_benchmark_archive.sh \
      --case-id "$CASE_ID" \
      --archive-dir "$ARCHIVE_DIR" \
      --out-dir "$EVAL_DIR"
    EVAL_RC="$?"
    set -e
    EVALUATED="true"
  fi

  SEMANTIC_PASS="false"
  if [[ -f "$RUN_LOG" ]] && grep -q 'benchmark semantic assertion: PASS' "$RUN_LOG"; then
    SEMANTIC_PASS="true"
  fi

  SCENARIO_VALIDATION="missing"
  if [[ -f "$VALIDATE_LOG" ]]; then
    if grep -Eiq 'PASS|PASSED' "$VALIDATE_LOG" || grep -q 'scenario validation: PASS' "$RUN_LOG"; then
      SCENARIO_VALIDATION="pass"
    elif grep -Eiq 'FAIL|FAILED' "$VALIDATE_LOG" || grep -q 'scenario validation: FAIL' "$RUN_LOG"; then
      SCENARIO_VALIDATION="fail"
    else
      SCENARIO_VALIDATION="unknown"
    fi
  fi

  COLLECTION_RUNTIME_FAILURE="false"
  if [[ ! -f "$SCENARIO_JSON" || ! -f "$FINDINGS_JSON" || "$SCENARIO_VALIDATION" != "pass" ]]; then
    COLLECTION_RUNTIME_FAILURE="true"
  fi

  AWS_TERRAFORM_SETUP_FAILURE="false"
  if [[ "$RUN_RC" != "0" ]] && classify_setup_failure "$RUN_LOG"; then
    AWS_TERRAFORM_SETUP_FAILURE="true"
  fi

  TOOL_SEMANTIC_STABILITY="not_evaluated"
  if [[ "$COLLECTION_RUNTIME_FAILURE" == "false" ]]; then
    if [[ "$RUN_RC" == "0" && "$EVAL_RC" == "0" && "$SEMANTIC_PASS" == "true" ]]; then
      TOOL_SEMANTIC_STABILITY="pass"
    else
      TOOL_SEMANTIC_STABILITY="fail"
    fi
  fi

  export CASE CASE_ID RUN_INDEX="$run_index" RUN_ID ARCHIVE_DIR EVAL_DIR RUN_RC EVAL_RC EVALUATED
  export SEMANTIC_PASS SCENARIO_VALIDATION COLLECTION_RUNTIME_FAILURE AWS_TERRAFORM_SETUP_FAILURE
  export TOOL_SEMANTIC_STABILITY
  python - "$RESULTS_JSONL" <<'PY'
import json
import os
import sys

record = {
    "case": os.environ["CASE"],
    "case_id": os.environ["CASE_ID"],
    "run_index": int(os.environ["RUN_INDEX"]),
    "run_id": os.environ["RUN_ID"],
    "archive_dir": os.environ["ARCHIVE_DIR"],
    "evaluation_dir": os.environ["EVAL_DIR"],
    "runner_rc": int(os.environ["RUN_RC"]),
    "evaluation_rc": None if os.environ["EVAL_RC"] == "not_run" else int(os.environ["EVAL_RC"]),
    "evaluated": os.environ["EVALUATED"] == "true",
    "semantic_assertion_passed": os.environ["SEMANTIC_PASS"] == "true",
    "scenario_validation": os.environ["SCENARIO_VALIDATION"],
    "tool_semantic_stability": os.environ["TOOL_SEMANTIC_STABILITY"],
    "collection_runtime_failure": os.environ["COLLECTION_RUNTIME_FAILURE"] == "true",
    "aws_terraform_setup_failure": os.environ["AWS_TERRAFORM_SETUP_FAILURE"] == "true",
}
with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\n")
PY
done

python - "$RESULTS_JSONL" "$SUMMARY_JSON" "$REPORT_MD" "$CASE" "$CASE_ID" "$RUNS" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

jsonl_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
case = sys.argv[4]
case_id = sys.argv[5]
requested_runs = int(sys.argv[6])
runs = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
tool_counts = Counter(run["tool_semantic_stability"] for run in runs)
collection_failures = sum(1 for run in runs if run["collection_runtime_failure"])
setup_failures = sum(1 for run in runs if run["aws_terraform_setup_failure"])
summary = {
    "case": case,
    "case_id": case_id,
    "requested_runs": requested_runs,
    "completed_run_records": len(runs),
    "tool_semantic_stability": {
        "pass": tool_counts.get("pass", 0),
        "fail": tool_counts.get("fail", 0),
        "not_evaluated": tool_counts.get("not_evaluated", 0),
    },
    "collection_runtime_failures": collection_failures,
    "aws_terraform_setup_failures": setup_failures,
    "all_runs_semantically_stable": len(runs) == requested_runs and tool_counts.get("pass", 0) == requested_runs,
    "no_composite_score": True,
    "runs": runs,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    f"# Benchmark Stability Probe: {case}",
    "",
    "This report covers repeated live runs for one existing benchmark case only. It is not a composite score and does not claim broad IAMScope stability.",
    "",
    "## Summary",
    f"- Case ID: `{case_id}`",
    f"- Requested runs: `{requested_runs}`",
    f"- Run records: `{len(runs)}`",
    f"- Tool semantic stability pass: `{tool_counts.get('pass', 0)}`",
    f"- Tool semantic stability fail: `{tool_counts.get('fail', 0)}`",
    f"- Not evaluated: `{tool_counts.get('not_evaluated', 0)}`",
    f"- Collection/runtime failures: `{collection_failures}`",
    f"- AWS/Terraform setup failures: `{setup_failures}`",
    "",
    "## Category Definitions",
    "- Tool semantic stability: artifacts existed, scenario validation/evaluation ran, and target semantic assertions passed.",
    "- Collection/runtime failure: expected runtime artifacts or scenario validation were missing/failing.",
    "- AWS/Terraform setup failure: the run log indicates setup/auth/provider/throttling failure before stable semantic judgment.",
    "",
    "## Runs",
]
for run in runs:
    lines.append(
        f"- Run {run['run_index']}: semantic=`{run['tool_semantic_stability']}`, "
        f"runner_rc=`{run['runner_rc']}`, evaluation_rc=`{run['evaluation_rc']}`, "
        f"scenario_validation=`{run['scenario_validation']}`, archive=`{run['archive_dir']}`"
    )
lines.extend(
    [
        "",
        "## What Not To Conclude",
        "- Do not conclude broad benchmark stability from this one case.",
        "- Do not treat AWS/Terraform setup failures as IAMScope semantic failures.",
        "- Do not collapse these categories into one score.",
    ]
)
report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "stability_summary=$SUMMARY_JSON"
echo "stability_report=$REPORT_MD"
