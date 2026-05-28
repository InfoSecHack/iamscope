#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate

ENV03_ARCHIVE=""
ENV05_ARCHIVE=""
ENV06_ARCHIVE=""
ENV07_ARCHIVE=""
ENV08_ARCHIVE=""
ENV09_ARCHIVE=""
ENV10_ARCHIVE=""
ENV11_ARCHIVE=""
ENV12_ARCHIVE=""
ENV13_ARCHIVE=""
ENV14_ARCHIVE=""
ENV15_ARCHIVE=""
ENV16_ARCHIVE=""
ENV17_ARCHIVE=""
ENV18_ARCHIVE=""
ENV19_ARCHIVE=""
ENV20_ARCHIVE=""
ENV21_ARCHIVE=""
ENV22_ARCHIVE=""
ENV23_ARCHIVE=""
ENV24_ARCHIVE=""
ENV25_ARCHIVE=""
ENV26_ARCHIVE=""
ENV27_ARCHIVE=""
OUT_ROOT="benchmarks/runs"
CORPUS_OUT="benchmarks/corpus-runs/phase0-latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env03-archive)
      ENV03_ARCHIVE="$2"
      shift 2
      ;;
    --env05-archive)
      ENV05_ARCHIVE="$2"
      shift 2
      ;;
    --env06-archive)
      ENV06_ARCHIVE="$2"
      shift 2
      ;;
    --env07-archive)
      ENV07_ARCHIVE="$2"
      shift 2
      ;;
    --env08-archive)
      ENV08_ARCHIVE="$2"
      shift 2
      ;;
    --env09-archive)
      ENV09_ARCHIVE="$2"
      shift 2
      ;;
    --env10-archive)
      ENV10_ARCHIVE="$2"
      shift 2
      ;;
    --env11-archive)
      ENV11_ARCHIVE="$2"
      shift 2
      ;;
    --env12-archive)
      ENV12_ARCHIVE="$2"
      shift 2
      ;;
    --env13-archive)
      ENV13_ARCHIVE="$2"
      shift 2
      ;;
    --env14-archive)
      ENV14_ARCHIVE="$2"
      shift 2
      ;;
    --env15-archive)
      ENV15_ARCHIVE="$2"
      shift 2
      ;;
    --env16-archive)
      ENV16_ARCHIVE="$2"
      shift 2
      ;;
    --env17-archive)
      ENV17_ARCHIVE="$2"
      shift 2
      ;;
    --env18-archive)
      ENV18_ARCHIVE="$2"
      shift 2
      ;;
    --env19-archive)
      ENV19_ARCHIVE="$2"
      shift 2
      ;;
    --env20-archive)
      ENV20_ARCHIVE="$2"
      shift 2
      ;;
    --env21-archive)
      ENV21_ARCHIVE="$2"
      shift 2
      ;;
    --env22-archive)
      ENV22_ARCHIVE="$2"
      shift 2
      ;;
    --env23-archive)
      ENV23_ARCHIVE="$2"
      shift 2
      ;;
    --env24-archive)
      ENV24_ARCHIVE="$2"
      shift 2
      ;;
    --env25-archive)
      ENV25_ARCHIVE="$2"
      shift 2
      ;;
    --env26-archive)
      ENV26_ARCHIVE="$2"
      shift 2
      ;;
    --env27-archive)
      ENV27_ARCHIVE="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      shift 2
      ;;
    --corpus-out)
      CORPUS_OUT="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ENV03_ARCHIVE" && -z "$ENV05_ARCHIVE" && -z "$ENV06_ARCHIVE" && -z "$ENV07_ARCHIVE" && -z "$ENV08_ARCHIVE" && -z "$ENV09_ARCHIVE" && -z "$ENV10_ARCHIVE" && -z "$ENV11_ARCHIVE" && -z "$ENV12_ARCHIVE" && -z "$ENV13_ARCHIVE" && -z "$ENV14_ARCHIVE" && -z "$ENV15_ARCHIVE" && -z "$ENV16_ARCHIVE" && -z "$ENV17_ARCHIVE" && -z "$ENV18_ARCHIVE" && -z "$ENV19_ARCHIVE" && -z "$ENV20_ARCHIVE" && -z "$ENV21_ARCHIVE" && -z "$ENV22_ARCHIVE" && -z "$ENV23_ARCHIVE" && -z "$ENV24_ARCHIVE" && -z "$ENV25_ARCHIVE" && -z "$ENV26_ARCHIVE" && -z "$ENV27_ARCHIVE" ]]; then
  echo "at least one of --env03-archive, --env05-archive, --env06-archive, --env07-archive, --env08-archive, --env09-archive, --env10-archive, --env11-archive, --env12-archive, --env13-archive, --env14-archive, --env15-archive, --env16-archive, --env17-archive, --env18-archive, --env19-archive, --env20-archive, --env21-archive, --env22-archive, --env23-archive, --env24-archive, --env25-archive, --env26-archive, or --env27-archive is required" >&2
  exit 2
fi

mkdir -p "$OUT_ROOT"

materialize_case() {
  local short_name="$1"
  local case_id="$2"
  local archive_path="$3"

  if [[ -z "$archive_path" ]]; then
    echo "omitted ${short_name}: no archive supplied"
    return 0
  fi
  if [[ ! -d "$archive_path" ]]; then
    echo "missing archive directory for ${short_name}: $archive_path" >&2
    return 1
  fi

  local archive_basename
  archive_basename="$(basename "$archive_path")"
  local run_id="$archive_basename"
  local prefix="iamscope-benchmark-${short_name}-"
  if [[ "$archive_basename" == "$prefix"* ]]; then
    run_id="${archive_basename#${prefix}}"
  fi
  local out_dir="${OUT_ROOT}/${short_name}-${run_id}"

  echo "evaluating ${short_name}: archive=${archive_path} -> out=${out_dir}"
  bash scripts/evaluate_benchmark_archive.sh \
    --case-id "$case_id" \
    --archive-dir "$archive_path" \
    --out-dir "$out_dir"
}

materialize_case "env03" "env03_identity_deny_group_escalation" "$ENV03_ARCHIVE"
materialize_case "env05" "env05_permission_boundary_blocked_chain" "$ENV05_ARCHIVE"
materialize_case "env06" "env06_validated_admin_reachability" "$ENV06_ARCHIVE"
materialize_case "env07" "env07_validated_non_admin_reachability" "$ENV07_ARCHIVE"
materialize_case "env08" "env08_trust_condition_blocked_admin" "$ENV08_ARCHIVE"
materialize_case "env09" "env09_boundary_removed_validated_admin" "$ENV09_ARCHIVE"
materialize_case "env10" "env10_trust_condition_removed_validated_admin" "$ENV10_ARCHIVE"
materialize_case "env11" "env11_broad_trust_condition_blocked_admin" "$ENV11_ARCHIVE"
materialize_case "env12" "env12_scp_blocked_assumerole" "$ENV12_ARCHIVE"
materialize_case "env13" "env13_complete_scp_blocked_assumerole" "$ENV13_ARCHIVE"
materialize_case "env14" "env14_permission_condition_blocked_admin" "$ENV14_ARCHIVE"
materialize_case "env15" "env15_permission_condition_removed_validated_admin" "$ENV15_ARCHIVE"
materialize_case "env16" "env16_identity_deny_removed_validated_group_escalation" "$ENV16_ARCHIVE"
materialize_case "env17" "env17_scp_removed_validated_admin" "$ENV17_ARCHIVE"
materialize_case "env18" "env18_lambda_passrole_validated" "$ENV18_ARCHIVE"
materialize_case "env19" "env19_passedtoservice_scoped_away_nonvalidated" "$ENV19_ARCHIVE"
materialize_case "env20" "env20_ecs_passrole_validated" "$ENV20_ARCHIVE"
materialize_case "env21" "env21_ecs_passedtoservice_scoped_away_nonvalidated" "$ENV21_ARCHIVE"
materialize_case "env22" "env22_cross_account_validated_admin" "$ENV22_ARCHIVE"
materialize_case "env23" "env23_cross_account_trust_scoped_away_nonvalidated" "$ENV23_ARCHIVE"
materialize_case "env24" "env24_s3_resource_policy_allow" "$ENV24_ARCHIVE"
materialize_case "env25" "env25_s3_resource_policy_allow_scoped_away_nonvalidated" "$ENV25_ARCHIVE"
materialize_case "env26" "env26_multihop_chain_validated_admin" "$ENV26_ARCHIVE"
materialize_case "env27" "env27_multihop_trust_scoped_away_nonvalidated" "$ENV27_ARCHIVE"

echo "summarizing corpus: runs=${OUT_ROOT} -> out=${CORPUS_OUT}"
bash scripts/summarize_benchmark_corpus.sh \
  --runs-dir "$OUT_ROOT" \
  --out-dir "$CORPUS_OUT"

echo "materialized_runs_root=${OUT_ROOT}"
echo "corpus_summary=$(realpath "$CORPUS_OUT/corpus_summary.json")"
echo "promotion_decision=$(realpath "$CORPUS_OUT/promotion_decision.json")"
echo "corpus_report=$(realpath "$CORPUS_OUT/corpus_report.md")"
