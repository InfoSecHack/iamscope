#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

pass() {
  echo "PASS: $*"
}

tracked_files=()
while IFS= read -r -d '' path; do
  tracked_files+=("$path")
done < <(git ls-files -z)

terraform_artifacts=()
snapshot_raw_artifacts=()
cr_filenames=()

for path in "${tracked_files[@]}"; do
  basename="${path##*/}"

  if [[ "$path" == *$'\r'* ]]; then
    cr_filenames+=("$path")
  fi

  case "$path" in
    */.terraform/*|.terraform/*|*/terraform.tfstate|terraform.tfstate|*/terraform.tfstate.backup|terraform.tfstate.backup|*.tfplan|*/terraform.tfvars|terraform.tfvars|*/terraform-provider-*|terraform-provider-*)
      terraform_artifacts+=("$path")
      ;;
  esac

  if [[ "$path" == benchmarks/snapshots/* ]]; then
    case "$path" in
      */collect/*|*/archives/*|*/archive/*|*/iamscope-benchmark-*/*)
        snapshot_raw_artifacts+=("$path")
        ;;
    esac
    case "$basename" in
      scenario.json|findings.json|binding_metadata.json|run.log)
        snapshot_raw_artifacts+=("$path")
        ;;
    esac
  fi
done

gitlinks=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  gitlinks+=("$line")
done < <(git ls-files -s | awk '$1 == "160000" {print}')

if ((${#terraform_artifacts[@]} > 0)); then
  fail "tracked Terraform state/cache/provider artifacts found"
  printf '  %s\n' "${terraform_artifacts[@]}"
else
  pass "no tracked Terraform state/cache/provider artifacts"
fi

if ((${#snapshot_raw_artifacts[@]} > 0)); then
  fail "tracked benchmark snapshot raw live artifacts found"
  printf '  %s\n' "${snapshot_raw_artifacts[@]}"
else
  pass "no tracked raw live artifacts in benchmark snapshots"
fi

if ((${#gitlinks[@]} > 0)); then
  fail "tracked gitlinks/submodules found"
  printf '  %s\n' "${gitlinks[@]}"
else
  pass "no tracked gitlinks/submodules"
fi

if ((${#cr_filenames[@]} > 0)); then
  fail "tracked filenames contain carriage returns"
  printf '  %q\n' "${cr_filenames[@]}"
else
  pass "no tracked filenames contain carriage returns"
fi

if ((failures > 0)); then
  echo "Benchmark artifact hygiene check failed with ${failures} issue group(s)."
  exit 1
fi

echo "Benchmark artifact hygiene check passed."
