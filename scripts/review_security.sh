#!/usr/bin/env bash
set -euo pipefail

source .venv/bin/activate

TARGETS=(iamscope tests)

printf '\n[1/3] Bandit scan\n'
if command -v bandit >/dev/null 2>&1; then
  bandit -q -r "${TARGETS[@]}"
else
  echo 'bandit not installed in the active environment; skipping Bandit scan.'
fi

printf '\n[2/3] Heuristic grep checks\n'
PATTERNS=(
  'subprocess\.(Popen|run|call)\('
  'yaml\.load\('
  'pickle\.loads?\('
  '(^|[^[:alnum:]_])eval\('
  '(^|[^[:alnum:]_])exec\('
  'shell=True'
  'verify=False'
)

for pattern in "${PATTERNS[@]}"; do
  echo "-- checking pattern: ${pattern}"
  grep -RInE "${pattern}" "${TARGETS[@]}" || true
done

printf '\n[3/3] Reminder\n'
echo 'Review authz, secrets handling, logging, and untrusted-input flows manually for critical features.'