#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f ".venv/bin/activate" && -z "${VIRTUAL_ENV:-}" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

python -m benchmarks.runtime.sts_probe_executor "$@"
