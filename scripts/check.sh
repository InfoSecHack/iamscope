#!/usr/bin/env bash
set -euo pipefail

if [[ -f ".venv/bin/activate" && -z "${VIRTUAL_ENV:-}" ]]; then
  source .venv/bin/activate
fi

bash scripts/check_benchmark_artifact_hygiene.sh
ruff format --check iamscope/ tests/
ruff check iamscope/ tests/
mypy iamscope/
