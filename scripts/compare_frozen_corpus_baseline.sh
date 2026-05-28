#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f ".venv/bin/activate" && -z "${VIRTUAL_ENV:-}" ]]; then
  source .venv/bin/activate
fi

python -m benchmarks.scalability.frozen_corpus_baseline_compare "$@"
