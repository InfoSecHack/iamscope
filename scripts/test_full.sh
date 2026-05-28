#!/usr/bin/env bash
set -euo pipefail

if [[ -f ".venv/bin/activate" && -z "${VIRTUAL_ENV:-}" ]]; then
  source .venv/bin/activate
fi

pytest -q
