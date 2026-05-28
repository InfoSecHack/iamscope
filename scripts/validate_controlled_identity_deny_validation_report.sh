#!/usr/bin/env bash
set -euo pipefail

python -m benchmarks.runtime.controlled_identity_deny_validation_report "$@"
