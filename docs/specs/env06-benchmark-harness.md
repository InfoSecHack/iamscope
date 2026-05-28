# Env06 Benchmark Harness Contract

This harness is benchmark-oriented, not reasoner-authoritative.

Rules:
- The inner `acceptance/env06_ar_validated_admin/run.sh` command may exit non-zero.
- If `findings.json` does not exist, that command failure remains the benchmark failure.
- If `findings.json` exists, the harness evaluates benchmark truth using the Env06 target semantics recorded in `acceptance/env06_ar_validated_admin/expected_findings.json`:
  - `admin_reachability` validated count >= 1 for the benchmark source/target path
  - `admin_reachability` blocked count == 0 for that path
  - `admin_reachability` inconclusive count == 0 for that path
  - validated target findings have zero `blockers_observed`
- Extra non-target findings do not fail the benchmark unless they contradict the target path semantics.
- The harness writes semantic assertion counts and PASS/FAIL status to `run.log`.
- The harness copies `expected_findings.json`, archives collect artifacts, and requires `iamscope validate` to pass for `scenario.json`.
- Final harness exit code is the sanitized benchmark result code, not the raw pipeline code, when artifacts exist and semantic assertion passes.
