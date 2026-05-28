# Benchmark Stability Probe: env03

This report covers repeated live runs for one existing benchmark case only. It is not a composite score and does not claim broad IAMScope stability.

## Summary
- Case ID: `env03_identity_deny_group_escalation`
- Requested runs: `3`
- Run records: `3`
- Tool semantic stability pass: `3`
- Tool semantic stability fail: `0`
- Not evaluated: `0`
- Collection/runtime failures: `0`
- AWS/Terraform setup failures: `0`

## Category Definitions
- Tool semantic stability: artifacts existed, scenario validation/evaluation ran, and target semantic assertions passed.
- Collection/runtime failure: expected runtime artifacts or scenario validation were missing/failing.
- AWS/Terraform setup failure: the run log indicates setup/auth/provider/throttling failure before stable semantic judgment.

## Runs
- Run 1: semantic=`pass`, runner_rc=`0`, evaluation_rc=`0`, scenario_validation=`pass`, archive=`/tmp/iamscope-stability-env03/archives/env03-20260428T033129Z-stability-01`
- Run 2: semantic=`pass`, runner_rc=`0`, evaluation_rc=`0`, scenario_validation=`pass`, archive=`/tmp/iamscope-stability-env03/archives/env03-20260428T033231Z-stability-02`
- Run 3: semantic=`pass`, runner_rc=`0`, evaluation_rc=`0`, scenario_validation=`pass`, archive=`/tmp/iamscope-stability-env03/archives/env03-20260428T033331Z-stability-03`

## What Not To Conclude
- Do not conclude broad benchmark stability from this one case.
- Do not treat AWS/Terraform setup failures as IAMScope semantic failures.
- Do not collapse these categories into one score.
