# Benchmark Corpus Summary

## Scope
- Add one tiny Phase 0 corpus summarizer over already-evaluated benchmark run directories.
- It consumes existing evaluation outputs only.
- It must not change scoring, gates, IAMScope logic, or add any composite score.

## Inputs
- Either `--runs-dir` or repeated `--run-dir`
- `--out-dir`

## Required evaluated run files
- `run_manifest.json`
- `scorer_result.json`
- `gate_result.json`
- `report.md`

## Outputs
- `corpus_summary.json`
- `promotion_decision.json`
- `corpus_report.md`

## Promotion decision
- `block` if any evaluated run has `promotion_blocked=true`
- `block` if any evaluated run is artifact-insufficient
- `hold_review` if no blocks exist but any run still requires human review
- `promote` only if no blocks exist and no run requires human review

## Reporting contract
- No composite score.
- Aggregate statements apply only to the evaluated corpus cases.
- Markdown output must separate:
  - directly proven
  - strongly supported
  - only implied
  - still unknown