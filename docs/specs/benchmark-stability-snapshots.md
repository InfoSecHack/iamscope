# Benchmark Stability Snapshots

## Purpose
Stability snapshots preserve selected repeat-run evidence in the repo without copying raw live AWS archives or Terraform artifacts.

## Layout
```text
benchmarks/stability-snapshots/
  INDEX.md
  <snapshot-id>/
    README.md
    stability_summary.json
    stability_report.md
    stability_runs.jsonl
```

## Allowlist
Only these files should be copied into a stability snapshot:
- `stability_summary.json`
- `stability_report.md`
- `stability_runs.jsonl`
- snapshot `README.md`

## Explicitly Excluded
- raw benchmark archive directories;
- Terraform state files;
- `.terraform/` provider caches;
- provider binaries;
- collected `scenario.json`, `findings.json`, or `binding_metadata.json` copies outside the stability summary evidence.

## Evidence Boundary
Snapshots record stability for the named case and run count only. They must not claim broad IAMScope stability, broad benchmark correctness, production readiness, or a composite score.
