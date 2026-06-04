# Complex Replay Subset: PassRole-to-Lambda

This fixture is a tiny local-only replay-ready subset for the complex synthetic benchmark theme. It exists to check whether selected PassRole-to-Lambda rows can be replayed from IAMScope-compatible `scenario.json` and `binding_metadata.json` artifacts using existing local replay machinery.

## Contents

- `scenario.json`: emitted by IAMScope scenario serialization helpers with synthetic account `000000000000`.
- `binding_metadata.json`: emitted IAMScope binding sidecar format; empty for this subset.
- `expected_rows.json`: expected subset oracle for one generated PassRole-to-Lambda row plus one missing-precondition/static-only row.

## Boundaries

- Local-only synthetic fixture.
- No live AWS evidence.
- No Terraform, AWS CLI, STS, Lambda API, or `iam:PassRole` calls.
- Missing-precondition/static-only rows are not treated as generated findings.
- This does not prove replay-equivalence for the full complex synthetic benchmark.
- This does not prove broad IAMScope correctness, broad PassRole correctness, exploitability, downstream authorization, Lambda invocation behavior, or production readiness.
- No composite benchmark score or pass/fail benchmark label is produced.
