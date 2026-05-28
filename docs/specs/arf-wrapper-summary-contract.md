# ARF wrapper summary contract

Wrapper summary `inputs.*` fields in `tools/serim_arf_rt_compare.py`:

- `inputs.scenario`
  - Kind: explicit input when `--scenario` is supplied, otherwise intentionally defaulted from `--input-dir` to `scenario_with_objective.json`
  - Presence rule: always present in successful summary emission
  - Failure rule: unreadable or invalid scenario fails before summary emission

- `inputs.normalized_scenario`
  - Kind: derived informational field
  - Presence rule: always present in successful summary emission after the wrapper writes `serim_scenario_arf_compat.json`
  - Failure rule: if normalization or write fails, no summary is emitted

- `inputs.binding_metadata`
  - Kind: optional explicit report artifact path only
  - Presence rule: present only when `--binding-metadata` was explicitly supplied and points to a file
  - Failure rule: invalid supplied path is omitted from `inputs` and recorded in `ingest_warnings`

- `inputs.findings`
  - Kind: optional explicit truth artifact path only
  - Presence rule: present only when `--findings` was explicitly supplied and the run reached summary emission
  - Failure rule: invalid or unreadable supplied path fails before summary emission

- `inputs.probe_overlay`
  - Kind: optional explicit truth artifact path only
  - Presence rule: present only when `--probe-overlay` was explicitly supplied and the run reached summary emission after a successful load
  - Failure rule: invalid or unreadable supplied path fails before summary emission

Intentional fail-closed behavior in this pass:

- The summary does not invent default semantics for `binding_metadata`, `findings`, or `probe_overlay`.
- Invalid `findings` and `probe_overlay` inputs fail before summary emission.
- Invalid `binding_metadata` input does not fail the run, but it is not reported as present.