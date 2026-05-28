# ARF probe overlay input honesty

- Scope: keep `serim_arf_rt_compare.py` summary metadata truthful about probe overlay input state
- Actual contract in this pass: `probe_overlay` is optional and explicitly supplied only; there is no intentional default path
- Summary behavior: include `inputs.probe_overlay` only when `--probe-overlay` was supplied and the run reached summary emission after a successful load
- Invalid supplied paths fail before summary emission, so the summary must not imply probe overlay presence in that case