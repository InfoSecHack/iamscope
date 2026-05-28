# ARF findings input honesty

- Scope: keep `serim_arf_rt_compare.py` summary metadata truthful about findings input presence
- Contract: `inputs.findings` is only present when `--findings` was explicitly supplied and the run reached summary emission
- Failed findings load must not leave behind a summary that implies findings were loaded
- No unrelated summary fields change in this pass