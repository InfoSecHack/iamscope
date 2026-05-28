# ARF binding metadata honesty

- Scope: keep `serim_arf_rt_compare.py` summary metadata truthful about binding metadata input state
- Actual contract in this pass: `binding_metadata` is an optional explicitly supplied report artifact path only; the wrapper does not intentionally default or load it for planner execution
- Summary behavior: include `inputs.binding_metadata` only when an explicit file path was supplied and is a file
- Invalid supplied paths must not be reported as present; distinguish them via warning text instead