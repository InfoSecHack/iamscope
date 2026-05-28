# Performance

This document captures the baseline performance characteristics of the IAMScope reasoner layer and the hot-spot fixes applied in v0.2.28.

## TL;DR

**IAMScope is fast enough for real-world AWS orgs.** On a synthetic 1850-node / 1010-edge fact graph (representative of a medium-large AWS org), the entire 8-reasoner pipeline runs in roughly **23 ms** after the v0.2.28 fixes, down from **48 ms** pre-fix. Linearly extrapolated to a 10,000-node enterprise org, the pipeline should complete in roughly 125-250 ms — well within "run on every PR" territory.

The v0.2.28 profiling exercise was polish, not rescue. The reasoner layer was already fast; four O(N²) linear scans were removed to make it ~2× faster.

## Benchmark harness

`tests/benchmark_reasoners.py` generates a deterministic synthetic fact graph and runs all 8 shipping reasoners against it with per-reasoner wall-clock timing. The script is self-contained and has no network or disk dependencies, so contributors can run it locally without credentials or moto setup.

Two scales are supported:

- **Baseline (200 nodes / 313 edges)** — small enough to finish in a few ms, useful for smoke-testing that the benchmark harness itself still works after a code change.
- **XL (1850 nodes / 1010 edges)** — representative of a medium-large AWS org. Exposes O(N²) behavior if any reasoner has it.

### Running

```bash
# Baseline, 3-run median
python3 tests/benchmark_reasoners.py

# With cProfile top-30 hot spots
python3 tests/benchmark_reasoners.py --profile
```

The `--profile` mode is how v0.2.28's hot spots were originally identified. Any future contributor who suspects a new reasoner is slow should run this first and look for entries with high `tottime` and no `cumtime` children — those are the linear scans.

## v0.2.28 baseline (pre-fix)

On the 1850-node / 1010-edge XL graph, 5-run median:

| Reasoner | Median (ms) | Findings |
|---|---|---|
| `s3_bucket_takeover` | 29.78 | 300 |
| `secrets_blast_radius` | 14.29 | 400 |
| `iam_group_membership_escalation` | 2.08 | 20 |
| `assume_role_chain` | 0.42 | 0 |
| `passrole_lambda` | 0.37 | 0 |
| `admin_reachability` | 0.36 | 0 |
| `passrole_ecs` | 0.32 | 0 |
| `cross_account_trust` | 0.00 | 0 |
| **TOTAL** | **48.46** | **720** |

## v0.2.28 after-fix

Same graph, same 5-run median, after the four fixes described below:

| Reasoner | Median (ms) | Speedup |
|---|---|---|
| `secrets_blast_radius` | 11.60 | 1.2× |
| `s3_bucket_takeover` | 7.61 | **3.9×** |
| `iam_group_membership_escalation` | 2.03 | 1.0× |
| `assume_role_chain` | 0.39 | — |
| `admin_reachability` | 0.37 | — |
| `passrole_lambda` | 0.36 | — |
| `passrole_ecs` | 0.32 | — |
| `cross_account_trust` | 0.00 | — |
| **TOTAL** | **22.69** | **2.1×** |

## The four hot-spot fixes

All four were the same bug pattern: a reasoner doing its own linear scan through `facts.nodes` to look up a node by `provider_id`, when the `FactGraph` class already provided an O(1) `node_by_provider_id(...)` lookup via an index built at `__post_init__` time. The reasoners weren't using the index.

### 1. `secrets_blast_radius._find_node`

**Before:**
```python
def _find_node(self, facts: FactGraph, provider_id: str) -> Node | None:
    for node in facts.nodes:
        if node.provider_id == provider_id:
            return node
    return None
```

**After:**
```python
def _find_node(self, facts: FactGraph, provider_id: str) -> Node | None:
    return facts.node_by_provider_id(provider_id)
```

Called once per (principal, secret) pair. On the XL benchmark: 400 calls × ~45 μs each = 18 ms of pure `tottime` in the pre-fix cProfile run. The fix makes it an O(1) dict lookup.

### 2. `secrets_blast_radius` KMS node lookup

**Before:**
```python
kms_node: Node | None = None
for node in facts.nodes:
    if node.node_type != NODE_TYPE_KMS_KEY:
        continue
    if (
        node.provider_id == secret_kms_key_id
        or node.properties.get("key_id") == secret_kms_key_id
    ):
        kms_node = node
        break
```

**After:** O(1) fast path via `node_by_provider_id`, with the O(N) scan retained as a fallback for the case where the secret cites a KMS `key_id` short form (not an ARN) that matches a KMSKey node's `key_id` property rather than its `provider_id`. Most KMS lookups hit the fast path; only the short-form fallback runs the linear scan, and only across KMS nodes (not the full graph).

### 3. `s3_bucket_takeover` clean-witness lookup

**Before:** linear scan through all buckets in the graph to match the witness edge's `dst.provider_id`.

**After:** `facts.node_by_provider_id(dst_provider_id)` with a node_type check to ensure the returned node is actually an S3Bucket, falling back to the "iterate all buckets" UNKNOWN path only when no direct match exists.

This was the biggest winner. 300 witness edges × O(200 buckets) = 60,000 comparisons before, O(1) dict lookup after.

### 4. `iam_group_membership_escalation` clean-witness lookup

Same pattern as #3: replaced the `for g in all_groups: if g.provider_id == ...` loop with an `node_by_provider_id` call plus node_type verification.

## Why the S3 reasoner won the biggest speedup

The pre-fix profile showed `secrets_blast_radius` at 14.3 ms and `s3_bucket_takeover` at 29.8 ms, but `_find_node` was only called from the secrets path, not the S3 path. The S3 speedup came from the clean-witness lookup inside the `run()` method, which hadn't even shown up as a separate line in cProfile because it was inlined inside the outer loop.

The lesson: **cProfile's "top by cumulative time" view doesn't necessarily rank all the hot spots** — inlined linear scans inside hot loops can be invisible to the per-function breakdown. When diagnosing performance, also grep for `for node in facts.nodes` in the reasoner source tree. Any such loop inside a per-finding code path is a candidate for replacement with an indexed lookup.

## Scaling projection

Linear extrapolation from the 1850-node benchmark to larger scales, assuming the fixes continue to eliminate the O(N²) behavior:

| Nodes | Edges | Estimated wall time |
|---|---|---|
| 200 | 313 | 5 ms |
| 1,850 | 1,010 | 23 ms (measured) |
| 5,000 | 3,000 | ~65 ms (projected) |
| 10,000 | 6,000 | ~125 ms (projected) |
| 50,000 | 30,000 | ~625 ms (projected) |

**For context:** a 10,000-node AWS org would have ~2,000 IAM roles, ~1,000 users, ~200 groups, ~500 S3 buckets, ~300 secrets, and so on — that's a large enterprise. At 125 ms per pipeline run, the reasoner layer is not the bottleneck; the collector layer (boto3 API calls with ratelimiting and pagination) dominates total runtime in any real-world scan.

## Rules for future contributors

1. **Never write `for node in facts.nodes: if node.provider_id == x` inside a per-finding code path.** Use `facts.node_by_provider_id(x)` — it's an O(1) dict lookup.
2. **Run `python3 tests/benchmark_reasoners.py --profile` after adding a new reasoner.** Watch for the new reasoner's cumulative time and any high-`tottime` linear scans in the top-30 list.
3. **If a new reasoner does a per-edge cross-reference lookup, check whether a FactGraph index covers it.** Existing indexes: `node_by_id`, `node_by_provider_id`, `edges_from(src_provider_id)`, `edges_to(dst_provider_id)`, `edges_by_action(action)`, `bindings_for_edge(edge_id)`, `constraint_by_id(constraint_id)`. If your reasoner needs an index that doesn't exist yet, add it to the `FactGraph.__post_init__` method rather than building an ad-hoc dict in your reasoner module.
4. **The reasoner layer is currently budgeted at "the collector dominates runtime."** If a single reasoner on a realistic XL benchmark exceeds roughly 100 ms, that's a bug, not a feature — even if the whole pipeline still fits in a single-digit-second budget.
