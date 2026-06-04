# Case-Sensitive ARN ID Collision Design

## Purpose

This checkpoint documents a confirmed deterministic ID collision before
changing IAMScope ID behavior. The goal is to pin the bug, compatibility risk,
candidate migration shape, and required tests before any production code
change.

## Confirmed Bug

`iamscope/identity/deterministic_ids.py::canonical_id` lowercases all string
fields before hashing.

As a result, `node_id(provider, node_type, provider_id)` collides for
case-distinct provider IDs. AWS IAM role and user names are case-sensitive, so
these two distinct ARNs currently produce the same `node_id`:

- `arn:aws:iam::000000000000:role/CaseRole`
- `arn:aws:iam::000000000000:role/caserole`

`edge_id` can also be affected because the shared `canonical_id` function
lowercases `src_provider_id` and `dst_provider_id` before hashing. A pair of
edges that differs only by source or destination ARN case can therefore collide
even when AWS treats the principals or resources as distinct.

`constraint_id` needs separate review. Some constraint fields, such as provider,
constraint type, scope type, account IDs, and Organizations IDs, may be
intentionally case-insensitive or fixed-case. Other fields, such as policy or
statement identifiers, may have different semantics. This design does not
change `constraint_id`.

## Minimal Local Reproduction

```python
from iamscope.identity.deterministic_ids import node_id

a = node_id("aws", "IAMRole", "arn:aws:iam::000000000000:role/CaseRole")
b = node_id("aws", "IAMRole", "arn:aws:iam::000000000000:role/caserole")
assert a == b  # current bug
```

The expected fixed behavior is that the two IDs differ because the provider IDs
refer to case-distinct IAM roles.

## Why It Matters

The current collision can cause IAMScope to deduplicate distinct principals or
resources in the fact graph. That can corrupt downstream evidence in both
directions:

- a distinct case-sensitive principal can disappear during graph construction;
- edges can attach to the wrong merged node;
- reasoners can evaluate a path against the wrong principal or target;
- findings can cite evidence from a merged shape that does not exist as a
  single AWS identity;
- comparisons across runs can look stable while hiding a graph identity loss.

This is especially risky for IAM users and roles because IAM names are
case-sensitive within an AWS account.

## Compatibility Risk

Changing deterministic ID behavior is high compatibility risk. The current ID
module already documents that algorithm changes can break ARF-RT references,
observation logs, probe overlays, and cross-run comparisons.

A direct in-place fix would change `node_id` and potentially `edge_id` values
for every node or edge whose canonical input contains uppercase characters.
That would make old and new scenarios non-comparable unless the algorithm
version and migration rules are explicit.

The design must therefore treat this as an ID algorithm migration, not as a
silent bug fix.

## ARF-RT and Downstream Blast Radius

Known downstream surfaces that depend on stable IDs include:

- scenario `nodes[].node_id`;
- scenario `edges[].edge_id`;
- edge-constraint bindings keyed by `edge_id`;
- findings evidence that cites node and edge IDs;
- ARF-RT edge remapping and wrapper summaries;
- probe overlays keyed by `edge_id`;
- observation logs and review artifacts that cite IDs;
- cross-run comparisons and `findings_diff` output;
- any external reviewer notes that reference existing scenario IDs.

The migration must make old and new ID spaces explicit so consumers do not
mistakenly compare v2 and v3 IDs as if they were the same identifier family.

## Candidate Fix

Introduce a new deterministic ID algorithm version, tentatively:

`sha256_null_separated_v3_case_sensitive_provider_ids`

The candidate v3 behavior should use field-aware canonicalization:

- keep provider and structural type fields normalized where they are intended to
  be case-insensitive, such as `provider`, `node_type`, `edge_type`, and
  `region`;
- preserve case for provider-owned identity fields, especially
  `provider_id`, `src_provider_id`, and `dst_provider_id`;
- keep feature canonicalization deterministic and unchanged unless a separate
  review finds a feature-level case collision;
- review `constraint_id` separately before deciding whether it should stay on
  the existing canonicalization behavior or move to a field-aware formula.

The code fix should avoid a broad "never lowercase anything" change. The safer
boundary is to make each deterministic ID formula choose the canonicalization
rule for each field it owns.

## Migration and Versioning Plan

1. Add focused regression tests that pin the current collision as design
   evidence, preferably as `xfail` or another non-enforced marker until the
   algorithm migration is approved.
2. Define the v3 formula in code and update the public `ID_ALGORITHM` metadata
   value in the same slice as the behavior change.
3. Emit scenario metadata that clearly identifies the v3 algorithm.
4. Treat v2 and v3 scenarios as different ID spaces. Cross-version comparison
   tools should refuse ID-based equality unless both artifacts use the same
   `id_algorithm`.
5. Add migration notes for ARF-RT, probe overlays, observation logs, and
   findings diffs.
6. Preserve deterministic sort order after IDs change.
7. Do not rewrite historical public artifacts in this repo. If historical
   scenarios are regenerated later, label them as regenerated under the new
   algorithm.

## Tests Required Before Code Fix

Before changing production ID behavior, add tests that cover:

- `node_id` differs for case-distinct IAM role ARNs.
- `node_id` differs for case-distinct IAM user ARNs.
- `node_id` remains stable for exact repeated inputs.
- `edge_id` differs when only `src_provider_id` case differs.
- `edge_id` differs when only `dst_provider_id` case differs.
- `edge_id` still changes when `features_digest` changes.
- deterministic scenario metadata records the new `id_algorithm`.
- `findings_diff` or equivalent comparison code refuses to treat v2 and v3 IDs
  as directly comparable unless explicit migration support is added.
- ARF-RT/probe-overlay tests either reject cross-version edge IDs or use an
  explicit remapping path.
- `constraint_id` behavior is covered by a separate review, including which
  fields are case-sensitive and which remain normalized.

## Non-Goals

This checkpoint does not:

- change production ID behavior;
- change `node_id`, `edge_id`, `constraint_id`, or `finding_id` algorithms;
- add live AWS validation;
- run Terraform;
- change reasoner behavior;
- change benchmark semantics;
- add composite scores;
- add pass/fail benchmark labels;
- claim broad IAMScope correctness;
- claim production readiness.

## Exact Next Slice

Recommended next slice: add xfail case-sensitive ARN ID collision regression tests.
