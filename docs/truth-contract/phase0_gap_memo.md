# Phase 0 Gap Memo: Org-Control Truth Surface

## Existing Surface

`iamscope.collector.organization` already collects custom SCPs, parses each
Deny statement into `Constraint` objects, records attachment scope, and computes
`ou_account_map` as a recursive scope-to-account map. That gives IAMScope enough
information to flatten effective SCPs per account without a second Organizations
collector.

`iamscope.truth.org_controls` already contains a first-pass normalization helper
for effective SCPs. It enumerates controls per governed account using
`OrgData.scp_constraints` and `OrgData.ou_account_map`, records attachment level,
content hash, inherited status, and a heuristic `sts:AssumeRole` relevance flag.

`iamscope.output.scenario_json` already computes `metadata.canonical_hash` over
nodes, edges, constraints, edge_constraints, objectives, and observations while
excluding metadata. That hash is the right sidecar anchor for probe overlays.

## Gaps

The current truth prototype mixed runtime truth into `scenario.json` metadata and
edge features. That conflicts with the Phase 0-2 plan because edge features are
part of the edge ID formula. Runtime truth must not perturb graph identity.

No frozen probe overlay schema exists yet. There is no canonical load/save path,
no hash-mismatch rejection, and no stable join keyed by `edge_id`.

Confounded-state derivation needs a closed dataclass surface. The org-control
normalizer can remain the low-level source, but Phase 2 needs an explicit
`ConfoundedJudgment` that cites contributing SCPs and labels heuristic evidence.

There is no `iamscope edge-truth` command that joins scenario data, binding
metadata, and probe overlay state for a single edge.

## Decision

Extend `org_controls.py` only for effective-control normalization. Add a thin
`truth/confounded.py` module for Phase 2 judgments. This avoids duplicating SCP
normalization while keeping confounded verdict semantics separate and testable.

Use sidecars for runtime truth and probe state. Do not add truth fields to
`scenario.json`, edge features, constraint properties, or scenario metadata in
this phase.
