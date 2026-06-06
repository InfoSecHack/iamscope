# IAMScope vs Pacu vs PMapper

Pacu and PMapper are useful tools with different goals. This comparison is positioning, not a ranking.

| Tool | Primary purpose | What it is good at | What IAMScope is not trying to replace | IAMScope difference |
| --- | --- | --- | --- | --- |
| Pacu | Offensive AWS exploitation / attack module framework. | Running AWS attack modules in authorized security testing, demonstrating exploitation workflows, and exploring attacker tradecraft. | IAMScope is not trying to replace Pacu as an exploitation framework or attack-module runner. | IAMScope does not attempt exploitation. It produces evidence-grade findings with verdicts, required checks, blockers, `collection_context`, capability boundaries, replay, human labels, and owner-confirmation trail. |
| PMapper | IAM graph/query/local authorization simulation / privilege-escalation path mapping. | Building IAM relationship graphs, querying policies, local authorization reasoning, and mapping privilege-escalation paths. | IAMScope is not trying to be a full replacement for PMapper’s graph/query and simulation workflows. | IAMScope focuses on reviewer-facing findings: what is validated, blocked, inconclusive, expected-benign, unsupported, or needs more evidence. It emphasizes capability honesty and bounded non-claims. |
| IAMScope | Evidence-grade IAM finding workflow. | Collecting or replaying IAM graph artifacts, running reasoners, emitting verdicts and required checks, preserving blockers and `collection_context`, supporting human labels, owner-confirmation, and sanitized review summaries. | IAMScope is not trying to replace offensive testing tools or general IAM graph/query tools. | IAMScope’s value is the review workflow: it says what the evidence supports, what remains uncertain, and what a human should review first. |

## Positioning Summary

- Pacu helps authorized testers exercise offensive AWS techniques.
- PMapper helps users inspect IAM graph and authorization relationships.
- IAMScope helps reviewers handle evidence, verdicts, blockers, capability boundaries, `collection_context`, human labels, and owner-confirmation without claiming exploitation.

## Non-Claims

IAMScope’s demo evidence does not claim:

- production readiness.
- exploitability proof.
- full IAM safety.
- full AWS authorization semantics.
- complete IAM privilege-escalation coverage.
- broad IAMScope correctness.
- a composite score.
- a pass/fail benchmark label.

No findings does not mean safe. Validated does not mean exploited.
