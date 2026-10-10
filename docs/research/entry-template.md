# Technology: Name of candidate

**Record ID:** `stable-kebab-case-id`  
**Scope:** Define the specific Linura use case and environment.

The authoritative classification, owner, and review dates live only in `docs/research/technology-radar.md`. After copying this template into `entries/`, link to `../technology-radar.md` from the new entry. This is a research record, not a product/support claim.

## Summary and motivation

What concrete Linura problem might this solve? What is explicitly out of scope?

## Evidence and source provenance

Separate independently verified facts from primary-source assertions and hypotheses. For each material source, include its URL, publication or release date, and the date reviewed. Capture version/commit, hardware, workload, reproducibility, conflicting findings, and remaining uncertainty when relevant.

## Benefits and architectural fit

Explain which bounded mechanism could fit an existing provider/platform contract and which existing authority/control invariants must remain unchanged.

## Security and trust boundaries

Threat model, isolation claims versus guarantees, privileged operation and admission, failure containment, rollback/recovery, attestable independent observation, and unknowns. Do not treat provider assertions as qualification.

## Alternatives and costs

Include doing nothing and established baselines. Note maintenance, portability, licensing, and operational costs.

## Investigation and acceptance gates

Define bounded experiments, trusted test environment, baseline comparisons, stop conditions, evidence required before advancing to Assess or Adopt, and any RFC/ADR triggers. No work is scheduled merely by writing this section.

## Reassessment triggers

Describe measurable upstream changes or new evidence that justify re-review.

## Links and decision log

Reference Discussions, Issues, RFCs, ADRs, and PRs only when they actually exist. Append dated material conclusions without rewriting historical decisions.
