# Technology research and radar

This is Linura's non-normative intake for external technologies that **might** eventually be relevant. The [radar](technology-radar.md) is the only source of truth for each entry's classification, owner, and review dates. An [entry](entries/) contains evidence and rationale; it must not restate or independently set classification.

This is not the release roadmap, a feature backlog, an approved architecture, or a support matrix. Nothing here activates a provider, changes a trust boundary, allocates a milestone, or constitutes release qualification. Those decisions remain governed by the [roadmap](../roadmap.md), [RFC process](../rfcs/README.md), [ADRs](../adr/README.md), release contracts, and exact-source qualification evidence.

## Classification

| State | Meaning | Next action |
| --- | --- | --- |
| **Watch** | A plausible opportunity with insufficient or unverified evidence. | Follow explicit reassessment triggers; no implementation commitment. |
| **Assess** | A maintainer has accepted a bounded research question and evaluation plan. | Create a scoped Issue with owner, baselines, acceptance/stop criteria, and security boundaries. |
| **Adopt** | A direction has been deliberately approved after evaluation and any required RFC/ADR review. | Schedule implementation separately; do not claim it shipped or is qualified. |
| **Hold** | Not being pursued (e.g., unacceptable risk, lack of benefit, or incompatible maturity). | Preserve reasons and revisit only when the blocking evidence changes. |

Transitions are evidence-driven, not automatic. Watch → Assess requires a documented problem, alternatives, a testable question, a responsible owner, and a bounded evaluation scope. Assess → Adopt requires reproducible positive evidence, a completed threat/compatibility review, explicit maintainer acceptance, and an accepted RFC/ADR when the [RFC policy](../rfcs/README.md) requires one. Assess → Watch or any state → Hold is allowed with recorded reasons. A previous Adopt decision cannot be silently reversed: supersede the governing RFC/ADR as applicable. Classifications never authorize execution or expand release claims.

## Record an idea

1. Search the radar, [Discussions](https://github.com/linura-org/linura/discussions), and [Issues](https://github.com/linura-org/linura/issues) to avoid duplicate candidates. For early exploration, open an **Architecture & RFCs** Discussion when appropriate; Discussions are not decisions.
2. Write one substantive entry from the [template](entry-template.md) under `entries/<stable-kebab-case-id>.md`. Separate verified facts, upstream assertions, hypotheses, and Linura-specific evaluation. Capture source URL, source date, inspection date, applicability, and important unknowns. Never treat an upstream benchmark as independent Linura qualification.
3. Add exactly one row to the [radar](technology-radar.md) with the relative record link, classification, review owner, last-assessed date, and next-review date (ISO `YYYY-MM-DD`). The table owns these fields; do not duplicate status in entry files or issue labels.
4. Review through the normal pull-request process. Research documentation cannot bypass security disclosure rules: do not publish undisclosed vulnerabilities or credentials.
5. When an evaluation becomes actionable, use a scoped feature/research Issue with measurable deliverables and link it from the entry. Do **not** create an Issue for every Watch entry. Architecture changes follow an [RFC](../rfcs/README.md) and, when accepted as durable decisions, an [ADR](../adr/README.md); implementation PRs and release qualification follow afterward.

## Maintenance and evidence

- **Review cadence:** Watch at least every 90 days, Assess at least every 30 days, Adopt when its governing decision or implementation evidence changes, and Hold only on material new evidence. Dates are manual review targets, **not** scheduled background monitoring.
- **Review outcome:** Update the last-assessed and next-review dates only after an actual review. Append meaningful changes to the entry's decision log, preserving earlier findings and the reason for any stage change.
- **Accountability:** Each row has a named maintainer or accountable team; a team label denotes stewardship, not an automated assignment. An overdue date triggers triage, not automatic promotion or deletion.
- **Evaluation standard:** Prefer primary sources and reproducible experiments. Identify hardware/kernel/tool versions, comparable baselines, workloads, performance variance, and failure modes. Report negative and inconclusive results, security assumptions, license/support dependencies, and recovery implications.
- **Separation of authority:** Proposals remain untrusted research. A future provider may only expose bounded mechanisms and cannot take over policy, approval, preparation, independent verification, audit, or reconciliation. New managed effects use Linura's canonical lifecycle.
- **Safety:** Research on unsafe or untrusted kernel technology must use an isolated, disposable, non-production testbed. Claims of VM-equivalent isolation, production readiness, or platform support require independent evidence, not upstream descriptions.

The repository's canonical tooling discovers the research validation tests under `tests/tooling/test_technology_radar.py` and checks relative Markdown links via `scripts/check_repository.py`. No new required GitHub check or release contract is introduced by the radar.
