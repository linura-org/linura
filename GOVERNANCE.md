# Governance

Linura uses a maintainer-led governance model during pre-1.0 development. Governance exists to make technical authority, security authority, release authority, and project stewardship explicit rather than implicit.

## Current governance state

The current active maintainer is **Ehsan Azari (`@Ehsan-Azari`)**. At this stage one person may hold maintainer, security-response, and release-authority responsibilities, but those roles are defined separately so they can be delegated without changing the project model.

CODEOWNERS records repository ownership metadata; this document defines how that ownership is exercised and how it evolves.

## Decision hierarchy

When constraints conflict, Linura uses this order:

1. security invariants and accepted architectural decisions;
2. published protocol, platform, compatibility, and release guarantees;
3. accepted RFCs and recorded maintainer decisions;
4. implementation convenience.

No implementation shortcut, sponsor request, roadmap preference, or release deadline may override a security invariant or a published support boundary.

## Roles

### Contributors

Contributors may propose issues, discussions, RFCs, documentation, code, tests, qualification evidence, and other project improvements. Contribution does not by itself confer merge, release, security, or privileged repository authority.

### Reviewers

Reviewers provide technical review in areas where they have demonstrated competence. A review is advisory unless repository policy or a maintainer explicitly makes it a required decision input.

### Maintainers

Maintainers may merge ordinary changes, triage project work, accept or reject RFCs within their authority, manage repository policy, and represent Linura's documented project decisions.

Maintainers are expected to:

- preserve security and compatibility boundaries;
- separate evidence from claims;
- disclose material conflicts of interest;
- avoid using privileged repository access for ordinary development when a narrower path exists;
- document decisions that materially affect contributors or public contracts;
- keep accepted ADR history append-only.

### Security responders

Security responders receive private reports, coordinate triage and remediation, limit disclosure on a need-to-know basis, and decide disclosure timing with the maintainer responsible for the affected boundary.

Security-response authority does not permit silently weakening a security invariant. Any intentional change to an invariant requires the same documented architecture/governance process as other security-sensitive changes.

### Release authority

Release authority may authorize or operate the documented release lifecycle. Linura's release process deliberately separates reviewed semantic readiness from mechanically constrained post-readiness handoffs.

Repository-wide approval rules must not introduce a hidden human gate into those mechanically constrained release handoffs. Human review requirements for ordinary or security-sensitive development should therefore be scoped so they do not break the accepted release-control architecture.

## Merge authority

During the current sole-maintainer phase, the active maintainer may merge changes after required checks, review-thread resolution, and any change-class-specific review requirements are satisfied.

Self-review does not transform weak evidence into strong evidence. Security-sensitive, architecture-sensitive, and release-sensitive changes should seek independent review whenever an appropriate reviewer is available, even when repository rules do not require an approval count.

When multiple trusted maintainers exist, ownership should move from individual CODEOWNERS entries toward organization teams such as `@linura-org/maintainers` and `@linura-org/security`.

## Architectural decisions and RFCs

Use ADRs for durable architectural decisions and RFCs for changes requiring broader design discussion.

The RFC lifecycle, states, decision recording, and relationship to ADRs are defined in [`docs/rfcs/README.md`](docs/rfcs/README.md). Accepted ADRs remain immutable historical records and are superseded by later ADRs rather than rewritten.

Before 1.0, RFC acceptance authority rests with maintainers responsible for the affected area. An RFC that changes a security invariant, release authority, or a published compatibility guarantee requires explicit review by the maintainer holding that responsibility.

## Decision process

Maintainers should prefer documented consensus when multiple maintainers or domain reviewers are involved.

If maintainers disagree:

1. identify the concrete decision and affected contract;
2. record alternatives and evidence in the issue, RFC, or PR;
3. seek domain or security review when the disagreement crosses that boundary;
4. prefer the option that preserves existing public/security contracts when evidence is insufficient;
5. record the final maintainer decision and rationale.

A maintainer must not use administrative access to erase unresolved technical disagreement from project history. Security incidents may require temporary private coordination, but the resulting public policy or architecture change must still be documented at the appropriate time.

## Becoming a maintainer

Maintainership is earned through sustained project contribution and demonstrated judgment, not through sponsorship, employment status, social prominence, or contribution volume alone.

A maintainer candidate should demonstrate:

- repeated high-quality contributions or reviews;
- understanding of Linura's authority and security model;
- reliable handling of failure, migration, recovery, and compatibility concerns;
- respectful technical collaboration;
- willingness to document decisions and disclose conflicts;
- responsible use of repository and release privileges.

Admission is recorded in a governance pull request naming the maintainer, scope of authority, and any team memberships or CODEOWNERS changes. Privileges should follow least privilege and may be narrower than full repository administration.

## Inactivity, removal, and succession

Maintainers may step down voluntarily at any time. Extended inactivity does not automatically erase historical credit or standing, but privileged access should be reviewed when it is no longer needed.

Access may be suspended promptly for a compromised account, credible security risk, or abuse of project authority. Permanent removal should be documented with enough public rationale to make the governance action understandable without exposing confidential security or conduct information.

The project should avoid a single unrecoverable administrative dependency as additional trusted maintainers emerge. Organization ownership, release credentials, domain administration, and security-response access should be deliberately distributed or recoverable rather than informally shared.

If the current sole maintainer becomes unavailable before succession is established, repository history and published contracts remain authoritative; no contributor gains implicit project authority merely by continuing development in a fork.

## Conflicts of interest and sponsorship

Maintainers must disclose material relationships that could reasonably affect a project decision.

Sponsorship, grants, donations, vendor relationships, or commercial relationships do not purchase roadmap vetoes, architectural authority, security exceptions, merge rights, release authority, or undisclosed influence. See [`docs/community/sponsorship.md`](docs/community/sponsorship.md).

## Governance changes

Material governance changes require a focused pull request and, when they alter authority allocation or long-term project structure, an RFC.

After 1.0, Linura may adopt a broader multi-maintainer or foundation-style model. That transition must be explicit; pre-1.0 governance does not silently convert into another structure.
