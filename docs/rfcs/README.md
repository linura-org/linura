# Request for Comments

RFCs are the public design-discussion mechanism for changes that need broader review before Linura commits to a direction. They complement, but do not replace, Architecture Decision Records.

## When an RFC is required

Use an RFC when a proposal materially changes one or more of:

- authority or trust boundaries;
- public protocol, SDK, schema, provider, or compatibility contracts;
- persistence, migration, recovery, or reconciliation semantics;
- supported platform/profile behavior;
- release or supply-chain authority;
- extension/plugin boundaries;
- cross-cutting system architecture;
- governance or project authority.

A focused implementation detail that is already covered by an accepted decision normally does not need an RFC.

## RFC lifecycle

An RFC uses one of these states:

`Draft → Discussion → Accepted | Rejected → Implemented → Superseded`

- **Draft:** the proposal is being written and may change substantially.
- **Discussion:** the problem, alternatives, compatibility, security, and failure behavior are ready for broader review.
- **Accepted:** maintainers have accepted the design direction. Acceptance is not proof that implementation is complete or release-qualified.
- **Rejected:** the proposal will not proceed in its current form. The rationale remains part of project history.
- **Implemented:** the accepted design has landed with the required tests/evidence.
- **Superseded:** a later RFC or ADR replaces the relevant decision.

An accepted RFC may move directly to Superseded without reaching Implemented if the project changes direction before implementation.

## Process

1. Start from [`0000-template.md`](0000-template.md).
2. Open or identify the related GitHub Discussion in **Architecture & RFCs** when broader exploration is useful.
3. Open a focused pull request containing the RFC and link the Discussion, relevant Issues, ADRs, and affected contracts.
4. Move the RFC from Draft to Discussion when its alternatives, trust-boundary impact, compatibility/migration, failure behavior, and test plan are reviewable.
5. Maintainers record acceptance or rejection in the RFC pull request and update the RFC status.
6. If the accepted RFC creates a durable architectural decision, add or update the corresponding ADR through the append-only ADR process.
7. Link implementation pull requests from the RFC and mark it Implemented only after the accepted design is actually present with required evidence.
8. Supersede rather than silently rewrite a materially changed accepted decision.

## Decision authority

Before 1.0, the maintainer responsible for the affected area accepts or rejects RFCs after considering review evidence.

RFCs that change security invariants, release authority, contributor/governance authority, or a published compatibility guarantee require explicit review by the maintainer holding that responsibility.

Sponsorship, commercial relationships, contribution volume, or social pressure do not grant RFC acceptance authority.

## Relationship to ADRs

RFCs optimize for design discussion. ADRs are the durable record of accepted architectural decisions.

An RFC can be accepted without requiring a new ADR when it does not create or change a durable architectural decision. When it does, the ADR is authoritative history and must not be rewritten later; a later decision supersedes it with a new ADR.

## Numbering and files

`0000-template.md` is reserved as the template.

New RFCs use a unique four-digit identifier and a short descriptive filename:

```text
0001-example-title.md
```

Do not reuse an identifier. Once an RFC is accepted or rejected, preserve the file as project history. Material changes after acceptance are made through a new RFC/ADR that links the earlier decision.

## Security and disclosure

Do not use the public RFC process to disclose an unpatched vulnerability. Report the vulnerability through [`../../SECURITY.md`](../../SECURITY.md) first. A public RFC may follow when disclosure is safe and an architectural change needs public review.
