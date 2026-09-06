# ADR 0025 — Component maturity and milestone activation are explicit contracts

- Status: Accepted
- Date: 2026-09-06

## Context

Linura intentionally creates architectural structure before every product milestone is integrated: workspace crates, placeholder applications, future UI directories, executors, verifiers and subsystem foundations can exist before they become active product surfaces. Workspace membership is useful for compilation and architectural ownership, but it is not evidence that a component is integrated, release-qualified, user-facing or supported.

Without a machine-readable maturity contract, a placeholder can accidentally be packaged, a future component can be described as active merely because it compiles, or a proposal/UI scaffold can appear to have authority it has not earned. A repository audit found a concrete instance of this class of drift: `linura-firstboot` is owned by the later First Boot milestone but remained in the release and development-image binary sets.

## Decision

`contracts/components.toml` is the canonical machine-readable ledger for component ownership, maturity, activation milestone, release-artifact intent and authority role.

Every Cargo workspace member and every explicitly planned application directory must have exactly one component record. Workspace membership and filesystem presence do not imply product maturity.

### Maturity model

The implemented maturity order is:

```text
roadmap-scaffold
→ foundation
→ integrated-experimental
→ stable
```

- `roadmap-scaffold`: architectural placeholder or future-owned component; it must not be represented as an active release capability.
- `foundation`: reusable implementation substrate with real code/contracts but no claim that it is an integrated end-user capability.
- `integrated-experimental`: actively composed into an Experimental Linura path at or after its activation milestone.
- `stable`: eligible for Stable claims only after the repository's stability and support requirements are satisfied.

Release qualification is deliberately not a maturity state. Qualification is exact-source evidence for a particular candidate/release, while component maturity describes the architectural/product state of a component. An `integrated-experimental` component can therefore be qualified repeatedly without being mislabeled as Stable.

The contract does not infer maturity from source size, test count, workspace membership or package publication.

### Required ownership fields

Each component declares at least:

- stable component ID;
- repository path;
- kind (`app`, `crate`, `executor`, `verifier`, `tool`, or `planned-app`);
- whether it is a Cargo workspace member;
- maturity;
- activation milestone;
- whether it is a release artifact;
- binary name when it is a release artifact;
- authority role;
- bounded scope statement.

Privileged or authority-relevant components must have an explicit role. Proposal-only components cannot acquire release or privileged mutation authority merely through dependency, workspace or packaging changes.

### Packaging is a maturity claim

`release_artifact = true` is an architectural claim, not a convenience flag. The sealed release payload and development-image binary sets must agree with the component ledger.

A `roadmap-scaffold` cannot silently become a release artifact. Conversely, an integrated binary that is intentionally distributed must be represented in the component contract so build, SBOM, checksum and reproduction logic can be audited against the same source of truth.

The baseline audit correction removes `linura-firstboot` from current release/image artifact sets while keeping its workspace scaffold and later activation milestone intact. This does not delete or activate First Boot; it makes packaging agree with the roadmap.

### Machine enforcement

`tools/check_component_maturity.py` and its regression tests enforce the component ledger in canonical repository validation. At minimum the checker rejects:

- unowned workspace or planned components;
- duplicate component ownership;
- missing paths or inconsistent workspace declarations;
- release artifacts without valid binary identity;
- roadmap scaffolds packaged as release artifacts;
- future components shipped before their activation milestone;
- release/image binary drift from the ledger;
- proposal-only components gaining release authority;
- invalid privileged-executor or authority-runtime ownership;
- invalid maturity or milestone relationships.

The machine roadmap remains the source of milestone sequencing; the component ledger records which component becomes active at which milestone.

## Consequences

### Positive

- Repository structure can remain broad without pretending every directory is an implemented product surface.
- Future architecture can be scaffolded without silently widening release claims.
- Packaging, roadmap language and component authority can be checked against explicit maturity facts.
- Component activation becomes reviewable and auditable rather than inferred from commits.
- Release qualification remains a separate evidence concern instead of being conflated with architectural maturity.

### Costs

- Adding or materially activating a component requires updating the component contract and tests.
- Release/image changes become architecture changes that must agree with maturity declarations.
- Broad vision documentation must distinguish future topology from current integrated runtime.

## Rejected alternatives

### Treat every workspace member as active

Rejected. The workspace intentionally contains future and foundation components; compilation is not maturity evidence.

### Track maturity only in prose

Rejected. Prose alone cannot reliably prevent a placeholder from reappearing in packaging or an unowned component from drifting between milestones.

### Delete all future scaffolds until implementation begins

Rejected. Early typed boundaries and ownership can be useful architecture, provided maturity and activation are explicit and they cannot be mistaken for shipped capability.

### Use release packaging as the only maturity signal

Rejected. Many integrated crates are not standalone artifacts, while some safety/tooling binaries can be release artifacts without representing a broad end-user feature. Maturity and packaging are related but distinct facts.
