# ADR 0026 — Component maturity and milestone activation are explicit contracts

- Status: Accepted
- Date: 2026-09-06

## Context

Linura intentionally created a broad architecture skeleton early: workspace crates, placeholder applications, future UI directories and subsystem foundations existed before their product milestones. Workspace membership is useful for compilation and architectural ownership, but it is not evidence that a component is integrated, release-qualified, user-facing or supported.

Without a machine-readable maturity contract, a placeholder can accidentally be packaged, a future component can be described as active merely because it compiles, or an agent/UI scaffold can appear to have authority it has not earned. The v0.6 audit found a concrete example: `linura-firstboot` remained a placeholder for later First Boot work but was still present in the release/image binary set.

## Decision

`contracts/components.toml` is the canonical machine-readable ledger for component ownership, maturity, activation milestone and release-artifact intent.

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
- `stable`: eligible for Stable claims only after the repository's later stability/support requirements are satisfied.

The contract deliberately does not infer maturity from source size, test count, workspace membership or package publication.

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

Privileged or authority-relevant components must have an explicit role. Proposal-only agent components cannot acquire privileged mutation authority merely through dependency or packaging changes.

### Packaging is a maturity claim

`release_artifact = true` is an architectural claim, not a convenience flag. Release and development-image binary sets must agree with the component ledger.

A `roadmap-scaffold` cannot silently become a release artifact. Conversely, an integrated binary that is intentionally part of the release must be represented in the component contract so sealed build, SBOM, checksum and reproduction logic can be audited against the same source of truth.

For v0.6 specifically:

- `linura-authorityd` is `integrated-experimental`, activates at `v0.6.0`, and is a release artifact because it is the bounded managed-authority runtime;
- `linura-executor-systemd` remains an `integrated-experimental` privileged executor and release artifact;
- `linura-verifier-systemd` is integrated but not a standalone release artifact;
- `linura-firstboot` remains `roadmap-scaffold`, activates at `v0.9.0`, and is not a v0.6 release/image artifact;
- `linura-agent-runtime` and `linura-agent-ui` remain proposal-only future components for v0.8 and have no mutation authority;
- `linura-control-center`, `linura-shell`, managed configuration and supported-reference-environment bootstrap/hardware work remain owned by later milestones rather than being pulled into v0.6.

### Machine enforcement

`tools/check_component_maturity.py` and its regression tests enforce the component ledger in canonical repository validation. At minimum the checker must reject:

- unowned workspace/planned components;
- duplicate component ownership;
- missing paths or inconsistent workspace declarations;
- release artifacts without valid binary identity;
- roadmap scaffolds packaged as release artifacts;
- release/image binary drift from the ledger;
- proposal-only agent components gaining privileged authority roles;
- invalid maturity or milestone relationships.

The machine roadmap remains the source of milestone sequencing; the component ledger records which component becomes active at which milestone.

## Consequences

### Positive

- Repository structure can remain broad without pretending every directory is implemented product surface.
- Future architecture can be scaffolded without silently widening release claims.
- Packaging, documentation and roadmap language can be checked against explicit maturity facts.
- Component activation becomes reviewable and auditable rather than being inferred from commits.
- First Boot, agents, hardware and UI work can stay out of v0.6 while retaining explicit future ownership.

### Costs

- Adding or materially activating a component requires updating the component contract and its tests.
- Release/image changes are now architecture changes that must agree with maturity declarations.
- Some existing broad documentation must distinguish vision/future topology from current integrated runtime.

## Rejected alternatives

### Treat every workspace member as active

Rejected. The workspace intentionally contains future and foundation components; compilation is not maturity evidence.

### Track maturity only in prose

Rejected. Prose alone cannot reliably prevent a placeholder from reappearing in packaging or an unowned component from drifting between milestones.

### Delete all future scaffolds until implementation begins

Rejected. Early typed boundaries and ownership can be useful architecture, provided their maturity and activation are explicit and they cannot be mistaken for shipped capability.

### Use release packaging as the only maturity signal

Rejected. Many integrated crates are not standalone artifacts, while some safety/tooling binaries can be release artifacts without representing a broad end-user feature. Maturity and packaging are related but distinct facts.
