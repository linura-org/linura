# ADR 0011: Linura owns the product and code namespace

Status: Accepted

## Decision

Linura is the only proper-noun umbrella brand. The control plane remains an architectural concept implemented by `linura-control`; it does not receive a second product brand.

Public and system namespaces use Linura consistently: `linura-*`, `linurad`, `linuractl`, and `org.linura.*`.

`linura.org` is the authority anchor for the canonical reverse-DNS namespace `org.linura`. Repository-owned public identifiers are allocated through `contracts/namespaces.toml`; external registry/store ownership is tracked separately in `docs/ecosystem-registry.md`.

`Linura OS` is reserved for the installable distribution product. Linura Control and the SDK remain capable of targeting supported non-Linura-OS Linux platform profiles.

## Rationale

A single namespace reduces user and contributor cognitive load, avoids duplicated compatibility/version identities, and preserves the ability to explain the architecture precisely without turning architecture terminology into separate brands.

Separating internal identifier allocation from external registry ownership also prevents a source-level reservation from being misrepresented as an npm, crates.io, PyPI, Flathub, AUR, container-registry, or store publication claim.

## Consequences

- The authority crate is named `linura-control`.
- Developer-facing stable types are exposed through `linura-sdk` rather than requiring direct coupling to internal authority crates.
- Product application directories carry explicit Linura names.
- Architecture documentation uses “control plane” and “authority plane” as common nouns.
- D-Bus, desktop/AppStream, QML, Polkit and related reverse-DNS identifiers use `org.linura.*`.
- systemd units and first-party local components use the established `linura-*`, `linurad`, and `linuractl` roots.
- `cargo xtask check` validates active repository namespace surfaces against `contracts/namespaces.toml`.
- External ownership state is updated only when the corresponding provider actually grants or publishes the identity.
