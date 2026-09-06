# Architecture Decision Records

Accepted ADRs are append-only historical decisions. A changed decision is superseded by a new ADR rather than silently rewriting the original record.

## Governance

- ADR filenames use a unique four-digit identifier: `NNNN-short-title.md`.
- The leading ADR number in the document heading must match the filename identifier.
- Every ADR file must appear exactly once in this index, and every index entry must resolve to an ADR file.
- Accepted decisions remain historical records. Material changes are recorded by a later ADR that explicitly supersedes or refines the earlier decision.
- Status values are case-insensitive but must be one of: `Proposed`, `Accepted`, `Superseded`, `Deprecated`, or `Rejected`.
- New ADR identifiers are monotonically allocated from the next unused number. Reusing an existing identifier is forbidden.

### Historical identifier normalization

On 2026-09-06, three previously accepted files that collided with already-used identifiers were renumbered without changing their decisions:

- repository-owned development/system-proof pipeline: `0012` → `0022`;
- build-once/promote-exact-bytes: `0013` → `0023`;
- native break-glass recovery: `0014` → `0024`.

This repairs the ledger identity while preserving the historical decision text. Future changes to those decisions must use new ADRs rather than another renumbering.

## ADR ledger

- [0001 — Rust 2024 for core/control processes](0001-rust-core.md)
- [0002 — No privileged monolithic daemon](0002-no-root-monolith.md)
- [0003 — Start with one explicit Arch/Hyprland profile](0003-platform-profile-first.md)
- [0004 — D-Bus local boundary; remote gateway later](0004-local-dbus.md)
- [0005 — No unsandboxed third-party plugins in control processes](0005-plugin-isolation.md)
- [0006 — Linura umbrella; authority/intelligence separation](0006-linura-umbrella.md)
- [0007 — Approved structured intent is durable source](0007-intent-is-durable-source.md)
- [0008 — System graph and semantic provenance are core](0008-system-graph-and-semantic-provenance.md)
- [0009 — Agent-native does not mean agent-dependent](0009-agent-native-not-agent-dependent.md)
- [0010 — Constrained derived UI](0010-constrained-derived-ui.md)
- [0011 — One Linura namespace](0011-one-linura-namespace.md)
- [0012 — Canonical trustworthy mutation lifecycle](0012-canonical-mutation-lifecycle.md)
- [0013 — Reusable setups and local-first Linura Library](0013-reusable-setups-library.md)
- [0014 — Version-scoped release contracts and machine-readable evidence](0014-release-contracts-and-evidence.md)
- [0015 — Isolated and independently reproducible release builds](0015-isolated-reproducible-release-build.md)
- [0016 — Machine classes and portable profile semantics](0016-machine-classes-portable-profiles.md)
- [0017 — Bounded probes and control-plane-owned context queries](0017-bounded-probes-context-query.md)
- [0018 — Canonical plan-review authority and exact approval binding](0018-canonical-plan-review-authority.md)
- [0019 — Durable authority transactions with SQLite/WAL persistence](0019-durable-authority-transaction-store.md)
- [0020 — Durable mutation authority is sealed across Control and persistence](0020-sealed-durable-mutation-authority.md)
- [0021 — v0.5 qualifies an isolated executor and pure verifier before lifecycle integration](0021-v0.5-isolated-executor-verifier-qualification.md)
- [0022 — Repository-owned development and system-proof pipeline](0022-repository-owned-development-pipeline.md)
- [0023 — Build once, promote exact release bytes](0023-build-once-promote-exact-bytes.md)
- [0024 — Native break-glass recovery is an invariant](0024-native-break-glass-recovery.md)
- [0025 — Component maturity and milestone activation are explicit contracts](0025-component-maturity-and-milestone-activation.md)
- [0026 — Bounded v0.6 managed mutation authority and Authority1 boundary](0026-bounded-v0.6-managed-mutation-authority.md)
