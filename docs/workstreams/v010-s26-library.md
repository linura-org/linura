# S26 WIP engineering reference — Library, Setups and MachineProfiles workstation workflows

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s26-library`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

v0.7 already released durable local intent/Setup/MachineProfile revisions, integrity-checked deterministic portable bundles, import/adopt and backup/restore, with causal ownership/removal-impact. Work with `crates/linura-intent`, existing persistence/Library and first-boot APIs; do not create a new catalog database or incompatible UI-specific objects. MachineProfile, PlatformProfile and QualificationEnvironment are distinct.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Every UI selection binds stable object ID, immutable revision, content digest and authenticated local principal. Imported bundle content is untrusted and has no approval, executor or retained credential authority. Preview must use exact current target observation and platform/capability resolution and preserve provenance chains; revision IDs, titles and display order are not proof that content remains unchanged.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Catalog search, revision compare and impact preview are `AuthoritativeQuery` or pure nonauthoritative projections as appropriate; UI navigation is `ExperienceEphemeral`. Save/rename/version/import of Linura-owned objects uses typed `LinuraOwnedState` durability/CAS and independent readback. Adoption of configurations is NOT a direct library effect: fresh canonical planning, risk/policy, trusted operation registry, approval where needed and per-effect lifecycle are mandatory.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Create/edit/save new immutable Setup and MachineProfile revisions; compose dependency graphs, detect cycles, compare versions and diff current machine; explain why resources are owned; export/import with integrity, secret references and explicit user review; dry-run and adopt with fresh plan, visible unresolved requirements and reversible cleanup impact. Keep complete CLI/SDK/no-model parity and path independent of hosted sync.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Malformed/oversized bundle, duplicate ID with conflicting digest, cycle/depth explosion, stale revision CAS, tamper/corrupted SQLite/WAL, interrupted import, local backup/restore mismatch, shared-resource removal, secret material embedded in export, foreign-machine-specific realization, unsupported profile, stale observed machine state, malicious operation-class downgrade, replay of historical approval/effect, duplicate adoption, offline provider.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Adaptive decomposition into independently reviewed PRs

**No fixed PR count, fixed four-stage template or mandatory PR size.** This WIP branch is a reference workspace; an eventual implementation may require one, several or many PRs. Determine the actual number *for this slice* from its concrete code, architecture, dependencies, qualification gaps and review outcomes. The top-level v0.10 slice IDs in the canonical ledger must not be renumbered or multiplied just because implementation is divided into PRs.

Potential technical seams to evaluate, combine or subdivide as the implementation matures:

1. versioned read/query and revision-graph projections reusing existing local Library
2. typed editing/import/export and CAS with integrity, causal ownership and recovery tests
3. deterministic plan/impact/adoption UI converging on canonical Control semantics
4. first-party Library/Setups/MachineProfiles UX, accessibility and exact-source persistence/VM qualification

**Decision procedure before opening any PR:**

1. Inventory the actual changed code, callers, existing shared contracts, authority/security boundaries, native integration and dependency graph. Recheck S17/S21 and existing released/versioned behavior.
2. Separate independently reviewable and independently verifiable capabilities. Split at substantive ownership/trust/qualification boundaries or when one PR cannot be properly reviewed; combine tightly coupled edits when extracting either alone would leave an unusable or incoherent contract.
3. Make a slice-specific ordered PR plan with explicit base/dependency, active vs inactive operation state, acceptance tests, native evidence and rollback/recovery obligations. Revise its count when findings materially change the boundaries; never inflate or force a fixed quota.
4. Extract cohesive implementation and its negative tests together onto a fresh, accepted `main` base. Keep unfinished effects inactive, no speculative bypasses or placeholders masquerading as working providers. Run mandatory exact-head gates and resolve reviews for *each* PR.
5. Only after dependent PRs merge should the canonical ledger record dependency-closed, merged evidence. WIP commits, documents, CI results or partial qualification are not production support.

These are **capability seams, not PR-A–D promises**. Some seams may produce multiple PRs (for example separate authentication, executor, recovery or native qualification); others may merge into one coherent PR. No PRs are created from this document.

## WIP implementation checkpoint — source, not qualification

The WIP branch now contains actual additive source for:

- S26-1 bounded transactional pages for existing Intent, Setup and Profile
  identities, typed SDK exposure, immutable exact-closure inspection digests.
- S26-2 pure identity/base-revision-checked editor draft preparation and
  deterministic revision-field comparisons. Existing released CAS saves remain
  the only local commit path; this work does not create an authenticated UI save.
- S26-3 in-memory deterministic portable export preview plus untrusted
  setup/profile import decoding and native collision/missing-ref preflight;
  filesystem publication and authenticated local commit are not wired.
- S26-4 read-only bounded backup validation and digest. Destructive live
  restore remains inactive; released restore alone does not prove quiescence.
- S26-5 blocked-or-needs-fresh-Control-plan readiness projection, with
  separate machine effect authority deliberately inactive.
- S26-6 staged first-party QML presentational views and an offline read-only
  CLI using the released SQLite Library, with explicit local-only labeling.

Added native tests cover revision history/CAS, profile revision references,
portable roundtrips/tampering, non-mutating preflight, read-only database
opening, file backup validation, malformed files and symlink rejection.
Source-level structural inspection was performed, not full compilation.

**Remaining critical gaps:** Verified authenticated owner/current DB epoch in
ShellBridge; complete graph/ownership review surfaced into the GUI; safe,
descriptor-bound managed file publication and quiescent destructive recovery;
fresh real target observation plus canonical Control plan and domain-only
execution; wired fully operable keyboard/screen-reader/high-DPI experience,
CLI/SDK parity beyond listing, real SQLite concurrency/crash fault injection,
exact-head rustfmt/Clippy/native/VM qualification and maintained physical
Q11 for supported effects. Do not advance the v0.10 ledger or mark S26
production-ready on WIP source or static checks.

**Branch rule:** All remaining work stays on
wip/v010-s26-library. No PR opening, merging, retargeting or rebuilding
until explicitly requested. Existing reserved #271 must remain untouched.

## Acceptance evidence and nonclaims

Use released v0.7/v0.9 deterministic SQLite/portable bundle tests as baseline and add restart/corruption/backup-restore, depth/cycle/owner, cross-platform unsupported mapping and no-model evidence. Native shell checks must confirm every rendered successful adoption reflects independent verified state and audit rather than imported receipts.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S26, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/library/, setups/, machine-profiles/, crates/linura-library/ as justified, and existing intent/persistence/Control contracts.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
