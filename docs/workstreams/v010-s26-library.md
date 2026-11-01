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

## Intended extraction into independently reviewed PRs

1. PR-A — versioned read/query and revision-graph projections reusing existing local Library
2. PR-B — typed editing/import/export and CAS with integrity, causal ownership and recovery tests
3. PR-C — deterministic plan/impact/adoption UI converging on canonical Control semantics
4. PR-D — first-party Library/Setups/MachineProfiles UX, accessibility and exact-source persistence/VM qualification

These are architectural cut lines, **not PRs and not fixed PR numbers**. As code matures, rebase/extract reviewed coherent commits onto fresh `main` branches, minimize the diff per real dependency, compact final PR history, and run all applicable exact-head checks. If a cut does not stand on its own safely, keep its later effect inactive until dependencies merge.

## Acceptance evidence and nonclaims

Use released v0.7/v0.9 deterministic SQLite/portable bundle tests as baseline and add restart/corruption/backup-restore, depth/cycle/owner, cross-platform unsupported mapping and no-model evidence. Native shell checks must confirm every rendered successful adoption reflects independent verified state and audit rather than imported receipts.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S26, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/library/, setups/, machine-profiles/, crates/linura-library/ as justified, and existing intent/persistence/Control contracts.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
