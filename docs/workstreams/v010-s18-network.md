# S18 WIP engineering reference — NetworkManager connectivity experience

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s18-network`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

The repository already ships a bounded `NetworkManagerObserver` in `crates/linura-linux-observation/src/lib.rs` with `networkmanager.manager.observe` / `networkmanager.device.observe` capabilities; the v0.10 profile discovery also checks for a managed non-loopback device. Reuse the canonical `ObservationEnvelope`, Control aggregation, registered operation semantics, shell host and UI SDK. This is NOT a production connection editor or credential-management capability.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Current WIP implementation checkpoint — observation safety baseline

- **Code state:** Incremental read-only implementation under this WIP branch; **not** a complete S18-1 capability, native acceptance result, or merge proposal.
- **Native owner:** Resolve the actual NetworkManager system-bus unique owner before manager/device reads, address object reads to that owner, then reject an observed owner replacement. This is one owner-epoch guard, not an atomic cross-object snapshot.
- **Devices:** Enforce a 128-row post-decoding enumeration limit, bounded interface identifiers, duplicate-interface and duplicate-object-path denial, and a second identity mapping check before publishing a device envelope. The list bound alone does **not** impose a D-Bus wire-byte limit or transport deadline.
- **Existing contract:** Retain manager and `networkmanager:device:<interface>` query aliases and canonical Control observation. Report owner and selected native radio/config references as correlation attributes, **not** permissions or effect identities. No new mutation or active scan is registered.
- **Initial regression cases:** Pure tests cover duplicate aliases/paths, oversized enumeration, invalid interface names, owner-epoch mismatch, and property text bounds; they do not replace real NM restart/rename/hotplug/timeout fixtures.
- **Observed predecessor validation:** A discarded standalone PR candidate failed multiple exact-head workflows because a zbus proxy borrowed a D-Bus object path while its value was moved (`E0505`). The branch integration explicitly drops that proxy before moving the path. All checks must be rerun on **this WIP head** before asserting the fix or any test success.
- **Outstanding:** Complete typed AP/SSID scan results, saved/active profiles, IPv4/IPv6, DNS, routes, radio/device state, provider generation coherence, bounded native transport/deadlines, repeatable negative fixtures and qualification. Preserve the Phase-1 specifications as the architecture record; this checkpoint does not promote support.

This branch is the **single ongoing S18 WIP workspace**. A previously opened PR (#267) was closed unmerged because implementation PR extraction was premature. Do not infer a PR plan, reviewed status, or permission to merge from this checkpoint.

## S18-2 native-observation WIP checkpoint — November 1, 2026

- **Source:** Read-only native NetworkManager observation improvements are implemented on `wip/v010-s18-network`; **S18-2 is still incomplete**, not a production or review-ready capability.
- **Concrete changes:** The existing manager/device resource aliases are preserved; `GetDevices` identities are read from unique-owner `GetAll` snapshots rather than property-cache lookups; duplicate name/path and oversized post-decoded device lists are rejected; selected device mappings and service owner are rechecked.
- **Boot and time:** Read-only observations now include the current kernel boot ID and reject changed boot/NetworkManager owner epochs; an elapsed-time guard denies results older than the two-second snapshot window. It is **not** a D-Bus transport deadline, raw message size limit, or atomic multi-object proof.
- **Additional hints:** Device `IpInterface`, `Mtu`, `Autoconnect` and `FirmwareMissing` are conditionally exposed as typed read-only attributes. They **do not** establish working DNS, default route, Wi-Fi association, reachability, or a mutation identity.
- **First WIP check:** The branch-scoped `S18 WIP validation` workflow on commit `957d3b478fb0cdd817efdc43d26a1cb2ba67c5b3` passed Rust formatting, `linura-linux-observation` and `linura-observation-control` tests, and native-observer Clippy. It identified a test argument error in `test_v010_s18_decomposition.py`, corrected in the next WIP commit. These are developer feedback, **not** canonical exact-head release gates.
- **Blocking work:** True receive/decode-byte and transport deadline caps, fully typed AP/profile/active-connection/IP/DNS/routes with bounded privacy-safe projection, coherent native NM snapshots under daemon/device churn, adversarial real NM fixtures, complete S18-3–S18-10 authority, security, managed effects, UX and qualification, mandatory source-pinned A/B testing, maintained physical C/Q11 and inherited canonical CI/security qualification are still unqualified.
- **Workflow:** `.github/workflows/wip-s18-validation.yml` is a branch-only development check, not an alternative to the required CI or qualification rules. No PR is opened or changed by these WIP commits; `#267` remains a reserved draft outside this branch.

## Exact resource, identity and observation requirements

Bind the live `org.freedesktop.NetworkManager` unique D-Bus owner, manager/device/active-connection/settings object generation, native interface identity, boot/session/seat as needed and fresh connectivity, IP/DNS/route observations. Interface names, SSIDs, BSSIDs, UUID strings and object paths on their own are not authorization identities; scan results and cached connection profiles cannot establish current link state. Explicitly distinguish unowned/unmanaged interfaces, absent radios, airplane mode, portal connectivity and daemon restarts.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Queries (adapter/device/link/connection state and passive Wi-Fi scan results) are `AuthoritativeQuery`; requesting a fresh active Wi-Fi scan is an external effect requiring separate classification and qualification; purely local panel selection is `ExperienceEphemeral`. Candidate toggles, connect/disconnect and profile edits require separate trusted descriptors and risk classification. Any privileged connection/profile mutation, durable desired state or uncertain activation is `ManagedExternalEffect`, with one Control-owned authorization/preparation path; never turn a client D-Bus call into an implicit transient shortcut. Do not implement raw NM method forwarding or unrestricted secrets.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Present owner-bound available networks and wired links, explicit stale/provider-unavailable state, Wi-Fi/radio controls only when qualified, connection profile inspection and a deterministic review of DNS/route consequences. Secret entry uses protected local facilities; never persist Wi-Fi passwords in intent, plan, audit, logs or model context. CLI/SDK/Control Center/Quick Settings must converge to the same operation identity and final verified state.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Unknown/vanished device; roaming/replaced access point; competing network-controller state; foreign authenticated principal; stale owner or session; NM restart; disconnect between authorization and dispatch; missing or changed secrets; portal/no Internet despite an activated link; partial DNS/route change; duplicate/late activation signal; timeout after an effect may have occurred; loss of all recoverable networking (protect an offline local recovery route); offline/no-model operation.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Adaptive decomposition into independently reviewed PRs

**No fixed PR count, fixed four-stage template or mandatory PR size.** This WIP branch is a reference workspace; an eventual implementation may require one, several or many PRs. Determine the actual number *for this slice* from its concrete code, architecture, dependencies, qualification gaps and review outcomes. The top-level v0.10 slice IDs in the canonical ledger must not be renumbered or multiplied just because implementation is divided into PRs.

Potential technical seams to evaluate, combine or subdivide as the implementation matures:

1. canonical bounded NM observation, identity/generation proof and negative parser tests; no mutation
2. trusted operation contracts, deterministic plans, policy and durable ambiguity/recovery models; inactive until qualification
3. narrow native NM executor plus independently sourced re-observation, commit/reconcile and protection of secrets
4. first-party network UX, CLI/SDK parity, keyboard/a11y, exact-source native and failure qualification

**Decision procedure before opening any PR:**

1. Inventory the actual changed code, callers, existing shared contracts, authority/security boundaries, native integration and dependency graph. Recheck S17/S21 and existing released/versioned behavior.
2. Separate independently reviewable and independently verifiable capabilities. Split at substantive ownership/trust/qualification boundaries or when one PR cannot be properly reviewed; combine tightly coupled edits when extracting either alone would leave an unusable or incoherent contract.
3. Make a slice-specific ordered PR plan with explicit base/dependency, active vs inactive operation state, acceptance tests, native evidence and rollback/recovery obligations. Revise its count when findings materially change the boundaries; never inflate or force a fixed quota.
4. Extract cohesive implementation and its negative tests together onto a fresh, accepted `main` base. Keep unfinished effects inactive, no speculative bypasses or placeholders masquerading as working providers. Run mandatory exact-head gates and resolve reviews for *each* PR.
5. Only after dependent PRs merge should the canonical ledger record dependency-closed, merged evidence. WIP commits, documents, CI results or partial qualification are not production support.

These are **capability seams, not PR-A–D promises**. Some seams may produce multiple PRs (for example separate authentication, executor, recovery or native qualification); others may merge into one coherent PR. No PRs are created from this document.

## Acceptance evidence and nonclaims

Pinned Arch/NetworkManager system-bus identity; real managed Ethernet and Wi-Fi or explicitly unsupported hardware paths; device/seat changes, DNS/routes, daemon loss and reconnect, expired evidence, partial activation and no-replay recovery. Capture exact trace from authenticated principal through plan/policy, prepare, native effect, independent result and audit. VM virtual networking must not masquerade as physical Wi-Fi qualification.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S18, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/network/, proposed crates/linura-provider-networkmanager/, narrow Linux observation adapter, Control registry/plan/policy, CLI/SDK and applicable v0.10 qualification.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
