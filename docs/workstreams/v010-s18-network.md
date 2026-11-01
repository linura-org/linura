# S18 WIP engineering reference — NetworkManager connectivity experience

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s18-network`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

The repository already ships a bounded `NetworkManagerObserver` in `crates/linura-linux-observation/src/lib.rs` with `networkmanager.manager.observe` / `networkmanager.device.observe` capabilities; the v0.10 profile discovery also checks for a managed non-loopback device. Reuse the canonical `ObservationEnvelope`, Control aggregation, registered operation semantics, shell host and UI SDK. This is NOT a production connection editor or credential-management capability.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Bind the live `org.freedesktop.NetworkManager` unique D-Bus owner, manager/device/active-connection/settings object generation, native interface identity, boot/session/seat as needed and fresh connectivity, IP/DNS/route observations. Interface names, SSIDs, BSSIDs, UUID strings and object paths on their own are not authorization identities; scan results and cached connection profiles cannot establish current link state. Explicitly distinguish unowned/unmanaged interfaces, absent radios, airplane mode, portal connectivity and daemon restarts.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Queries (adapter/device/link/connection state, Wi-Fi scan) are `AuthoritativeQuery`; purely local panel selection is `ExperienceEphemeral`. Candidate toggles, connect/disconnect and profile edits require separate trusted descriptors and risk classification. Any privileged connection/profile mutation, durable desired state or uncertain activation is `ManagedExternalEffect`, with one Control-owned authorization/preparation path; never turn a client D-Bus call into an implicit transient shortcut. Do not implement raw NM method forwarding or unrestricted secrets.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

Present owner-bound available networks and wired links, explicit stale/provider-unavailable state, Wi-Fi/radio controls only when qualified, connection profile inspection and a deterministic review of DNS/route consequences. Secret entry uses protected local facilities; never persist Wi-Fi passwords in intent, plan, audit, logs or model context. CLI/SDK/Control Center/Quick Settings must converge to the same operation identity and final verified state.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

Unknown/vanished device; roaming/replaced access point; competing network-controller state; foreign authenticated principal; stale owner or session; NM restart; disconnect between authorization and dispatch; missing or changed secrets; portal/no Internet despite an activated link; partial DNS/route change; duplicate/late activation signal; timeout after an effect may have occurred; loss of all recoverable networking (protect an offline local recovery route); offline/no-model operation.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Intended extraction into independently reviewed PRs

1. PR-A — canonical bounded NM observation, identity/generation proof and negative parser tests; no mutation
2. PR-B — trusted operation contracts, deterministic plans, policy and durable ambiguity/recovery models; inactive until qualification
3. PR-C — narrow native NM executor plus independently sourced re-observation, commit/reconcile and protection of secrets
4. PR-D — first-party network UX, CLI/SDK parity, keyboard/a11y, exact-source native and failure qualification

These are architectural cut lines, **not PRs and not fixed PR numbers**. As code matures, rebase/extract reviewed coherent commits onto fresh `main` branches, minimize the diff per real dependency, compact final PR history, and run all applicable exact-head checks. If a cut does not stand on its own safely, keep its later effect inactive until dependencies merge.

## Acceptance evidence and nonclaims

Pinned Arch/NetworkManager system-bus identity; real managed Ethernet and Wi-Fi or explicitly unsupported hardware paths; device/seat changes, DNS/routes, daemon loss and reconnect, expired evidence, partial activation and no-replay recovery. Capture exact trace from authenticated principal through plan/policy, prepare, native effect, independent result and audit. VM virtual networking must not masquerade as physical Wi-Fi qualification.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S18, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/network/, proposed crates/linura-provider-networkmanager/, narrow Linux observation adapter, Control registry/plan/policy, CLI/SDK and applicable v0.10 qualification.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
