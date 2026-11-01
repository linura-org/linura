# S20 WIP engineering reference — Complete audio and media experience

> **Status: development reference only. No PR, operation registration, implementation completion, release claim or evidence promotion.**
>
> Origin: `main` commit `e867f5348f1a0b6833d0b622187e1213cac0039e`; branch `wip/v010-s20-audio-media`. This file intentionally lives **only** on that WIP branch. New implementation work must be independently reviewed and qualified before extraction into clean PRs.

## Authoritative scope and reuse

S08 already introduced `operation:audio.output.set-session-volume`, the `Session1.SetAudioOutputVolume` same-UID path, session-specific PipeWire/WirePlumber observation, root-owned pinned `linura-session-audio.lua` helper and fresh post-effect verification. Control Center and Quick Settings currently share one `AudioSessionController`. Extend that trusted model rather than adding `wpctl`, raw PipeWire or QML-side mutation shortcuts.

This workstream is defined by `contracts/v010-workstation-slices.toml`, `docs/milestones/v0.10.0.md`, ADR 0031/0032/0033 and `docs/qualification/v0.10.0.md`. S16 is the declared predecessor; completed code/merge evidence and separate physical Q11 release qualification are not interchangeable. A WIP branch is never merged into `main` directly.

## Exact resource, identity and observation requirements

Preserve exact PipeWire node ID + object serial + node name, user bus/boot/session and WirePlumber graph generation. Changing default sink is not an authorization to retarget a previous exact-sink draft. Source inputs, microphone capture, stream routes, profiles, mute and media players must have separate identities and freshness; MPRIS player metadata/status are not proof of an audio graph mutation. Validate app/protocol caller and avoid leaking mic/device metadata.

Provider and transport objects are adapter mechanisms, not domain authority. Canonical `linura-observation::ObservationEnvelope` and Control-side resolution own freshness/identity decisions. Duplicate, missing, contradictory or stale proof must be visible as unavailable or indeterminate.

## Operation semantics and authority boundary

Existing output-volume transient effect retains its established operation ID and limited `UserState` semantics. New mute, default-route, profile, microphone or stream operations require independently classified, registered contracts; privileged, privacy/security-impacting or persistently ambiguous operations remain managed/unsupported. Playback navigation may be unprivileged experience integration only for explicit eligible player identity; it must not infer system Control authorization from an MPRIS transport.

A mutable effect must follow the exact Control-owned trusted descriptor, authenticated principal, canonical plan, policy and trusted risk floor. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`. No raw commands, ambient credentials, arbitrarily forwarded D-Bus methods or model-selected permits. Qualified transient paths, if any, still require fresh preconditions, narrow unprivileged execution, independent verification and audit.

## Workstation experience and accessibility

One current-session authoritative audio graph across panel, Control Center, Quick Settings and OSD; safe sink/source selection, volume and mute, mic privacy state, stream routing when qualified, media session list and playback controls. Separate observed state from a user draft; reobserve before dispatch and after response; report 'unverified' rather than optimistic success. Preserve independent no-model CLI/SDK functionality.

The first-party ShellBridge and shared `org.linura.UI` SDK are presentation/adaptation boundaries only. Keyboard/pointer/screen-reader/reduced-motion/HiDPI and offline/no-model paths are required. An optimistic UI receipt is never authoritative success.

## Required adversarial and regression coverage

PipeWire node recycling, object-serial drift, switched default, moved stream, muted vs zero volume, broken mixer helper, same-UID foreign session, stale session owner, untrusted media metadata, player disappeared after selection, permission denial, lost observer, async receipt without postcondition, failure to regain session on restart, microphone activation without supported privacy policy.

Test policy denial, missing provider, unsupported hardware, actor/seat/session/boot substitution where applicable, before/after-effect crash, dispatch ambiguity, daemon replacement and exact source pinning. Preserve all S17/S21 lock, power, display and recovery protections plus inherited v0.4/v0.6/v0.9/v0.10 gates; do not delete, skip or weaken checks.

## Intended extraction into independently reviewed PRs

1. PR-A — audited reusable audio graph/source/stream/MPRIS observation and exact identity
2. PR-B — separately registered bounded controls (mute/profile/route/microphone as justified), independent verification and audit
3. PR-C — media player presentation/control integration and consistent audio UX without second effect paths
4. PR-D — native PipeWire/WirePlumber/MPRIS/Qt runtime, input/a11y, failure and physical Q11 qualification

These are architectural cut lines, **not PRs and not fixed PR numbers**. As code matures, rebase/extract reviewed coherent commits onto fresh `main` branches, minimize the diff per real dependency, compact final PR history, and run all applicable exact-head checks. If a cut does not stand on its own safely, keep its later effect inactive until dependencies merge.

## Acceptance evidence and nonclaims

Exact-source pinned Arch and user-session graph, real PipeWire/WirePlumber with multiple sinks/sources and route changes; failure and restart cases, cross-session rejection, post-effect evidence, same CLI/GUI operation identity. Virtual sinks prove only fixture cases; maintain physical Q11 for supported real audio path. Preserve S08/S13/S15/S16 qualified behavior and contract fingerprints.

WIP tests do not establish experimental support, production readiness, hardware proof or v0.10 release status. Before completing S20, record dependency-closed, merged-PR evidence in the canonical slice ledger and retain the proper native/visual/security/recovery artifact identities. Do not set `interactive_workstation.evidence_ready` or any Q10/Q11 readiness marker on the basis of this plan.

## Owned implementation areas to inspect before editing

apps/linura-shell/plugins/audio/, apps/linura-shell/plugins/media/, apps/linurad/src/session_audio.rs (only when justified), WirePlumber helper, Control/SDK and native audio qualification.

Before runtime changes: read scoped `AGENTS.md` and `agents/skills/` guides; perform full consumer/regression-impact analysis, threat review, then tests and implementation. For authority or security work, read `SECURITY.md`, `docs/security-model.md`, `docs/agent-architecture.md` and `docs/vision-coverage.md`. Preflight the pinned development environment and do not claim CI or physical tests that have not run.
