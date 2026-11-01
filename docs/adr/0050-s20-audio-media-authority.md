# ADR 0050 — S20 current-session audio, microphone privacy and media control authority

- Status: Proposed
- Scope: v0.10 S20, `arch-hyprland-v1`; dependency S16
- Refines: ADR 0012, ADR 0017, ADR 0018, ADR 0024, ADR 0031, ADR 0032 and ADR 0033
- Preserves: accepted S08 exact-sink PipeWire volume implementation and the published `Session1.SetAudioOutputVolume` contract
- Companion: [inactive proposed design](../../contracts/v010-s20-design.toml), [domain qualification](../qualification/v0.10.0-s20.md), [security qualification](../qualification/v0.10.0-s20-security.md)
- ADR number is a WIP proposal and must be reconciled with the append-only global ADR ledger when extracting its implementation PR.

## Context and decision

S20 completes the audio/media experience without creating a second control plane. Unlike the earlier S18/S19 workstreams, the repository already implements a **real, registered** `operation:audio.output.set-session-volume` under the `pipewire` provider. The `audio.session.observe` authoritative observer enumerates `Audio/Sink` nodes using a reviewed WirePlumber helper; `Session1.SetAudioOutputVolume` takes exact numeric node ID and canonical 0–100 integer percentage. `TransientEffectControl` owns trusted operation/policy classification, pre-dispatch state, post-dispatch independent observation and bounded SQLite/WAL audit. The native helper resolves the exact node ID + `object.serial` + `node.name` within one WirePlumber event-loop turn, with packaged-helper immutability and sealed execution.

This existing registered implementation is **not** an indication that all S20 audio controls are present or that physical Q11/release support has been promoted. Do not change its operation ID, privilege boundary, 0–100 non-amplified mapping, exact-node verification, package/helper security or current-session authenticated same-UID caller semantics to make future controls easier. A client-supplied "default" sink remains query/navigation, not an effect target.

**Decision:** All new audio/media actions require trusted, typed, independently qualified semantics within the same Control-owned operation architecture. The accompanying `contracts/v010-s20-design.toml` contains only **inert candidate operations**. It does not register, enable, change risk or make any new effect executable. The existing output-volume registration must remain intact; a new input/mute/route/media action cannot inherit its permission, risk floor or temporary-effect proof merely by sharing the audio domain.

## Exact session, graph and object identities

Use the selected logind session, authenticated owning Unix UID, boot and actual user-bus peer identity; verify PipeWire core/WirePlumber manager generation and the exact `node.id`, `object.serial`, `node.name`, `media.class` and target device/port/stream identity before dispatch and after effect. Node ID, port name, object path, visible display name, "default" alias and application label alone are **not** authority identities. Recycled nodes and changed WirePlumber graph invalidate all derived permits.

Output/sink, input/source, capture stream, playback stream, device, profile, route, hardware/software mute, volume and default-device metadata are **different** typed resources and postconditions. Current output volume semantics do not confer permission to change capture, reroute microphone input, activate a profile, adjust input gain or control another session. PipeWire's configured default alias is not an atomic guarantee of active per-stream routing; routing must verify actual graph links/stream target and device profile when requested. Provider states may change concurrently; reject contradictory/mixed snapshots rather than assuming an atomic graph.

For MPRIS, enumerate the current user session bus's actual `org.mpris.MediaPlayer2.*` **unique owner**, current player instance/track identity, capability flags and change generation. A reusable well-known name, metadata/cover-art URL, player title, track ID or forged `CanGoNext` field cannot grant access to another player or a privileged path. Treat MPRIS metadata, artwork URLs, titles, track names, external links and URI fields as **untrusted presentation data**: bound lengths, escape markup, disallow arbitrary fetching/opening or rich text injection from metadata, and do not surface raw error strings. MPRIS media state is not PipeWire graph evidence.

## Audio classes and user consequences

The already registered output-volume action remains the qualified code-path **candidate for `TransientExternalEffect`** with trusted `UserState` risk under its exact existing operation. New output mute; default output selection; input volume/mute; default capture selection; stream routing; device profile; and player playback/seek are distinct proposed effects. They are conservatively proposed as managed until native proof permits independently reviewed transient classification for a precisely bounded unprivileged at-most-`UserState` action. In particular microphone capture, input routing, privacy-sensitive changes, persistent device/profile selection and any effect whose outcome survives loss of the caller require managed semantics or must remain unsupported. No implicit lower-risk `Session1` expansion.

An output "mute" is not simply 0% volume. A microphone being muted is **not** proof that no process can obtain/capture raw audio; privacy-facing indicators must distinguish hardware privacy switch, stream capture activity, permission grants and software mute where those facts can be independently observed. Do not promise a microphone kill switch without proving the exact inhibition mechanism and all supported capture routes. Remote MPRIS playback is not pure GUI navigation: Play/Pause/Next/Previous/Seek are external app/player effects even when unprivileged; require current owner, capability/precondition, trusted user-session request and bounded independent post-effect player observation. A media-key event must not call arbitrary user-specified D-Bus methods or cause a privileged Linura mutation.

For each later managed candidate require the complete Control lifecycle: request, observe, plan, validate, authorize, durable prepare, narrowly bounded execute, independently verify, commit, audit and reconcile. A later transient candidate can only use the existing bounded transient Control substrate once registered exact plan/risk and strictly newer native post-effect verification, durable attempt audit, authenticated unprivileged subject, and no indeterminate durable recovery need are proven. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`.

## Provider, caller and executor boundaries

`PipeWireSessionObserver` and `ObservationCoordinator` retain authoritative observation ownership; new helpers must not introduce an independent provider cache or conflicting authority. The same-UID authenticated `Session1` principal is not a global administrator or arbitrary PipeWire process owner. Any new native operation must use an independently reviewed purpose-bound adapter/helper and input contract: no `wpctl` shell commands, untrusted Lua scripts, arbitrary process invocation, unrestricted PulseAudio/PipeWire API forwarding, raw D-Bus method relay or direct QML mutation. Preserve S08 installed helper root/host integrity, no-follow descriptor acquisition, trusted embedded bytes, sealed anonymous execution, scrubbed environment, strict SQLite audit layout and bounded error diagnostics.

MPRIS is primarily a separately owned *user-session* provider, not a privileged system service; current player identity and user-bus authorizations must be re-established on each proposed effect. Do not impersonate another UID or infer application trust from the player name. Media metadata and input/capture permissions are not model/system authority.

## Recovery and UX

A PipeWire/WirePlumber restart, audio-device unplug, route change, default sink flip, player disappearance or lost callback invalidates pending identity, user draft and authority. An executor receipt, mixer queue acknowledgement or MPRIS method return cannot become "verified" UI state without the native observation postcondition. Crash/restart/timeout with possible durable mutation remains indeterminate; re-observe, never blindly reapply. Preserve existing output-volume audit behavior exactly.

Control Center, Quick Settings, OSD, media controls and CLI/SDK project one typed machine state and operation ID/risk per supported effect, with keyboard/pointer/screen-reader/reduced-motion/HiDPI, visible unavailable/unknown and no-model operation. Session lock and protected-input coverage under S17 and audio-device coexistence with S19 Bluetooth pairing must not be bypassed. Microphone metadata, app titles, media artwork and device names are privacy/untrusted data and cannot become root or rendering authority.

## Qualification and nonclaims

[Domain acceptance](../qualification/v0.10.0-s20.md) and [security acceptance](../qualification/v0.10.0-s20-security.md) refine v0.10 Q9–Q14. Preserve inherited v0.1/v0.4/v0.6/v0.9, S08 volume, S17 security-owner, S21 display/power and immutable exact-source gates. A VM PipeWire virtual sink and MPRIS fixture may prove its exact scope, **not** a real microphone/privacy switch, physical sound device or Q11. The existing volume control remains unpromoted where required physical evidence is missing. No candidate S20 effect is activated or considered qualified by this record.

Implementation and eventual PR extraction are based on actual independent observation, security, native execution/recovery, MPRIS and user-interface boundaries; no fixed PR count is established.
