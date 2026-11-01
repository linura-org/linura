# S20 — implementation work-in-progress evidence and remaining gates

**Branch:** `wip/v010-s20-audio-media` only. No S20 PR extraction, approval, merge, release, support promotion or new operation registration.

## Added native read-only observation (unqualified)

- `pipewire-graph` provider: fixed `/usr/bin/pw-dump --no-colors` (machine JSON, never interpreted as commands), cleared process environment, same-UID private XDG runtime, process timeout, bounded stdout/stderr and object counts; no mutation method.
- Strict projection of exact PipeWire object ID and `object.serial` for audio sink/source and playback/capture stream nodes, directly attached devices, ports and independently reported links. Link endpoints are checked against the actual graph port/node identities.
- Presentation labels are bounded and HTML-escaped. Raw PipeWire JSON, application identifiers, arbitrary properties, privacy-sensitive labels, shell commands and credentials do not enter canonical observations.
- Observations explicitly say `snapshot_atomic = false` and `capture_privacy_verified = false`. A PipeWire link is **not** capture authorization or proof of a recording app's privacy state.
- Existing `audio.session.observe` S08 sink/volume provider and immutable WirePlumber helper remain unchanged. The graph observer has a separate ID and cannot register effects.
- `mpris` player observer remains a separate current-UID session-bus provider. Its five test-site `unwrap()` occurrences identified by CI were replaced with repository-standard panic-explicit test assertions; production D-Bus auth and operation scope are unchanged.

## What this change does NOT implement

- No source gain/mute, microphone permission/inhibition or hardware-privacy assertion
- No default output/input selection, per-application route mutation, card profile activation or recovery
- No MPRIS Play/Pause/Next/Previous/Seek dispatch
- No Control Center/Quick Settings/OSD native end-to-end media controls beyond the existing S08 output-volume baseline
- No qualified A/B/C hardware/visual/rollback evidence, no S20 milestone closure

The twelve proposed operations in `contracts/v010-s20-design.toml` remain inert; this branch must not be advertised as production-ready. The current generic CLI/SDK observation path can consume newly exposed capabilities after they pass native tests.

## Mandatory follow-up acceptance

1. Run pinned preflight and `cargo xtask check` on the **WIP exact head** with Rustfmt, Clippy, Rust unit tests and tooling contracts. No separate PR is authorized for this purpose.
2. Exercise a real Arch/Hyprland PipeWire user runtime with multiple audio sinks, sources, playback and recording streams, devices and route links. Verify missing/foreign ports, object-ID reuse, changed serial, timeout, crashed provider and systemd sandbox permissions; the native JSON adapter is not yet qualified.
3. Revalidate MPRIS behavior against real session bus and players: unique-owner rebinding, bus restart, user mismatch, malicious metadata and unsupported player.
4. Add individually authorized and separately verified new audio/microphone/MPRIS operation families behind the registered trusted Control contracts; do not bypass the managed authority or promote candidate flags.
5. Connect GUI/CLI/SDK and accessibility to the exact approved Control path. Prove negative state and no optimistic success.
6. Collect exact-source A, interactive B and maintained physical C/Q11 acceptance. VM and mock evidence cannot prove physical audio hardware or capture privacy.

**Safety:** Stale, contradictory or unsupported graph state is a read-only observation failure, never permission for an effect. The existing S08 transient effect is not broadened.