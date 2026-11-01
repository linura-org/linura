# S20 — implementation PR extraction and acceptance contract

**State:** proposed implementation plan on the S20 WIP branch. This record does not itself register or enable a capability, execute a test, complete a PR, qualify Q11 or change `main`. The machine-readable companion is [`contracts/v010-s20-pr-extraction.toml`](../../contracts/v010-s20-pr-extraction.toml). Existing [Phase 1](v010-s20-audio-media-phase1.md), [ADR 0050](../adr/0050-s20-audio-media-authority.md), [inactive candidate design](../../contracts/v010-s20-design.toml), [domain qualification](../qualification/v0.10.0-s20.md) and [security qualification](../qualification/v0.10.0-s20-security.md) remain the source requirements, subject to reconciliation with newer accepted `main`.

## Decision and safety invariants

Five **planning identifiers**, not allocated GitHub PR numbers. A unit can be split if native evidence exposes a distinct authority or recovery boundary; combine only if separation would leave incomplete or unreviewable behavior. No WIP branch is merged as a substitute for individually qualified implementation PRs. Each implementation PR starts from the accepted `main` head, and its entire affected consumer set is re-audited.

The existing S08 `operation:audio.output.set-session-volume` is non-negotiable: the exact `TransientExternalEffect`/`UserState` descriptor, trusted `Audio/Sink` identity (`node_id`, `object.serial`, `node.name`), immutable embedded/sealed WirePlumber helper, same-UID `Session1.SetAudioOutputVolume`, 0–100 non-amplifying input, durable bounded SQLite/WAL attempt and independent strictly newer post-observation stay unchanged. Existing virtual-sink qualification is not Q11. Never add a general PipeWire/DBus shell relay, a second UI authority, a default-output mutation alias or an optimistic receipt.

All new operation candidates remain disabled until **each** gets a trusted registry descriptor, risk/class review, actual principal and session identity, canonical Linura plan/policy, narrow permissioned transport/provider, independently observed postcondition, auditable failure/denial, indeterminate recovery and exact-head qualification. Managed mutations require durable prepare/commit/reconcile as applicable. An unprivileged path can be transient only after separate evidence proves its strict risk/failure limits; S08's result is not transferable.

## Ordered units

### S20-1 — Native PipeWire Audio Graph

**Result:** an authoritative bounded, read-only source of sink, source, device, card/profile, port, playback/capture stream, native link and selected-default facts using the canonical ObservationEnvelope and Control-owned coordination. The separate MPRIS owner is *not* PipeWire. A default alias remains a read-only query. Preserve the existing sink observation and all S08 consumers.

**Do not implement** a generic mutable helper merely to discover the graph. A new native observation mechanism must have its own pinned trusted identity, version compatibility and bounded parsing/execution if required; it must not edit the existing sealed S08 helper or weaken helper verification. Establish the actual UID, selected logind session/user-bus, PipeWire core and WirePlumber epoch, exact node ID/serial/name/media.class, parent device/profile/port identity, stream and link generations, and a snapshot-consistency strategy. Treat multi-call graph reads as non-atomic and reject mixed epochs, duplicate identities, ambiguous defaults and overlarge payloads. Health must distinguish unsupported, absent, degraded and current without equating cache with truth.

**Acceptance:** real pinned native PipeWire/WirePlumber fixture with multiple sinks and sources, stream/links, unplug/reuse, stale/restarted core, inconsistent snapshots, duplicate/oversized values, exact resource re-resolution and unchanged prior S08 exact-source regression. Merge only as an independently reviewable **observation-only** feature with no newly authorized operation.

### S20-2 — Playback and Output Authority

**Result:** typed exact-output mute and default selection with actual route impact preview, authenticated request and managed safety lifecycle. Preserve existing S08 output-volume behavior instead of reclassifying it or duplicating its executor. Mute is not zero volume. A moved default must not silently retarget an old draft.

Output operation candidates `operation:audio.output.set-mute` and `operation:audio.output.set-default` are separate from output volume and from each other. No source/capture mutation enters this PR. Review actual native support, user intent and rollback before activating any candidate; unsupported subcapabilities remain explicitly unsupported. Full per-application routing belongs to the shared typed stream operation in S20-3 so no competing playback/capture link authorities arise.

**Acceptance:** same-UID session/auth, policy denial, source-bound stale target, default flip, exact changed state, no-change classification, helper integrity, audit-full/restart/lost reply/indeterminate, and pre/post native verification. Existing 0–100 volume and QML/CLI behavior continue to pass unmodified. A managed effect that cannot be durably prepared and recovered remains inactive.

### S20-3 — Input, Microphone Privacy and Shared Routing Authority

**Result:** input/capture graph use, native microphone gain/mute, selected input, exact stream routing and real device-profile transitions under distinct current capabilities and conservative `SecuritySensitive` floors. This unit owns the candidate IDs `operation:audio.input.set-volume`, `operation:audio.input.set-mute`, `operation:audio.input.set-default`, `operation:audio.stream.set-route` and `operation:audio.device.set-profile`. The latter two must cover both playback and capture impact in one typed Control-owned route/profile authority; S20-2 does not pre-enable them.

**Privacy:** software mute, hardware/firmware privacy switch, active capture links, app permissions and available sources are different observations. No UI may claim that mute prevents *all* recording or that an unobserved permission is denied. Explicitly distinguish unknown from off, and restrict sensitive app/device details in diagnostics and model contexts. Profile changes can remove both output and microphone input and require review/compensation, not just a successful method response.

**Acceptance:** same/far UID, wrong `Audio/Sink`/`Audio/Source`, replaced stream/port, profile and serial drift, simultaneous app capture, lost reply after actual effect, durable indeterminate, restarts, actual native routing verification and privacy indicator truthfulness. VM fixtures do not prove hardware privacy.

### S20-4 — MPRIS Player Observation and Media Authority

**Result:** a separate user-session MPRIS observer with real unique D-Bus name owner and player/track instance identity, bounded sanitized metadata, capability flags and typed Play/Pause/Next/Previous/Seek candidates. This work is independent of S20-1's PipeWire transport, but must reuse the same trusted principal/Control and UI state conventions. Player titles, metadata, URIs and artwork are untrusted display data, not authority. Never auto-fetch network art or expose arbitrary D-Bus method forwarding.

**Acceptance:** hostile overlong markup/URL values, wrong/fresh owner, player disappears, capability lied about, track changes, seek race/auto-next, cross-UID bus, failures and post-dispatch independent reobservation. Some MPRIS actions cannot have a naive exact-track postcondition; do not report verified success if a sound postcondition cannot be observed. Inactive actions remain visibly unsupported.

### S20-5 — Audio/Media Experience and Qualification

**Result:** Control Center, Quick Settings, OSD, media keys and CLI/SDK use one consistent typed Control observation/request/receipt state machine; no QML/agent direct mutation. Reuse existing AudioSessionController and `org.linura.UI`/ShellBridge where appropriate. Include all supported output, input, stream and media controls, accurate unavailable/denied/indeterminate feedback, keyboard/pointer/screen-reader/reduced-motion/HiDPI and no-model workflows.

**Acceptance:** inherited and new native A exact-source VM, B interactive visual/accessibility VM and C maintained physical workstation Q11 with real supported audio and microphone hardware, together with locked-session, Bluetooth S19, power/session S17/S21, app crash, daemon restart, stale shell draft and replay failures. Inaccessible hardware must be recorded **not run/blocked**, not waived or substituted with virtual sources or video. Merge the UI only with the actually enabled capability surface; close S20/release ledger only after required merged evidence and real applicable qualification are complete.

## Exact PR extraction / review protocol

1. Rebase/re-extract each unit on the accepted `main`; read root and scoped `AGENTS.md`, provider, architecture, protocol, security and native VM guides; inventory source owners, callers, tests, package pins and existing support claims. ADR 0050 is **proposed** and its number must be checked against the append-only ledger.
2. Before enabling effects, prove the actual native identity and lifecycle, expected state changes, false-success avenues, independent verification and indeterminate recovery for *that operation*. No risk downgrade and no widening of S08's trusted registration.
3. Keep each PR independently reviewable: code + typed contract + security/adversarial negative tests + existing regression + docs/ADR updates + applicable native evidence. Avoid placeholder runtime, waived check, disabled regression or claims that another future PR will validate already-active behavior.
4. Use cohesive commits and the repository's full exact-head gate, security checks, reviews and applicable qualification. No passing check from an old SHA is evidence for a changed head; CI failures and unavailable Q11 leave the PR draft.
5. Shared `linura-linux-observation`, `linurad`, registry, D-Bus, ShellBridge and qualification edits need single ownership per extraction; parallel contributions must reconcile on current accepted main to prevent conflict. Keep S19/S17/S21 changes outside S20 unless explicitly independently reviewed.

## Promotion conditions and nonclaims

The WIP decomposition is an implementation source, **not** an implementation or qualification milestone. No new S20 candidate operation is registered, no S20 PR is created by adding this record, no canonical slice completion is advanced, no protected UX or physical support is claimed. Design source paths in WIP are deliberately not main runtime sources. The authoritative `contracts/v010-workstation-slices.toml` remains unchanged until dependency-closed merged PR evidence exists.
