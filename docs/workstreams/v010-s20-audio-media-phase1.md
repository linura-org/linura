# S20 Phase 1 — source audit, audio/media architecture and implementation requirements

- Status: Proposed **contract-first architecture**, no new executable operation, runtime code, completed feature or Q11 evidence.
- Slice: v0.10 S20, "complete audio and media experience"; `arch-hyprland-v1`; dependency S16.
- Audited base: `e867f5348f1a0b6833d0b622187e1213cac0039e`.
- Engineering contracts: [ADR 0050](../adr/0050-s20-audio-media-authority.md), [inactive design](../../contracts/v010-s20-design.toml), [domain qualification](../qualification/v0.10.0-s20.md), [security acceptance](../qualification/v0.10.0-s20-security.md), [existing workstream reference](v010-s20-audio-media.md).
- Accepted ADRs, runtime operation registry, existing released/versioned contracts and actual qualification evidence are authoritative over this proposed specification.

## 1. Audited implementation and prior support boundaries

| ID | Source | Confirmed implemented foundation | S20 limitation |
| --- | --- | --- | --- |
| A20-01 | `contracts/operation-semantics.toml` | Registered `operation:audio.output.set-session-volume`: `transient-external-effect`, `user-state`, provider `pipewire`, `audio.session.observe`, `volume_percent` | Registration applies **only** to this exact output-volume operation |
| A20-02 | `interfaces/dbus/org.linura.Session1.xml` | Experimental typed `SetAudioOutputVolume(request_id,node_id,volume_percent,reason)` with structured receipt | No registered input, mute, default route, profile or MPRIS methods |
| A20-03 | `apps/linurad/src/session_audio.rs` | `SessionAudioRuntime` uses `TransientEffectControl`, source-bound plan, canonical requested volume, `SqliteTransientAudit`, helper execution and post-effect validation | Reuse current trusted session architecture; do not broaden unchecked operation families |
| A20-04 | `crates/linura-linux-observation/src/lib.rs` | `PipeWireSessionObserver` lists `Audio/Sink`, numeric exact resource and observation envelope; default-output alias is read-only | No complete source/input, stream, device/profile or MPRIS inventory |
| A20-05 | `packaging/wireplumber/linura-session-audio.lua` | Root-packaged embedded trusted helper uses ObjectManager and mixer API; exact `node_id`, `object.serial`, `node.name`, `Audio/Sink`; canonical 0–100% | Do not add generic Lua, source routing or arbitrary operations to this helper |
| A20-06 | `apps/linura-shell/bridge/audio_session_controller.{h,cpp}` | Typed `AudioSessionController`, exact fresh observations, draft/feedback state and Session1 operation | Covers currently selected output volume, not full graph/media |
| A20-07 | `apps/linura-shell/shell.qml` / Control Center / Quick Settings | Reuses one `AudioSessionController` for presentation | Media player and input/microphone interface are incomplete |
| A20-08 | `docs/qualification/v0.10.0.md` / shell-runtime native lane | Real PipeWire/WirePlumber virtual-sink exact-source development qualification and negative volume tests | Physical Q11 support remains separate/unpromoted |
| A20-09 | `docs/security-model.md` and ADR 0032 | Session1 same-UID transport, immutable helper/sealed execution, trusted risk and durable audit | No new privileges or cross-user inference from this existing operation |
| A20-10 | `apps/linuractl/src/main.rs` | Existing authoritative read and registered output-volume call path | Need typed CLI/SDK parity for new independently reviewed actions |
| A20-11 | `docs/milestones/v0.10.0.md` / ADR 0033 | Complete Experimental workstation scope includes audio and media | No v0.10 product claim just from one implemented effect |
| A20-12 | Repository search of source for `MPRIS` and `MediaPlayer` | No discovered first-party production MPRIS player provider/control implementation on this audited base | Implement separately from PipeWire graph and avoid privileged/general D-Bus relay |

These statements are source inspection, not native retesting or a claim of a presently exploitable bug. Existing S08 volume status and qualification are never weakened to fund S20 work.

## 2. Capability inventory and bounded product outcome

| Domain | Baseline | Required / qualified outcome |
| --- | --- | --- |
| S20-01 output sink and default discovery | Partial | Bounded fresh real graph, all outputs, exact IDs and alias separation |
| S20-02 exact output-volume control | Implemented code | Preserve Session1 operation class, helper, native tests and unpromoted release state |
| S20-03 output mute and unmute | Not established | Separate typed exact-node effect, distinguish mute from 0% volume |
| S20-04 output default selection/ports | Not established | Actual selected sink/port and per-stream consequences, independently verified |
| S20-05 input/source inventory and gain | Not established | Authoritative Audio/Source identity, present supported hardware/software controls |
| S20-06 microphone mute and privacy | Not established | Separate source mute, hardware privacy switch where applicable and actual capture activity |
| S20-07 default input and input routing | Not established | Exact device/port and currently effective capture links |
| S20-08 per-application playback/capture routing | Not established | Stream nodes, endpoints and graph links, no foreign/retargeted stream |
| S20-09 card/device profile and hotplug | Not established | Supported device profiles, impact preview and recoverable transitions |
| S20-10 media player discovery and status | Not established | User-session MPRIS players, unique owner, capabilities, title/track/position/metadata sanitized |
| S20-11 playback control/seek | Not established | Typed exact-player request, capability and current track, verified postcondition |
| S20-12 OS media keys and status notifications | Not established | No direct privileged method/command fallback; no optimistic progress |
| S20-13 Quick Settings/Control Center/panel | Partial | All supported audio/media controls same typed Control machine state |
| S20-14 GUI/CLI/SDK accessibility, no-model | Partial | Keyboard/pointer/screen reader/reduced motion/HiDPI, bounded current feedback |
| S20-15 A/B/C acceptance and recovery | S08-specific A only | Source-bound native multi-device/input/stream/MPRIS failure proof and physical Q11 |

Universal codec support, professional JACK patch-bay, arbitrary DSP, cross-user media, raw capture/recording, global microphone kill-switch and network album-art fetching are **not** implicitly authorized by "complete"; expose unsupported scope separately. Audio devices supplied by Bluetooth (S19) remain dependent on real BlueZ pairing/profile readiness, not a future S20 bypass.

## 3. Architecture: one graph, typed classes, one Control authority

```text
Control Center / Quick Settings / OSD / CLI-SDK / model proposal
                           |
                    typed action / query
                           |
   Linura Control: trusted operation + authenticated same-UID
       principal + canonical plan/risk/policy + exact target
             |                            |
             | authoritative query        | external effect
             v                            v
   Control observation + PipeWire/MPRIS   existing S08 transient
   bounded native graph/owner facts       or proposed managed path
             |                            |
             +------------+---------------+
                          |
          strictly newer independent native observation
                          |
             verified receipt / audit / reconcile
```

The diagram is conceptual, not an invitation to collapse user-session and system/root transport or to expose a general D-Bus mutation gateway. S08's `Session1` handles **only** its existing exact registered transient volume operation; new trusted descriptors and transports follow their actual class/permissions. `policy allow != executor grant`; `executor != verification`; `cache != truth`.

### 3.1 PipeWireSessionEpoch and graph

Bind authenticated UID, logind session epoch/seat where needed, actual user bus identity, PipeWire core and WirePlumber generation, authoritative observation time/freshness and exact node ID + object.serial + node.name + media.class. For inputs, ports, device/card/profile, streams and graph links bind actual parent/object IDs plus revisions. No numeric node ID, application label, default-output alias or media-class guess alone grants effect authority. A graph with multiple calls is not atomic; use bounded revalidation or return indeterminate/insufficient evidence.

### 3.2 Sound capture privacy

`Audio/Source` is not `Audio/Sink`; an active source node isn't necessarily an application currently recording. Distinguish node availability, mute, hardware/firmware privacy switch as reported, source/stream connections, software permissions and actively capturing clients as separately observed facts. If any relevant capture path cannot be observed or inhibited, do not advertise a complete microphone privacy or kill-switch guarantee. Microphone metadata and app names are privacy-bearing; exclude raw detail from provider diagnostics/audit/model as necessary.

### 3.3 MPRIS player identity, metadata and postconditions

MPRIS is a distinct session-bus provider with well-known names `org.mpris.MediaPlayer2.*`, actual unique owner, selected player instance/track ID and bounded normalized metadata. A user-provided track title, playback URI, album art and player identity string are untrusted; escape rich text, bound length and never automatically load arbitrary external artwork/URLs. Play/Pause/Next/Previous/Seek are player effects, not navigation. A player may auto-advance, ignore requests, or disappear: review each effect's satisfiable postcondition and never call it verified purely on the method reply. App-level media handling must not confer Control/root authority.

### 3.4 Operation registry and privilege

The inactive contract declares **twelve new candidates** and **one pre-existing registered operation**. New output-mute/selection and MPRIS controls are conservatively managed candidates with `user-state` floors; input/source/privacy, stream routing and device/profile changes have conservative `security-sensitive` floors. Exact class and risk refinement is subject to separate native/security review. A subsequent transient candidacy is possible only with proved unprivileged at-most-`UserState` semantics, fresh post-dispatch evidence, durable attempt audit and bounded no-durable-ambiguity failure. No direct `wpctl`, `pactl`, unrestricted D-Bus, shell, arbitrary wpexec helper, client-created permission or privilege relaxation.

## 4. Failure recovery and authority conflicts

A moved default sink, node ID recycled with new serial, stale input, stream changed, MPRIS owner name rebound, session change, capture permission revoked, helper integrity error or audit write failure must invalidate the old request and leave an observable typed unavailable/blocked/indeterminate state. A volume draft and player playback action cannot be silently re-targeted to "current default". Managed route/profile uncertainty is durable and cannot automatically replay. A new action requires current native state and new review/authorization, never merely an old UI button or previous plan digest.

User session lock/power under S17, S19 Bluetooth device profile changes and S21 protected display/power can invalidate audio routing/session preconditions; cross-workstream conflicts require actual owner and epoch checks rather than modifying those subsystems' security primitives.

## 5. Adversarial regression catalogue

| Case | Failure/attack | Expected behavior |
| --- | --- | --- |
| M20-01 | S08 volume operation ID or risk changed by S20 design | Contract rejection; existing registration identical |
| M20-02 | Wrong UID/user bus or stale logind session | Untrusted caller denied; no cross-user audio |
| M20-03 | Reused PipeWire node ID, differing object.serial/node.name | Exact effect denied |
| M20-04 | Default output changes between draft/dispatch | No moved-target mutation |
| M20-05 | Helper file modified, symlinked, writable, mismatched hash or namespace owner ambiguity | Sealed root immutable helper boundary denies |
| M20-06 | Volume >100, noncanonical integer, false amplification | S08 rejects |
| M20-07 | "mute" represented as zero gain or false capture privacy | Distinct state, no fabricated privacy support |
| M20-08 | Source/sink/media.class spoof, wrong capture/source route | Exact type/identity rejection |
| M20-09 | Profile/stream/port changes after review | New generation invalidates effect; no partial verified success |
| M20-10 | Packet/IPC reply lost after route/profile effect | Indeterminate, re-observe, no blind replay |
| M20-11 | WirePlumber/PipeWire restarts during observation or effect | Provider epoch invalid, fresh authoritative recovery |
| M20-12 | Full/corrupt/broken SQLite/WAL audit | No unaudited dispatch or false receipt |
| M20-13 | MPRIS well-known owner recycled or player disappears | Old player target denied |
| M20-14 | Malicious MPRIS title/markup/artwork/URI | Bounded escaped metadata, no arbitrary fetch/injection |
| M20-15 | Player advances during Next/Seek; track ID differs | Correct postcondition model or explicitly unverified |
| M20-16 | Client/model classifies microphone/routing as transient | Trusted class/risk gate rejects downgrade |
| M20-17 | App capture continues with microphone software-muted | Do not display hardware/capture inhibition guarantee |
| M20-18 | Lost microphone permission/foreign capture stream | Explicit unknown/privacy warning, no unauthorized effect |
| M20-19 | Shell restart while mutation pending / optimistic OSD success | No replay, verified state reconstructed |
| M20-20 | S17 locked session or S19/S21 native hotplug/power transition | No cross-session/protection bypass |
| M20-21 | VM sink/source claimed as physical speaker/microphone | Evidence rejection; Q11 remains unqualified |
| M20-22 | No-change result before policy/freshness or post-effect verifier | Denied, not audited as success |
| M20-23 | Duplicate/oversized graph objects or metadata | Bounded error; no silently hidden duplicate target |
| M20-24 | MPRIS method forwarding or raw wpctl from quick settings | Unknown/unregistered effect fails closed |

## 6. Requirement and qualification traceability

| ID | Requirement | Evidence |
| --- | --- | --- |
| R20-BASE-01 | Preserve all S08 volume registry, helper, Session1 and audit invariants | M20-01–06/12; existing exact-source shell-runtime regression |
| R20-OBS-01 | Complete bounded PipeWire input/output/stream/card/profile graph with node identity | M20-02–04/08–11/23; controlled native graph |
| R20-OBS-02 | Distinct microphone mute, hardware/privacy, capture activity and native permissions | M20-07/16–18; native capture/privacy fixtures and physical test |
| R20-OBS-03 | Bounded sanitized session-bus MPRIS player/track observations | M20-13–15/23; hostile player fixture |
| R20-AUTH-01 | Separately registered typed actions, reviewed class/risk and exact current principal | M20-01/16/24; policy substitution tests |
| R20-AUTH-02 | Narrow effect + independent postcondition, managed recovery as needed | M20-09–12/15/22; crash and lost-reply native tests |
| R20-SEC-01 | Cross-UID/session safety, sealed helper and media metadata boundaries | M20-02/05/14/18; security regression |
| R20-UX-01 | Shell/Quick Settings/CLI/SDK/OSD converge without optimism | M20-04/19/24; exact-source UI & a11y |
| R20-REC-01 | Restart/reroute/departed player recovery without blind replay | M20-03/09–13/19; before/after effect integration |
| R20-QUAL-01 | Source-bound A/B/C physical evidence without premature release | M20-21, v0.10 Q9–Q14 and retained evidence verifier |

## 7. Ownership, sequencing and adaptive PR extraction

1. **Baseline/consumer audit:** Read root and scoped AGENTS, S08 Session1/XML, helper, observer, Control registry/risk/audit, existing CLI/ShellBridge, packaging, pinned native profile and exact-source test contract. Establish baseline SHA/toolchain/test run separately.
2. **Observation:** Add bounded source/device/card/profile/stream/route facts to canonical PipeWire provider only after complete identity model; separately observe MPRIS players on selected user bus. Keep existing sink observer and capability backward-compatible.
3. **Privacy and authentication:** Define typed real mic/capture permissions, protected input/indicator semantics and hostile metadata handling. No false global microphone privacy switch.
4. **Inert trusted operation review:** Stabilize new operation IDs/classes/risk/keys/target epochs/policy without changing the existing volume registration. Preserve fixed helper and same-UID contract.
5. **Narrow execution/verification:** Implement each approved new control in a reviewed bounded provider adapter, independent postcondition tests and managed or strictly qualified transient lifecycle. Never extend the old volume helper into a generic executor.
6. **Complete UI/media:** Reuse `org.linura.ShellBridge`, `org.linura.UI 1.0`, existing AudioSessionController where appropriate; connect Control Center, Quick Settings, source/mute, route/player and CLI/SDK to a single typed authority path.
7. **Qualification:** Real pinned PipeWire/WirePlumber and MPRIS fixture, helper-sealing regressions, security/privacy/adversarial matrix, interaction/a11y, physical Q11 and prior release gates. Record missing hardware evidence as blocked/not-run.
8. **Review and extraction:** Identify PR cuts from actual isolation of observer, microphone/privacy, managed route/profile execution, MPRIS, UX and qualification—not a fixed number or branch-per-feature recipe. Rebuild each final PR on accepted main, use independent exact-head check/review and merge only with satisfied gates.

**No new operation is registered in Phase 1.** No native tests, `cargo xtask check`, hardware or CI were executed by simply authoring these contracts. S20 remains planned; prior S08 transient implementation and its separate evidence are unchanged.
