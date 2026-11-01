# ADR 0049 — S19 BlueZ Bluetooth identity, pairing and trusted Control authority

- Status: Proposed
- Scope: v0.10 S19, `arch-hyprland-v1`; depends on S16
- Refines: ADR 0012, ADR 0017, ADR 0018, ADR 0024, ADR 0031, ADR 0032, ADR 0033 and ADR 0042
- Companion: [inactive design](../../contracts/v010-s19-design.toml), [domain acceptance](../qualification/v0.10.0-s19.md), [security acceptance](../qualification/v0.10.0-s19-security.md)
- ADR number is reserved for this WIP design; reconfirm the global ADR ledger immediately before independent PR extraction.

## Context and decision

The current platform discovery implementation treats the live `org.bluez` service as a selected provider identity. It verifies D-Bus ownership and a direct `Peer.Ping` at `/`. It does **not** expose an authoritative per-adapter/per-device ObjectManager inventory, a pairing agent or an effect executor. The first-party shell and canonical Control observer/operation architecture already exist; S19 must reuse them rather than create a root-level Bluetooth control service or run `bluetoothctl` through UI.

**One machine model, one trusted Control-owned authority architecture.** The proposed operation entries in `contracts/v010-s19-design.toml` are **inert design data**, not registrations, policies or effect grants. No runtime change, Bluetooth support promotion or physical Q11 claim follows from this record.

## Provider epoch and bounded native observation

Read `org.freedesktop.DBus.GetNameOwner("org.bluez")` and bind the actual **unique service owner**, system bus and boot identity to the bounded `org.freedesktop.DBus.ObjectManager.GetManagedObjects` inventory. Revalidate owner/object identities before/after related reads. Use the existing canonical `linura_observation::ObservationEnvelope` and Control-owned orchestration, budgeting, freshness and graph provenance. A D-Bus object path, `hci0`, MAC address, remote alias, Bluetooth name, UUID or RSSI is not a grant to act on a device.

Model an exact AdapterEpoch (BlueZ owner, controller identity, native adapter object, relevant controller generation and state), DeviceEpoch (parent adapter, owner, object path, transport/address *type*, observed identity, advertised properties and generation) and BondRevision (paired state and locally retained/trusted bond continuity where natively proven). BR/EDR addresses, BLE public/random/resolvable private addresses, human names and discovered service UUIDs have different reliability and spoofing properties. **Before bonding, spoofed identity cannot be cryptographically proven from an alias/address alone**; user confirmation and native capability evidence must reflect that limitation. After bonding, do not assume a previous address proves key continuity after daemon/controller restart. Unsupported or ambiguous identity => blocked effect.

Keep `Paired`, `Trusted`, `Blocked`, `Connected`, `ServicesResolved`, discovery state and adapter `Powered`/`Discoverable`/`Pairable` distinct. A `Connect` method return or `Connected=true` does not prove the requested audio/HID/GATT profile functions; independently observe required service readiness when that is part of the requested postcondition. Service or client notification must never become verified state by itself.

Bound adapters, devices, D-Bus variant depth/size, UUIDs, aliases, property values, object fan-out and deadlines. Fail closed on duplicates, mixed owner epochs, invalid paths, stale observations, hotplug, rfkill or transport loss; do not truncate an inventory that would hide competing identities. BlueZ provider discovery remains a separate narrow platform fact, not a second domain graph authority.

## Discovery, power, trust and operation classes

Passive reading of an existing observed adapter/device inventory is `AuthoritativeQuery`; UI selection is `ExperienceEphemeral`. **Starting/stopping discovery and setting discovery filters are external actions**, never passive reads. BlueZ `Adapter1.StartDiscovery` and `StopDiscovery` sessions are caller-scoped while scanning and filters may be shared with other clients: S19 must track the exact BlueZ connection, adapter and one owned discovery lease, preserve other clients' sessions, bound filtering and scanning duration, and clean up after restarts. Do not turn `StopDiscovery` into a global "radio off" command.

Proposed adapter `Powered`, `Discoverable`, `Pairable`; device `Pair`, `CancelPairing`, `Connect`, `Disconnect`, `Trusted`, `Blocked`; and adapter `RemoveDevice` are separate operations with distinct consequences, subject/target, postcondition and recovery. A trust flag is not pairing, pairing is not service authorization, connected state is not profile readiness, blocking is not removal, and removing a device may delete local bonding material. Discovery/pairing cancellation may later qualify for a narrower, registered transient semantic path only if unprivileged, at-most-`UserState`, and bounded-failure proof exists; until then all external candidate operations conservatively remain inactive managed proposals.

Each eventual `ManagedExternalEffect` follows request → observe → plan → validate → authorize → durable prepare → narrow dispatch → independent verify → commit → audit → reconcile. Native privilege, security-sensitive pairing/trust, durable state, uncertain dispatch or loss of service excludes transient shortcuts. Trusted registration fixes class/risk floor and allowed keys; no caller, agent or provider can downgrade it. `policy allow != executor grant`; `reviewed plan != prepared mutation`; `executor != verification`.

## Pairing agent and protected consent

BlueZ `org.bluez.Agent1` callbacks (including `RequestPinCode`, `RequestPasskey`, `DisplayPasskey`, `RequestConfirmation`, `RequestAuthorization`, `AuthorizeService`, `Cancel` and `Release`) are privileged security interactions, **not** ordinary notifications or approval-bearing model responses. A trusted native agent broker must bind the **actual BlueZ sender**, exact BlueZ service owner epoch, current agent registration/client instance, adapter/device epoch, intended pairing operation or explicitly permitted incoming request, requested service UUID, authenticated current user/session and unique challenge generation/deadline.

Only protected first-party local input for the exact active challenge may approve. All requests that cannot be correlated to a permitted active request (including unsolicited "Just Works" incoming pairing) must be rejected unless a separate explicitly reviewed inbound authorization contract exists. A raw D-Bus callback, typed response, UI click, passkey field or previous pairing confirmation does not itself grant Control authority. Reject spoofed callback sender, old challenge, same-device parallel prompts, changed seat/lock state, agent restart/release, device disappearance, wrong service UUID and expired input. Never register a global/default BlueZ agent that steals authority from other users/agents without proving exclusivity and restoring prior ownership.

Choose and communicate supported IO capability and MITM limitations. "Just Works" is not authenticated MITM protection; do not claim hardware identity assurance from display name or mere success of bonding. Keep PIN/passkey, link/bonding keys, service authorization secrets and protected input out of model, plan, audit, diagnostics, tests, screenshots and retained videos. Persist only reviewed non-secret metadata and references; credentials/keys stay in upstream protected storage.

## Recovery and authorization

Polkit/BlueZ permissions must derive from the actual authenticated principal, service/agent and seat/session context; an ambient root helper or session-bus caller cannot launder a system-bus permission. Pairing and removing/trusting devices can persist after a method reply is lost. At every crash/timeout/daemon restart, re-observe current BlueZ owner, adapter/device and bond/trust state before deciding a new explicit action. Never replay `Pair`, `RemoveDevice`, trust changes or discovery session claims merely because a pending request was recovered. Missing physical radio, virtual HCI, rfkill, stale owner, wrong transport, unsupported profile or uncertain authorization remains unsupported/blocked/indeterminate.

Coordinate with S17 protected lock/session-owner authentication, S20 audio device routing, S21 power/display and S26 durable Library. A Bluetooth pairing result does not authenticate a desktop session, release secure coverage, authorize services or qualify media routing. The first-party QML/CLI/SDK share typed Control observations and verified receipts, explicit unavailable/progress/error states, accessibility, reduced motion, HiDPI and no-model manual access; no raw BlueZ D-Bus authority in ShellBridge.

## Qualification and consequence

S19 acceptance must prove negative identities, protected pairing/authorization, caller-scoped discovery, failure/restart without replay, actual service readiness and policy/operation-class convergence. Level A exact-source VM/virtual HCI can test scoped native BlueZ mechanics only; Level B interactive VM adds UX and safe consent; Level C/Q11 physical hardware is required to claim real radio, discovery, secure pairing, multi-device/reconnect and input/audio profiles where supported. Video and synthetic fixtures are supporting artifacts, never the correctness oracle.

These remain unexecuted proposed requirements until later native implementation and tests. No activation, ledger completion, support elevation or change to inherited release gates is authorized here.
