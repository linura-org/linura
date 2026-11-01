# S19 Phase 1 — source audit, complete BlueZ architecture and implementation requirements

- Status: Architecture and acceptance design only. **No runtime feature completion or support claim.**
- Slice / target: v0.10 S19, `arch-hyprland-v1`, declared predecessor S16.
- Audited source baseline: `e867f5348f1a0b6833d0b622187e1213cac0039e` (S19 WIP reference derives from this main snapshot).
- Canonical engineering contracts: [proposed ADR 0049](../adr/0049-s19-bluez-bluetooth-authority.md), [inactive S19 operation design](../../contracts/v010-s19-design.toml), [qualification](../qualification/v0.10.0-s19.md), [security](../qualification/v0.10.0-s19-security.md), [existing workstream](v010-s19-bluetooth.md).
- This is an audit and proposed architecture, not native code, CI, VM, physical acceptance or a PR. Accepted ADRs and production contracts remain authoritative until reviewed change.

## 1. Existing code and evidence boundaries

| Audit | Actual source | Verified function | Missing S19 behavior |
| --- | --- | --- | --- |
| A19-01 | `crates/linura-linux-observation/src/platform_discovery.rs` | `observe_bluetooth_provider` calls `observe_selected_dbus_provider("bluez", "bluetooth", ..., "org.bluez", "/")` | No Adapter1/Device1 ObjectManager inventory, pairing or native effect authority |
| A19-02 | Same file, `observe_selected_dbus_provider` / `require_owned_service` | Live system D-Bus `NameHasOwner` and `org.freedesktop.DBus.Peer.Ping` | No exposed unique service owner epoch or continuous per-device state binding |
| A19-03 | `crates/linura-hardware/src/platform_profile.rs` | Typed `PLATFORM_BLUETOOTH_PROVIDER_CAPABILITY` and BlueZ provider-role contract | Candidate platform compatibility does not establish a usable physical adapter |
| A19-04 | `profiles/arch-hyprland-v1.toml` / Arch package sets | Platform selects BlueZ with development target | Package/service availability is neither radio nor pairing qualification |
| A19-05 | `apps/linurad/src/main.rs` and `crates/linura-linux-observation/src/lib.rs` | Daemon registers systemd, NetworkManager and PipeWire session observers | No `BlueZObserver` registered as authoritative per-device resource provider |
| A19-06 | `crates/linura-observation-control/src/lib.rs`, `crates/linura-observation/src/lib.rs` | Canonical provider registration, bounded history/freshness, `ObservationEnvelope` | Need domain-specific adapter/device/bond scopes without a duplicate aggregator |
| A19-07 | `contracts/operation-semantics.toml` / ADR 0032 | Trusted `OperationClass` and controlled managed/transient lifecycles | No audited registered S19 pairing/trust/connect/remove operation |
| A19-08 | `docs/qualification/v0.10.0.md` / ADR 0033 | Q9–Q14 and complete Experimental workstation product boundary | Bluetooth feature and hardware acceptance still unproven |
| A19-09 | `tools/verify_v010_slice_pr_evidence.py` | S19 path ownership identifies `apps/linura-shell/plugins/bluetooth/` and `crates/linura-provider-bluez/` | Future real code/tests must satisfy genuine reviewed S19 scope, not docs-only evidence |
| A19-10 | `apps/linura-shell/`, ShellBridge and UI SDK | First-party shell/Control Center design foundation | No established complete typed Bluetooth panels, protected pairing agent, CLI/SDK parity |

**Non-finding distinction:** These are missing capabilities in the audited S19 implementation, not claims that a presently supported pairing service is vulnerable. The service presence probe must not be rewritten to look like a full Bluetooth domain observer. No test run is claimed here.

### 1.1 Upstream native API boundaries to preserve

The target integration uses `org.bluez` with `org.freedesktop.DBus.ObjectManager.GetManagedObjects`, `org.bluez.Adapter1`, `org.bluez.Device1`, `org.bluez.AgentManager1`, `org.bluez.Agent1`, and `org.freedesktop.DBus.Properties`. For the pinned native BlueZ version, validate the actual supported methods and fields before executor design; do not assume optional properties or experimental APIs exist.

`Adapter1.StartDiscovery` begins a client-scoped session; `StopDiscovery` releases only a session owned by the caller. BlueZ combines clients' discovery behavior, so neither a client's filter nor `Discovering` proves exclusive control. `Adapter1.RemoveDevice` removes device data including bond material, whereas `Device1.Pair`, `Connect`, `Disconnect` and `CancelPairing` have distinct postconditions and ambiguity windows. `Agent1` supports passkeys, confirmation and per-service authorization; Agent1 callback replies are not independent Linura policy approvals.

Review pinned BlueZ upstream Adapter/Device/Agent native interface docs and runtime package behavior before writing effectful code. Ref: `https://github.com/bluez/bluez/tree/master/doc`.

## 2. Feature inventory and target acceptance

| Capability | Current status | Normative implementation outcome |
| --- | --- | --- |
| S19-01 BlueZ service/provider presence | Partial | Reuse existing health/PlatformProfile probe, owner epoch and explicit service unavailable |
| S19-02 Adapter inventory and controller capabilities | Missing | Bounded, typed adapter `Powered`, `Discoverable`, `Pairable`, discover/session/rfkill and native generation |
| S19-03 Device inventory and Bluetooth identity | Missing | Parent adapter, address type, transport, UUID/profile/alias, signal and authenticated bond continuity |
| S19-04 Discovery / scan results and filter | Missing | Consent/scope/lease-bound native discovery, bounded duration/filters, non-global StopDiscovery |
| S19-05 Radio power / public visibility / pairability | Missing | Independently reviewed typed consequences and native state, privacy risk and ownership |
| S19-06 Pairing and protected Agent1 | Missing | Exact authenticated user/device/challenge, secure local passkey/confirmation and cancellation |
| S19-07 Existing device connect / disconnect | Missing | Bond/profile/service readiness and exact device connection epoch; no optimistic connection |
| S19-08 Trust/block and forget | Missing | Separate persistent security decisions, destructive bond removal review and restart recovery |
| S19-09 BLE/BR/EDR, address rotation and profile capabilities | Missing | Explicit supported scope per adapter/device; no fake guarantee that address proves identity |
| S19-10 Multi-controller and hotplug | Missing | Adapter identity and fail-closed owner/adapter/remote device generation checks |
| S19-11 Control Center, Quick Settings, CLI/SDK | Missing | Shared registered typed operation and result; accessible, protected and no-model UX |
| S19-12 Native A/B/physical C qualification | Missing | Exact-source, adapter/BlueZ/boot/session-bound positive/negative evidence with real physical acceptance |

The words "complete Bluetooth" do not imply universal raw GATT access, arbitrary SDP, every audio codec/profile, firmware management, global default-agent takeover or unbounded BLE advertisement recording. Each unsupported extension must fail closed and remain separately scoped. User-visible connection/profile readiness is only claimed for actually supported functions.

## 3. Exact resource and observation design

### 3.1 BlueZProviderEpoch

Bind boot, actual system D-Bus unique owner and a verified live BlueZ owner health read, bounded ObjectManager call, sequence/freshness and native API version. The well-known `org.bluez` string is an address, not continuity proof. A replaced owner invalidates dependent adapters, devices, pending pairing prompts, discovery leases and prepared effects.

### 3.2 AdapterEpoch

Bind provider epoch, exact Adapter1 object and validated controller identity (native controller index, address/type where applicable, power, seat/ownership context). Names such as `hci0` can be reused and do not independently authorize mutation. Unpowered, rfkill-blocked, unavailable and software-disabled must not be collapsed. Treat an adapter power reset as a new effect precondition generation.

### 3.3 DeviceEpoch and BondRevision

Bind exact parent adapter, current BlueZ Device1 object, address **and address type**, indicated transport/capabilities, observed epoch and cryptographic bond continuity *only where natively verifiable*. BLE private/random addresses can rotate; a human alias, RSSI, advertisement or service UUID is not proof of trusted device identity. Distinguish new/prebond/paired/trusted/blocked/connected/service-resolved. Unsupported identity assurance must be explicit: Just Works does not provide MITM-authenticated peer identity by itself.

### 3.4 DiscoveryLease, AgentChallenge and ServiceAuthorization

A discovery lease binds the caller's exact BlueZ client connection, adapter, filter, start/stop generation and bounded expiry. Another client's scan/filters cannot be adopted or stopped by Linura. A protected pairing challenge binds source BlueZ owner sender, registered Agent1 invocation/agent instance, intended operation or explicit approved inbound scope, device/bond epoch, original principal/active session and specific challenge kind/service UUID, one-time response and suspend-inclusive deadline. Cancel/Release, session lock, switch, provider restart, wrong adapter or removed device invalidates it. A service authorization is distinct from bonding and from connection readiness; never reuse a previous confirmation.

### 3.5 Typed state, quotas and observation coherence

Use `ObservationEnvelope` for narrow authoritative per-provider/resource facts and Control-owned aggregation; no cross-domain poll loop inside BlueZ provider. Bound total managed objects, adapter/device count, nested variants/UUID count, human labels, advertisement lengths, response bytes, deadline, concurrent Agent1 prompts and active scan duration. Source-specific caps must be justified by pinned native tests before implementation. Mixed-object snapshots are not atomic; validate BlueZ owner and native object consistency after reads. Duplicate/unknown/conflicting data fails closed, not quietly truncated.

## 4. Trusted action semantics and consent

The inactive design proposes **twelve candidate external-effect families**: discovery start/stop; adapter power/pairable/discoverable; device pair/cancel-pairing/connect/disconnect/trust/block/remove. In the initial security design they remain managed and unregistered; transient candidacy for bounded scan/cancel requires separate native proof, never a shortcut on perceived low risk.

For an authorized managed external effect:

```text
Human or deterministic CLI / configuration / accepted agent proposal
                               |
                               v
              Typed intent / current state / draft
                               |
                               v
        Control: native-authenticated Principal, plan,
         trusted operation & risk, policy authorization
                               |
                               v
       Durable prepared attempt + bound BlueZ provider,
        adapter/device/bond/agent/subject generation
                               |
                               v
          Narrow native BlueZ adapter / Agent1 broker
                               |
                               v
          Independent fresh native state verification
                               |
                               v
                  Commit / audit / reconcile
```

The UI is not a policy engine. A BlueZ callback is not a user credential or approval record. No arbitrary `bluetoothctl`, privileged shell, unbounded D-Bus method forwarding, client-chosen risk, replay of cached Agent1 responses, or generic trusted "yes" button. Cross-user and cross-seat support requires explicit real authenticated subject policy; no ambient root shortcut.

## 5. Recovery, privacy, UX and qualification consequences

Pairing or `RemoveDevice` may have completed when a D-Bus reply is lost. Recover by freshly inspecting **the same** BlueZ owner/device/bond context and by retaining an indeterminate attempt, never retrying on an old permission. Native service restart and HCI reset can invalidate a pairing challenge without undoing previously persisted bond keys. A successful `Connected` observation does not necessarily mean the user's HID, audio or GATT service works.

Protect credentials, trust state and identifying broadcasts in logs, UI, telemetry and retained qualification evidence. A non-authorizing offline/no-AI pairing/settings interface must still display unavailability, policy denial and recoverable/indeterminate state. First-party shell surfaces must use `org.linura.UI 1.0`, real keyboard and accessible focus, reduced motion/HiDPI, protected input and appropriate locked-session behavior.

A/B VM qualification is not Level C physical radio proof. S17 protected owner authentication, S20 audio route governance, S21 power/display, v0.9 First Boot and v0.1 platform discovery remain unaffected.

## 6. Adversarial and regression matrix

| ID | Required attack or failure | Required result |
| --- | --- | --- |
| B19-01 | Service absent, activatable-only or hung root Ping | Unavailable/degraded with bounded error, no claimed radio support |
| B19-02 | Unique BlueZ owner swaps during ObjectManager inventory | Reject mixed epoch |
| B19-03 | Adapter `hci0` or native controller index reused after hotplug | Reject obsolete adapter effect |
| B19-04 | Duplicate Device1 path/address, spoofed alias/advertisement | No mistaken same-device authorization |
| B19-05 | LE random/private address rotates; same public ID advertised by attacker | No MAC/name-only trust; label prebond identity uncertainty |
| B19-06 | Oversized managed-object map, UUIDs or variants | Bounded fail-closed, no silent omission of conflicting target |
| B19-07 | Missing/invalid Paired, Trusted, Blocked, Connected or ServicesResolved | Unknown/unsupported rather than guessed success |
| B19-08 | Second client starts discovery; Linura stops its own scan | Other client lease preserved |
| B19-09 | Stale filter, reused lease, radio rfkill/disable during scan | Deny or retire lease; no global stop |
| B19-10 | Foreign system-bus sender for Agent1 callback | Reject; no prompt/consent |
| B19-11 | Mismatched PIN/passkey, target, UUID or Just Works unsolicited request | Reject; no implicit approval |
| B19-12 | Agent `Cancel`/`Release`, session lock or seat switch mid-prompt | Invalidate challenge, no stale consent |
| B19-13 | Two simultaneous pairing prompts or late duplicate reply | Single exact purpose/challenge only |
| B19-14 | Caller/model/provider supplies weaker class/risk/target | Trusted registry/policy denies |
| B19-15 | Foreign UID/Polkit subject or root identity laundering | Native authenticated subject fails closed |
| B19-16 | Device paired but not trusted; connected but service unresolved | Distinguish facts, verify requested postcondition |
| B19-17 | RemoveDevice on shared/foreign bond, changed revision | Require impact review and reauthorization |
| B19-18 | Pair/remove applied then reply lost or BlueZ crashes | Indeterminate, re-observe, no blind replay |
| B19-19 | Battery/firmware/controller disappears or profile changes | Explicit unsupported/degraded without fallback |
| B19-20 | Plaintext PIN/passkey/bond keys reach logs/model/test evidence | Security failure, redaction enforced |
| B19-21 | Shell restarts, no model, wrong session or S17 lock | Protected no-model UX, no replay or unlock |
| B19-22 | Virtual HCI passes while real physical radio not executed | Native scope retained; Q11 stays unqualified |
| B19-23 | No-change reported without policy/current evidence | Denied; must run authorization |
| B19-24 | Startup/registration steals BlueZ global default agent | Denied without exclusive owner/restore proof |

Adversarial cases are acceptance requirements, not assertions that test harnesses already exist. Test positive and negative paths for every claimed adapter/device effect, including before/after native dispatch, crash and recovery.

## 7. Requirement-to-evidence traceability

| Requirement | Binding | Evidence needed |
| --- | --- | --- |
| R19-OBS-01 | Preserve platform BlueZ compatibility without false domain support | Existing Q3/provider regressions and A/B provider native fixture |
| R19-OBS-02 | Unique service owner and complete bounded ObjectManager identity | B19-01–07, restart/hotplug and malformed native state tests |
| R19-OBS-03 | Correct adapter/device/transport/bond/service facts | B19-03–07, B19-16 and physical multi-device proof |
| R19-DISC-01 | Client-scoped discovery, filters, expiry and stop ownership | B19-08–09 and actual multi-client BlueZ VM test |
| R19-AGENT-01 | Protected purpose-bound Agent1 challenge and authorization | B19-10–13, B19-20, B19-24 and current-session native acceptance |
| R19-AUTH-01 | Trusted class, principal/risk floor and Polkit/BlueZ subject | B19-14–15, B19-23 and negative authority tests |
| R19-AUTH-02 | Narrow managed effect with independently verified postcondition | B19-16–19, dispatch-timeout and no-replay tests |
| R19-REC-01 | Durable ambiguity/reconcile, agent retirement and no blind replay | B19-12/18/21; daemon/HCI restart and audit-disk failure |
| R19-UX-01 | GUI/CLI/SDK/no-model parity and accessible protected input | B19-10/21, Q10/Q11 interaction/visual/physical |
| R19-QUAL-01 | Honest source-bound A/B/C evidence and no premature release | B19-22, qualification evidence verifier and dependency ledger |

## 8. Implementation ownership and sequence, without fixed PRs

1. **Baseline and consumers:** inspect native BlueZ pinned version, `org.bluez` PlatformProfile probe, Control observation/operation registries, first-party session/security owner, packaging and existing tests. Verify no current BlueZ per-device effect path before adding one.
2. **Typed read-only inventory:** implement bounded OwnerEpoch → AdapterEpoch → DeviceEpoch/BondRevision and canonical authoritative envelope, deterministic parser/freshness tests, duplicates, owner replacement and hotplug.
3. **Discovery lease and native observation:** prove caller-owned scan session and filter behavior, bounded cancellation and no impact on other clients. Treat active scanning as an external effect requiring reviewed trusted semantics.
4. **Pairing architecture:** design purpose-bound Agent1 service, authenticated exact sender/registration, protected input and security characteristics; reject default-agent takeover, replay, service confusion and unsolicited Just Works.
5. **Inert trusted operation review:** stabilize exact operation IDs, resource/material/risk floors, policy subject and no-bypass/secret rules before native effect activation.
6. **Managed native effects:** narrow BlueZ executor, independent verifier and durable postcondition/recovery one capability at a time; never use `bluetoothctl` or shell authority.
7. **Unified interfaces:** Control Center, Quick Settings, CLI/SDK and accessibility/no-model parity. Keep shared shell host changes dependency-ordered with S17/S20/S21.
8. **Qualification, audit and extraction:** native exact-source tests, adversarial crash/agent and real physical acceptance, architecture/security review; decide actual independently reviewable PR boundaries from completed code. Preserve baseline S16 and S17/S21 guarantees.

The initial review may combine or split implementation seams. No PR count is imposed; neither this audit nor an inert design can close S19, register effects or promote Q11 support.

## 9. Validation and nonclaims

Run `bash scripts/preflight_codex_environment.sh`, relevant environment doctor, existing provider/PlatformProfile and Control tests, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py`, the S19 design test suite and `cargo xtask check`. Add true native BlueZ and exact-source Arch qualification and physical cases before any respective support claim. Follow scoped AGENTS/security/architecture guides and retain failures honestly.

This Phase 1 is source inspection and an implementation-ready design only. No unit test, native BlueZ HCI, paired hardware, CI, security signoff or release readiness is attested by publication of this document.
