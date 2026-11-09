# S18 — NetworkManager workstation capability: Phase 1 audit and architecture

- **Status:** Proposed engineering specification; requirements and architecture, not implemented authority or qualification evidence
- **Milestone / slice:** v0.10.0 / S18, "NetworkManager connectivity experience"
- **Supported target under design:** `arch-hyprland-v1` (development PlatformProfile)
- **Dependency:** S16; cross-cutting security and experience invariants of S17 and S21 also apply
- **Audited source baseline:** `e867f5348f1a0b6833d0b622187e1213cac0039e`
- **Related technical reference:** [S18 workstream](v010-s18-network.md)
- **Decision authority:** Canonical accepted ADRs/contracts take precedence over this working specification
- **Effect activation:** **None** introduced by this document. Every proposed operation remains unregistered/unsupported until independently reviewed and qualified.

Related proposed architecture and acceptance: [ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive S18 design](../../contracts/v010-s18-design.toml), [qualification](../qualification/v0.10.0-s18.md) and [security qualification](../qualification/v0.10.0-s18-security.md). The audit remains the implementation traceability record; no proposed operation is activated.

## 1. Scope and nonclaims

S18 must provide a usable, secure first-party network experience on the exact v0.10 workstation target, instead of treating NetworkManager's mere presence or read-only manager state as a complete product capability. The first supported reference-profile experience must let a human inspect current Ethernet/Wi-Fi connectivity, see available/saved connections, perform explicitly qualified network actions, understand progress/failure/recovery and use deterministic manual/no-model paths. All displayed final state must come from fresh authoritative provider evidence.

The release claim is bounded by the profile and accepted qualification. This document **does not** silently commit v0.10 to arbitrary VPN plugins, mobile broadband, hotspots, routing/firewall management, enterprise 802.1X, every Wi-Fi chipset, every NetworkManager feature, or cross-distribution support. Those features require separate, explicit scope and capability decisions; an unsupported feature must remain visible as unsupported, not disappear or use a generic native fallback. Wi-Fi scan, activation, profile editing and DNS changes are separate operation families even when they share a panel.

No public API, stable contract, security or release statement is changed here. Do not change the canonical 32-slice ledger or the S18 status from `planned` on the basis of this document.

## 2. Audited implementation and existing contracts

Source observations below are grounded in the stated commit. Their presence is **not** a claim that new runtime behavior has been tested in this phase.

| ID | Actual source / contract | Confirmed current behavior | Implication for S18 |
| --- | --- | --- | --- |
| A01 | `crates/linura-linux-observation/src/lib.rs`, `NetworkManagerObserver` | System-bus observer registered under `networkmanager`; exposes `networkmanager.manager.observe` and `networkmanager.device.observe`. | Reuse and extend; do not replace the canonical observer route. |
| A02 | Same file, `NetworkManagerObserver::resources` and `find_device_path` | Uses `GetDevices`, looks up device by `Interface` string, returns sorted/deduplicated `networkmanager:device:<interface>` IDs. | Existing interface names are query-addressable aliases, not trusted mutation identities. Duplicates/races require explicit detection. |
| A03 | Same file, `observe_manager` | Reads `Version`, `State`, `Connectivity` and `NetworkingEnabled` from NM properties. | Manager status is a partial observation, not Wi-Fi/profile/IP/route functionality. |
| A04 | Same file, `observe_device` | Reads `Interface`, `State`, `DeviceType`, `Managed`, `Driver` and an `object_path` after interface recheck. | A validated name and path do not alone establish generation identity, link continuity or authorization. |
| A05 | Same file, `service_health` / `require_available` | Health checks `NameHasOwner` and reports availability; degraded health can continue to the read. | Health alone is not the same as pinned unique NM owner, bounded native response or stable multi-object snapshot. |
| A06 | `crates/linura-linux-observation/src/platform_discovery.rs` | Independent PlatformProfile probe requires owned NM service, a direct health `Ping`, and at least one managed non-loopback device, with a 128-device ceiling. | Preserve this compatibility rule; do not turn it into a second network-state aggregation or effect authority. |
| A07 | `apps/linurad/src/main.rs` and `apps/linura-firstboot/src/lib.rs` | Compose/register `NetworkManagerObserver` alongside existing observers. | Any observer-contract change affects daemon and First Boot; check all consumers before editing. |
| A08 | `apps/linuractl/src/main.rs` | Infers `networkmanager` manager/device observe routes; supports explicit typed provider/capability/resource queries. | Preserve tested query compatibility or migrate all in-repo consumers coherently under `contracts/stability.toml`. |
| A09 | `crates/linura-observation-control/src/lib.rs` | Owns provider registration, capability checks, canonical envelope validation, freshness and retained evidence. | Use this Control coordination; do not create a second observation envelope/cache authority in the NM adapter. |
| A10 | `contracts/operation-semantics.toml` and ADR 0032 | Define trusted classes and registered managed/transient effect semantics. No S18 NetworkManager mutation descriptor is registered in the audited baseline. | Proposed operation names/classes in this specification remain inert design candidates. |
| A11 | `docs/qualification/v0.1.0.md` | Earlier experimental claim includes native NM observation where available, and explicit service-absent results. | Retain this regression boundary; v0.1 read-only success does not prove v0.10 write support. |
| A12 | ADR 0031/0033; `docs/milestones/v0.10.0.md`; `docs/qualification/v0.10.0.md` | Demand complete bounded Experimental workstation experience, one typed authority path, Q9 native effects, Q10 UI convergence and Q11 hardware evidence. | GUI/CLI/SDK convergence and independent verification are nonoptional for every claimed S18 action. |
| A13 | `profiles/arch-hyprland-v1.toml` | Selects NetworkManager in a development profile; Arch package sets contain NM. | Provider choice is a target constraint, not evidence that a specific NIC/Wi-Fi path is qualified. |
| A14 | `tools/verify_v010_slice_pr_evidence.py` | Identifies S18-owned areas including `apps/linura-shell/plugins/network/` and `crates/linura-provider-networkmanager/`. | Honor ownership while adapting to real code and reviewed dependency boundaries. |

Important audit distinction: `platform_discovery::observe_network_provider` answers "is the selected NetworkManager provider available for this candidate platform?" It does **not** answer "is this specific interface connected?", "which DNS/route is active?", or "did the authorized network operation succeed?". S18 needs those separately via canonical observation and verification.

### 2.1 Audit findings and implementation risks

The following are concrete source observations or gaps, **not assertions of a currently exploitable supported mutation vulnerability**:

- **F01 — Missing network domain breadth:** Current NM observation does not expose saved/active connection topology, Wi-Fi access points, per-family IP/DNS/default routes, radio/rfkill state or supported NM-specific connection operations. Existing read-only support is narrower than S18's product scope.
- **F02 — Weak alias for effects:** `networkmanager:device:<interface>` uses interface text. That query alias may be renamed, reused, replaced or duplicated; it cannot be the sole identity in a prepared managed-effect authority binding.
- **F03 — Ambiguous selection and enumeration:** `find_device_path` returns the first interface name match; `resources` sorts/deduplicates. A duplicated or changed name must fail closed rather than silently choose one for any future identity-sensitive path.
- **F04 — Boundedness asymmetry:** Platform compatibility discovery has an explicit 128-device ceiling, while the regular observer's `GetDevices` enumeration/search has no S18-specific explicit count limit in the audited code. Provider-level response, string, variant and deadline limits also require verification against real zbus behavior. Add bounds without accidentally weakening established v0.1 semantics.
- **F05 — Owner/TOCTOU continuity:** Regular observer health uses `NameHasOwner`; calls use the NM well-known name and do not explicitly pin all object reads to one unique service owner. An NM restart across reads must not yield a mutation precondition assembled from different daemon instances.
- **F06 — Non-atomic native snapshot:** Manager, device, active connection and IP properties can change between separate D-Bus calls. A multi-object network state must be correlated and checked for generation/identity consistency, not labeled atomic merely because all calls succeed.
- **F07 — Limited existing negative proof:** Audited NM unit coverage includes a resource-prefix parser test. Native exhaustive daemon-restart, property drift, duplicate-device, bounded enumeration, cancellation and network-effect recovery acceptance is not established by that unit test.
- **F08 — Security and availability:** Network changes can terminate the user's only working network route or disrupt a managed installation. Treat remote lockout, secret-agent impersonation and ambiguous dispatch as review-critical before enabling effects.
- **F09 — Stability and consumers:** NM query surfaces exist in CLI, daemon and First Boot. Read `contracts/stability.toml` / `docs/api-versioning.md` and update all existing contracts, tests and consumers coherently, rather than creating compatibility shims or breaking tested observational routes accidentally.

## S18-1 contract-first evidence and extraction map

The [S18-1 architecture review](../development/v010-s18-1-network-architecture-contracts.md) is a contract-first checkpoint, not an implementation or Q11 hardware milestone. PR #267 must carry traceable ADR 0048, inactive operation-design, security/qualification dossiers, validation routing, the Phase-1 audited baseline, milestone/ADR/qualification indexes, and threat-model references. The earlier placement of Rust identity code in #267 was incorrect; only **S18-2 / PR #268** owns core identity types and bounded passive NetworkManager observation.

| Acceptance boundary | Required source or proof | Must not be inferred from S18-1 |
| --- | --- | --- |
| Trusted observation model | Existing `ObservationEnvelope`/Control coordination and boot/bus-instance/unique NM owner design | Cached alias or a typed ID is native authority |
| Safe proposed effects | Nine disabled NetworkManager operation candidates; trusted Control/Polkit, route/DNS impact, durable recovery | A reviewed operation name or class authorizes dispatch |
| Credential safety | Original authenticated caller, purpose-bound secret-agent scope and retained evidence redaction | A saved Wi-Fi profile or shell prompt is protected authentication |
| Source and qualification routing | Canonical v0.10 contract/negative tests, real native A/B lineage and independently maintained physical C/Q11 | A successful unit test, mock, screenshot or VM proves physical Wi-Fi support |
| Development separation | S18-1 proposed architecture; S18-2 identity/observation; S18-3–8 authority/effects; S18-9 user experience; S18-10 integrated qualification | WIP ancestry makes any draft PR completed or independently qualified |

Do not copy the entire WIP history into #267 to manufacture a large diff. When extracting this PR onto accepted `main`, explicitly include all architecture documents and their exact traceability, independently rerun required gates, and retain S18's `planned` ledger state and inactive effects until qualified implementation is accepted.

## 3. Capability inventory and bounded v0.10 claim

States below represent the **audited S18 baseline**, not completed capabilities. "Partial" means the cited limited function exists, not that the full row passes S18 qualification.

| ID | Required/considered user capability | Baseline | S18 completion criterion |
| --- | --- | --- | --- |
| N18-01 | NetworkManager identity, health, networking enabled, global connectivity | Partial | Exact provider epoch and bounded fresh authoritative observations; degraded/offline/replaced service explicit. |
| N18-02 | Device inventory: wired, Wi-Fi, unmanaged, absent, carrier/state | Partial | Complete bounded typed device enumeration; no silent duplicate/name substitution. |
| N18-03 | Available Wi-Fi networks and scan-result presentation | Missing | Exact adapter-scoped, timestamped, privacy-bounded AP inventory, security/type flags and stale indication. Requesting an active scan is a separate effect. |
| N18-04 | Saved profiles and active connections | Missing | Read-only, identity-bound profile/activation inventory with immutable revision/effective-state distinction. |
| N18-05 | IPv4/IPv6, gateways, routes, DNS and connectivity interpretation | Missing | Authoritative effective configuration; distinguish link, IP allocation, default route, captive portal, limited/Internet and unknown. |
| N18-06 | Networking/radio and per-device enable/disable | Missing | Separate typed, policy-reviewed operations only where qualified; preserve recoverable connectivity. |
| N18-07 | Activate eligible existing Ethernet/Wi-Fi profile | Missing | Prepared exact profile/device/subject, bounded native effect, independent connected/effective-state verification. |
| N18-08 | Join Wi-Fi, with secure secret collection where necessary | Missing | Authenticated purpose-bound credentials, safe save policy, explicit user consent and verified resulting association. |
| N18-09 | Disconnect/deactivate exact connection | Missing | Correct owner/current activation binding, safety review, independent state and route verification. |
| N18-10 | Create/update/remove supported NM connection profiles | Missing | Versioned typed edits, full diff and impact/recovery, no arbitrary NM settings map or secret export. |
| N18-11 | Request active Wi-Fi scan | Missing | Separately classified and authorized/proved bounded radio action; never mislabeled a passive query. |
| N18-12 | Supported VPN inventory/status and plugin-specific workflows | Not established | Present explicit availability and unsupported reasons; activation only for a separately defined qualified plugin/secret scope, not arbitrary VPN plugins. |
| N18-13 | Manual DNS/IP/route editing, hotspot/mobile networking | Not established | Scope gate: remain unsupported until an explicit reviewed extension defines bounded types, risks and qualification; read-only status can be supported independently. |
| N18-14 | Control Center, Quick Settings, CLI/SDK, keyboard and accessibility parity | Missing S18 UI | One shared typed state and one Control operation identity; consistent denial/stale/offline/progress/verified outcome. |
| N18-15 | Loss/restart/rollback/no-network recovery | Missing S18 effect path | Durable ambiguity handling and independently reachable local recovery appropriate to each consequential operation. |

The accepted v0.10 product contract controls the final required subset. Network status/managed Ethernet/Wi-Fi and coherent connection controls are the first S18 implementation baseline; rows flagged "not established" cannot be promoted merely to satisfy a broad word such as "complete".

## 4. Target architecture: one model, one authority

```text
         Human / CLI / Control Center / Quick Settings / config / agent
                                        |
                                        v
                         Typed query or network request
                                        |
                                        v
                         +-----------------------------+
                         | Linura Control              |
                         | Authenticated principal     |
                         | Trusted class, risk, policy |
                         +--------------+--------------+
                                        |
                                        v
                              Class / support check
                                        |
             +--------------------------+--------------------------+
             |                          |                          |
             v                          v                          v
      READ-ONLY QUERY            MANAGED EFFECT               UNSUPPORTED
             |                          |                          |
    Observation Control         Plan / authorize          Blocked; no effect
             |                          |                          |
    Bounded NM observer          Durable prepare            Explicit reason
             |                          |                          |
    Fresh native facts         Narrow NM executor                  |
             |                          |                          |
             |                Independent verifier                 |
             |                          |                          |
             |                   Verify / commit                   |
             |                          |                          |
             |                  Audit / reconcile                  |
             |                          |                          |
             +--------------------------+--------------------------+
                                        |
                                        v
                        State / verified effect / denial
                               UI / CLI / SDK view
```

This is a **conceptual diagram**, not a new protocol or process. S18 must reuse the existing canonical `ReconciliationPlan`, `ObservationEnvelope`, Control-owned operation semantics, authenticated principal, existing managed-lifecycle machinery and established adapter/policy separation. Neither NM, a shell plugin, a library import nor an agent may select operation class or risk, manufacture executor grants or approve itself.

**Owner boundaries:**

- `linura-linux-observation` or a reviewed dedicated `linura-provider-networkmanager`: bounded native read mechanisms and typed platform/provider facts. One semantic NM observer identity must remain registered per Control coordinator; do not register overlapping `networkmanager` providers or mix separate aggregate authorities.
- `linura-observation-control` / `linura-control`: normalized authoritative observation orchestration, bounded fan-out/freshness, plan/effect binding, policy, transaction and outcome.
- Trusted operation registry and policy: fixed allowed operation IDs, typed permitted material keys, risk floors and provider/capability identities. All candidate entries remain unregistered until actual security review and tests.
- Narrow executor: constrained NM method families only after durable authorization and independently rechecked preconditions, never an ambient root D-Bus/`nmcli` command proxy. Privilege and Polkit subject must be proven for the *actual* caller/seat and service identity.
- Independent verifier/reconciler: obtain fresh post-effect state from authoritative NM/native signals, not receipt/return code alone. Bound reconciliation after crashes; do not replay indeterminate effects blindly.
- First-party `org.linura.ShellBridge` + `org.linura.UI`: user-facing presentation and typed invocation, with no provider handle, privileged executor or authority/risk selection. CLI/SDK share the same canonical operation names.

## 5. Proposed resource and evidence model (design only)

The existing `networkmanager:manager` and `networkmanager:device:<interface>` read-only query routes should remain functional while new typed identity-bearing evidence is developed. **Do not reuse a mutable interface-name alias as the unique authorization target.** Candidate resource revisions and typed structures are proposed below, not frozen public APIs.

### 5.1 NetworkProviderEpoch

An observed NM provider instance should carry:

- actual D-Bus **unique owner** (not merely `org.freedesktop.NetworkManager` or `NameHasOwner`), trusted system bus and kernel boot identity;
- bounded service health, NM version and provider status;
- Control observation sampling/sequence and stated freshness window;
- explicit source/provenance and replacement/unavailability state.

The native adapter should resolve `GetNameOwner`, bind operations on the unique destination where supported, and recheck owner before and after related reads/effects. A new unique owner invalidates old device, connection and operation preconditions. Do not elevate owner-name strings supplied by clients or snapshots.

### 5.2 NetworkDeviceEpoch

Bind a device to the provider epoch plus native object path **and cross-checked kernel/NM identity**, such as interface index (within the correct net namespace), interface name, NM UDI/permanent hardware identity where reliably provided, device type, managed state and current generation. Interface index, MAC, UDI, object path or driver text alone is not globally unique or immutable. On virtual interfaces or unsupported identities, use stricter fresh owner/object/generation checks and deny effects if continuity cannot be proven.

Do not silently collapse two different native devices that have the same interface alias; represent ambiguity as invalid/unsupported. Preserve a read-only human alias for navigation where appropriate.

### 5.3 ConnectionProfileRevision and ActiveConnectionEpoch

Differentiate:

- saved settings connection (profile UUID, native settings object, resolved type, typed normalized settings and **revision/content fingerprint** from accepted non-secret fields);
- activation instance (native ActiveConnection path, provider epoch, exact assigned devices, activation/state generation, resulting IP configuration);
- visible Wi-Fi network (adapter + AP object identity, SSID as bounded opaque bytes, BSSID/security capabilities and scan/result generation); and
- requested target operation (explicit device and profile/visible-network scope, not a moving "default" or "currently selected" alias).

Profile UUID, SSID, BSSID, connection name and D-Bus path are correlation attributes, **not** reusable authorization grants. A saved profile changing after planning requires fresh replan/reapproval if material state changes.

### 5.4 NetworkStateSnapshot

Project bounded authoritative manager/device/activation/radio/address/route/DNS state into typed envelopes, with a Control-owned coherent synthesis. NM's global `Connectivity` is an NM-reported category, not proof that the user's desired service is reachable. Require separate values for managed/unmanaged, carrier/link, authenticated Wi-Fi association, IP family/addressing, routes, DNS and connectivity as applicable. Missing or conflicted facts remain unknown rather than inferred from UI labels.

For multi-object observations: either establish consistent owner/generation and bounded revalidation or return insufficient evidence. Individual `GetAll` responses are not a whole-network atomic transaction. The provider emits narrow facts; Control owns cross-fact coordination, freshness, replay protection, query timeouts, resource budgets and aggregation.

### 5.5 Resource and performance ceilings

The existing PlatformProfile NM probe imposes a 128-device bound. S18 requires separately reviewed ceilings for returned devices, profiles, APs, active connections, settings keys, string/SSID byte lengths, nested D-Bus variants, total response bytes, timeouts, attempts and cross-provider concurrency. Fail closed with a typed boundedness error, not truncation that could hide a device or profile relevant to authorization. Never turn an unsupported/missing device into a success through an empty result.

No fixed timeout or capacity beyond existing audited constants is declared production-safe here; pin choices through native measurements, deterministic threat testing and the Control query policy before activation.

## 6. Operation classes, candidate effects and risk

The following is an **inert design inventory**; no row registers an executable operation. In all cases trusted classification and risk must be reviewed separately, with candidate risk floors not downgradable by UI/provider/model:

| Candidate operation family | Semantic class / consequence | Decision before activation |
| --- | --- | --- |
| Read manager/device/profile/active/IP/DNS/radio/scan *results* | `AuthoritativeQuery` | Fresh native observation, no external effect. |
| Open network panel, select adapter, edit an undispatched draft | `ExperienceEphemeral` | Local UI only; no privilege or machine effect. |
| Request a new radio scan | **External effect**, not read-only scan-result query | Review actual NM permissions, radio emissions, risk and session scope; qualified bounded transient only if fully proven unprivileged/at-most-UserState/no durability obligation, otherwise managed/unsupported. |
| Toggle NM networking, Wi-Fi radio, device management | Candidate `ManagedExternalEffect` | Machine-wide impact, Polkit and alternate connectivity/recovery; do not assume lightweight transient eligibility. |
| Activate/deactivate a connection | Candidate `ManagedExternalEffect` | Exact provider/device/profile/activation epochs, system routing impact and durable ambiguity/recovery. |
| Add/update/remove saved connection profile | `ManagedExternalEffect` for NM-owned durable settings changes | Typed allowlist, secret-handling, explicit review of material diff and shared profile ownership; retain rollback/recovery proof. |
| Adjust DNS, IP, routes, VPN or hotspot | Separate **unsupported** effect families until scoped/qualified | No arbitrary NM settings or VPN plugin passthrough; independent risk and native state verification. |

Do not conflate a read-only query with an external scan just because both appear under "Wi-Fi networks." Avoid optimistic "connected" success based solely on NM method return, ActiveConnection object creation or D-Bus `PropertiesChanged` delivery. For all managed families the canonical lifecycle is:

`request → observe → plan → validate → authorize → prepare → execute → independently verify → commit → audit → reconcile`.

A qualified transient action, if any, must obey the separately frozen transient Control contract, fresh post-dispatch verification and durable attempt audit; it cannot use a privileged executor or durable ambiguous recovery. Uncertainty requiring durable recovery forces managed semantics or unsupported.

## 7. Identity, authentication, privilege and secrets

- Derive `Principal` from trusted transport-authenticated caller metadata, not user-entered `Actor` fields; keep human provenance distinct from authority.
- Bind exact boot, host system bus/NM unique owner, selected resource epochs and current owner/session/seat where interaction or Polkit subject requires them. Do not infer local session ownership from environment variables or NM service credentials.
- Use purpose-bound system authorization/Polkit with fixed operation/subject and authentic subject identities where privileged NM calls require it. A Polkit "yes", prior user review or accepted plan is not a reusable executor credential.
- Wi-Fi PSKs, 802.1X credentials, VPN tokens and secret-agent responses never enter persistent intent, plan, SQLite audit, logs, test artifacts, generated UI copy or model context as plaintext. Use only reviewed protected native entry and secret facilities. Explicitly distinguish saving a credential from using it for one connection attempt.
- Secret handling must not turn NM's `GetSecrets` or `Update2` data into arbitrary unfiltered settings passthrough. Redact secret-bearing keys before diagnostic/audit export and enforce bounded native parsing.
- Disable/suspend controls during protected authentication, incompatible session state, stale identity or provider loss as required by S17 secure lock and S21 protected effects. S18 may not replace, unlock or bypass S17's owning protected session authority.
- No root-run `nmcli`, unrestricted shell, generic privileged D-Bus relay, agent-generated method names, client-selected policy floors, reusable approval tokens or user-controlled filesystem paths in the executor.

## 8. Connection safety and independently verified recovery

Network changes have unusual availability risk: unlike wallpaper/audio, an incomplete operation can destroy the communication channel used for administration. A graphical panel becoming unavailable is not a recovery mechanism.

1. **Preflight:** Identify the actual current default route(s), active interfaces, affected IP families, local/remote control path, and at least one known viable recovery route. A mere NM "connected" state is insufficient.
2. **Review:** Render the exact proposed effect, which active link(s)/DNS/routes it may displace, secrets required, trusted risk and whether a recoverable fallback exists. If safety cannot be proven on the target, deny rather than claiming an auto-revert guarantee.
3. **Prepare:** For managed effects, persist canonical plan, previous authoritative state, source/target epochs, expected postconditions, idempotency, attempt and bounded compensation/recovery strategy *before* executor dispatch.
4. **Dispatch:** Use a narrowly constrained exact NM action. Immediately before dispatch, re-attest source owner, device/profile/activation identity and relevant protected connection safety. A changed epoch or plan material invalidates authorization.
5. **Verify:** Independently re-observe required native NM objects, assigned devices, IP/DNS/routes and connection state after effect start. Verify the *requested* postcondition and separately present reachability/connectivity when actually tested; a provider receipt alone never proves success.
6. **Commit/reconcile:** Make durable success conditional on verified result and canonical lifecycle completion. After timeout, process death, disconnection, changed NM owner or ambiguous dispatch, re-observe before deciding repair/retry; never blindly replay a potentially applied action.
7. **Restore:** Any offered revert must be a separately authorized/revalidated operation using actual retained safe state, not guessed inverse D-Bus calls. Test that local, non-network-dependent recovery still works with NM or the GUI unavailable.

A remotely managed machine, single-link host or system with no independent local recovery may have narrower supported actions than an interactive workstation with a physical console. Explicitly distinguish connection rollback, independent local recovery and retry after uncertain effects.

## 9. First-party UX and no-model parity

The S18 user interface is a client of existing Linura Control, not a new network manager:

- **Overview:** provider availability/version, network enablement, current effective connectivity, wired/Wi-Fi device list, true/false/unknown observed state and freshness.
- **Wi-Fi:** safely rendered scanned networks with names/security types, bounded list/refresh, per-adapter identity, explicit active-scan consent and connection action only where a trusted operation exists.
- **Connections:** saved/active profiles and explicit connection/destructive-review drafts; current activation, route and DNS impact visible before dispatch.
- **Protected secrets:** purpose-bound network credential prompt isolated from presentation/agent/audit data, with cancellation/timeouts and no plaintext persistence.
- **Progress/outcome:** preparing/dispatching/verifying/verified/blocked/failed/indeterminate; no optimistic "connected" from a receipt. Re-open must reconstruct from fresh observation.
- **Unavailable:** degraded or replaced NM, unsupported Wi-Fi, network disabled, unmanaged/absent device, stale graph, unsupported VPN and denied policy visible with actionable reasons; no invisible fallback.
- **Interaction:** Control Center, Quick Settings, CLI/SDK, keyboard/shortcut and any accepted declarative/manual actions converge on the same registered operation; implement bounded focus/keyboard/screen-reader/reduced-motion/HiDPI presentation using `org.linura.UI 1.0` and ShellBridge. No command strings in QML.

The first-party shell must not keep a durable "connected" cache that conflicts with later NM observations. Any network lifecycle OSD/notification is presentation over actual verified state, not an alternate success source.

## 10. Threat model, adversarial and regression matrix

Every test must retain exact code/source and identify whether it used pure fixtures, native VM or physical hardware; synthetic fixtures alone cannot qualify native or Q11 support.

| Case | Threat / fault | Required oracle and outcome |
| --- | --- | --- |
| T01 | NM service absent / activatable but not owned | Provider unavailable; no synthetic success or request activation. |
| T02 | `NameHasOwner` true but NM unresponsive / health probe fails | Degraded/unsupported state; bounded timeout, no assumed truth. |
| T03 | Unique NM service owner replaced across `GetDevices` and `GetAll` | Reject mixed epoch; fresh re-observation; no mutation permit reuse. |
| T04 | Duplicate device interfaces, renamed interface, reused ifindex | Detect ambiguity; do not authorize based on name/ifindex alone. |
| T05 | Device vanishes / replaced after request but before dispatch | Precondition mismatch; cancel; no fallback to similarly named device. |
| T06 | Oversized device/AP/profile/variant array and nested data | Fail closed within resource/time budgets; no truncation masking conflicts. |
| T07 | Malformed or missing manager/device/connection property | Typed invalid/unsupported; no partial fabricated postcondition. |
| T08 | Concurrent NM settings change or replaced saved profile UUID | Reject stale revision; replan and rereview as required. |
| T09 | Moving default route, dual-stack asymmetry or late DHCP result | Independently verify exact requested IPv4/IPv6/routing postconditions. |
| T10 | NM reports connected but captive portal/limited/no Internet | Distinct observation labels; do not call connectivity/reachability verified without proof. |
| T11 | AP roaming, identical SSIDs or BSSID spoof/substitution | Keep exact requested adapter/AP association binding; no silent retarget. |
| T12 | Request scan crosses privilege/intent boundary | Never classify active scan as passive read; deny or use reviewed typed effect. |
| T13 | Wrong UID/seat/session, unauthenticated caller or confused deputy | Trusted transport/Polkit identity rejects effect before prepare/dispatch. |
| T14 | Expired, revoked, mismatched or reused approval | Reject; no executor grant derived from policy decision alone. |
| T15 | Changed trusted operation class/risk/material keys | Fail closed; cannot downgrade to transient or execute different request. |
| T16 | Wi-Fi secret denial, cancellation, substitution or agent impersonation | No credential leakage or unintended connection attempt. |
| T17 | Malicious profile with untrusted DNS/routes/secret-bearing fields | Typed allowlist, bounded sanitization and explicit material diff. |
| T18 | Single live network link about to be disconnected | Review and deny/require independently viable recovery; prevent unsupported lockout. |
| T19 | NM crashes or restarts during prepare, effect or verification | Durable indeterminate state/re-observe; no blind replay. |
| T20 | IPC reply lost after native effect applied | Idempotent reconciliation from independent observations; never double-dispatch. |
| T21 | Partial activation: link up, DNS/route missing | No verified success; explain incomplete effect and recovery state. |
| T22 | Device rfkill, airplane mode or unmanaged policy | Accurate unavailable/blocked status, no fake radio enablement. |
| T23 | GUI/compositor or remote model network unavailable | Local deterministic CLI/recovery remains available for supported paths. |
| T24 | Late duplicate native signal, old UI draft or reused request ID | Correlation/epoch checks reject stale completion. |
| T25 | Network profile shared by other intents/users | Ownership/dependency impact reviewed before destructive removal. |
| T26 | Change triggers S17 lock/session or S21 power/display transitions | Respect protected session epochs; no cross-slice bypass or stale feedback. |
| T27 | VM reports Ethernet while physical Wi-Fi untested | VM case may pass its own scope; physical radio/hardware claim stays unqualified. |
| T28 | Log or evidence captures SSID/PSK/BSSID/enterprise credentials | Data-class and redaction policy enforced; no secret-bearing audit/model payload. |
| T29 | No-change result after outdated authorization or stale evidence | Still require policy review and valid current precondition; no fake audit success. |
| T30 | Daemon restart restores an old progress badge from cache | Show observed fresh state/indeterminate outcome; never reanimate historic permit. |

Do not weaken existing v0.1 NM observation tests, First Boot, `ObservationCoordinator` identity/freshness, v0.6 managed systemd lifecycle, S08 volume, S17 protected session/security owner, S21 display/power/storage recovery or inherited v0.9 security/recovery acceptance.

## 11. Implementation requirements with verification traceability

The implementation of S18 should be organized around requirements, not a predetermined PR count:

| Requirement | Normative expectation | Minimum verification before claiming complete |
| --- | --- | --- |
| R18-OBS-01 | Read-only network observations use canonical envelope/provider/capability and preserve existing query aliases. | Existing v0.1 tests + native NM manager/device success/unavailable. |
| R18-OBS-02 | Unique NM owner, native resource generation and bounded simultaneous observations are explicit. | T01–T08, source restart and duplicate/race fixtures. |
| R18-OBS-03 | Device/AP/profile/active/IP/DNS/route/radio facts are typed, bounded and fresh. | T05–T12; exact-native provider tests with independent expected facts. |
| R18-AUTH-01 | Every external action is a separately registered typed operation and trusted risk floor. | T12–T15; operation-class substitution and policy negative tests. |
| R18-AUTH-02 | Privileged/durable/ambiguous operations use the full canonical managed lifecycle. | T13–T21, T24/T29; crash/restart/idempotency/independent verifier tests. |
| R18-SEC-01 | Identity, Polkit and secret-agent handling cannot be substituted or replayed. | T13–T17, T28; protected entry and audit redaction tests. |
| R18-REC-01 | Supported connection changes have proven failure/recovery behavior and local fallback. | T18–T23; native partial effect and lost reply tests. |
| R18-UX-01 | Control Center/Quick Settings/CLI/SDK agree on exact operation and current evidence. | T09/T10/T22/T24/T30; cross-interface negative and no-model tests. |
| R18-UX-02 | Usable keyboard/accessibility/HiDPI/lock interactions with explicit unavailable states. | S17 lock interaction, Q10 visual/a11y/interaction evidence. |
| R18-QUAL-01 | Exact-source native A/B and applicable physical C results are recorded independently. | v0.10 Q9/Q10/Q11 matrix and retained digest-bound artifacts. |
| R18-REL-01 | Release/ledger status changes only after complete dependency-closed merged PR evidence. | `tools/verify_v010_slice_pr_evidence.py`, applicable gates and release checks. |

## 12. Dependency and ownership plan

| Source area | Existing authority / intended owner | Phase 2 action |
| --- | --- | --- |
| `crates/linura-linux-observation/src/lib.rs` | Existing NM manager/device and PipeWire/systemd observers | Tight change-impact review; preserve old query identity while adding bounded NM facts or a reviewed separate module. |
| `crates/linura-linux-observation/src/platform_discovery.rs` | Exact supported PlatformProfile fact probe | No second network aggregate; preserve managed non-loopback rule and native probe budgets. |
| `crates/linura-observation-control/src/lib.rs` | Canonical coordination/freshness/retention | Integrate narrow new observations only through existing policy; no provider-owned global orchestration. |
| `apps/linurad/src/main.rs` / `apps/linura-firstboot/src/lib.rs` | Composition of read-only observer and First Boot | Preserve registration behavior and startup availability; inspect all consumer expectations. |
| `apps/linuractl/src/main.rs` / SDK | Read-only query surfaces | Preserve old routes and later add typed, parity-tested S18 actions through Control. |
| `crates/linura-provider-networkmanager/` (proposed) | Candidate narrow NM-specific adapter | Introduce only when it improves typed ownership without duplicate provider identity. |
| Control/planner/policy/transaction/executor | Existing trusted operation and managed lifecycle | Plan separate reviewed registry/authority changes, initially fail closed and unregistered. |
| `apps/linura-shell/bridge/`, `shell.qml`, `plugins/network/` | Existing unprivileged shell and shared Qt/QML SDK | Integrate after typed states/operations stabilize, minimizing shared-file conflicts with other slices. |
| `contracts/v010-workstation-slices.toml` / qualification | Machine-readable dependency and evidence | Do not change S18 completion/readiness until merged PR and actual applicable acceptance. |

**Cross-slice coordination:** S17 owns session/secure authentication and lock identity; S21 owns protected display/power/storage; S23 owns package source management; S24 owns coordinated updates/snapshots; S26 owns portable Library content; S27 owns broader declarative convergence; S28 owns First Boot installer. A network profile embedded in a Setup remains declarative, untrusted, nonauthorizing input. Bootstrap network connectivity is not an excuse to bypass S18 managed-network authority in the final workstation.

## 13. Exact implementation sequence (adaptive, not PR quotas)

1. **Baseline/consumer audit:** Check scoped AGENTS instructions, reviewed APIs, all NM query/First Boot/CLI consumers and applicable tests; verify actual toolchain and exact branch/base before coding.
2. **Bounded query foundation:** Refine resource/owner/health/budget behavior with independent pure tests and native fixture proof; keep existing observational routes, no write calls.
3. **Domain breadth:** Add typed Wi-Fi/AP, saved/active profile, IPv4/IPv6, DNS/route/radio observations with versioned contract, boundedness and coherence negative tests.
4. **Inert operation architecture:** Review trusted operation IDs, exact resource bindings, class/risk floors, current-principal semantics, policy/permission details and secret protections. Do not register unsupported effects for production.
5. **Narrow managed execution:** For approved scope, implement prepare → exact NM operation → independently verified postconditions → commit/audit/reconcile with restart and ambiguous-dispatch recovery. Effects remain unavailable until proven.
6. **First-party experience:** Implement shared Control Center/Quick Settings/QML, protected credential entry, CLI/SDK parity, accessibility and safe OSD/notification outcomes.
7. **Adversarial qualification:** Run all source, VM and applicable physical tests and document the real gaps; do not substitute mock/VM/network presence for a physical radio claim.
8. **Internal review and PR extraction:** After architecture/code are mature, identify *actual* independent trust and dependency cut lines. Some observations may become one or more PRs, others may require distinct secret agent, native executor, recovery or UX PRs. Consolidate each final PR on current accepted `main`; apply the full exact-head review/CI sequence. **No fixed number of PRs.**

## 14. Completion and evidence policy

Phase 1 is completed by a reviewed audit and this explicit specification, **not** by passing runtime qualification. The following remain implementation/qualification obligations:

- typed network resources beyond existing manager/device snapshots;
- real full-featured native NM adapter implementation and adverse-state behavior;
- independently reviewed risk/operation registration; authenticated narrow executor and protected secrets;
- durable prepare/verification/recovery and shared-ownership safety;
- first-party GUI/CLI/SDK parity and no-model operation;
- exact-source Arch VM runtime and genuine hardware/network adapter evidence as required by the claimed workflow;
- applicable Q9/Q10/Q11, inherited older-release, security/visual/accessibility checks, formal review and merged-PR evidence.

Run before implementation in a prepared environment: `bash scripts/preflight_codex_environment.sh` (Codex/cloud), `python3 tools/codex/doctor.py --all`, existing affected crate/unit tests, `python3 scripts/check_repository.py`, `python3 tools/check_roadmap.py` and `cargo xtask check`. For architecture/ADR changes also run `python3 tools/check_adrs.py`; follow scoped `docs/AGENTS.md`. On shell changes add pinned QML/bridge/native/visual gates. Keep exact-head CI, audit and CodeQL required by the repository's gate matrix.

**Evidence statement for this document:** Source and contract inspection only; no build, unit test, VM execution, physical Q11 run, operation enablement, security signoff or release acceptance is claimed. The proposed identities/classifications are subject to implementation review and native proof before registration.
