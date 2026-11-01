# ADR 0048 — S18 NetworkManager authority, identity and network recovery

- Status: Proposed
- Scope: v0.10 S18, `arch-hyprland-v1`
- Refines: ADR 0012, ADR 0017, ADR 0018, ADR 0024, ADR 0031, ADR 0032 and ADR 0033

## Context and decision

Linura already offers experimental read-only NetworkManager manager/device observation in `crates/linura-linux-observation`. Platform discovery checks the live selected provider separately. Neither feature authorizes connection/profile mutations, Wi-Fi scans, access to secrets, or runtime claims of recoverable connectivity.

**One model, one trusted Control authority architecture.** The companion [S18 proposed design](../../contracts/v010-s18-design.toml) is inert specification data, **not** operation registration, policy, a native adapter or runtime support evidence. Client/provider/agent input cannot choose operation class, trusted risk, policy outcome, executable plan or effect grant.

## Authoritative network observations

Bind the actual system-bus `org.freedesktop.NetworkManager` **unique owner**, boot and coherent read generation, then the exact device, saved settings/profile revision, active connection instance, AP and IP configuration identities. Interface names, MAC/BSSID, SSID, profile UUID, ifindex and native D-Bus paths are useful correlation but do **not** independently confer mutation identity. Detect duplicates and replacement rather than first-match selection. A multi-object `GetAll` sequence is not atomic; inconsistent provider epochs, changed device paths, profile revisions or contradictory routes fail closed.

Preserve v0.1 `networkmanager:manager` and `networkmanager:device:<interface>` read-only aliases and CLI/First Boot consumers; use `ObservationEnvelope` and Control-owned `ObservationCoordinator`. Provider probes stay bounded, typed and native. PlatformProfile discovery is selection evidence, not a parallel network-state authority.

## Distinct operation families

Passive reads of adapter, scanned AP results, saved/active profiles, IP/DNS/routing and radio state are `AuthoritativeQuery`; selecting UI panels/drafts is `ExperienceEphemeral`. **Requesting a new Wi-Fi scan is an external effect**, not a query. Conservatively propose it as managed until a separately reviewed narrow transient proof establishes unprivileged, at-most-`UserState`, nondurable, bounded semantics and correct audit.

Network enablement, Wi-Fi radio toggling, profile activation/deactivation, joining authenticated networks and durable NM profile creation/update/deletion are conservatively **candidate `ManagedExternalEffect`** operations. Each requires a reviewed trusted operation/risk floor, canonical deterministic plan, exact actor/principal and resource epochs, authenticated native subject, durable prepare/attempt, narrow effect, independently verified requested postcondition and audit/reconcile. Do not expose unrestricted `nmcli`, privileged shell, D-Bus method relay, settings map passthrough or class downgrade. Unknown/unsupported effect remains denied.

## Caller, secrets and subject

Derive `Principal` from authenticated transport, separately from descriptive `Actor`. Preserve original user/session/seat and the real Polkit subject required by NetworkManager; administrator/root presence is not a transferable approval. PSKs, EAP/802.1X secrets, VPN tokens and secret-agent exchanges must not enter intent, plans, audit, logs, model context or retained evidence in plaintext. A purpose-bound protected UI and reviewed native secret-agent path are prerequisites for credential-required joining; saving secrets and using one-time credentials are separately reviewed choices.

## Network-loss and uncertain-effect recovery

Before a disruptive request, observe impacted wired/Wi-Fi links, active IPv4/IPv6 default routes, DNS, ownership and usable **offline local** recovery. If a dependable fallback is required but cannot be proven, deny the operation; do not assume a GUI timer or remote connection can restore it.

A provider acknowledgement, new ActiveConnection object, PropertiesChanged signal or optimistic UI receipt does not prove connected state. Only later independent, identity-bound native observation of the *requested* device/connection/IP/DNS/route state can verify. NM's reported connectivity category is not proof of end-to-end reachability. For lost reply, partial DHCP/DNS/route application, daemon restart or crash, retain indeterminate durable state and **re-observe before any re-execution**; never replay blindly. Revert is a new safely authorized/verified operation using authentic previous evidence, not a guessed inverse.

Preserve S17 secure-owner/lock and S21 power/display protections, v0.9 First Boot nonauthorizing bootstrap, v0.6 managed transaction and native break-glass recovery. S18 cannot weaken these to provide an easier quick toggle.

## Experience, acceptance and consequences

Control Center, Quick Settings, CLI/SDK, manual/no-model, approved configuration and agent proposals must map to the same typed operations and verified state. First-party ShellBridge/UI is presentation-only, with explicit unknown/stale/denied/indeterminate status, protected credentials, keyboard/pointer/a11y, scale and offline recovery.

The [domain qualification](../qualification/v0.10.0-s18.md) and [adversarial security dossier](../qualification/v0.10.0-s18-security.md) refine Q9–Q14. Exact-source native VM tests and real maintained physical Wi-Fi hardware are separate evidence classes; video/synthetic fixtures do not substitute for native or Q11 proof. S18 remains planned; no operation, hardware support, interactive readiness or release claim changes from this ADR.

Implement read-only identity and bounded coverage before evaluating operation registration; then authenticated narrow execution, independent recovery and user interfaces. Determine future PR boundaries adaptively by actual trust/feature/qualification dependencies, not a quota.
