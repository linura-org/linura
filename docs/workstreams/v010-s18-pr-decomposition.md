# S18 v0.10 implementation extraction — five reviewable PRs

> **WIP decomposition only.** Do not merge this branch directly, create a PR from this planning step, activate NetworkManager mutations or promote S18/Q11 evidence. The Phase-1 source is [S18 Phase 1](v010-s18-network-phase1.md), [proposed ADR 0048](../adr/0048-s18-networkmanager-authority.md) and [inactive S18 design](../../contracts/v010-s18-design.toml).

The machine-checkable decomposition is [`contracts/v010-s18-pr-decomposition.toml`](../../contracts/v010-s18-pr-decomposition.toml). **S18-1–S18-5 are slice-local identifiers, not assigned GitHub PR numbers.** Each eventual PR is extracted onto independently checked accepted `main`, including its entire source-owned functionality, negative/adversarial tests, canonical security/regression checks, native source-bound acceptance and review. No placeholder test or documentation can satisfy implementation evidence.

| Order | Boundary | Main dependency | Activation |
|---|---|---|---|
| S18-1 | native-network-observation | S16 | No external effect |
| S18-2 | wifi-discovery-radio | S18-1 | Only after independently qualified managed authorization, native verification and offline recovery |
| S18-3 | connection-lifecycle | S18-1, S18-2 | Only after independently qualified managed authorization, native verification and offline recovery |
| S18-4 | connection-profile-management | S18-1, S18-3 | Only after independently qualified managed authorization, native verification and offline recovery |
| S18-5 | experience-qualification | S18-1, S18-2, S18-3, S18-4 | No external effect |

## Engineering requirements

### S18-1 — feat(network): establish bounded native NetworkManager observation

**Capabilities:** `networkmanager.manager.observe`, `networkmanager.device.observe`, `networkmanager.wifi.observe`, `networkmanager.connections.observe`, `networkmanager.ipconfig.observe`.

**Owned source (proposed boundary):** `crates/linura-linux-observation/src/`, `crates/linura-observation-control/`, `apps/linurad/src/`, `apps/linura-firstboot/src/`.

**Must deliver:**
- Extend the canonical NetworkManagerObserver and ObservationEnvelope; preserve tested manager/device query aliases, daemon/CLI/First Boot integration, and existing PlatformProfile provider-discovery behavior without creating a second authority.
- Pin actual NetworkManager system-bus unique owner and boot epoch across bounded manager, device, saved-profile, active-connection, AP and IP reads; detect daemon replacement, alias/path reuse and inconsistent multi-object snapshots rather than claiming an atomic GetAll.
- Provide typed observed wired/Wi-Fi inventory, passive AP results, saved/active connection identities and revisions, IPv4/IPv6 assignment, gateways, DNS, default routes and radio/rfkill with explicit stale/unknown/unsupported states; distinguish NM connectivity category from independent Internet reachability.
- Enforce native transport byte/variant/depth, list count, string and time ceilings before unsafe allocation/retention; reject duplicates and oversized/malformed data, not truncation or first-match identity selection.
- Keep all observations read-only; reading scan results is permitted, but RequestScan, secret retrieval, profile mutation and connection activation cannot be reached from the observer; add source-pinned negative/real-native tests.

**Negative cases:** T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T22, T27, T28.

**Evidence:** unit-malformed-and-duplicate-device-fixtures; level-a-real-networkmanager-system-bus; existing-control1-cli-firstboot-regressions; observation-control-regression.

**Release-blocking until:**
- Exact-source Rust unit/adversarial and inherited regression checks pass
- Real NM owner-replacement, hotplug, service-absent, malformed-object and budget/deadline tests pass
- Complete AP/profile/active/IP/DNS/route observations are verified without claiming physical Wi-Fi support

**No native external effects are authorized by this boundary.

### S18-2 — feat(network): qualify Wi-Fi scan and radio management authority

**Capabilities:** `networkmanager.manager.observe`, `networkmanager.wifi.observe`, `networkmanager.device.observe`.

**Owned source (proposed boundary):** `crates/linura-linux-observation/src/`, `crates/linura-control/`, `crates/linura-policy/`, `contracts/operation-semantics.toml`.

**Must deliver:**
- Keep passive AP reads separate from active RequestScan, which is an external effect; define exact adapter- and epoch-scoped scan limits, permissions and privacy, never a read-only shortcut.
- Qualify independently typed networking-enabled and Wi-Fi-radio operations against observed NM, rfkill, hardware block and managed/unmanaged state; never conflate adapter and global toggles.
- Route each proposed effect through trusted Control registration, canonical ReconciliationPlan, authenticated principal, policy, prepare, bounded native execution and independent postcondition verification; no shell/nmcli or generic D-Bus forwarding.
- Bind unique NM owner, boot, device and relevant route generations before dispatch; reject changed epochs, changed risk class, reused approval, ambiguous replies and foreign session/Polkit subjects.
- Protect the last working link and system/remote administration; deny when a proven local recovery path is required but unavailable, with durable indeterminate state and no blind replay.

**Negative cases:** T02, T03, T05, T06, T11, T12, T13, T14, T15, T18, T19, T20, T22, T23, T26, T29.

**Evidence:** unit-scan-authorization-and-rfkill; level-a-real-nm-scan-radio; managed-effect-denial-and-no-replay; local-recovery-and-security-review.

**Release-blocking until:**
- Separately reviewed operation classes, risk floors and authenticated NM/Polkit subject are accepted
- Native scan permissions/emission/privacy and bounded request/verification are independently proven
- Networking/radio toggles have viable offline local recovery and full durable ambiguity qualification

**Inactive candidate operations:** `operation:network.wifi.scan`, `operation:network.networking.set-enabled`, `operation:network.wifi.set-enabled`. None can be registered or enabled simply by extracting this plan.

### S18-3 — feat(network): implement protected connection activation and recovery

**Capabilities:** `networkmanager.connections.observe`, `networkmanager.wifi.observe`, `networkmanager.ipconfig.observe`.

**Owned source (proposed boundary):** `crates/linura-control/`, `crates/linura-policy/`, `crates/linura-linux-observation/src/`, `apps/linura-shell/plugins/network/`.

**Must deliver:**
- Prepare exact profile revision, device/adapter, active-connection instance, owner/boot/session generation and impact on current IPv4/IPv6 default routes before activation or deactivation.
- Keep authenticated Wi-Fi credentials in purpose-bound protected native handling; prohibit plaintext PSK, 802.1X, SSID/BSSID-sensitive diagnostics and secret-agent payloads in model, intent, plan, logs or retained evidence.
- Distinguish one-time join from saving credentials/profiles; durable creation or editing must use S18-4 approved allowlisted profile authority, not hidden auto-save or arbitrary NM settings passthrough.
- Verify independent association, active profile, IP, DNS, routes and requested postcondition; NM Connected/Connectivity category or D-Bus method receipt alone cannot prove Internet reachability or completion.
- Retain uncertain-effect intent and native attempt; after crash, restart, lost reply, lock transition or route loss re-observe before compensation/retry and never replay blindly, with offline local recovery for consequential changes.

**Negative cases:** T03, T05, T08, T09, T10, T11, T13, T14, T15, T16, T18, T19, T20, T21, T23, T24, T26, T29.

**Evidence:** unit-identity-route-secret-and-ambiguity; level-a-native-ethernet-and-wifi-lifecycle; level-b-protected-credentials; level-c-maintained-wifi-recovery; security-and-managed-lifecycle-regressions.

**Release-blocking until:**
- S17 protected credential/session handling, true native principal and exact NM subject are qualified
- Native connect/disconnect/join proof includes default route and DNS postconditions, partial activation and no-blind-replay recovery
- Physical Wi-Fi connection and offline local recovery evidence exist before claiming physical support

**Inactive candidate operations:** `operation:network.connection.activate`, `operation:network.connection.deactivate`, `operation:network.wifi.join`. None can be registered or enabled simply by extracting this plan.

### S18-4 — feat(network): add revisioned NetworkManager profile management

**Capabilities:** `networkmanager.connections.observe`, `networkmanager.ipconfig.observe`.

**Owned source (proposed boundary):** `crates/linura-control/`, `crates/linura-policy/`, `crates/linura-linux-observation/src/`, `apps/linura-shell/plugins/network/`.

**Must deliver:**
- Provide typed, allowlisted saved-profile create/update/delete with exact setting revision, UUID and original owner scope; reject arbitrary settings maps, unreviewed VPN plugins and unsupported IP/DNS/hotspot extensions.
- Present complete material diff, credential-save choice, owners/dependents and activation/default-route impact before any persisted change, with explicit conflict refusal and rereview.
- Bind authentic Polkit subject, native settings owner epoch, exact previous profile version and durable Control-prepared transaction before mutation; never treat a user-supplied UUID as authority.
- Make profile deletion destructive-risk with shared-owner/dependent and safe-restoration checks; never remove an active/last viable profile without qualified recovery.
- Verify persisted native revision and intended effective state separately; detect edits by foreign applications, NM restart and ambiguous/lost replies without blindly re-executing.

**Negative cases:** T03, T05, T08, T09, T13, T14, T15, T16, T17, T18, T19, T20, T21, T24, T25, T28, T29.

**Evidence:** unit-allowlist-revision-ownership; level-a-native-nm-profile-edits; shared-owner-and-secret-redaction; indeterminate-rollback-security-review.

**Release-blocking until:**
- Allowlisted typed profile schema and exact current NM settings revision are accepted
- Real NM profile mutation, concurrent-edit detection, shared-ownership safety and independent recovery are proven
- Destructive deletion risk remains non-downgradable and protected secrets are never leaked

**Inactive candidate operations:** `operation:network.profile.create`, `operation:network.profile.update`, `operation:network.profile.delete`. None can be registered or enabled simply by extracting this plan.

### S18-5 — feat(network): deliver unified network experience and qualification

**Capabilities:** `networkmanager.manager.observe`, `networkmanager.device.observe`, `networkmanager.wifi.observe`, `networkmanager.connections.observe`, `networkmanager.ipconfig.observe`.

**Owned source (proposed boundary):** `apps/linura-shell/plugins/network/`, `apps/linura-shell/bridge/`, `apps/linuractl/src/`, `crates/linura-sdk/`, `qualification/v010/interactive-workstation/`.

**Must deliver:**
- Use one typed Control state across network Control Center, Quick Settings, CLI/SDK and no-model flows; preserve existing manager/device query aliases, provider health and separate readiness/effect status.
- Show fresh link, association, profile, IPv4/IPv6, DNS, route, portal/limited/unknown observations; never promote cached, inferred or NM-reported connectivity into independently verified Internet access.
- Render purpose-bound protected credentials, exact review/approval, denial, stale data, progress, indeterminate/compensating state and verified outcome with correct S17 lock/session ownership.
- Prove keyboard, focus, pointer, screen-reader, high-DPI/reduced-motion, screenshot/privacy and native offline fallback in actual ShellBridge/Qt/QML without direct QML NetworkManager mutation.
- Retain exact-head A/B/Q9/Q10 and separate real physical C/Q11 hardware evidence; missing physical NIC/roaming/rfkill/recovery proof cannot be replaced by VM, mock or video.

**Negative cases:** T01, T02, T09, T10, T16, T18, T20, T21, T22, T23, T24, T26, T27, T28, T30.

**Evidence:** level-a-source-pinned-arch-nm-native; level-b-interactive-control-center-quick-settings; level-c-maintained-physical-nic-wifi-q11; q10-accessibility-and-visual; full-inherited-regressions.

**Release-blocking until:**
- All predecessor S18 implementation PRs independently merge with exact-head canonical/security gates
- GUI/CLI/SDK and offline no-model parity prove fresh observed outcomes without optimistic success
- Maintained physical Wi-Fi/Q11 plus exact-source Q9/Q10 and inherited Q12-Q14 evidence are accepted before slice-wide support

**No native external effects are authorized by this boundary.

## Extraction and integration rules

1. Re-audit the true accepted `main` source, ADR ledger, `contracts/stability.toml` and all daemon/CLI/First Boot/Control consumers before extracting any work from this WIP branch.
2. The current WIP branch already has **partial read-only observer edits** in `crates/linura-linux-observation/src/lib.rs`; do not mistake these for the complete S18-1 implementation. Re-review the owner/path `E0505` correction, boundedness, zbus cached property behavior, coherent D-Bus generations and native source qualification before porting it.
3. Split by reviewed feature/trust boundaries, not by commit quotas. Each PR must carry its actual implementation, adverse-case tests, separate qualified evidence and a cohesive commit history; re-evaluate the five boundaries if real code findings require a different number of PRs.
4. `S18-2` owns active RequestScan and both network/radio toggles; these are distinct from passive scan observations. All nine candidate effects remain inert until each trusted class and risk floor, transport-authenticated principal/Polkit subject, canonical plan, durable prepare, narrowly typed native effect, independent verify, durable reconcile and offline recovery are accepted.
5. `S18-3` may use one-time credentials only through purpose-bound protected handling; durable profile/secret saving belongs to `S18-4`. Never implement an implicit profile-save side effect, secret in logs/audit/model, generic privileged D-Bus relay, direct `nmcli` or arbitrary NM settings map.
6. Enforce S17 protected lock/session, S21 power/display/storage, S23/S24 package/update boundaries, Control-owned observation coordination and shared-route safety. Cross-slice shell/QML files require coordinated integration ownership.
7. Supported observations must distinguish NM-reported connectivity, local routing/DNS, real Internet reachability and unknown/portal; never claim a postcondition from an NM method receipt or an optimistic cached UI state.
8. Keep release ledger S18 `planned` until merged implementation PRs with exact-head CI and applicable Q9/Q10/Q11/Q12/Q13/Q14 evidence. An Arch VM or simulated Wi-Fi does not prove physical C/Q11. Do not merge WIP directly or create a PR until extraction is explicitly authorized.

**Validation before any later extraction:** `python3 -m unittest tests.tooling.test_v010_s18_decomposition tests.tooling.test_v010_s18_design`, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py` and the canonical `cargo xtask check`, followed by applicable source-pinned CI/native qualification on each actual implementation PR.

## Decisions requiring explicit review

- A D-Bus unique NM owner identifies a service generation, but does not make multi-object reads atomic or provide authenticated device/profile mutation identity. Enforce owner/boot/device/active/profile revision coherence and bounded transport data.
- `GetAccessPoints` and `RequestScan` have different semantics. NetworkManager may restrict scanning by permissions; no hidden radio emissions or automatic scans on read-only queries.
- Wi-Fi join, activation, profile changes and network disablement may remove the control plane's only route. Safety depends on actual independent offline local recovery, not a GUI timer or NM connectivity category.
- Native network secrets require protected session/Polkit handling and data minimization. An SSID, BSSID or profile UUID is not a credential or safe stable effect authority.
- Profile deletion has a destructive trusted floor and requires owner/dependency review, exact current revision and a recovery policy before authorization. Arbitrary VPN/hotspot/multimode administration remains explicitly unsupported.
