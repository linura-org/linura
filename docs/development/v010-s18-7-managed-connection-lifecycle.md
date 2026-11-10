# S18-7 — add managed connection lifecycle

**Status:** Typed Control effect and passive native lifecycle preflight/readback implemented; **no qualified execution or native mutation**. Draft.
**Milestone:** v0.10.0 / S18-7.
**Profile:** `arch-hyprland-v1` (development).
**Authoritative reference / draft PR base:** `wip/v010-s18-network` at `63265739f8a62f2e7a7d3c665d7c9af7f8946537`.

## Ownership and dependencies

This S18 feature is independently reviewable after S18-2, S18-3, S18-4. This PR now contains S18-7-specific Control and passive native observation modules against the S18-4 base; sibling radio PR #272 remains unqualified and is not inherited.

Normative WIP sources:
- [Phase-1 S18 architecture](../workstreams/v010-s18-network-phase1.md), [ten-part implementation plan](../workstreams/v010-s18-pr-decomposition.md), [machine-checked breakdown](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive candidate operations](../../contracts/v010-s18-design.toml).
- [Native qualification](../qualification/v0.10.0-s18.md), [adversarial qualification](../qualification/v0.10.0-s18-security.md).

## Source ownership, requirements and negative cases

- `crates/linura-control/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-linux-observation/src/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-policy/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `executors/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.

Requirements: R18-AUTH-01, R18-AUTH-02, R18-SEC-01, R18-REC-01.
Required negative cases: T03, T05, T08, T09, T10, T11, T13, T14, T15, T16, T18, T19, T20, T21, T23, T24, T26, T29.

## 2026-11-10 native safety and recovery extension

- [x] Independently sample bounded Linux IPv4 and IPv6 main-table routes and IPv6 kernel-address inventory from the original host network namespace, with double-read drift checks and typed source parsing. These checks may **deny** lifecycle settlement on a missing kernel route or loss of unaffected routes, but policy rules, marked sockets, source routing, effective DNS and offline recovery remain **unverified**.
- [x] Deny deactivation when an affected family loses its last observed main-table default route, the target keeps a default route, or unrelated route/address state changes. This cannot be used as an approval for physical connectivity loss.
- [x] Add authenticated **historical-only** S18-7 transaction-status access through the retained request journal, canonical verb/resource classifier, request digest and durable Control transaction; no replay, mutation or current-state inference.
- [x] Add a fixed native original-user NetworkManager **call encoder** for `ActivateConnection(saved, device, AP)` and `DeactivateConnection(active)`, with strict native object-path and unique-daemon-owner syntax, no generic methods, secrets, settings map, autostart or execution endpoint. Separate native tests reject substituted targets, verbs, media, AP, and permissions other than exact `network-control=yes`.
- [ ] Prove a real original-user signed, one-use Control-to-native NetworkManager dispatch and subject-specific Polkit permission. A fixed method encoder alone does not authenticate the sender or attest Control's durable spend. There is no public enabled effect on this PR.
- [ ] Independently verify actual kernel IPv4 addresses, effective policy routing, per-domain DNS, remote admin socket survival and physical offline restoration, then qualify native A/B and physical C/Q11.

## Required implementation (not yet completed)

- [x] Bind activation to an exact saved profile and original kernel device; bind deactivation to its original active-connection generation. Reject replaced profile revision, changed NM boot/bus/owner, device/ifindex/netns, foreign path and active generation.
- [x] Add a non-cloneable, durably spent Control handoff constructor from the original AuthorizedEffect, with exact request, transaction, effect and permit equality; no native executor consumes it yet.
- [x] Add real, owner-pinned passive NetworkManager preflight and readback, with profile version, device, active generation, association, per-family addresses, nameservers and routes. No Wi-Fi scan required.
- [ ] Connect the actual original-user native sender and real NetworkManager effect after independent safety qualification.
- [x] No secret values, generic settings maps, profile saves or dynamic D-Bus methods are present in the new effect; unsaved/foreign profiles are rejected.
- [ ] Wire S18-4 protected one-time credentials into join-specific original-user execution. Join and persistent configuration remain different effects.
- [ ] Review route/DNS/dual-stack impact and protect last viable control path before dispatch.
- [x] Type both activation/deactivation effects and check post-dispatch fresh NM device/active/IPv4/IPv6/DNS/route/association data rather than treating NM's method reply as proof.
- [ ] Add independent **kernel** IP/route and effective resolver evidence, verify original remote administrator survival and safely handle partial DHCP. Current NM-only readback is explicitly **not** a durable commit verification.
- [ ] Preserve durable indeterminate attempt and re-observation after daemon restart, changed profile, partial DHCP or lost reply; never auto-retry.

## Acceptance evidence (not yet established)

- [ ] real-nm-ethernet-and-wifi-lifecycle
- [ ] protected-credential-native-qualification
- [ ] partial-ip-dns-route-and-no-replay
- [ ] Real native and protected Wi-Fi qualification pending; unsupported physical hardware remains explicitly unqualified

## Security, recovery and explicit non-claims

- Candidate operations: `operation:network.connection.activate`, `operation:network.connection.deactivate`, `operation:network.wifi.join`; none are enabled, registered or qualified.
- Preserve the real user/session/Polkit subject, canonical Control plan, trusted risk floor, bounded native effects, independent verification, durable indeterminate/no-replay recovery, S17 protected session, S21 device safety, and offline local recoverability.
- No generic D-Bus/nmcli/shell or model/GUI command execution; reject unknown/stale/incomplete identity, owner replacement, last viable link loss and replay.
- This draft contributes passive native source diagnostics and non-transmitting typed effect contracts but **no executable runtime authority, client UI, feature flag, operation registry, privilege, physical Q11 proof or released support**. The prior PR branch name does not define this feature.

## Implementation extraction and eventual release

Continue reviewed S18-7 source changes on the intended PR branch (WIP is a reference). Require exact-head CI, fresh Security and CodeQL, native real-NM A/B/physical C and required inherited gates. Do not enable the managed-network effect while original-user dispatch, offline local recovery, independent kernel/effective DNS verification or required qualification is missing.

Original reserved head: `archive/pre-s18-rebuild-20261101-pr-273`; retained GitHub PR head name: `feat/v010-s23-1-xdg-observation`.

## 2026-11-11 original-user private sender foundation

- [x] Added a native **unexposed** sender type that can consume one privately constructed attempt, verify the current protected user UID and NetworkManager daemon, query the actual user's `GetPermissions` and dispatch only the two fixed typed lifecycle methods. Malformed, duplicate-key or non-`yes` permission data fail closed. Transport errors, lost replies or a replaced manager are indeterminate and must never be retried. The activation acknowledgement is checked for a typed active-connection object path; it is **not** a commit or postcondition.
- [x] Added isolated no-I/O C++ negative tests for mismatched original lock/user/daemon, unsupervised manager, root identity, consumed attempts and move-only replay; fixed the exact-head Rust Clippy qualification diagnostic.
- [ ] The **private attempt has no production constructor invocation or Control-to-native caller**. Authentic sealed Control spend and original-session/Polkit proof, safe impact policy, durable attempt journal, crash recovery and independently verified effective routing/DNS/reachability must be connected before any call site or operation is enabled.
- [ ] Real NetworkManager/Polkit Level A and interactive Level B, plus physical Level C/Q11 evidence remain outstanding. Source work is not release qualification.

## 2026-11-11 kernel IPv4 correlation and profile recheck

- [x] Added an independent, bounded RTM_GETADDR local-IPv4 read-only witness, tied to the exact Linux ifindex and initial host network namespace; malformed, duplicate, stale, interrupted and user-origin netlink replies fail closed.
- [x] Reject lifecycle readback when current NetworkManager IPv4 address/prefix rows differ from installed kernel IPv4 addresses; also reject lingering target IPv4 addresses after deactivation and unrelated-interface IPv4 address drift.
- [x] Re-read the saved profile's exact settings revision **after** dependent device, active, IP and AP observations; reject profile edits or native device-type/interface substitution during the source read.
- [x] Add independent positive and negative kernel IPv4 parser fixtures; all native network operations remain unregistered and disabled.
- [ ] IPv4 kernel address correlation is not proof of policy/marked routes, split DNS, administrator survival, offline recoverability or a causally authorized native effect. Durable Control-to-native sending, original session/Polkit subject and Level A/B/C acceptance remain outstanding.

## 2026-11-11 exact Wi-Fi AP-binding extension

- [x] Separate typed Ethernet and Wi-Fi activation contracts. Wi-Fi requires a device-bound `NetworkAccessPointId`; the Control effect's canonical descriptor includes media, exact AP native path and observed AP generation. Substituted APs cannot match the original reviewed descriptor.
- [x] Native passive preflight rejects Wi-Fi media masquerading as Ethernet and vice versa, requires the selected AP in the exact device's bounded native AP inventory, and double-reads its nonsecret SSID/BSSID/frequency/security-flags projection after IP/device/profile observation.
- [x] Fresh post-state readback rejects active Wi-Fi association to any AP other than the reviewed one. Ethernet activation rejects a Wi-Fi active connection or unexpected AP.
- [x] Unit fixtures reject foreign-device and substituted AP correlations, media substitution and altered post-association; corrected the empty-datagram incomplete-dump test without weakening its deadline/termination requirements.
- [ ] Actual original-session and Polkit-subject proof, spent Control grant transport, durable attempt/recovery, effective routing/DNS, administrator survival and Level A/B/C/Q11 remain outstanding. These typed AP checks are correlation, not trust in an SSID, proof of radio reachability or an executable grant. No network effect is enabled.

## 2026-11-11 independent IPv6 address cross-check

- [x] The kernel's independently collected IPv6 address/ifindex/prefix/flags inventory now checks claimed NetworkManager IPv6 addresses. A missing, foreign, tentative, duplicate, failed or deprecated provider address denies positive readback. Unexpected link-local kernel addresses cannot be used to claim effective DNS or routing.
- [x] Adversarial fixtures cover changed interface index, substituted addresses, invalid prefix and unready address flags. The separate effective routing/split-DNS/remote admin/offline recovery gates remain outstanding.
