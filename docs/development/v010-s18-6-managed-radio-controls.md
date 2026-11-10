# S18-6 — add managed networking and radio controls

**Status:** Draft implementation in progress. Non-authorizing radio review, independent readback diagnostics, original-user single-use native D-Bus sender and historical Control recovery inspection have source/tests. End-to-end durable Control dispatch, independently proven effective routing/split DNS/remote and offline recovery, authorized native transition, and A/B/C qualification remain outstanding. **All radio changes remain unregistered and unreachable from public APIs.**
**Milestone:** v0.10.0 / S18-6.
**Profile:** `arch-hyprland-v1` (development).
**Authoritative reference / draft PR base:** `wip/v010-s18-network` at `63265739f8a62f2e7a7d3c665d7c9af7f8946537`.

## Ownership and dependencies

This S18 feature depends on S18-2, S18-3, S18-4. The current PR builds its own isolated review code on the existing #270 integration base. Neither WIP development checks nor CI on a pre-existing placeholder qualify the new effect.

Normative WIP sources:
- [Phase-1 S18 architecture](../workstreams/v010-s18-network-phase1.md), [ten-part implementation plan](../workstreams/v010-s18-pr-decomposition.md), [machine-checked breakdown](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive candidate operations](../../contracts/v010-s18-design.toml).
- [Native qualification](../qualification/v0.10.0-s18.md), [adversarial qualification](../qualification/v0.10.0-s18-security.md).

## Source ownership, requirements and negative cases

- `crates/linura-control/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-linux-observation/src/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `crates/linura-policy/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.
- `executors/` — feature-specific source, typed API and associated positive/adversarial native tests as applicable.

Requirements: R18-AUTH-01, R18-AUTH-02, R18-REC-01.
Required negative cases: T03, T05, T09, T10, T13, T14, T15, T18, T19, T20, T21, T22, T23, T24, T26, T29.

## Required implementation (not yet completed)

- [ ] Type machine-wide networking and Wi-Fi radio toggles independently from rfkill, hardware state and managed/unmanaged adapter state.
- [ ] Review and independently corroborate each impacted link, IPv4/IPv6 default routes, DNS and local/remote administration viability.
- [ ] Use only exact prepared managed Control effect, authenticated Polkit subject and narrowly enumerated native methods.
- [ ] Deny last viable link disruption unless independently proven accessible offline local recovery exists.
- [ ] Verify observed effective state after the toggle; retain indeterminate attempt and no blind replay on crash, lost reply or NM restart.

## Acceptance evidence (not yet established)

- [ ] real-nm-radio-rfkill-test
- [ ] last-link-and-remote-lockout-proofs
- [ ] durable-recovery-disruption
- [ ] No effect enabled until protected local recovery and independent verification demonstrated

## Security, recovery and explicit non-claims

- Candidate operations: `operation:network.networking.set-enabled`, `operation:network.wifi.set-enabled`; none are enabled, registered or qualified.
- Preserve the real user/session/Polkit subject, canonical Control plan, trusted risk floor, bounded native effects, independent verification, durable indeterminate/no-replay recovery, S17 protected session, S21 device safety, and offline local recoverability.
- No generic D-Bus/nmcli/shell or model/GUI command execution; reject unknown/stale/incomplete identity, owner replacement, last viable link loss and replay.
- This Markdown reservation contributes no runtime authority, client UI, feature flag, operation registry, privilege, physical Q11 proof or released support. The prior PR branch name does not define this feature.

## Implementation extraction and eventual release

Implement the full capability in the WIP source. After internal architecture, regression, security and adverse-case review, extract only this feature into an independently reviewable commit, test canonical exact-head CI, fresh Security and CodeQL, native real-NM A/B/physical C and required inherited gates, and resolve final Codex findings. For eventual integration, rebase/retarget to accepted `main` only once extraction and evidence are complete; never merge the WIP branch wholesale.

Original reserved head: `archive/pre-s18-rebuild-20261101-pr-272`; retained GitHub PR head name: `feat/v010-s22-1-protected-capture-foundation`.


## Source-bound diagnostic progress (November 10, 2026)

- [x] Native resolver-source drift probe: bounded root-owned `/etc/resolv.conf` / recognized systemd-resolved or NetworkManager file, double-read identity and content, nameserver syntax, and no promotion of this data to split-DNS authority. Unknown resolver or changed source is a denial.
- [x] Read-only bounded `/proc/net/tcp` and `tcp6` inventory: possible active remote-administration peers are conservatively retained, checked for original netns and cross-snapshot continuity, with adversarial malformed and IPv6 source tests. A TCP socket list does not establish whether a user is local, whether a peer is SSH, or if UDP/other remoting exists.
- [x] Socket-source/UID-conditioned kernel `RTM_GETROUTE` FIB lookup for up to four active remote sockets. Kernel TCP readback independently pins local and remote address/port, owner UID and inode (ABA rejection); the netlink query binds source, destination, UID and a bounded aggregate deadline. Kernel sender, sequence, response family, unicast type and egress ifindex are strictly checked. A link selected by a remote FIB query cannot be accepted as safely disabled.
- [ ] A source/UID-conditioned FIB lookup still lacks per-socket fwmark, effective policy/VPN overlay path and proof that a live original administrator remains connected. `/etc/resolv.conf` does not prove effective per-domain resolver routing. Both remain **diagnostic-only** until independent full source/path proof exists.
- [ ] The offline-local recovery and original-user Polkit/control-spend-to-private-sender integration is not qualified; physical C/Q11 remains unproven. All nine effects remain disabled.
## Source implementation progress (not release evidence)

- [x] Exact canonical two-method Control radio effect and reverse parser, checked against native original-user protected review, operation/state, execution binding and principal/request-derived durable transaction ID. Descriptor correlation is not a spent Control permit or mutation grant; all network effects remain unregistered and denied.
- [x] Native radio message encoder explicitly prohibits D-Bus auto-start of any NetworkManager owner; both exact methods have negative and message-shape tests.

- [x] Control composition now registers the already authenticated, read-only NetworkManager observer in the canonical ObservationCoordinator when its bounded system-bus connection is available; failure to connect does not disable unrelated systemd/session authority or invent substitute evidence. No NM mutation port is installed.
- [x] Native-NM provider recovery is explicitly excluded from v0.6's reprepare/re-dispatch path in the real Control managed lifecycle, with guards at resumed, indeterminate and reprepared execution branches. An uncertain network effect cannot become a second dispatch merely because an administrator approved a retry; S18 observe-only recovery remains unimplemented and the network registration remains off.

- [x] Scoped radio operation taxonomy and read-only managed/Wi-Fi disruption preview in `crates/linura-control/src/network_radio.rs`, with conservative rejection for missing or stale source, mixed/duplicate link inventory, missing dual-stack route/DNS evidence, rfkill/hardware uncertainty, unmanaged WLAN, remote management and last viable link. The positive preview result is **not a grant**.
- [x] Disambiguated canonical manager-state change keys: `networking_enabled` versus `wireless_enabled`, matching independently sampled manager observation and separate S18 candidate contracts. Operation identity remains an inactive classification, not an executable registration.
- [x] Adversarial unit fixtures covering those review branches and a non-authorizing postcondition shape check.
- [x] Exact original radio consent-to-subject binding over purpose, local lock/principal, action/desired-state encoded request identity, canonical request/plan, observation digest, request digest and review digest; invalid/cross-request/credential reuse denies. This is still no network effect approval, NM Polkit permission or durable handoff.
- [x] Bounded, no-interaction Polkit `CheckAuthorization` read-only witness for the original live `unix-process` and NetworkManager's fixed `enable-disable-network`/`enable-disable-wifi` actions, rechecking supervised polkitd, live original login and the exact NM owner. A successful query **cannot** authorize native mutation or substitute for a one-use native effect grant.
- [x] Radio-specific first-party protected original-session owner consent (purpose 9), purpose-bound request prefix, `auth_self` active-session Polkit policy, protected UI and adversarial credential/cross-purpose replay tests. This is **not** NetworkManager's own original-subject CheckAuthorization, durable effect permit, or an enabled operation.
- [x] Native SecurityOwner1 D-Bus approval decoder admits exact purpose 9 (and denies greater values), with direct positive wire round-trip and foreign-purpose/credential-substitution negatives; no additional public mutation method.
- [x] Read-only original-user/logind/seat, supervised Polkit daemon, and root-owned NetworkManager unique-bus-owner correlation on the native Control connection, including cross-epoch and canonical request validation. This is not CheckAuthorization, protected human consent, a prepared durable permit or a native effect executor.
- [x] Radio-only exact supervised NetworkManager process attestation: root system bus peer credentials, systemd `NetworkManager.service`/MainPID/invocation/ExecStart, immutable Arch unit/binary and PID-start witness, double-read before accepting a source. Unqualified configurations fail closed; this is a process identity prerequisite, not an effect grant.
- [x] Read-only bounded kernel rtnetlink route/rule dump across IPv4/IPv6 and all routing tables with kernel-port, sequence, size, attribute, deadline and dump-completion checks; stable source snapshot checked before/after NM sampling. Typed per-ifindex route readback allows expected affected-link route removal while denying changes on unaffected/unknown links, policy-rule replacement and remaining defaults on disabled links. This is not route reachability, effective DNS or proof of safe fallback.
- [x] Independent read-only native post-change resampling with original owner/boot/namespace continuity, monotonic generation/freshness fencing, unchanged device identity, preserved unaffected links and routes, no lingering active/route-bearing disabled WLAN, and radio/rfkill readback tests. These diagnostics never become an execution permit, causal effect proof or final verified transaction.
- [x] Add a bounded, dual-source NM/kernel passive radio observation in `crates/linura-linux-observation/src/radio_impact.rs`, including exact owner/boot/bus/kernel namespace, device/ifindex/managed state, rfkill, and native IPv4/IPv6 main-table route counts (double read and strict parser negative tests).
- [ ] Verify kernel *policy* routing tables, effective split DNS and local/remote administration, then bind fully corroborated source to Control's review. The current sample explicitly marks these unverified and grants no authority; *booleans supplied by untrusted clients are not evidence*.
- [x] Native user-process-side typed *wire encoder* for only `Enable(bool)` and `Properties.Set(WirelessEnabled, bool)` targeting an already pinned unique NM owner, with direct positive and adversarial message-shape tests; it cannot send messages or create authority.
- [ ] Seal exact radio effect to a prepared one-use Control mutation, real authenticated Polkit subject and narrowly enumerated native NetworkManager methods.
- [x] Add a private, move-only native one-attempt sender on the original user's attested system-bus connection. An attempt spends before any call, pins the supervised NetworkManager owner, checks real *sender-side* `GetPermissions` for the exact fixed operation, transmits only `Enable(bool)` or `Properties.Set(WirelessEnabled, bool)` with autostart disabled, and reports lost reply/owner replacement as indeterminate rather than retrying. This is native implementation, **not** an available authority path: no caller can mint the attempt from client input, no Control permit is handed to it, and the operation registry remains closed.
- [x] Add authenticated read-only S18 radio attempt-history inspection from the retained canonical request and exact Control durable transaction anchor. Reject foreign/mismatched principal, request, capability, operation and desired state. This returns **historical** durable state, not fresh network verification, recovery authority or replay permission.
- [ ] Connect Control's durably spent one-use `DispatchPermit` to the original user's live native sender with exact reviewed intent, consent, NM/logind/Polkit identity and a protected no-replay crash handoff. No consent or sender-side permission readback alone is authority to dispatch.
- [ ] Implement independently verifiable effective policy-route, IPv4/IPv6, split-DNS, remote-administration and accessible offline-local-recovery preflight, and bind source-pinned before/after observations to durable transaction causality.
- [ ] Complete native post-effect independent verification, indeterminate/no-replay restart recovery and real pinned NetworkManager/Polkit/rfkill Level A, interactive Level B and hardware Level C/Q11 evidence. Keep registration disabled until accepted.
- [ ] Run canonical exact-head CI, Security, CodeQL and applicable native A/B/C evidence. No support claim or operation registration is permitted before this acceptance.

The pre-existing `require_network_effect_inactive` guard remains unchanged; all nine S18 effects are still denied. The private native sender does not by itself authorize an NM call, establish real-Polkit original-session permission or prove any network-safety postcondition. This is an implementation increment, **not** completion of S18-6.
