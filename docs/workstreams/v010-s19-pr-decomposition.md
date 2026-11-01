# S19 v0.10 implementation extraction — six reviewable PRs

> **Development planning only.** Do not merge this WIP branch directly; do not register BlueZ mutations or promote S19/Q11 evidence from these documents. The normative proposed Phase-1 source is [S19 Phase 1](v010-s19-bluetooth-phase1.md), [ADR 0049](../adr/0049-s19-bluez-bluetooth-authority.md) and [inactive operation design](../../contracts/v010-s19-design.toml).

The exact, machine-checkable decomposition lives in [`contracts/v010-s19-pr-decomposition.toml`](../../contracts/v010-s19-pr-decomposition.toml). These are **slice-local identifiers, not GitHub PR numbers**. Each eventual PR begins on independently rechecked `main`, carries its own affected implementation, negative tests, source-bound evidence, architecture/security review and established checks.

| Order | Boundary | Main dependency | Activation |
|---|---|---|---|
| S19-1 | bluez-observation | S16 | No effect |
| S19-2 | discovery-radio | S19-1 | Only after independently qualified managed native authorization/verification/recovery |
| S19-3 | secure-pairing | S19-1, S19-2 | Only after independently qualified managed native authorization/verification/recovery |
| S19-4 | connection-lifecycle | S19-1, S19-3 | Only after independently qualified managed native authorization/verification/recovery |
| S19-5 | trust-management | S19-1, S19-3, S19-4 | Only after independently qualified managed native authorization/verification/recovery |
| S19-6 | experience-qualification | S19-1, S19-2, S19-3, S19-4, S19-5 | No effect |

## Engineering requirements

### S19-1 — feat(bluetooth): establish bounded native BlueZ observation

**Capability:** `bluez.adapter.observe`, `bluez.device.observe`, `bluez.bond.observe`.

**Owned source:** `crates/linura-provider-bluez/`, `apps/linurad/src/`.

**Must deliver:**
- Real ObjectManager native read without BlueZ autostart or mutation; pinned and bounded owner-scoped response.
- Unique owner and boot epoch bound across pre/post inventory reads; reconnect, owner swap, adapter reset and path reuse invalidate evidence.
- Typed Adapter1 and Device1 inventory with parent relationship, address plus address type, explicit unknown bonding and profile readiness, provider-owned observations in canonical envelopes.
- Bounded raw payload, object counts, variant nesting, UUIDs, strings and deadline; ambiguous, duplicate or oversized inventory rejected, not truncated.
- Daemon registered to Control observer; no duplicate graph, policy engine, mutator or live effect registration.

**Negative cases:** B19-01, B19-02, B19-03, B19-04, B19-05, B19-06, B19-07, B19-16, B19-19. **Evidence:** unit-malformed-fixtures, level-a-real-bluez-objectmanager, provider-regression, observation-control-regression.

**Release blocking until:** Exact-source Rust unit/adversarial checks; Native owner/hotplug proof for supported inventory; Read-only capability and provider health remain separate from adapter hardware support.

**No native external effects are authorized by this PR.**

### S19-2 — feat(bluetooth): add owned discovery leases and reviewed adapter radio authority

**Capability:** `bluez.discovery.observe`.

**Owned source:** `crates/linura-provider-bluez/`, `crates/linura-control/`.

**Must deliver:**
- Caller-owned StartDiscovery/StopDiscovery session, non-global filters, bounded lease, lifetime and cleanup without stopping a second client.
- Separate reviewed adapter Powered/Discoverable/Pairable consequences with rfkill, privacy, inbound pairing exposure and authenticated subject checks.
- Trusted operation registry fixes managed class and risk floors; durable prepare, independent reobserve and safe indeterminate state precede any activation.
- Exact adapter/owner/lease generation; no scan-as-query shortcut or raw BlueZ method forwarding.

**Negative cases:** B19-03, B19-08, B19-09, B19-14, B19-15, B19-18. **Evidence:** unit-lease-races, level-a-real-bluez-multiclient, native-rfkill-negative, security-review.

**Release blocking until:** Actual caller-owned discovery and multi-client noninterference proof; Prepared effect/subject/verification/recovery proof for each enabled operation.

**Inactive candidate operations:** `operation:bluetooth.discovery.start`, `operation:bluetooth.discovery.stop`, `operation:bluetooth.adapter.set-powered`, `operation:bluetooth.adapter.set-discoverable`, `operation:bluetooth.adapter.set-pairable`. These must never be enabled simply by extracting this plan.

### S19-3 — feat(bluetooth): implement purpose-bound Agent1 and protected pairing

**Capability:** `bluez.bond.observe`.

**Owned source:** `crates/linura-provider-bluez/`, `apps/linura-shell/plugins/bluetooth/`.

**Must deliver:**
- Agent1 request sender is exact live BlueZ unique owner; no ambient global default agent takeover.
- Purpose-bound one-time challenge binds device, adapter, original principal, active seat/session, service UUID, agent and boot generation.
- Protected first-party input and explicit MITM/Just Works limitations; unsolicited pairing and uncorrelated service authorization denied.
- Cancel/Release/session lock/restart invalidate prompts; passkeys and keys never enter audit, model, telemetry or retention.
- No blind Pair retry after ambiguous reply, crash or native owner replacement; separate Paired and Trusted postconditions.

**Negative cases:** B19-10, B19-11, B19-12, B19-13, B19-15, B19-18, B19-20, B19-24. **Evidence:** unit-agent-spoof-and-expiry, level-a-real-bluez-agent, level-b-protected-input, security-review.

**Release blocking until:** Protected S17 current-session identity and actual native agent callback proof; Independent bond verification and no-replay crash recovery; Physical passkey and pairing proof before Q11 support.

**Inactive candidate operations:** `operation:bluetooth.device.pair`, `operation:bluetooth.device.cancel-pairing`. These must never be enabled simply by extracting this plan.

### S19-4 — feat(bluetooth): manage exact-device connection and profile readiness

**Capability:** `bluez.device.observe`.

**Owned source:** `crates/linura-provider-bluez/`, `crates/linura-control/`.

**Must deliver:**
- Connect/Disconnect bind original adapter/device/bond/connection generations and authenticated subject.
- D-Bus method success alone never proves Connected or requested profile readiness; ServicesResolved and requested profile observed independently.
- Disconnection impact, competing controller, auto-reconnect and partial profile release have explicit postconditions.
- Crash, timeout, owner replacement and device disappearance result in independently reconciled indeterminate attempts.

**Negative cases:** B19-03, B19-05, B19-14, B19-16, B19-18, B19-19. **Evidence:** unit-identity-and-profile-mismatch, level-a-native-connect-disconnect, level-c-profile-readiness, security-review.

**Release blocking until:** Per-operation managed prepare, native execution, authoritative verify and recovery; Real profile and device proof for hardware support.

**Inactive candidate operations:** `operation:bluetooth.device.connect`, `operation:bluetooth.device.disconnect`. These must never be enabled simply by extracting this plan.

### S19-5 — feat(bluetooth): enforce persistent trust, block and bond-removal authority

**Capability:** `bluez.bond.observe`.

**Owned source:** `crates/linura-provider-bluez/`, `crates/linura-control/`.

**Must deliver:**
- Trust, untrust, block, unblock and RemoveDevice are separate reviewed intents and never inferred from Pair or Connect.
- Exact bond revision and shared owner/dependent impact review precede destructive removal.
- Trusted managed operation semantics fixed by Control, native subject authenticated, no alias/address-only approval.
- Lost D-Bus reply after bond deletion or trust update is indeterminate; observe and reauthorize rather than replay.
- No link-key, PIN/passkey or protected pairing content in plan, logs, fixtures or audit.

**Negative cases:** B19-05, B19-14, B19-15, B19-17, B19-18, B19-20, B19-23. **Evidence:** unit-bond-revision-and-ownership, level-a-real-bluez-bond-state, level-c-bond-persistence, security-review.

**Release blocking until:** Verified durable security-state semantics and auditable exact-principal consent; Native bond removal/recovery and real hardware acceptance.

**Inactive candidate operations:** `operation:bluetooth.device.set-trusted`, `operation:bluetooth.device.set-blocked`, `operation:bluetooth.device.remove`. These must never be enabled simply by extracting this plan.

### S19-6 — feat(bluetooth): deliver unified Bluetooth experience and qualified acceptance

**Capability:** `bluez.adapter.observe`, `bluez.device.observe`, `bluez.discovery.observe`, `bluez.bond.observe`.

**Owned source:** `apps/linura-shell/plugins/bluetooth/`, `qualification/v010/interactive-workstation/`.

**Must deliver:**
- Control Center, Quick Settings, CLI and SDK share typed registered operations, observed progress/receipts and denial/indeterminate states.
- No direct BlueZ calls in QML, ShellBridge authorization, generic executor or optimistic success.
- Protected S17 authentication and keyboard/pointer/screen-reader/reduced-motion/HiDPI coverage, including locked/no-model state.
- Exact-source Level A and interactive Level B evidence retained; Level C real controller, pairing, reconnect and profile evidence separately qualified.
- Q11 absence remains a release blocker, never replaced with virtual HCI/video or waived inherited CI.

**Negative cases:** B19-10, B19-12, B19-16, B19-20, B19-21, B19-22. **Evidence:** unit-experience-state-machine, level-b-interactive-vm, level-c-maintained-hardware, q10-accessibility, full-inherited-regressions.

**Release blocking until:** All prior S19 provider and authority PRs merged and verified; Actual independent UI/CLI/native oracles, visual/a11y and device evidence; Physical Q11 qualification before slice-wide release support.

**No native external effects are authorized by this PR.**

## Extraction and integration rules

1. Re-audit the true `main` head, existing S17/S21 authority and ADR ledger before copying any part of the WIP architecture.
2. Extract the minimum cohesive, source-owned change for each PR; preserve stable API guarantees and update only necessary experimental contracts. Do not commit ChatGPT conversation artifacts, credentials, incidental local files or unqualified evidence.
3. Use one/few cohesive commits per PR; include unit, malformed-data and adversarial negative tests with the implementation. Qualifying physical work cannot be replaced by mocks, virtual HCI, screenshots or CI labels.
4. Every mutating candidate has an independently reviewed trusted registry/risk floor, authenticated native principal, canonical plan, durable prepare, narrow BlueZ effect, independent re-observation and no-blind-replay recovery before activation.
5. Keep `apps/linura-shell/plugins/bluetooth/` a presentation-only authority boundary; prevent parallel shared-shell changes from conflicting with S17 and S20.
6. Merge only dependency-closed, green, reviewed PRs. Until then, S19 remains planned and Q11 unqualified. Verify `python3 -m unittest tests.tooling.test_v010_s19_decomposition`, existing S19 contract tests, then required canonical CI; documentation is never implementation evidence.

## Design decisions requiring explicit review

- A BlueZ service owner and D-Bus path identify current transport state, not authenticated remote peer identity. Pairing, trust and profile readiness use different postconditions.
- Scan filtering and StopDiscovery are scoped to a caller-owned lease; the same native bus connection and owner epoch are necessary to prevent interference with other clients.
- Agent1 callbacks cannot launder consent. A purpose-bound challenge belongs to one exact user/session/device/service and expires across lock/restart/cancel; no default agent takeover.
- `RemoveDevice` is destructive bond-data deletion, not merely disconnect or untrust. An ambiguous completed removal must not be replayed.
