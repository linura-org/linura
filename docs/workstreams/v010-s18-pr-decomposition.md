# S18 v0.10 — architecture-first and nine implementation boundaries

> **Design-only extraction contract.** Historical reserved PR numbers are not authorizations, proof of implementation, review readiness or accepted qualification. Preserve the existing `wip/v010-s18-network` implementation; never merge WIP directly. **Do not merge this branch directly.** S18-1 now follows the S21 architecture/security-contract first gate; S18-2 begins implementation with native identities and passive observation, following the S17 trust-boundary separation thereafter.

**Draft PR base/reference:** `wip/v010-s18-network`. This WIP branch is the authoritative live integration/development source. All ten draft PRs (#267–#276) target WIP; their actual diffs must match their scope, and none may be merged into WIP as an implementation claim. After the reviewed implementation is extracted and qualified, rebase/retarget for final integration into accepted `main` without merging the WIP branch wholesale. S18-8, S18-9 and S18-10 are now reserved as draft PRs #274, #275 and #276, respectively.

Source of truth: [Phase-1 inventory](v010-s18-network-phase1.md), [ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive effect design](../../contracts/v010-s18-design.toml), [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).

Existing WIP native observation and PR #267's previously misassigned core identity code belong **exclusively to S18-2**; S18-1 owns documentation, architecture/security and executable design contracts only. Move them into a future review branch only after source/compilation/native qualification checks. No runtime registration, permission downgrade or unsupported feature is introduced by this plan.

| ID | Boundary | Reserved PR | Required predecessors | Candidate native effects |
| --- | --- | --- | --- | --- |
| S18-1 | docs(v0.10): define NetworkManager connectivity architecture and security contracts | [#267](https://github.com/linura-org/linura/pull/267) | S16 | none |
| S18-2 | feat(network): establish native NetworkManager identities and observation | [#268](https://github.com/linura-org/linura/pull/268) | S18-1 | none |
| S18-3 | feat(control): add managed network authority semantics | [#269](https://github.com/linura-org/linura/pull/269) | S18-1, S18-2 | none |
| S18-4 | feat(security): add protected network credentials and native authorization | [#270](https://github.com/linura-org/linura/pull/270) | S18-1, S18-3 | none |
| S18-5 | feat(network): add bounded Wi-Fi discovery and scan authority | [#271](https://github.com/linura-org/linura/pull/271) | S18-2, S18-3, S18-4 | `operation:network.wifi.scan` |
| S18-6 | feat(network): add managed networking and radio controls | [#272](https://github.com/linura-org/linura/pull/272) | S18-2, S18-3, S18-4 | `operation:network.networking.set-enabled`, `operation:network.wifi.set-enabled` |
| S18-7 | feat(network): add managed connection lifecycle | [#273](https://github.com/linura-org/linura/pull/273) | S18-2, S18-3, S18-4 | `operation:network.connection.activate`, `operation:network.connection.deactivate`, `operation:network.wifi.join` |
| S18-8 | feat(network): add revisioned connection profile management | [#274](https://github.com/linura-org/linura/pull/274) | S18-2, S18-3, S18-4 | `operation:network.profile.create`, `operation:network.profile.update`, `operation:network.profile.delete` |
| S18-9 | feat(shell): add unified network controls | [#275](https://github.com/linura-org/linura/pull/275) | S18-2, S18-3, S18-4, S18-5, S18-6, S18-7, S18-8 | none |
| S18-10 | test(qualification): qualify native network integration | [#276](https://github.com/linura-org/linura/pull/276) | S18-1, S18-2, S18-3, S18-4, S18-5, S18-6, S18-7, S18-8, S18-9 | none |

## Reviewable scopes and acceptance

### S18-1 — docs(v0.10): define NetworkManager connectivity architecture and security contracts

**Source ownership:** `docs/adr/0048-s18-networkmanager-authority.md`, `contracts/v010-s18-design.toml`, `docs/qualification/v0.10.0-s18.md`, `docs/qualification/v0.10.0-s18-security.md`, `docs/workstreams/v010-s18-network-phase1.md`, `tests/tooling/test_v010_s18_design.py`, `contracts/qualification-gate-matrix.toml`, `.github/workflows/v010-qualification.yml`.

**Dependencies:** S16. **Requirements:** R18-OBS-01, R18-OBS-02, R18-OBS-03, R18-AUTH-01, R18-AUTH-02, R18-SEC-01, R18-REC-01, R18-QUAL-01, R18-REL-01. **Adversarial cases:** T01, T02, T03, T04, T05, T08, T11, T13, T15, T16, T17, T18, T19, T20, T21, T24, T26, T28, T29, T30.

- Finalize ADR 0048, proposed read-only/effect architecture, trust boundaries, and workstream ownership before native changes.
- Specify boot, system-bus incarnation, NetworkManager unique owner, exact native identity and nonauthorizing correlation aliases without runtime code.
- Define risk floors, real Polkit subject, purpose-bound protected secrets, route impact and offline recovery, independent verification and no blind replay.
- Lock all nine candidate operations inactive, retain manager/device query aliases and reject unsupported VPN/hotspot/mobile/arbitrary settings forwarding.
- Add adversarial design/qualification contract checks with exact v0.10 routing; distinguish real native A/B and physical C/Q11 from mock evidence and release claims.

**Required evidence:** design-contract-negative-and-inert-operation-tests; adr-threat-model-and-qualification-routing; existing-observer-and-Control-authority-regression; canonical-exact-head-repository-validation.

**Blockers:** Architecture/security review, exact-head validation, and retained inactive-state evidence required; no native effect or physical support inferred.

**No operation activated or granted here.**

### S18-2 — feat(network): establish native NetworkManager identities and observation

**Source ownership:** `crates/linura-core/src/`, `crates/linura-linux-observation/src/`, `crates/linura-observation-control/`, `apps/linurad/src/`, `apps/linura-firstboot/src/`.

**Dependencies:** S18-1. **Requirements:** R18-OBS-01, R18-OBS-02, R18-OBS-03. **Adversarial cases:** T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, T15, T22, T24, T27, T28.

- Implement typed boot/system-bus/NM owner epochs, device and AP identities, saved profile revisions, active connections and bounded observation generations.
- Unit-test malformed, mixed-owner, reused path, interface, ifindex, profile revision and AP aliases without granting approval or mutation authority.
- Extend canonical read-only observer/coordinator, preserving manager/device aliases and daemon, CLI and First Boot consumers.
- Observe bounded typed manager/device/passive AP, saved/active profiles, radio, dual-stack IP, DNS and route facts with explicit unknown/unavailable/stale semantics.
- Enforce true receive/decode byte and nesting budgets, list and transport deadlines and coherent owner/device/profile revalidation; no RequestScan, secrets or native mutation.

**Required evidence:** typed-identity-adversarial-unit-tests; real-networkmanager-native-system-bus-observation-level-a; observation-control-and-firstboot-compatibility; owner-swap-nonatomic-multiobject-and-malformed-provider-tests.

**Blockers:** Native boundedness, full typed facts, real NM Level A, owner-swap and inherited exact-head checks remain unqualified until demonstrated.

**No operation activated or granted here.**

### S18-3 — feat(control): add managed network authority semantics

**Source ownership:** `crates/linura-control/`, `crates/linura-policy/`, `crates/linura-transaction/`, `crates/linura-persistence-sqlite/`, `contracts/operation-semantics.toml`.

**Dependencies:** S18-1, S18-2. **Requirements:** R18-AUTH-01, R18-AUTH-02, R18-REC-01. **Adversarial cases:** T03, T05, T08, T09, T10, T12, T13, T14, T15, T18, T19, T20, T21, T24, T25, T26, T29.

- Define trusted typed operation classification and risk floors for all nine candidate effects; keep them inactive until feature-specific native qualification.
- Extend canonical reconciliation plans, exact principal/resource/epoch preconditions and bounded protected review of default-route/DNS impact.
- Persist prepare/attempt and indeterminate recovery through existing Control authority and SQLite; never mint grants from receipts or UI selections.
- Specify independently corroborated postconditions, no-change semantics and loss-of-control-path refusal with offline fallback.
- Test denial, replay, changed risk, ambiguous reply, crash recovery and route-impact conflicts without enabling unqualified effects.

**Required evidence:** canonical-policy-negative-tests; durable-attempt-recovery-and-enospc; v06-managed-lifecycle-regressions.

**Blockers:** All durable authorizations and recovery paths independently reviewed before native registration.

**No operation activated or granted here.**

### S18-4 — feat(security): add protected network credentials and native authorization

**Source ownership:** `crates/linura-linux-session/`, `apps/linura-shell/security-owner/`, `crates/linura-control/`, `packaging/dbus-1/`.

**Dependencies:** S18-1, S18-3. **Requirements:** R18-AUTH-02, R18-SEC-01. **Adversarial cases:** T03, T05, T11, T13, T14, T15, T16, T17, T19, T23, T24, T26, T28.

- Bind actual authenticated transport sender, logind session and Polkit subject to the exact operation, device/profile epoch and owner generation.
- Establish purpose-bound native Wi-Fi secret-agent and protected credential input without exposing passwords, EAP material or BSSID-sensitive data to model, QML, audit or logs.
- Separate one-time connection credentials from durable profile secret persistence and require explicit authenticated user consent.
- Cancel and zeroize on lock/session/seat/owner changes, timeout, focus loss and connection cancellation; no reusable proof or arbitrary GetSecrets/Update2 relay.
- Adversarially test confused deputy, root versus real user, foreign sessions, locked input, replay and redaction across native IPC.

**Required evidence:** real-polkit-subject-adversarial; native-protected-input-credential-tests; secret-redaction-and-ownership-audit.

**Blockers:** No native credential use until genuine protected-input and secret-agent subject are qualified.

**No operation activated or granted here.**

### S18-5 — feat(network): add bounded Wi-Fi discovery and scan authority

**Source ownership:** `crates/linura-linux-observation/src/`, `crates/linura-control/`, `crates/linura-policy/`.

**Dependencies:** S18-2, S18-3, S18-4. **Requirements:** R18-OBS-03, R18-AUTH-01, R18-AUTH-02, R18-SEC-01. **Adversarial cases:** T02, T03, T05, T06, T07, T11, T12, T13, T14, T15, T16, T19, T20, T22, T23, T28, T29.

- Keep passive AP result observation separate from active RequestScan radio emission and permission-sensitive action.
- Bind scan authorization to exact adapter/owner/session and a reviewed non-downgradable operation floor.
- Limit native scan attempts, frequency, payloads, power/airplane mode interaction and privacy leakage.
- Verify fresh scoped scan completion without treating cached AP list, methods or signals as proof.
- Deny when rfkill, stale owner, missing authorization, foreign caller, timeout or uncertain effect makes scan unverifiable.

**Required evidence:** real-nm-wifi-scan-negative-tests; rate-and-payload-budget; rfkill-owner-swap-no-replay.

**Blockers:** Native authenticated RequestScan and exact-freshness oracle still unqualified.

**Proposed inactive operations:** `operation:network.wifi.scan`.

### S18-6 — feat(network): add managed networking and radio controls

**Source ownership:** `crates/linura-control/`, `crates/linura-linux-observation/src/`, `crates/linura-policy/`, `executors/`.

**Dependencies:** S18-2, S18-3, S18-4. **Requirements:** R18-AUTH-01, R18-AUTH-02, R18-REC-01. **Adversarial cases:** T03, T05, T09, T10, T13, T14, T15, T18, T19, T20, T21, T22, T23, T24, T26, T29.

- Type machine-wide networking and Wi-Fi radio toggles independently from rfkill, hardware state and managed/unmanaged adapter state.
- Review and independently corroborate each impacted link, IPv4/IPv6 default routes, DNS and local/remote administration viability.
- Use only exact prepared managed Control effect, authenticated Polkit subject and narrowly enumerated native methods.
- Deny last viable link disruption unless independently proven accessible offline local recovery exists.
- Verify observed effective state after the toggle; retain indeterminate attempt and no blind replay on crash, lost reply or NM restart.

**Required evidence:** real-nm-radio-rfkill-test; last-link-and-remote-lockout-proofs; durable-recovery-disruption.

**Blockers:** No effect enabled until protected local recovery and independent verification demonstrated.

**Proposed inactive operations:** `operation:network.networking.set-enabled`, `operation:network.wifi.set-enabled`.

### S18-7 — feat(network): add managed connection lifecycle

**Source ownership:** `crates/linura-control/`, `crates/linura-linux-observation/src/`, `crates/linura-policy/`, `executors/`.

**Dependencies:** S18-2, S18-3, S18-4. **Requirements:** R18-AUTH-01, R18-AUTH-02, R18-SEC-01, R18-REC-01. **Adversarial cases:** T03, T05, T08, T09, T10, T11, T13, T14, T15, T16, T18, T19, T20, T21, T23, T24, T26, T29.

- Implement exact saved-profile revision, device and active-connection binding for activation/deactivation, without requiring an unrelated Wi-Fi scan.
- Use S18-4 protected one-time credentials and prohibit hidden durable profile saves; join and persistent configuration are different effects.
- Review route/DNS/dual-stack impact and protect last viable control path before dispatch.
- Use typed, narrowly constrained NM effect and independent IP/DNS/routes/association postcondition verification, not method-return optimism.
- Preserve durable indeterminate attempt and re-observation after daemon restart, changed profile, partial DHCP or lost reply; never auto-retry.

**Required evidence:** real-nm-ethernet-and-wifi-lifecycle; protected-credential-native-qualification; partial-ip-dns-route-and-no-replay.

**Blockers:** Real native and protected Wi-Fi qualification pending; unsupported physical hardware remains explicitly unqualified.

**Proposed inactive operations:** `operation:network.connection.activate`, `operation:network.connection.deactivate`, `operation:network.wifi.join`.

### S18-8 — feat(network): add revisioned connection profile management

**Source ownership:** `crates/linura-control/`, `crates/linura-linux-observation/src/`, `crates/linura-policy/`, `executors/`.

**Dependencies:** S18-2, S18-3, S18-4. **Requirements:** R18-OBS-03, R18-AUTH-01, R18-AUTH-02, R18-SEC-01, R18-REC-01. **Adversarial cases:** T03, T05, T08, T09, T13, T14, T15, T16, T17, T18, T19, T20, T21, T24, T25, T28, T29.

- Define typed allowlisted NM profile fields and revision-aware create/update/delete; no arbitrary settings maps, VPN or hotspot passthrough.
- Bind actual owner/UUID/native settings path and content fingerprint with native Polkit subject and durable Control prepare.
- Separate protected secret saving from one-time credential use and redact all sensitive material in evidence.
- Treat delete as destructive; review active/default route, dependent profiles and shared owner before any physical change.
- Reject concurrent updates, restarted owners, lost replies, uncertain deletion or unavailable independent restoration; no blind re-dispatch.

**Required evidence:** native-saved-profile-revision-tests; destructive-shared-ownership-denials; protected-secret-redaction; recovery-after-profile-replacement.

**Blockers:** Exact revision CAS, destructive policy and real native settings proof still pending.

**Proposed inactive operations:** `operation:network.profile.create`, `operation:network.profile.update`, `operation:network.profile.delete`.

### S18-9 — feat(shell): add unified network controls

**Source ownership:** `apps/linura-shell/`, `apps/linuractl/src/`, `crates/linura-sdk/`.

**Dependencies:** S18-2, S18-3, S18-4, S18-5, S18-6, S18-7, S18-8. **Requirements:** R18-UX-01, R18-UX-02, R18-REC-01. **Adversarial cases:** T09, T10, T13, T14, T16, T18, T20, T21, T22, T23, T24, T26, T28, T30.

- Expose the same Control-owned typed capabilities in Control Center, Quick Settings, SDK, CLI and deterministic offline/no-model paths.
- Show provider/link/AP/profile/IP/DNS/routes and unknown/stale/portal states distinctly from independently proven reachability.
- Render exact risk/material impact, authenticated protected credential handoff and explicit denied/preparing/indeterminate/recovery states.
- No direct QML/networkmanager/nmcli/agent mutation; client never selects risk, native identity or authority.
- Qualify keyboard, pointer, screen-reader, scaled/multi-output, locked-session and screenshot/privacy behavior with negative regression tests.

**Required evidence:** shellbridge-and-qt-integration; a11y-keyboard-pointer-high-dpi; offline-cli-sdk-parity.

**Blockers:** All required backends accepted and integrated before presenting effects as available.

**No operation activated or granted here.**

### S18-10 — test(qualification): qualify native network integration

**Source ownership:** `qualification/v010/`, `docs/qualification/`, `tests/acceptance/`, `tools/`.

**Dependencies:** S18-1, S18-2, S18-3, S18-4, S18-5, S18-6, S18-7, S18-8, S18-9. **Requirements:** R18-QUAL-01, R18-REL-01, R18-UX-02. **Adversarial cases:** T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30.

- Establish source/guest/provider/boot/owner/subject and observed pre/postcondition binding for each accepted native network operation.
- Exercise real NM native A, interactive B and maintained physical NIC/Wi-Fi Level C/Q11 separately; VM and mock are not physical support.
- Adversarially prove hotplug, rfkill, owner restart, Polkit denial, credential cancellation, lost reply, route loss, partial dual stack and no blind replay.
- Verify GUI/CLI/SDK, no-model and offline recovery parity and S17 secure lock/S21 power/display/storage integration.
- Run exact-head canonical CI, security, CodeQL, native qualification, inherited v0.9 tests and evidence admission; release support remains planned otherwise.

**Required evidence:** level-a-source-pinned-real-networkmanager; level-b-real-quickshell-accessibility; level-c-maintained-physical-wifi-q11; q12-q14-inherited-security-and-recovery.

**Blockers:** Entire nine-PR dependency closure and real source-pinned A/B/C evidence required; no synthetic Q11 promotion.

**No operation activated or granted here.**
## Extraction rules

1. A PR reservation is not source qualification. Existing reserved PRs use this WIP branch as their current GitHub review base/reference and carry only inert scope-document differences. Do not merge these reservations into WIP, confuse inherited WIP code with PR-delivered implementation, or treat WIP CI as final release acceptance. Once implementation is qualified, extract the exact boundary onto accepted `main`, rebase/retarget intentionally and rerun all exact-head gates; do not merge WIP history wholesale.
2. Original reserved PR heads may belong to other slices; archive their old refs before any destructive rebuild and do not lose S19, S20, S22, S23, S25 or S26 WIP code. A historic branch name is not an authority or scope declaration.
3. The nine existing `contracts/v010-s18-design.toml` operations stay unregistered and off. S18-1/2/3/4/9/10 cannot enable effects. S18-5/6/7/8 must prove each separately reviewed native effect, exact authenticated subject and independent verification before registration.
4. Allow S18-5, S18-6, S18-7 and S18-8 to develop independently after shared identity, observation, Control and protected security. Do not make Ethernet activation depend on Wi-Fi scanning or radio toggles; do not implement hidden profile persistence in Wi-Fi join.
5. S18-9 is UI/CLI/SDK/no-model integration with no second authority. S18-10 is integrated exact-source qualification and never a substitute for per-feature adverse-case testing.
6. Every extracted PR must pass all required exact-head canonical CI, Security, CodeQL and applicable native qualification; accepted S17 protected session and S21 display/power/storage authority remain unchanged. Q11 physical NIC/Wi-Fi remains unqualified absent actual hardware evidence; never lower/skip a red gate.
7. Never create a new PR merely to fill a numbering gap. A future PR number, if required, is assigned when an actual PR is opened and authorized, not predicted by the decomposition.

**Known incompleteness:** Current read-only WIP provider tests and source-level Rust checks do not establish bounded D-Bus wire/decode budgets, coherent AP/profile/IP/DNS/routes data, real native A/B, physical C/Q11 or complete managed effects.
