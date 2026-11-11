# S18-8 — add revisioned connection profile management

**Status:** Source implementation started; actual native mutations and integrated qualification remain disabled and unfinished.  
**Milestone:** v0.10.0 / S18-8.  
**Development profile:** `arch-hyprland-v1`.  
**Authoritative reference and draft PR base:** `wip/v010-s18-network` (moving development branch; exact source identity is verified independently on each test run).

## Ownership and dependencies

The reviewed S18 ten-boundary plan assigns this slice to feat(network): add revisioned connection profile management. Prerequisites: `S18-2`, `S18-3`, `S18-4`. Its draft PR is intentionally one independent non-executable scope file **relative to WIP**; any code inherited through WIP ancestry is not contributed by this PR.

Normative WIP engineering references:
- [S18 Phase-1 architecture](../workstreams/v010-s18-network-phase1.md), [implementation breakdown](../workstreams/v010-s18-pr-decomposition.md), and [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).
- [Proposed NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md) and [nine inactive network-operation candidates](../../contracts/v010-s18-design.toml).
- [Native acceptance](../qualification/v0.10.0-s18.md), [adversarial security dossier](../qualification/v0.10.0-s18-security.md), and [v0.10 workstation milestone](../milestones/v0.10.0.md).

## Planned source ownership and regression scope

- `crates/linura-control/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `crates/linura-linux-observation/src/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `crates/linura-policy/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `executors/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.

Requirements: R18-OBS-03, R18-AUTH-01, R18-AUTH-02, R18-SEC-01, R18-REC-01.  
Threat/failure coverage: T03, T05, T08, T09, T13, T14, T15, T16, T17, T18, T19, T20, T21, T24, T25, T28, T29.

## Required implementation (not yet completed)

- [ ] Define typed allowlisted NM profile fields and revision-aware create/update/delete; no arbitrary settings maps, VPN or hotspot passthrough.
- [ ] Bind actual owner/UUID/native settings path and content fingerprint with native Polkit subject and durable Control prepare.
- [ ] Separate protected secret saving from one-time credential use and redact all sensitive material in evidence.
- [ ] Treat delete as destructive; review active/default route, dependent profiles and shared owner before any physical change.
- [ ] Reject concurrent updates, restarted owners, lost replies, uncertain deletion or unavailable independent restoration; no blind re-dispatch.

## Required acceptance and outstanding blockers

- [ ] native-saved-profile-revision-tests
- [ ] destructive-shared-ownership-denials
- [ ] protected-secret-redaction
- [ ] recovery-after-profile-replacement
- [ ] Exact revision CAS, destructive policy and real native settings proof still pending

## Architecture, security and non-claims

- Candidate operations: `operation:network.profile.create`, `operation:network.profile.update`, `operation:network.profile.delete`. **All inactive, no registry exposure or execution authorization.**
- Linura Control remains the sole owner of canonical `ReconciliationPlan`, authenticated principal, trusted risk floor, native operation admission and independent verification; no UI/provider/model-selected authority or generic privileged D-Bus/shell proxy.
- Maintain S17 protected identity, login/seat/lock and native secret safety, S21 display/power/storage safeguards, durable prepare/recovery and no-blind-replay for any managed effect, and safe offline/no-model recovery.
- No source implementation, public runtime/API, actual executor, native transaction, qualification artifact, Q11 physical evidence, new release support or milestone completion is delivered by this draft PR.
- Negative, malformed, stale, ambiguous, concurrent and restart situations remain fail-closed, not reclassified as successful observations or accepted approval.


## Acceptance before leaving draft

Complete source work inside `wip/v010-s18-network`, perform architecture, affected-consumer, security/adversarial and regression review, then extract only the independently reviewable S18-8 boundary for eventual integration to accepted `main`. Consolidate a cohesive history and prove all mandatory exact-head canonical CI, fresh Security/cargo-audit, CodeQL, applicable specialized native A/B, physical C/Q11 where required and inherited gates. Resolve review findings and obtain final Codex review **after** checks pass. Do not merge WIP wholesale, weaken gates or promote unsupported hardware.

This scope document is not itself correctness evidence. The PR base is WIP only for the **draft reservation and reference**; a fully qualified implementation must be explicitly rebased/retargeted for final integration into accepted `main` after review.

## 2026-11-11 typed profile revision and native read-only foundation

This PR now includes independently owned S18-8 source. **Nothing below is
registered as a runtime operation or establishes live NetworkManager mutation
qualification.** The draft remains ineligible for release or merge.

- [x] Added a *non-secret*, bounded, typed profile draft that only represents
  exact Ethernet/Wi-Fi media, UUID, bounded safe label, IPv4/IPv6 automatic or
  disabled method and autoconnect. No caller-controlled NetworkManager settings
  maps, VPN, hotspot, arbitrary routing, DNS, EAP, WPA key, token or secret
  map is accepted. Binary SSIDs are bounded and redacted from debug strings.
- [x] Added exact source-revision request correlations for Create/Update/Delete.
  Update must retain UUID, epoch and settings object; before-source must match
  version and fingerprint and after-source must advance generation and reflect
  changed settings. Create requires observed absence and same owner/UUID;
  delete requires observed original presence then absence.
- [x] Even a matching observation only returns
  RequiresIndependentNativeQualification—never an execution/commit
  authorization. Durable indeterminate or recovery-blocked transactions are
  observe-only; terminal outcomes never replay.
- [x] Added a conservative destructive profile-impact preview veto for active
  profiles, shared ownership, dependent defaults, threatened remote sessions
  and incomplete/offline recovery evidence. Its scalar inputs are *not*
  independently attested, and its result can never authorize deletion.
- [x] Added bounded native *read-only* double observation of saved profile
  version, fingerprint, UUID, flags and complete settings inventory under the
  same NetworkManager unique owner, boot and bus. This is not an atomic
  native compare-and-swap.
- [x] Pure contract tests cover malformed fields, redaction, foreign owner,
  replaced settings path, ABA/unchanged generation, stale fingerprint, unsafe
  deletion, incomplete create/delete and no replay.

**Still outstanding:** A genuinely atomic native revision CAS; independently
authenticated user, seat/session and subject-specific Polkit; durable prepared
attempt journal and original-user sender; protected credential save as an
independent reviewed authority; an exact allowlisted native settings encoder;
complete inventory/absence proof; independent post-state verification; no-blind-
replay recovery; effective route/DNS and offline access; actual Level A/B
native acceptance and retained C/Q11 physical evidence. Keep all three profile
mutation operations unregistered, and treat this as unfinished source work.

## 2026-11-11 fail-closed visible-inventory UUID collision check

- [x] Added a bounded, read-only NetworkManager profile UUID inventory scan against the exact boot, system-bus instance and unique NM owner, with settings-version and inventory rechecks after all dependent profile reads.
- [x] Strict canonical UUID and duplicate identity rejection, including invalid requested UUIDs, hidden/replaced native profile paths and excessive inventories. Added adversarial unit tests.
- [ ] An empty or apparently noncolliding *visible* ListConnections inventory is **not** evidence of global UUID uniqueness. Different users and Polkit subjects may see different profile lists. Before any create operation can be enabled, admission must independently prove original-user authorization, system-wide uniqueness, and a durable exact source/attempt grant. This read-only function cannot authorize AddConnection2.

## 2026-11-11 bounded native-settings projection (create only)

- [x] Created a fixed, immutable, redacted **nonsecret Ethernet creation**
  projection with exact connection / 802-3-ethernet / ipv4 / ipv6
  sections and only canonical NetworkManager properties. No caller-selected
  field or variant, SSID, secret, VPN, EAP, route, DNS, or hotspot map enters
  this projection. It enforces **autoconnect disabled** until Control authorizes
  any later activation effect.
- [x] Deliberately reject Wi-Fi until protected credential or explicit open-
  network policy is proven by a separate authenticated original-user effect.
- [x] Deliberately reject use of this projection as an **Update2 replacement**:
  Update2 replaces the original settings and would silently discard unrelated
  policy, shared ownership, protected or secret fields. The real profile-
  specific version-id guard has no approved independent source in this slice.
  The settings-wide Settings.VersionId and device-applied version are
  **different evidence and must not be used as the Update2 version-id**.
- [x] Added strict exact-projection/redaction/secret/unknown-field tests;
  successful equality of two caller-provided projections is only a correlation,
  never authenticated native readback or durable authorization.
- [ ] Real native wire serializer, authenticated Control spend and
  original-session/Polkit transport, exact global UUID/owner proof,
  effective routing/DNS impact and replay-proof recovery remain blocked.
  No create/update/delete operation was registered or enabled.
