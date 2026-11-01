# S18-8 — add revisioned connection profile management

**Status:** Reserved development scope; implementation and integrated qualification not yet completed.  
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
