# S18-10 — qualify native network integration

**Status:** Reserved development scope; implementation and integrated qualification not yet completed.  
**Milestone:** v0.10.0 / S18-10.  
**Development profile:** `arch-hyprland-v1`.  
**Authoritative reference and draft PR base:** `wip/v010-s18-network` (moving development branch; exact source identity is verified independently on each test run).

## Ownership and dependencies

The reviewed S18 ten-boundary plan assigns this slice to test(qualification): qualify native network integration. Prerequisites: `S18-1`, `S18-2`, `S18-3`, `S18-4`, `S18-5`, `S18-6`, `S18-7`, `S18-8`, `S18-9`. Its draft PR is intentionally one independent non-executable scope file **relative to WIP**; any code inherited through WIP ancestry is not contributed by this PR.

Normative WIP engineering references:
- [S18 Phase-1 architecture](../workstreams/v010-s18-network-phase1.md), [implementation breakdown](../workstreams/v010-s18-pr-decomposition.md), and [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).
- [Proposed NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md) and [nine inactive network-operation candidates](../../contracts/v010-s18-design.toml).
- [Native acceptance](../qualification/v0.10.0-s18.md), [adversarial security dossier](../qualification/v0.10.0-s18-security.md), and [v0.10 workstation milestone](../milestones/v0.10.0.md).

## Planned source ownership and regression scope

- `qualification/v010/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `docs/qualification/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `tests/acceptance/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `tools/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.

Requirements: R18-QUAL-01, R18-REL-01, R18-UX-02.  
Threat/failure coverage: T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30.

## Required implementation (not yet completed)

- [ ] Establish source/guest/provider/boot/owner/subject and observed pre/postcondition binding for each accepted native network operation.
- [ ] Exercise real NM native A, interactive B and maintained physical NIC/Wi-Fi Level C/Q11 separately; VM and mock are not physical support.
- [ ] Adversarially prove hotplug, rfkill, owner restart, Polkit denial, credential cancellation, lost reply, route loss, partial dual stack and no blind replay.
- [ ] Verify GUI/CLI/SDK, no-model and offline recovery parity and S17 secure lock/S21 power/display/storage integration.
- [ ] Run exact-head canonical CI, security, CodeQL, native qualification, inherited v0.9 tests and evidence admission; release support remains planned otherwise.

## Required acceptance and outstanding blockers

- [ ] level-a-source-pinned-real-networkmanager
- [ ] level-b-real-quickshell-accessibility
- [ ] level-c-maintained-physical-wifi-q11
- [ ] q12-q14-inherited-security-and-recovery
- [ ] Entire nine-PR dependency closure and real source-pinned A/B/C evidence required; no synthetic Q11 promotion

## Architecture, security and non-claims

- This slice grants no new native operation or execution authority.
- Linura Control remains the sole owner of canonical `ReconciliationPlan`, authenticated principal, trusted risk floor, native operation admission and independent verification; no UI/provider/model-selected authority or generic privileged D-Bus/shell proxy.
- Maintain S17 protected identity, login/seat/lock and native secret safety, S21 display/power/storage safeguards, durable prepare/recovery and no-blind-replay for any managed effect, and safe offline/no-model recovery.
- No source implementation, public runtime/API, actual executor, native transaction, qualification artifact, Q11 physical evidence, new release support or milestone completion is delivered by this draft PR.
- Negative, malformed, stale, ambiguous, concurrent and restart situations remain fail-closed, not reclassified as successful observations or accepted approval.
- This is the **integrated qualification** slice: simulated/VM results never substitute for nonvirtual physical Wi-Fi/hardware Level C/Q11 proof. Source/guest/boot/owner/provider/session/subject lineage and inherited gate admission must refer to actual accepted implementation heads.

## Acceptance before leaving draft

Complete source work inside `wip/v010-s18-network`, perform architecture, affected-consumer, security/adversarial and regression review, then extract only the independently reviewable S18-10 boundary for eventual integration to accepted `main`. Consolidate a cohesive history and prove all mandatory exact-head canonical CI, fresh Security/cargo-audit, CodeQL, applicable specialized native A/B, physical C/Q11 where required and inherited gates. Resolve review findings and obtain final Codex review **after** checks pass. Do not merge WIP wholesale, weaken gates or promote unsupported hardware.

This scope document is not itself correctness evidence. The PR base is WIP only for the **draft reservation and reference**; a fully qualified implementation must be explicitly rebased/retargeted for final integration into accepted `main` after review.
