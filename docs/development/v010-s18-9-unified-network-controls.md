# S18-9 — add unified network controls

**Status:** Reserved development scope; implementation and integrated qualification not yet completed.  
**Milestone:** v0.10.0 / S18-9.  
**Development profile:** `arch-hyprland-v1`.  
**Authoritative reference and draft PR base:** `wip/v010-s18-network` (moving development branch; exact source identity is verified independently on each test run).

## Ownership and dependencies

The reviewed S18 ten-boundary plan assigns this slice to feat(shell): add unified network controls. Prerequisites: `S18-2`, `S18-3`, `S18-4`, `S18-5`, `S18-6`, `S18-7`, `S18-8`. Its draft PR is intentionally one independent non-executable scope file **relative to WIP**; any code inherited through WIP ancestry is not contributed by this PR.

Normative WIP engineering references:
- [S18 Phase-1 architecture](../workstreams/v010-s18-network-phase1.md), [implementation breakdown](../workstreams/v010-s18-pr-decomposition.md), and [machine-checked decomposition](../../contracts/v010-s18-pr-decomposition.toml).
- [Proposed NetworkManager authority ADR 0048](../adr/0048-s18-networkmanager-authority.md) and [nine inactive network-operation candidates](../../contracts/v010-s18-design.toml).
- [Native acceptance](../qualification/v0.10.0-s18.md), [adversarial security dossier](../qualification/v0.10.0-s18-security.md), and [v0.10 workstation milestone](../milestones/v0.10.0.md).

## Planned source ownership and regression scope

- `apps/linura-shell/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `apps/linuractl/src/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.
- `crates/linura-sdk/` — expected implementation or acceptance source ownership; add adjacent positive, denial, fault and regression tests only as needed.

Requirements: R18-UX-01, R18-UX-02, R18-REC-01.  
Threat/failure coverage: T09, T10, T13, T14, T16, T18, T20, T21, T22, T23, T24, T26, T28, T30.

## Required implementation (not yet completed)

- [ ] Expose the same Control-owned typed capabilities in Control Center, Quick Settings, SDK, CLI and deterministic offline/no-model paths.
- [ ] Show provider/link/AP/profile/IP/DNS/routes and unknown/stale/portal states distinctly from independently proven reachability.
- [ ] Render exact risk/material impact, authenticated protected credential handoff and explicit denied/preparing/indeterminate/recovery states.
- [ ] No direct QML/networkmanager/nmcli/agent mutation; client never selects risk, native identity or authority.
- [ ] Qualify keyboard, pointer, screen-reader, scaled/multi-output, locked-session and screenshot/privacy behavior with negative regression tests.

## Required acceptance and outstanding blockers

- [ ] shellbridge-and-qt-integration
- [ ] a11y-keyboard-pointer-high-dpi
- [ ] offline-cli-sdk-parity
- [ ] All required backends accepted and integrated before presenting effects as available

## Architecture, security and non-claims

- This slice grants no new native operation or execution authority.
- Linura Control remains the sole owner of canonical `ReconciliationPlan`, authenticated principal, trusted risk floor, native operation admission and independent verification; no UI/provider/model-selected authority or generic privileged D-Bus/shell proxy.
- Maintain S17 protected identity, login/seat/lock and native secret safety, S21 display/power/storage safeguards, durable prepare/recovery and no-blind-replay for any managed effect, and safe offline/no-model recovery.
- No source implementation, public runtime/API, actual executor, native transaction, qualification artifact, Q11 physical evidence, new release support or milestone completion is delivered by this draft PR.
- Negative, malformed, stale, ambiguous, concurrent and restart situations remain fail-closed, not reclassified as successful observations or accepted approval.


## Acceptance before leaving draft

Complete source work inside `wip/v010-s18-network`, perform architecture, affected-consumer, security/adversarial and regression review, then extract only the independently reviewable S18-9 boundary for eventual integration to accepted `main`. Consolidate a cohesive history and prove all mandatory exact-head canonical CI, fresh Security/cargo-audit, CodeQL, applicable specialized native A/B, physical C/Q11 where required and inherited gates. Resolve review findings and obtain final Codex review **after** checks pass. Do not merge WIP wholesale, weaken gates or promote unsupported hardware.

This scope document is not itself correctness evidence. The PR base is WIP only for the **draft reservation and reference**; a fully qualified implementation must be explicitly rebased/retargeted for final integration into accepted `main` after review.
