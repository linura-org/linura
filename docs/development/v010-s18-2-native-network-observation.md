# S18-2 — native NetworkManager identities and observation

**Status:** Partially implemented; code review and native qualification pending.  
**Milestone:** v0.10.0 / S18-2.  
**Profile:** `arch-hyprland-v1`.  
**Reference / PR base:** `wip/v010-s18-network`.

## Ownership and dependencies

The S18-1 architecture and security contract precedes this implementation. S18-2 owns canonical Rust native network identity types and exact-source passive NetworkManager observation. The authoritative development/reference branch remains WIP; other WIP source is **not** claimed as work newly delivered by this PR.

Architecture: [ADR 0048](../adr/0048-s18-networkmanager-authority.md), [S18 contract-first decomposition](../workstreams/v010-s18-pr-decomposition.md), [inactive operation design](../../contracts/v010-s18-design.toml), [native qualification](../qualification/v0.10.0-s18.md), [adversarial dossier](../qualification/v0.10.0-s18-security.md).

## Files and present implementation

- `crates/linura-core/src/network_identity.rs`: the previous #267 identity model transferred unchanged, including pure malformed, replay, cross-epoch, ambiguous native identity, profile ABA and freshness tests.
- `crates/linura-core/src/lib.rs`: additive exports, transferred unchanged.
- Current WIP `crates/linura-linux-observation/src/`: read-only owner-pinned, boot-checked manager/device observation is inherited from WIP, **not** implemented by this PR diff.
- Remaining expected ownership: `crates/linura-linux-observation/src/`, `crates/linura-observation-control/`, `apps/linurad/src/`, `apps/linura-firstboot/src/`.

Identity types are correlation, never independently attested OS facts, approvals, verified native snapshots, executor grants or mutation permits.

## Implementation and tests

- [x] Add typed boot/system-bus/unique NetworkManager owner epoch; device/AP/activation/profile revisions with nonzero generation, namespace/ifindex, strict aliases and checked inventory.
- [x] Add malformed/path substitution/reused interface and ifindex/owner swap/profile ABA/monotonic-age Rust identity unit tests (final exact-head CI still required).
- [ ] Integrate those identities into live read-only native observation and coordinator without breaking manager/device query aliases, CLI, daemon or First Boot.
- [ ] Complete bounded typed AP, saved/active profile, radio/rfkill, IPv4/IPv6, DNS, routes and unknown/stale/unavailable facts.
- [ ] Demonstrate bounded native transport/decode bytes/nesting, real deadlines, unique-owner consistency across multi-object snapshots, and adversarial NM restart/race tests.

## Acceptance and explicit nonclaims

- [ ] Exact-head canonical CI, Security, CodeQL, targeted core/observation tests and native real NetworkManager Level A qualification passed.
- [ ] Regression, source/boot/owner/epoch, boundedness and v0.10 routing evidence accepted.
- [ ] Final architecture/security review and Codex findings resolved.

No runtime external effects, RequestScan, protected secrets, Polkit authorization, profile edits, privileged methods, hardware C/Q11 or release support are implemented or claimed by the extracted identity code. The other nine candidate operations remain inactive. This feature is **not complete**.

## Integration strategy

The original identity code was preserved at `archive/s18-267-before-contract-first-correction-20261101`. Continue S18-2 development using WIP, extract reviewed owned implementation without unrelated slices, and rerun final exact-head checks before a deliberate integration into accepted `main`. The historical PR head branch name (S20) is not the slice's actual ownership.
