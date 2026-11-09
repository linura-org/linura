# S18-2 — native NetworkManager identities and observation

**Status:** Native read-only implementation hardened; exact-source regression and real-NM Level A qualification pending. New capability support remains degraded.  
**Milestone:** v0.10.0 / S18-2.  
**Profile:** `arch-hyprland-v1`.  
**Reference / PR base:** `wip/v010-s18-network`.

## Ownership and dependencies

The S18-1 architecture and security contract precedes this implementation. S18-2 owns canonical Rust native network identity types and exact-source passive NetworkManager observation. The authoritative development/reference branch remains WIP; other WIP source is **not** claimed as work newly delivered by this PR.

Architecture: [ADR 0048](../adr/0048-s18-networkmanager-authority.md), [S18 contract-first decomposition](../workstreams/v010-s18-pr-decomposition.md), [inactive operation design](../../contracts/v010-s18-design.toml), [native qualification](../qualification/v0.10.0-s18.md), [adversarial dossier](../qualification/v0.10.0-s18-security.md).

## Files and present implementation

- `crates/linura-core/src/network_identity.rs`: the original #267 identity model, with negative test-only Clippy fixes (no changes to the published identity API or its invariants).
- `crates/linura-core/src/lib.rs`: additive exports, transferred unchanged.
- `crates/linura-linux-observation/src/lib.rs`: retains the existing manager/device resources while adding separately flagged read-only Wi-Fi, AP, profile, active-connection and IP configuration capabilities. Source reads additionally require exact kernel-boot, system-bus instance and unique NM owner epoch consistency.
- `crates/linura-linux-observation/src/networkmanager_native.rs`: uses the same original `NetworkManagerObserver` and Control observation envelope, with native read-only endpoint enumeration, bounded object rows, kernel namespace/ifindex correlation, re-observed membership, passive AP SSID bytes, saved-profile Settings.VersionId and GetSettings-based allowlisted SHA-256 projection, active-connection topology, IPv4/IPv6 address/route data and per-config resolver addresses.
- Existing WIP manager/device, daemon, First Boot and CLI consumers remain on the same observer route; no second authority/provider is introduced.
- Native method replies are rejected when their serialized body exceeds 64 KiB *before dynamic deserialization*, and profile content has explicit section/field ceilings. This bounds the decoder, but zbus has already read/framed the reply in memory; it does **not** establish a socket-level pre-allocation receive cap. A hardened transport bound and real Level A source/owner replacement evidence are still required before promotion.

Identity types are correlation, never independently attested OS facts, approvals, verified native snapshots, executor grants or mutation permits.

## Implementation and tests

- [x] Add typed boot/system-bus/unique NetworkManager owner epoch; device/AP/activation/profile revisions with nonzero generation, namespace/ifindex, strict aliases and checked inventory.
- [x] Add malformed/path substitution/reused interface and ifindex/owner swap/profile ABA/monotonic-age Rust identity unit tests (final exact-head CI still required).
- [x] Add exact-same-owner/boot/bus-instance read-only observation to the existing observer and retain the original manager/device aliases and Control-owned envelope.
- [x] Add separate typed/passive AP and Wi-Fi, saved-profile presence, active-connection, IPv4/IPv6 address, per-config DNS and route observation with duplicate-list and family/size denial tests.
- [x] Bound connection/authentication and per-D-Bus method timeouts, device/AP/connection/IP row inventories and post-read epoch checks.
- [x] Read GetSettings (which excludes credentials), verify native profile UUID, check the settings-wide VersionId and profile flags across the read, and retain only a digest of a bounded normalized non-secret setting allowlist. A global VersionId change rejects even a byte-identical settings ABA update. No raw nested settings are published.
- [x] Reject oversized D-Bus method body replies before decoding dynamic variants; bound section/field counts and rely on zvariant's checked D-Bus nesting rules. Bound the original transport's method and connection/authentication deadlines.
- [ ] Prove a true socket-level receive/allocation ceiling for the zbus transport (the post-frame guard is not equivalent), plus exhaustive malformed-provider, bus-restart and current native NetworkManager Level A tests. No real-hardware or cross-provider network readiness claim.

## Acceptance and explicit nonclaims

- [ ] Exact-head canonical CI, Security, CodeQL, targeted core/observation tests and native real NetworkManager Level A qualification passed.
- [ ] Regression, source/boot/owner/epoch, boundedness and v0.10 routing evidence accepted.
- [ ] Final architecture/security review and Codex findings resolved.

No runtime external effects, RequestScan, protected secrets, Polkit authorization, profile edits, privileged methods, hardware C/Q11 or release support are implemented or claimed by this read-only integration. The nine candidate operations remain inactive. The three new observation families deliberately advertise **Degraded**, never automatically Supported, pending their native byte-budget and exact-source qualification. **S18-2 is not yet complete or production-qualified.**

## Integration strategy

The original identity code and tests were preserved at `archive/s18-267-before-contract-first-correction-20261101`. Continue S18-2 development using WIP, extract reviewed owned implementation without unrelated slices, and rerun final exact-head checks before a deliberate integration into accepted `main`. The historical PR head branch name (S20) is not the slice's actual ownership.
