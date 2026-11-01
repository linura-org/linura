# S18-1 — NetworkManager architecture and security contracts

**Status:** Contract-first / proposed, with no native runtime authority.
**Milestone:** v0.10.0, S18-1; PR #267.
**Reference:** `wip/v010-s18-network`; final integration target `main`.
**Architecture:** ADR 0048, S18 Phase-1 inventory and the reviewed ten-PR decomposition.

## Architecture-first scope

This is the same gate pattern as the S21-1 architecture/security PR,
*not* an implementation PR. The earlier #267 `linura-core` network
identity code belongs to **S18-2 / PR #268**, together with the
read-only native NetworkManager adapter. That code has been preserved
unchanged and reassigned; its presence in S18-2 is not evidence
that native observation is complete.

## Decisions and existing contracts

- Preserve one authoritative `ObservationEnvelope` / Control
  aggregation path and existing `networkmanager:manager` and
  `networkmanager:device:<interface>` read-only resource aliases.
  Alias strings, ifindex, SSID/BSSID, UUID, native object paths or
  derived hashes are not independent mutation identity.
- Require trusted kernel boot, system-bus incarnation and current
  NetworkManager unique owner plus exact native generations and
  independent revalidation. A multi-object sequence is not atomic;
  missing, conflicting or replaced evidence fails closed.
- Keep passive AP inventory as a query; requesting an active scan
  is a separate proposed external effect.
- Nine listed network changes remain `ManagedExternalEffect`
  *candidates*, inactive and without operation registrations. Retain
  their exact risk floors, typed permit/plan, authenticated native
  Polkit subject, persisted prepare, postcondition verification
  and durable indeterminate/no-blind-replay recovery.
- Separate protected one-time Wi-Fi/802.1X credentials from durable
  profile secret management. No passwords, PSKs, EAP exchanges
  or sensitive network identifiers in model context or audit.
- Protect the last independently recoverable offline local connection
  and route/DNS state, including IPv4/IPv6 and S17 lock/S21 device
  interactions. An optimistic native acknowledgement is not success.
- Reject unsupported VPN, hotspot, mobile broadband, arbitrary
  settings maps and direct client/provider/shell mutations.

## Implementation ownership

| Boundary | Owner | No claims at S18-1 |
| --- | --- | --- |
| S18-1 / #267 | This ADR, design/security/qualification docs, negative contract tests and gate routing | No runtime source or native API |
| S18-2 / #268 | Core identity types and passive bounded NetworkManager observation | No external effect |
| S18-3 / #269 | Control plans, trusted policy, durable attempt and recovery | No unqualified execution |
| S18-4 / #270 | Actual Polkit subject and protected native credentials | No secret exposure |
| S18-5–8 / #271–274 | Independent scan, radio, lifecycle and profile effects | No registry support until qualified |
| S18-9–10 / #275–276 | Unified UI/CLI/SDK and exact-source integrated qualification | No second authority or synthetic Q11 |

## Required architecture acceptance

- [x] Boundaries and canonical inactive operation inventory specified.
- [x] Phase ownership and first-architecture PR assignment machine checked.
- [x] Required failure oracles, route recovery, identity substitution
      and protected credential principles documented.
- [ ] Exact-head workflow and contract negative tests pass.
- [ ] Internal ADR/security/qualification review completed with no
      unresolved findings.
- [ ] Final reviewer acknowledges contract-only scope and no hardware
      or product-support promotion.

The S18 WIP source remains the live development reference. This
architecture PR must never be merged into WIP as a substitute for
real native proof; final main integration is separately reviewed.
