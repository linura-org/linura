# S18-5 — bounded Wi-Fi discovery and managed scan events

**Milestone:** v0.10.0 / S18-5, PR #271. **Profile:** `arch-hyprland-v1`. **Status:** feature implementation source under exact-head qualification; **no network-changing operation is registered or released**. PR remains Draft until real native acceptance and the upstream S18-2/S18-4 evidence exist.

## Event model: do not substitute desired-state convergence

Passive AP enumeration is a read-only NetworkManager observation. `RequestScan` emits radio traffic and is a **one-use managed external event**: a desired value such as `scan_requested=true` must never be treated as a persistent state with automatic convergence/retry.

- Control's non-cloneable `AuthorizedEffect` is the only admissible privileged input to the private event coordinator. The separate S18-3 network deny-before-prepare guard remains active: there is no public/CLI/QML/agent mutation route.
- The coordinator reconstructs and validates exact authenticated principal/request-derived transaction, sealed effect and dispatch digest, boot/bus/NM unique owner, native Wi-Fi device path/ifindex/namespace, original logind lock/session and seat.
- An independent native preflight checks managed/enabled radio, hardware WLAN rfkill, bounded device inventory, `Scanning=false`, `LastScan` generation, original login and freshness before the event is spent.
- `SqliteWifiScanAttemptJournal::begin` persists the one-use event **before** native dispatch, with a separate key, authenticated append-only event chain, `synchronous=FULL`, exclusive SQLite write transaction and 30-second per-device interval. Missing/corrupt history, altered key, duplicate request, ambiguous earlier attempt and capacity exhaustion all fail closed.
- The only native effect is owner-pinned `Device.Wireless.RequestScan` with an empty options map; no SSID-directed probing, nmcli, generic D-Bus relay or arbitrary settings. No returned method reply is accepted as scan completion evidence.
- A **separate** post-dispatch native observer rereads current NetworkManager owner/device, kernel ifindex, original logind seat, WLAN state/rfkill, `Scanning` and fresh boot-relative `LastScan`. The completion journal accepts only the original request/device/boot/dispatch digest, bounded monotonic time and a strictly advanced scan sample.
- A lost reply, changed source, timeout, failed journal append or ambiguous completion leaves the original attempt **Indeterminate** with no automatic replay. The journal never silently reinitializes if its database vanishes on restart.

## Implemented code

| Boundary | Source |
| --- | --- |
| Conservative Control scan review, original identity and stale-observation checks | `crates/linura-control/src/wifi_scan.rs` |
| Owner-pinned native preflight, narrow `RequestScan` and independent completion sample | `crates/linura-linux-session/src/owner/wifi_scan.rs` |
| Persistent one-use event journal, independent-source completion binding and adversarial restart tests | `crates/linura-persistence-sqlite/src/network_scan_attempts.rs` |
| Privileged composition requiring consumed `AuthorizedEffect`, durable event spend and independent native verification | `apps/linura-authorityd/src/wifi_scan.rs` |

The composition is intentionally **not a public Authority1 method or an enabled operation registry**. Security-sensitive operation activation remains blocked before durable prepare until real native evidence is accepted. The private code must not be misrepresented as a released Wi-Fi scan feature.

## Security and recovery

There is no password, EAP material, SSID-directed probe, arbitrary NetworkManager settings or BSSID in the durable event record. Only canonical source/dispatch digests, exact request/principal, original boot ID and bounded timestamps are retained. Provisioning a new journal is explicit; ordinary reopen never creates a missing history. Existing S17 protected input and S21 device fences are not weakened.

**Attribution limitation:** NetworkManager provides `LastScan` and `Scanning`, but no unique identifier linking a completed scan to a particular `RequestScan` D-Bus call. A fresh, source-pinned observation is stronger than a method reply or cached AP list but **does not by itself prove exclusive causal attribution if another client initiates a concurrent scan**. The validation plan must either enforce an independently verified exclusive caller boundary or keep such attempts indeterminate. Do not turn correlation into a supported release claim.

**Rollback limitation:** the signed journal detects modifications and suffix deletion but a coherent rollback of *both* database and its protected metadata still needs an independently monotonic trusted recovery anchor; until that is qualified, do not enable scan dispatch in a rollback-capable release environment.

## Qualification still required for release

- [x] Source-level Rust formatting, native/session unit tests, persistent journal restart/tamper/no-replay tests and strict Clippy on isolated exact-source development candidate, including Control event coordinator.
- [ ] Canonical CI, Security, CodeQL and all inherited applicable qualification gates on the consolidated PR head.
- [ ] Level A, **real NetworkManager** `RequestScan` and independent owner/seat/Polkit authentication, malformed response/receive-budget, rfkill, power, timeout, owner swap and external concurrent-scanner cases.
- [ ] Level B, interactive maintained Arch/Hyprland user-session and protected-input negative/positive tests.
- [ ] Level C/Q11, maintained physical Wi-Fi hardware when available; not substituted by mock, headless VM or screenshots.
- [ ] Close the S18-2 native receive-allocation and S18-4 original-subject authorization/SecretAgent acceptance blockers; complete independent source review and device-specific rollback protection.

All nine S18 candidate effects remain disabled. Never merge WIP wholesale; keep PR #271 one consolidated commit, scope-limited and Draft until the exact evidence gates qualify any supported operation.
