# S18-4 — add protected network credentials and native authorization

**Status:** Protected native input, original-subject checks and the fixed S17-backed network Polkit action implemented. A real purpose-bound NM SecretAgent, protected use-time proof coupling and end-to-end native qualification remain outstanding; PR remains Draft.
**Milestone:** v0.10.0 / S18-4.
**Profile:** `arch-hyprland-v1` (development).
**Stacked review base:** S18-3 / PR #269. The historical head branch name is preserved for GitHub continuity; never merge the old WIP base.

## Ownership and dependencies

Depends on S18-1, S18-2 and S18-3. The PR diff is limited to S18-4-owned code and its native tests and documentation, stacked on PR #269. All nine network mutations remain unregistered and disabled.

Authoritative WIP sources:
- [S18 Phase 1](../workstreams/v010-s18-network-phase1.md), [ten-part implementation decomposition](../workstreams/v010-s18-pr-decomposition.md), [machine-checked plan](../../contracts/v010-s18-pr-decomposition.toml).
- [NetworkManager ADR 0048](../adr/0048-s18-networkmanager-authority.md), [inactive design](../../contracts/v010-s18-design.toml).
- [S18 qualification](../qualification/v0.10.0-s18.md), [security dossier](../qualification/v0.10.0-s18-security.md).

## Delivered native protected-input boundary

- `apps/linura-shell/security-owner/native_network_credentials.h/.cpp` — restrictive, non-QObject C++ session for one ephemeral password prompt using the existing S17 protected `SecretEntry` and non-dumpable/locked `SecretBuffer`. Binds original lock generation, UID, session, seat, original D-Bus sender, system-bus incarnation, NM owner, numeric native device and settings paths, revision fingerprint and exact request/review digests; no credential or consent object can be serialized into QML/audit.
- Deliberately refuses credential persistence; native callbacks consume the protected response once, with clearing on reply/cancellation/failure, owner/session/seat mismatch, protected-focus loss, monotonic clock rollback, deadline or device generation replacement. A session cannot be re-armed after cancellation or spent callback.
- Before beginning the prompt or submitting the one-use response, a typed `NativeNetworkSecretAgentCall` now requires the **exact** live NM sender, saved-profile path, WPA-PSK setting, supported hints, and user-requested interactive `GetSecrets` flags (0x5). This refuses background/unsolicited requests, `REQUEST_NEW`, unknown bits, VPN/WEP, foreign owners and substituted calls. Scope and incoming native metadata are both spent together. No raw connection/secret map is decoded by this component. `SaveSecrets`, `DeleteSecrets` and arbitrary `GetSecrets` callbacks remain impossible because the real D-Bus agent is not registered.
- Credential scopes are restricted to `operation:network.wifi.join`; the native correlation also requires a refreshed exact settings-wide `VersionId`, fingerprint, device/profile identity and explicit protected-human-consent evidence. These booleans are **inputs to a restrictive fence, not proof minted by a trusted Polkit or compositor adapter**. Real producer authority remains a final-review blocker.
- Fresh native credential witnesses must match the original exact profile `VersionId`, nonsecret settings fingerprint, settings object and device object, not merely NM's unique owner; a post-review edit or replacement cancels the prompt.
- `apps/linura-shell/security-owner/tests/native_network_credentials.cpp` and `CMakeLists.txt` — native negative fixtures for wrong owner, fake principal, substituted profile, forged Polkit/session witness, persistent-profile request, stale expiry, replay, and secret-retention checks. They use the existing protected-entry component and run under the canonical native CTest environment.

These are native-only *correlation and protected-input checks*. The unexported C++ wrapper does not register with NetworkManager, claim that caller-supplied witness fields independently attest Polkit/logind, or grant execution. S17's already-qualified official Polkit/PAM authentication mechanism remains distinct and cannot be reused as an arbitrary NetworkManager authorization.

- `crates/linura-linux-session/src/owner/network_credential.rs` — additive **read-only original Control subject** correlation: original attested S17 session leader/UID/PID/start ticks, exact login/boot, live system-bus incarnation and unique NM owner; bounded GetDevices/ListConnections membership plus twice checked **settings-wide VersionId, kernel namespace/ifindex, and native device interface** against the S18-2 typed identities. The original active local Wayland **logind seat** is also re-observed from the real session object and must match the requested seat; exact owner/subject rechecked after the probe. Tests deny mismatched UID, replaced NM owner, inconsistent device generation and stale/cross-epoch observations. This produces **no transferable permit**, and the settings-wide counter does not replace future independently verified profile fingerprints at dispatch.
- `crates/linura-linux-session/src/owner.rs` and `lib.rs` — expose the narrow read-only subject observation under the original authenticated Control channel rather than a second caller authority.
- The read-only network subject also carries the exact original Control network-credential request and immutable request/review digests. A new Control-role `authenticate_original_network_credential` helper requires the network-specific S17 `NetworkCredential` purpose and exact matching request/lock/principal/digests, rechecks the original NM owner and subject before and after the official session-owner Polkit authentication, consumes the S17 one-use proof and returns **no** credential-agent grant or effect authority. Expired observations deny the interaction rather than extending their original validity to accommodate a slow prompt.

- `crates/linura-linux-session/src/owner.rs`, `apps/linura-shell/security-owner/native_scope.*`, `native_endpoint.cpp`, and the canonical Polkit package: a fixed S18-4 **`AuthenticateNetworkCredential` (wire code 8)** action within the existing supervised S17 native Polkit/PAM owner. The action uses the native Control sender, original login leader, single-use exact lock/request/plan/review digests, active secure compositor and **session owner only**. It cannot be replayed for unlock, protective lock, power or a different network request. The new fixed Polkit action `org.linura.authority.use-network-credential` is `auth_self` on the active original session and otherwise denied; namespace policy bindings and cross-language negative fixtures are updated. Its successful authentication is a *prompt proof*, **not** a native secret delivery or an effect permit.

Pending owned source integration: a purpose-bound **real NetworkManager SecretAgent registration and GetSecrets callback** connected to the freshly authenticated original Control challenge, real profile revision and cancellation; full secret redaction across native IPC; and exact native-only admission policy if required. The new read-only correlation and Polkit approval are individually restrictive, not a combined transferable credential; none authorizes a network mutation. No new D-Bus service has been registered prematurely.

Relevant requirements: R18-AUTH-02, R18-SEC-01.
Adversarial cases: T03, T05, T11, T13, T14, T15, T16, T17, T19, T23, T24, T26, T28.

## Required S18-4 implementation and acceptance

- [x] Add the narrow original-Control read-only transport/logind/NM owner and device/profile membership correlation, checked on both ends of a bounded probe.
- [x] Add the exact native session-owner Polkit/PAM authentication purpose, Control-only original challenge, native owner protected interaction, short single-use proof and policy action (S17 boundary reused unchanged for older operations).
- [ ] Bind that original authenticated network-credential proof to the real SecretAgent use and fresh native profile generation at the exact secret transport boundary; no standalone prompt can authorize an effect.
- [ ] Establish purpose-bound native Wi-Fi secret-agent and protected credential input without exposing passwords, EAP material or BSSID-sensitive data to model, QML, audit or logs.
- [x] Separate one-time protected credential storage from durable profile persistence (the latter is denied).
- [ ] Couple actual protected human consent, original Polkit proof and live SecretAgent request in the same bounded native lifecycle. Component witness booleans are not authenticated consent.
- [x] One-use protected-entry scope and timeout/focus/cancellation/replacement guards with native buffer wipe, tested as a component; still require real runtime delivery and connection-cancellation signals before accepting full native qualification.
- [x] Adversarial *component* fixtures for confused metadata, wrong UID/seat/owner, replay, persisted-secret refusal and protected buffer consumption.
- [ ] Complete actual transport-origin, logind/Polkit and native IPC secret-agent adversarial qualification. Mocked witness arguments are not an authenticated Polkit identity.

## Required qualification and remaining blockers

- [ ] real-polkit-subject-adversarial — fixed S17 Polkit action exists, but a real NM SecretAgent request and use-time challenge have not yet been jointly accepted
- [ ] native-protected-input-credential-tests — component CTest added; exact-head result and production agent path remain to be validated
- [ ] secret-redaction-and-ownership-audit
- [ ] No native credential use until genuine protected-input and secret-agent subject are qualified

## Explicit safety and support boundaries

- No native effect or operation is registered.
- Linura Control retains canonical risk classification, authenticated principal, `ReconciliationPlan`, durable prepare/verification and recovery authority. Native mechanisms must be narrow and fail closed.
- No arbitrary privileged D-Bus or shell passthrough, leaked secrets, session/seat alias grant, blind effect replay, or replacement of S17 lock/security and S21 device protections.
- New C++ protected-input, Rust original-subject/Polkit helper and the fixed **network-credential authentication policy action** exist, but no SecretAgent or network effect is registered. The added Polkit action authenticates the original login only; it is **not** a NetworkManager mutation permission, credential transport or dispatch permit. No native agent, credential persistence, hardware or release support is claimed. Green component/VM checks cannot substitute for real NM SecretAgent, use-time subject verification or Q11.

## Acceptance and eventual release

Before **final review readiness**, integrate and independently qualify the original authenticated transport sender, logind seat/session, real Polkit subject, a purpose-bound NetworkManager SecretAgent registered with the exact NM owner, protected user consent and cancellation, and secret-redaction tests across the actual native IPC path. Then pass exact-head canonical CI, Security, CodeQL, native A/B and inherited gates, resolve source findings and complete final Codex review. No Q11/C physical proof may be claimed without maintained hardware. Do not merge this stacked branch into main until predecessors are accepted.

Historical PR head `feat/v010-s25-1-preference-authority` is retained for GitHub continuity; its old version is archived as `archive/pre-s18-rebuild-20261101-pr-270`.
