# S18-4 — add protected network credentials and native authorization

**Status:** Source integration now includes a purpose-bound live NetworkManager SecretAgent, native one-use Control-to-Polkit handoff and protected Wi-Fi password delivery. Exact-head CI, independently observed real NetworkManager/Polkit Level A, applicable Level B and original long-interaction freshness remain unqualified; PR stays Draft.
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
- Before beginning the prompt or submitting the one-use response, a typed `NativeNetworkSecretAgentCall` now requires the **exact** live NM sender, saved-profile path, WPA-PSK setting, supported hints, and user-requested interactive `GetSecrets` flags (0x5). This refuses background/unsolicited requests, `REQUEST_NEW`, unknown bits, VPN/WEP, foreign owners and substituted calls. Scope and incoming native metadata are both spent together. No raw connection/secret map is decoded by this component. `SaveSecrets` and `DeleteSecrets` are explicitly denied by the new native D-Bus adapter. Unauthorized or mismatched `GetSecrets` are rejected, and an agent is registered only after the exact original Control proof has been spent.
- Credential scopes are restricted to `operation:network.wifi.join`; the native correlation also requires a refreshed exact settings-wide `VersionId`, fingerprint, device/profile identity and explicit protected-human-consent evidence. The runtime constructs these inputs only after an exact original S17 Polkit approval has been consumed and separately checks the current Control sender, compositor, logind seat and NM target. The C++ component itself still treats caller-created witnesses as non-authoritative.
- Fresh native credential witnesses must match the original exact profile `VersionId`, nonsecret settings fingerprint, settings object and device object, not merely NM's unique owner; a post-review edit or replacement cancels the prompt.
- `apps/linura-shell/security-owner/tests/native_network_credentials.cpp` and `CMakeLists.txt` — native negative fixtures for wrong owner, fake principal, substituted profile, forged Polkit/session witness, persistent-profile request, stale expiry, replay, and secret-retention checks. They use the existing protected-entry component and run under the canonical native CTest environment.

The C++ protected input remains a restrictive, non-authorizing component. The separate `NativeNetworkSecretAgent` adapter now registers the canonical NM interface on the same trusted system bus after the original authenticated Control handoff, refuses persistence, and sends exactly one ephemeral WPA-PSK result. The native adapter does not enable a network operation or turn a witness into effect authority.

- `crates/linura-linux-session/src/owner/network_credential.rs` — additive **read-only original Control subject** correlation: original attested S17 session leader/UID/PID/start ticks, exact login/boot, live system-bus incarnation and unique NM owner; bounded GetDevices/ListConnections membership plus twice checked **settings-wide VersionId, kernel namespace/ifindex, and native device interface** against the S18-2 typed identities. The original active local Wayland **logind seat** is also re-observed from the real session object and must match the requested seat; exact owner/subject rechecked after the probe. Tests deny mismatched UID, replaced NM owner, inconsistent device generation and stale/cross-epoch observations. This produces **no transferable permit**, and the settings-wide counter does not replace future independently verified profile fingerprints at dispatch.
- `crates/linura-linux-session/src/owner.rs` and `lib.rs` — expose the narrow read-only subject observation under the original authenticated Control channel rather than a second caller authority.
- The read-only network subject also carries the exact original Control network-credential request and immutable request/review digests. A new Control-role `authenticate_original_network_credential` helper requires the network-specific S17 `NetworkCredential` purpose and exact matching request/lock/principal/digests, rechecks the original NM owner and subject before and after the official session-owner Polkit authentication, consumes the S17 one-use proof, atomically attempts the scope-bound native agent arm and reobserves the exact subject after registration. This is not an effect permit; stale initial observations and slow interactive exchanges continue to fail closed.

- `crates/linura-linux-session/src/owner.rs`, `apps/linura-shell/security-owner/native_scope.*`, `native_endpoint.cpp`, and the canonical Polkit package: a fixed S18-4 **`AuthenticateNetworkCredential` (wire code 8)** action within the existing supervised S17 native Polkit/PAM owner. The action uses the native Control sender, original login leader, single-use exact lock/request/plan/review digests, active secure compositor and **session owner only**. It cannot be replayed for unlock, protective lock, power or a different network request. The new fixed Polkit action `org.linura.authority.use-network-credential` is `auth_self` on the active original session and otherwise denied; namespace policy bindings and cross-language negative fixtures are updated. Its successful authentication is a *prompt proof*, **not** a native secret delivery or an effect permit.

### Added live native agent boundary

- `native_network_agent.h/.cpp` exports only the fixed NetworkManager SecretAgent interface `GetSecrets/CancelGetSecrets/SaveSecrets/DeleteSecrets` under `/org/freedesktop/NetworkManager/SecretAgent`. The object is exported and `RegisterWithCapabilities` is invoked only after the original S17 approval has been spent, matched to the actual supervised Control sender and the independent immutable root-owned NM service. It is unregistered on completion, cancellation, timeout and owner changes.
- Native GetSecrets wire metadata comes from `QDBusContext::message()`, never caller-created fields. The path, settings signature, `0x5` user-request flags and the original active WPA-PSK target are exact. The saved `GetSettings` projection is computed locally against the S18-2 SHA-256 projection and Settings.VersionId, and requires explicit `NOT_SAVED=2` PSK semantics; a Wi-Fi device/ifindex, kernel namespace, NM owner and logind seat are freshly probed. No general profile mutation, SaveSecrets, DeleteSecrets, credential persistence or public D-Bus/agent API is added.
- The native `ArmNetworkCredential` wire is deliberately restricted to the exact approved Control request, principal, lock, profile/target, review digests and original bus owner. Its proof is spent before target registration. `CancelNetworkCredential` belongs only to the original attested Control sender.
- `tests/native_network_agent.cpp` exercises nested wire signature, profile fingerprint, NOT_SAVED exclusivity, variant-substitution tests and root-owned NM peer constraints. Existing credential component tests additionally exercise request, ifindex, network namespace and profile identity substitution.
- **Security limitations needing real qualification:** D-Bus transport necessarily serializes the ephemeral PSK outside the locked native input buffer; the code must be tested for accidental second copies, logs, FDs and evidence redaction in a real NM/Polkit VM. The existing initial observation freshness requirement is five seconds; a user taking longer to authenticate is rejected and must obtain a newly observed and reviewed challenge. Do not extend it or auto-replay a failed attempt.
- No actual network connection effect is enabled here. S18-7 owns network effect dispatch and durable authorization. The new agent is an S18-4 native mechanism, not an independently authorized executor.

Relevant requirements: R18-AUTH-02, R18-SEC-01.
Adversarial cases: T03, T05, T11, T13, T14, T15, T16, T17, T19, T23, T24, T26, T28.

## Required S18-4 implementation and acceptance

- [x] Add the narrow original-Control read-only transport/logind/NM owner and device/profile membership correlation, checked on both ends of a bounded probe.
- [x] Add the exact native session-owner Polkit/PAM authentication purpose, Control-only original challenge, native owner protected interaction, short single-use proof and policy action (S17 boundary reused unchanged for older operations).
- [x] Source-code integration binds spent original Control/Polkit proof to one native SecretAgent arm and use-time profile/owner revalidation; still requires real native A/B acceptance.
- [x] Source-code implementation adds purpose-bound SecretAgent and protected one-time WPA-PSK input, with no model/QML/audit interface. Real IPC redaction evidence remains required.
- [x] Separate one-time protected credential storage from durable profile persistence (the latter is denied).
- [x] Source path couples original S17 PAM/Polkit consumption to native agent scope and protected-entry submission; native sender and target are independently checked. Qualification must prove this using real logind, Polkit and NM rather than constructed witnesses.
- [x] One-use protected-entry scope, timeout, focus/cancellation, peer replacement, bus name-owner change and buffer wipe are implemented; real runtime cancellation and connection-loss qualification are outstanding.
- [x] Adversarial *component* fixtures for confused metadata, wrong UID/seat/owner, replay, persisted-secret refusal and protected buffer consumption.
- [ ] Complete **real** transport-origin/logind/Polkit and native IPC SecretAgent adversarial qualification. Mocked witness arguments and offscreen CTest alone are not authenticated identities.

## Required qualification and remaining blockers

- [ ] real-polkit-subject-adversarial — agent source exists, but live NM/Polkit use-time challenge has not been accepted in a qualified VM
- [ ] native-protected-input-credential-tests and native-network-agent-boundary — exact-head CTest and real NM callback remain to be validated
- [ ] secret-redaction-and-ownership-audit
- [ ] No native credential use until genuine protected-input and secret-agent subject are qualified

## Explicit safety and support boundaries

- No native effect or operation is registered.
- Linura Control retains canonical risk classification, authenticated principal, `ReconciliationPlan`, durable prepare/verification and recovery authority. Native mechanisms must be narrow and fail closed.
- No arbitrary privileged D-Bus or shell passthrough, leaked secrets, session/seat alias grant, blind effect replay, or replacement of S17 lock/security and S21 device protections.
- A purpose-bound native SecretAgent now has a registration source path, but it cannot be invoked without a spent original Control proof. The Polkit action authenticates the original login only; it is **not** a NetworkManager mutation permission or dispatch permit. No network effect, credential persistence, maintained-hardware Q11 or release support is claimed. Green component/VM checks cannot substitute for real NM/Polkit use-time security acceptance.

## Acceptance and eventual release

Before **final review readiness**, independently qualify the now-integrated original Control sender, logind seat/session, real Polkit subject, purpose-bound NetworkManager SecretAgent, protected consent, restart/timeout/cancellation and secret-redaction tests across the actual native IPC path. Then pass exact-head canonical CI, Security, CodeQL, native A/B and inherited gates, resolve source findings and complete final Codex review. No Q11/C physical proof may be claimed without maintained hardware. Do not merge this stacked branch into main until predecessors are accepted.

Historical PR head `feat/v010-s25-1-preference-authority` is retained for GitHub continuity; its old version is archived as `archive/pre-s18-rebuild-20261101-pr-270`.
