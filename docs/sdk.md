# Linura SDK

S17's offline/no-model recovery procedure is documented in
[deterministic session recovery](session-recovery.md). Historical receipts never
authorize an unlock, repeat a power action or assert current native coverage.

`linura-sdk` is the public, non-privileged Rust façade for Linura clients and integrations.

The Experimental display client provides `DisplayLayoutRequest`,
`DisplayLayoutReceipt` and `DisplayLayoutState` through `LocalAuthorityClient`.
`begin_display_layout`, `display_layout_status`, `confirm_display_layout` and
`revert_display_layout` use the same Authority1 contract. The CLI test-client
commands are `begin-display-layout <operation-id> <canonical-intent> <reason>` and
`display-layout-status|confirm-display-layout|revert-display-layout <request-id>`.
They require the local authority and no model. There is no automatic effect
retry, executor handle, approval assertion or client-selected principal.
The begin material is a bounded complete `LNDI:1` intent, not a command string.
Receipts report the explicit lifecycle state and original deadline; they never
report a pending attempt as completion or history as current native layout.
The current production authority composition refuses these display operations
until its complete prepared native admission and recovery ports are connected
and qualified. These client/transport contracts alone are not usable production
display management or completion of S21-2. Full display UI remains S21-6.

## Purpose

Applications should not need to depend directly on internal authority, provider or executor crates merely to understand Linura's system model. The SDK therefore re-exports the stable client-facing concepts required to inspect and request Linura state:

- typed IDs and actors, including `SetupId` and `ProfileId`;
- intents, requirements, reusable setups and machine profiles;
- portable setup/profile export and adoption request/response contracts;
- system graph and removal-impact types;
- capability blueprints and resolution results;
- protocol requests/responses;
- explainability and semantic provenance types.

`linuractl` consumes this façade as an architectural proof that ordinary clients do not need authority internals.

The in-progress S17 `LocalAuthorityClient` connects only to the canonical
root-peer system bus and exposes typed own-session lock requests, observe-only
recovery, historical request status and committed-release acknowledgement. It
also exposes `SessionTransitionRequest`, `SessionTransitionRequestStatus` and
`SessionTransitionReceipt` for suspend, logout, reboot and power-off. The server
acquires the native suspend-cycle baseline; clients cannot substitute an ambient
session, caller-selected principal or reusable authorization credential.
It never exposes an executor/provider handle, sends credentials, chooses its
principal, asserts native authentication or retries an uncertain mutation.
`SessionLockReceipt` describes the server-verified completion at response time;
`SessionLockRequestStatus` describes historical durable state only, not current
secure coverage. A lost unlock acknowledgement is recovered by inspecting the
same stable request ID and acknowledging its committed release, not by issuing
another unlock or treating an old generation as the current one.

`linuractl own-session-lock`, `lock-session`, `unlock-session`,
`session-lock-status`, `recover-session-lock` and `acknowledge-session-release`
consume those same contracts without a model or network service. They require
the local authority/native session, not an online AI provider. Passwords remain
inside the native protected authentication conversation, never CLI arguments or
free-form reasons. Deployment/native qualification remains required before S17
is claimed complete; the component builder is not qualification evidence.

`own-session-transition`, `transition-session`, `session-transition-status`,
`recover-session-transition` and `acknowledge-session-transition` consume the
same typed power contracts. A power request requires independently verified
secure coverage first and separate purpose-bound administrator authentication.
Suspend acknowledgement retires only an already committed coverage fence; it
cannot unlock or execute another transition. Recovery never calls an executor,
reauthorizes, reprepares or blindly repeats a lost-reply operation.

Transition completion is deliberately narrow: `ResumedSecurely`,
`OriginalSessionEnded` or `OriginalBootEnded`. The last does not prove causation,
the boot mechanism, or that the machine is currently powered off. Historical
status is not a completion receipt or authoritative current machine state.
Stable request IDs remain important when logout/shutdown destroys the client.

The first-party Quick Settings session/power controls are ordinary clients of
these same Experimental Authority1 contracts. They preserve local request IDs
before dispatch, secure the session before requesting power, and do not resume
an abandoned power workflow on reload or observe-only recovery. Local tracking
is convenience state, never durable authority: forgetting it cannot cancel a
transaction, release a native fence or unlock. Real native interaction and
accessibility qualification remains pending.

Protective-lock consent uses the separate typed `ProtectiveLockSettingRequest`
and `ProtectiveLockSettingReceipt`. `configure_protective_lock` requires an exact
current secure lock generation and distinct native owner authentication; it
persists only login-scoped Linura-owned policy state. It does not lock, unlock or
request sleep. `recorded_protective_lock_setting` reads zero or one latest record
in the supplied own-login epoch; `protective_lock_setting_request_status` is a
read-only lost-reply lookup. Neither query asserts that the login is active or
sleep protection works. `latest_for_epoch` means retained history, not native
availability or an execution grant. An old enable receipt remains inspectable
after revocation but can never restore consent.

`linuractl configure-protective-lock <enable|revoke> <operation-id> <exact-lock-resource>`,
`protective-lock-setting <exact-session-epoch-resource>` and
`protective-lock-setting-status <request-id>` consume those same contracts.
The explicit lock resource preserves exact retry identity; clients do not
silently substitute a later generation after a lost reply. The CLI labels consent
as recorded history and native protection as `not-queried`. Configuration and
queries carry no passwords, authentication assertions, policy decision or
executor credential. The private pre-kernel gate and protective managed lifecycle
are composed separately; these APIs alone neither activate nor attest native
protection. `SleepGate1` is not an SDK endpoint: it takes no client-selected event
or operation and requires independently supervised native-helper metadata.
Real Arch/Hyprland deployment and security qualification remain outstanding.

`own_native_sleep_gate_status()` and `linuractl native-sleep-gate-status` expose
`NativeSleepGateStatus`: a freshly authenticated own-login epoch and one closed
diagnostic state (`unobserved`, `checking`, `coverage-fenced`, `denied`). This is
an authoritative query of bounded process-retained diagnostics, not an external
effect, durable intent, current lock observation, sleep authorization or evidence
of a successful sleep cycle. No client supplies the login, event or state. The
sanitized machine-wide report contains no other user's identity or raw error.
Restart begins at `unobserved`; wrong-owner/boot, unknown states and unavailable
native identity fail the read. The shell displays the failure/battery/ventilation
warning and polls with one coalesced, two-second read at most every five seconds;
busy Control and invalid replies display unavailable, never cached protection.
Diagnostic refresh cannot enroll policy, authenticate, replay or dispatch work.

The first-party session panel offers explicit enable/revoke controls for
protective-lock consent. Each secures the session through the existing managed
lock path, then requests separate purpose-bound owner authentication through
`ConfigureProtectiveLock`; it never supplies approval assertions. The exact
request ID, native lock resource and enable/revoke decision are atomically kept
before sending the setting write. Reload never resumes this chain, and recovery
uses only `GetProtectiveLockSettingRequestStatus`: superseded history cannot
reenroll or repeat a write. Retained consent never proves present native coverage.
The unreleased client-only tracker is coherently replaced by strict v2 typed-kind
records; unsupported v1/unknown records remain untouched and block new actions
until explicitly forgotten. They are not reinterpreted as authority or replay.

A client may save, inspect, export or request adoption of reusable setups through public contracts, but adoption still occurs behind Linura Control. The SDK does not turn a setup/profile into execution authority.

## Python package

`bindings/python` owns the canonical PyPI distribution and import namespace, both named
`linura`. Its initial `0.0.1` surface was deliberately narrower than `linura-sdk`:
canonical project metadata, Experimental `Control1` identifiers, and non-executing
local `linuractl` discovery. Version `0.0.2` retains that narrow API and raises
the client minimum to supported Python 3.12; the published `0.0.1` artifacts
remain immutable.

It contains no authority, policy, provider, executor, verifier, or persistence
implementation, does not connect to D-Bus, and does not invoke `linuractl`. A future
Python transport client must consume the same versioned public contracts and preserve
the same authority boundaries rather than introducing a parallel control path.

PyPI is also downstream of Linura's canonical release authority. Trusted Release
Proof constructs and independently reproduces the Python wheel under an exact Python
patch release and fully pinned PEP 517 build requirements. Release preflights the
sealed artifact without OIDC, then a minimal `pypi` GitHub Environment job with no
repository checkout receives the only PyPI OIDC publication authority. Release
Verification freshly downloads the PyPI file and compares its digest. A
package-specific tag or standalone rebuild is not publication authority.

## Explicit exclusions

The SDK does **not** expose:

- `linura-control` internals;
- policy-engine implementation details;
- provider registration/runtime internals;
- privileged executors;
- direct root/system mutation handles;
- model-provider credentials or model execution as authority;
- secret values inside portable setup/profile structures.

Future transports may add an SDK client implementation around D-Bus or a separately authenticated remote gateway. The domain types remain transport-neutral.
