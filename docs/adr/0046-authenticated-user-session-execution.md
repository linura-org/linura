# ADR 0046: Authenticated user-session execution preserves original OS authority

- **Status:** Proposed
- **Date:** 2026-10-28
- **Refines:** ADR 0012 (canonical mutation lifecycle), ADR 0020 (sealed durable authority), ADR 0024 (native recovery), ADR 0031 (one authority path), ADR 0032 (trusted operation classification), ADR 0042 (S17 native session identity) and ADR 0045 (S21 device effects)
- **First application:** v0.10 S21-3, PR #260; reusable for future session-scoped native operations
- **Activation:** None. This decision is not an executor implementation, a registered effect, a permission grant, or physical Level C/Q11 qualification.

## Context and problem

Linura Control decides **whether** a managed effect is justified, authorized,
durably prepared, and independently verified. The operating system decides
whether the **process actually sending** a native request may perform it.
These are distinct authority checks and neither can stand in for the other.

The S17 Authority1/Control composition has a dedicated authority service
account and a separately supervised root-owned native session executor.
Those roles do not automatically possess the original interactive user's
native session permission. In particular, upstream logind's session-scoped
`SetBrightness("backlight", device_name, native_value)` checks the active
session, device seat and D-Bus caller UID, and accepts UID 0 as a special
caller. A call sent by a root executor can thus bypass the distinction
between the original user and a privileged system service. A successful
root-origin reply is **not** evidence that the user's session was entitled
to dispatch the same request.

Likewise, the same numeric UID is not an authenticated session: a process
may run under the UID without belonging to the active graphical login,
and a user service may exist outside any specific login session.
An unprivileged process may itself be controlled by other same-UID code.
Neither a client-reported UID, process ID, session token, resource name,
`GetSessionByPID` response, nor user-process attestation alone creates a
Linura dispatch permit.

The first implementation is the S21-3 brightness candidate. The principle
also applies, with separately reviewed provider permissions, to session-
scoped UDisks2/Polkit, compositor, input, accessibility and similar effects.
It does **not** transfer Control policy authority to a desktop process.

## Decision

**One Control authority, separate native execution identity.** Control remains
the sole Linura authority for classifying, reviewing, approving, durably
preparing, dispatching and reconciling a registered managed effect. A
session-scoped native effect is executed only by a narrowly scoped,
independently authenticated mechanism whose *actual operating-system
caller* is an appropriate subject of the original active login session.
The execution mechanism does not become another policy plane.

"Root Control authority" denotes Linura's trusted system-control boundary,
**not** an assertion that `linura-authorityd` necessarily runs as UID 0.
Control, the root-owned S17 native executor, the user-session transport,
the compositor and the provider are separate security principals.
Root supervision may establish trusted service identity and protect the
handoff; it must not substitute its own UID in a user-scoped native call.

If that separation cannot be attested end to end, the operation is
**unsupported/blocked**, not rerouted through root, a shell, arbitrary
D-Bus forwarding, a sysfs write, a different seat, gamma or DDC/CI.

### 1. Roles and authority ownership

| Role | May do | Must not do |
| --- | --- | --- |
| UI, CLI, hotkeys, agent | Propose typed intent; display authoritative state | Select risk/approval, mint permits, issue direct managed native mutations |
| Trusted Control | Authenticate principal; plan/policy; bind approval; durable prepare and single-use handoff; verify/commit/reconcile | Claim root/native service permission is the user's permission |
| Trusted native supervisor/broker | Attest protected binary, execution role and exact session routing; deliver a bound, non-reusable handoff | Invent an effect, widen method/device/arguments or independently approve |
| Actual user-session executor | Perform **one fixed, already approved** native call as its attested OS subject | Execute a caller-chosen method, trust a raw token or UI, self-approve, retry an uncertain effect |
| logind / native provider | Independently apply its own permissions and target-seat checks | Supply Linura approval or durable success merely by replying |
| Independent verifier | Read a new authoritative native postcondition, retaining source/identity provenance | Trust the executor's reply as proof; dispatch an effect |

A root-owned broker is an acceptable **transport and identity-enforcement
component only**. A root-owned process making the final `SetBrightness` call
itself is **not** an acceptable implementation of the user-session route.

### 2. Original subject and session binding

Control authenticates the invoking transport principal independently of
human/agent Actor metadata and binds the **numeric original UID** and one
canonical `SessionEpoch`: kernel boot UUID, exact native session ID and
nonzero monotonic session creation generation. Native evidence must also
attest active local graphical session/class, seat and logind's unique
root-owned bus owner; a session name or UID string alone is not enough.

The reviewed target must additionally bind the provider's service
invocation/owner generation and the native device's independently qualified
physical generation, topology/seat relationship, maximum, actual state and
supported safe minimum. Kernel name, symlink path or inode are **correlations**,
not sufficient proof against hotplug/reuse. No ambient `self`, `auto`,
`current`, foreign session or caller-selected native path may change scope.

For a future user-session executor, the system must prove all of these,
not merely compare the requested UID:

1. The system-bus connection is to the canonical authenticated local bus;
   the provider is the expected **unique, root-owned** logind name, checked
   before and after native reads/call as applicable.
2. The executor's actual kernel/transport UID is the original non-root
   session owner. Its bus unique name, PID and process lifetime/generation
   are authenticated from the bus/kernel, not supplied by the requester.
3. Its real PID is associated with the same exact login session through
   logind, and fresh session/seat/boot/owner observations still agree.
   `GetSessionByPID` is one necessary check, **not** proof by itself:
   PID reuse, a changed bus sender, user-manager scope and same-UID process
   substitution must be excluded using a qualified supervision/IPC design.
4. The trusted supervisor attests the intended **exact worker invocation**,
   immutable executable/policy, isolation and the channel peer at handoff.
   Merely running a binary under the correct UID is not a trusted executor:
   same-UID ptrace, process injection, inherited file descriptors, credential
   theft, socket replacement and service-restart substitution are threat
   cases. A mechanism unable to protect this boundary remains disabled.
5. The final native D-Bus call is made from that qualified subject's own
   connection, so logind independently sees the intended caller, not UID 0
   or the Linura authority service's account.

An authenticated user-session identity is **necessary but not sufficient**:
Control still needs an exact approved plan and a durable one-shot dispatch.
Linura can constrain its *own managed path*; it does not claim to prevent a
user or other software from making independently permitted OS calls.

### 3. Fixed mechanism and logind authorization

The first qualified operation, once implemented, will have the exact
Control-owned semantics:

- Operation `operation:display.backlight.set-brightness`, provider
  `logind-backlight`, observation `display.backlight.observe`,
  `ManagedExternalEffect`, risk floor `SecuritySensitive` and single
  `native_value` material change.
- Provider method `org.freedesktop.login1.Session.SetBrightness` on the
  **attested exact session object** with fixed subsystem `backlight`,
  a validated physical kernel backlight name derived from trusted inventory,
  and a canonical bounded integer at or above the independently qualified
  visible minimum. The caller cannot choose an arbitrary D-Bus path,
  method, subsystem `leds`, shell command or raw sysfs filename.
- The native provider must independently accept the real user subject,
  active session and seat/device mapping. A Linura approval never overrides
  logind denial. A provider response only describes dispatch/acknowledgement,
  not independently measured hardware brightness.

For another session-scoped provider, first qualify its **actual** OS/Polkit
subject, resource, API and risk class. Do not assume logind's permission
rules apply to UDisks2, compositor or power operations.

### 4. Single-use authorized handoff

Only a *currently registered and qualified* trusted operation can create
the managed plan. The candidate operation in the inert S21 design TOML is
**not** a live registration and must stay disabled pending acceptance.

Control's canonical path remains:

`request → observe → plan → validate → authorize → prepare → execute
→ independently verify → commit → audit → reconcile`.

Before dispatch, Control independently revalidates operation registry/risk,
principal, exact plan and resource, approval purpose/expiry, active
session/seat, service owner, worker invocation, device generation and native
safety preconditions. The durable authority store must atomically record the
single dispatch reservation (`Prepared → Indeterminate`) **before** a call
might reach the operating system. Only the winning generation gets the
non-cloneable, process-local dispatch permit.

A protected, bounded handoff carries an **exact effect binding**, including
transaction ID, generation/state version, authority/dispatch digests, original
principal and epoch, fixed action and native arguments, intended worker
invocation and expiry. Its authenticity, integrity, endpoint identity and
one-use consumption must be enforced at the receiving trust boundary.
The worker must not accept client-synthesized requests, replayable bearer
tokens, database rows, arbitrary JSON, mutable plan fragments or general
D-Bus forwarding. A bearer object exposed to arbitrary same-UID processes
is **not** an adequate authority boundary.

No retry or second handoff follows a timeout, lost acknowledgement,
client reconnection, restart, duplicate message or worker replacement.
If durable consume-once semantics cannot survive the chosen transport's
failure points, the effect remains unsupported. The receiver must be
bounded in time and scope and must never mint an alternative authority.

### 5. Identity invalidation and concurrency

Invalidate pending authority on any material change **before** the native
effect: boot/relogin/epoch turnover; UID or seat change; foreground session
switch; logind unique owner replacement; worker PID/invocation/channel
replacement; unverified provider/device hotplug or generation reuse; panel
mapping/maximum/qualified minimum change; concurrent native brightness
writer; or expiry/revocation of approval/policy.

Before the one-shot call the executor repeats the required native
preconditions and verifies that the handoff is still bound to the same
original subject. Discovery-time identity is never sufficient for
execution-time authorization.

A change **after** dispatch reservation does not undo the attempt or allow
automatic retransmission. It enters explicit *indeterminate* recovery until
authoritative evidence proves a valid terminal disposition. Revoking a
session or losing a provider must not turn an uncertain call into
"not executed" or authorize a different target.

### 6. Native postconditions and failure recovery

Successful D-Bus transport return, UI slider state, `brightness`
requested value, or an executor's self-report **never** proves physical
success. After the attempt, an independent observer must acquire a strictly
newer native sample of the unchanged authoritative session/device
generation, compare the requested native value with **actual** brightness,
and validate safe bounds and usable visibility.

A lost reply or native uncertainty produces **observe-only** reconciliation:

- **Desired observed:** a fresh, matching native desired/actual state is
  consistency evidence, not proof of which actor caused it; Control applies
  its existing durable verification rules before any commit.
- **Original observed:** a fresh original value is not proof that the call
  never ran, and **never** grants permission to retry it.
- **Other value, unsettled actual, missing/stale source or changed identity:**
  indeterminate/blocked. Preserve the consumed attempt and audit uncertainty.

Recovery must be safe after daemon crash, worker death, logind restart,
seat switch, device removal, system reboot, unavailable actual-brightness
fact and storage failure. Do not blindly replay or execute a compensating
write; any such recovery effect needs separate typed current authority,
native safety proof and a way to recover visible access independent of an
invisible UI. No zero/below-minimum sole-output brightness. A verified
restoration observation is not itself a rollback authorization.

### 7. Qualification and implementation gates

Before enabling the first executable operation, require **all** of:

1. Reviewed native worker/supervisor and protected channel with authentic
   original UID, exact PID/session/seat, bus unique name, invocation,
   executable integrity and same-UID adversarial isolation. Show it cannot
   be spoofed by an unrelated user process or by the root S17 executor.
2. Exact typed Control registration, fixed provider action, SecuritySensitive
   policy/approval and one-use durable dispatch; fault-inject crash after
   reservation, lost response, duplicate IPC, timeout and restart. Verify
   zero blind redispatch and no alternate policy/privilege path.
3. Exact-source Level A tests for wrong UID/session, same-UID other login,
   recycled PID/session, forged bus/service owner, wrong seat/target, root
   special-caller substitution, changed device/worker generation, stale
   approval, competing writes and indeterminate native readings.
4. Independently qualified physical backlight/panel/seat mapping, supported
   driver and positive safe minimum with actual-brightness observation.
   Real hardware Level C/Q11 must prove visibility preservation, recoverability,
   hotplug and logind turnover. VM mocks are **not** physical evidence.
5. Green exact-head canonical, Security, CodeQL, inherited v0.4/v0.6/v0.9,
   S17/v0.10 and applicable qualification gates; internal architecture,
   code and adversarial review followed by external final review.

Until these gates are met, retain the current read-only candidate/verification
surface, the negative operation-registry assertion, and `enabled = false`
in `contracts/v010-s21-design.toml`. ADR acceptance alone does not make an
executor, safe profile, hardware proof or merge/release qualification.

## Implementation status: canonical data and recovery guard

The inert proposed effect now has a canonical `BacklightResourceId` consisting
of the original `SessionEpoch` and a nonzero device-generation UUID. Its parser
rejects root, ambient sessions and aliases, but cannot attest physical lineage;
no production generation issuer or supported hardware profile is introduced.
The reviewed observation must separately bind seat, provider invocation,
qualification revision and safe native bounds. The fixed effect payload contains
only the exact resource and native value, with strict re-encoding validation.

Control conservatively classifies this exact proposed shape as security-sensitive
and binds durable candidates to the original authenticated non-root principal.
The durable recovery boundary refuses every backlight recovery mode capable of
reprepare, including a fresh administrator approval. Recording-store Level A
tests cover signed reservation, Control reconstruction and observe-only recovery;
they are not native execution or SQLite crash/hardware evidence. Neither risk
review nor these tests register the operation. Actual staged worker admission,
protected native dispatch, concrete persistence composition and independent
physical qualification remain unfinished under all gates above.

Backend work can proceed independently, but the S21-2 display → S21-3 brightness
integration sequence in ADR 0045 remains applicable. Accepted output identity,
topology/hotplug and visible-access requirements must be reconciled with this
separate user-session path before native activation; no dependency waiver or
brightness support promotion follows from isolated read-only checks.

### Inactive native-call budget and integration checkpoint

The original-user mechanism uses one suspend-inclusive BOOTTIME/wall deadline
through subject discovery, native lookup and the fixed call. Caller-owned
lookup/mutation RPCs have 500 ms caps; the subject probe retains its existing
750 ms native RPC cap, tightened by the same remaining outer budget. Both use
pre/post-reply expiry checks, remember the latest clock sample to reject partial
regression, and reject replies observed at or beyond their exclusive RPC cap.
Discovery can accept a tighter remaining budget without extending its two-second native cap. Native reply bodies and
descriptors are bounded before decoding. A mutation reply failure is always
indeterminate after the local attempt is consumed. These mechanisms remain
inactive and cannot issue `QualifiedBacklightAttempt` or register an operation.

Before qualified worker admission, consume accepted S21-2 topology/output
identity, protected-owner output coverage and display/recovery fencing from
PR #259. Its current candidate types must not be duplicated in a second
observation authority or guessed from names/inodes/UUIDs. Protected original-login
process bootstrap, durable cross-process consume-once delivery and complete
native verification are still unfinished; the dependency checkpoint grants no
exception to any activation or physical gate above.

## Alternatives considered

- **Have the root S17 executor call logind directly:** rejected for
  user-session effects because logind treats root as a special caller; this
  substitutes privileged authority for the original user.
- **Trust a caller-supplied UID/session/PID or run an arbitrary user command:**
  rejected: same-UID processes, stale epochs, ambient sessions and process
  replacement are not independent native identity attestation.
- **Let shell, Quick Settings, a standalone agent or a user daemon authorize:**
  rejected: creates a parallel policy/approval plane with replay risk.
- **Send a generic privileged D-Bus RPC or write sysfs directly:** rejected:
  widens mechanism scope and can bypass logind's caller/seat controls.
- **Classify native brightness as transient for speed:** rejected:
  the safety/permission/indeterminate failure envelope is
  `SecuritySensitive` and requires managed authority and recovery.
- **Treat a successful reply or post-write equality as a complete result:**
  rejected: identity, time, causation and real visible-access proofs remain
  independent.

## Consequences and applicability

This adds a reusable distinction: **Control owns permission to attempt;
the native provider authenticates the actual executor subject; independent
observation supports durable verification.** The system may use distinct,
narrow execution identities without creating multiple Linura authorities.

It requires more native identity engineering, protected process/channel
attestation and real hardware evidence. The added complexity is intentional:
when a protected original-user path cannot be implemented and qualified,
a privileged shortcut is not a fallback.

Future session-scoped operations must explicitly document the same
six interfaces: original principal/epoch; provider OS-caller semantics;
trusted handoff; native target/seat/generation; invalidation rules; and
independent verification/recovery. Each requires separate domain-specific
review; this ADR grants no blanket OS permission.

## References

- [ADR 0042 — S17 native session authority](0042-s17-session-security-and-power-authority.md)
- [ADR 0045 — S21 workstation device effects](0045-s21-workstation-device-authority.md)
- [S21-3 native backlight qualification ledger](../qualification/v0.10.0-s21-3-backlight.md)
- [systemd logind Session API](https://www.freedesktop.org/software/systemd/man/254/org.freedesktop.login1.html)
- [Upstream logind SetBrightness caller/seat checks](https://github.com/systemd/systemd/blob/main/src/login/logind-session-dbus.c)
