# ADR 0042 — S17 binds session security and power to one managed authority path

- **Status:** Proposed
- **Date:** 2026-10-06
- **Refines:** ADR 0032 operation classification; ADR 0033 workstation completeness

Numbering history: this unaccepted decision was first drafted as ADR 0038 on
2026-10-06. Integrating main `197e316` allocated 0042 because accepted records
0036–0041 now occupy that range. Its original date, proposed status and decision
content are retained; it does not replace or supersede accepted ADR 0038.

## Context

S17 includes a secure locker, session-owner authentication, session/power control,
and first-party interaction surfaces. A shell overlay or direct QML mutation of
compositor/logind state would not implement this slice. Neither the systemd
active-state effect nor the transient audio effect qualifies these new domains.

## Proposed decision

Keep the full vertical slice in one S17 PR. Split a prerequisite only if its
authority contract is genuinely reusable and extends beyond S17.

### Session identity and observation

A session name or PID alone is not a generation. Bind kernel boot identity,
authenticated owning UID, native session ID, and monotonic creation generation.
Transport-authenticated principal stays distinct from Actor provenance. A
recycled handle, root caller, other user or caller-selected identity must not
retarget an approved request.

The native logind adapter uses the canonical system-bus socket, authenticates its
kernel peer and the service's unique root-owned bus name, and keeps reads bound to
that unique name. It rechecks boot, owner and session generation before returning.
Connection, authentication and calls are bounded; paths, process handles and
account names remain adapter details. Control owns cross-provider coordination.

`LockedHint` is informational. It does not prove secure compositor coverage,
authentication or successful locking. Obtain coverage separately from the trusted
native lock mechanism for the exact epoch. Cached evidence, UI state, PAM results
and dispatch acknowledgements never substitute for required postcondition facts.

### Security-owning locker and authentication

Separate the security-owning locker from the ordinary shell. Shell crashes,
reloads and panel dismissal must not release the secure lock. The qualified native
session-lock protocol must cover every output, including hotplug. QML owns
presentation and interaction, not authentication decisions or an unguarded unlock.

Bind native owner authentication to the reviewed request, principal, session epoch
and lock generation. Secrets travel only through the protected authentication
channel, never general Control DTOs, argv, logs, audit payloads, fixtures, model
context or reusable approval records. Wrong credentials, account denial,
cancellation, malformed responses, lost services and expired proof leave the
session locked. Do not accept an untrusted client boolean as proof of PAM success.

The security-owner startup itself must resist same-UID process injection, not just
disable dumping after a large UI runtime has initialized. The proposed private,
root-immutable runtime enters through Linux secure-exec with only `CAP_IPC_LOCK`,
requires the kernel-established `AT_SECURE` marker and an exec-time dumpability
state that denies unprivileged same-UID ptrace (disabled state 0 or Linux root-only
safe-path state 2), immediately forces and reads back state 0 before capability
use, memory locking, native input or toolkit initialization,
rejects saved-user/group identity escapes, establishes whole-process memory residency
(including native authentication temporaries), then drops that capability before
accepting input. Bounded cgroup/memlock limits must be natively qualified; inability
to establish protection disables input rather than falling back. No ambient
capabilities or additional native privileges are accepted.
The ordinary shell does not receive this file capability. The official Polkit
helper remains the separate protected PAM boundary; `NoNewPrivileges` cannot be
used to claim authentication readiness while silently disabling its setuid helper.
Repository-owned packaging now defines startup activation; it still requires native same-UID ptrace,
reload, loader-environment, helper and package-immutability qualification.

Owner authentication is **not** automatically administrator or destructive-action
approval. Qualify the exact purpose-scoped approval requirement without weakening
the existing protected approval-strength contracts. Policy approval, OS permission
and durable prepared dispatch authority remain distinct.

Each transition has a separate exact native authentication purpose and fixed,
non-retained `org.linura.authority.*-session` administrator Polkit action. The
owner's unlock proof cannot satisfy a power approval, nor can a suspend proof
authorize logout, reboot or power-off. The protected presentation names the
specific action and warns about lost unsaved work for destructive actions.
It accepts only the administrator identity supplied by the official Polkit
conversation; unlock still accepts only the exact session owner. Unknown or
ambiguous identity selection fails closed. Transition authentication requires
already-proven secure compositor coverage and never releases that lock.
Control preserves `Administrator` versus `DestructiveAction` requirements when
mapping a sealed challenge; neither a positive permission query nor PAM success
is a prepared executor credential. Native real-session qualification is pending.

The scoped `policy:session-lock:v1` rule keeps `SecuritySensitive` risk intact.
An exact own-session lock requires an explicit interactive request; an exact
unlock requires `SessionOwnerAuthentication`, not `Administrator`. Bind both to
`SessionLockId` (epoch, attested security-owner service invocation and nonzero
native lock generation). A restarted owner cannot recycle a former process's
counter into an old approval, even within the same login epoch. General baseline
approval strength remains unchanged. The transport maps only sealed canonical
unlock challenges to a fixed, non-retained native `auth_self` Polkit action.
Positive locking requires native candidate-bound human confirmation; an
active-user Polkit `yes` is not that confirmation. The native pre-lock dialog
and its actual-connection keyboard/pointer handlers implement that confirmation without
PAM or dispatch authority. Root graphical sessions are outside this qualification because
implicit root OS permission cannot stand in for fresh owner authentication.
The native authentication agent handles the protected PAM conversation, while
Control observes Polkit's authorization independently. An agent's success signal
does not release the compositor lock or become an executor credential.

Ephemeral native confirmation uses `CLOCK_BOOTTIME`, including suspended time.
A paused Qt/event-loop or `CLOCK_MONOTONIC` timer must not extend a short-lived
owner-authentication confirmation across a suspend/resume cycle. Clock failure,
rollback, timeout and excessive native prompts clear or terminally deny the
conversation; none of these states imply an unlock.

The native PAM callback converts bounded known questions to a closed presentation
kind (password, PIN, verification/recovery code or generic response). Raw native
questions and their echo flags never become QML strings or response display;
unknown/localized questions remain generic and all responses stay masked. A fixed
placeholder identifies the actual native-provided authentication UID and bounded
conversation step. Reentrant prompt/error delivery defers teardown until the
protected response buffer has been wiped. This is component-tested behavior,
not qualification of real multi-step PAM, accessibility or arbitrary PAM stacks.
The protected entry's public-Qt accessibility adapter exposes only fixed prompt
metadata, password-field role and availability/focus state. Text, editable text,
value and action interfaces are absent; setting accessible text cannot inject a
response or confirm anything. It does not report offscreen Qt coordinates as real
multi-output geometry. Native screen-reader traversal/focus/interaction remains
an explicit qualification requirement; metadata component checks are insufficient.

Session ownership/active-seat predicates are freshly coordinated by Control,
included as a canonical plan finding, and narrow the primary observation's
validity through prepare/handoff. Public previews and managed prepare share this
same canonical derivation. Exclusive native deadlines are translated to the
canonical envelope's inclusive last-valid endpoint without adding a millisecond
of authority. Fresh locker facts cannot extend an older session precondition.
Native transport/process attestation and fresh privilege-
boundary validation remain requirements of the production adapters.

Native startup binds the owned actual Wayland connection's kernel peer, rather than
checking one socket and subsequently trusting a separate pathname connection.
The currently proposed qualification requires that peer to be the authoritative
session leader, with exact owning UID, local active Wayland/user session, boot and
creation generation. Unknown launch topology is unsupported, not guessed. Native
session establishment and the pinned qualification login fixture must exercise
this requirement; the unit-level binding predicate is not evidence that arbitrary
existing desktop launchers satisfy it.

### Protective locking at native sleep entry

The revised S17 design does not universally disable laptop lid suspension.
The owner may explicitly approve a durable, revocable, exact-session policy for
protective locking before native sleep. This authorizes only `secure=false` to
`secure=true`, with unchanged `SecuritySensitive` risk and the complete managed
lifecycle. It cannot unlock, authorize sleep itself, approve power operations,
or weaken ordinary manual-lock confirmation. The initiating principal remains
the authenticated protective service; it is not relabeled as the human owner.
The approved owner intent and setting revision remain separate provenance.
Conversation approval selects this design, not a runtime policy credential.

Control must read the current authenticated policy record, independently attest
the native sleep entry and current session/locker, derive the canonical plan,
and recheck revocation, exact scope and freshness immediately before handoff.
Boot plus native sleep invocation and login epoch define stable request identity;
retries or an owner restart must not allocate fresh authority for the same event.
Crash/ambiguity recovery is observe-only, never reconstruction of an event permit.
Unknown owner/session, multiple unqualified sessions or missing facts fail closed.

An expiring logind delay inhibitor is coordination, not failure-fallback denial.
The fixed native pre-kernel gate must refuse continuation on missing verified
coverage, even after delay expiry or Control/locker/helper loss. The native gate
must also fence that coverage against concurrent unlock through the transition.
Already-secured managed suspend must remain usable without opting into automatic
locking: its existing authorization and fresh coverage/fence take that path;
the protective policy is needed only to authorize an otherwise unapproved lock.
Native power permission and foreign inhibitor checks are never skipped.

Native invocation identity proves a sleep lifecycle entry, not a physical
lid-close cause. Root UID, service Actor metadata, caller-supplied event IDs or
`PrepareForSleep` signals alone cannot authenticate the gate. The adapter checks
the actual supervisor's unique root connection, live pre-start helper PID,
invocation, immutable image/configuration, exact arguments and process generation.
No generic privileged command or client-selected native operation is introduced.
Unsupported hibernation/direct-entry paths require explicit native coverage or
denial; no universal guarantee is made against compromised root/kernel bypasses.
Blocking on protection failure may leave a closed laptop running; that condition
must be visible and its battery/heat tradeoff documented, not hidden as success.

The opt-in/revocation is a security-sensitive `LinuraOwnedState` operation, not
an external effect: no privileged executor or synthetic managed transaction is
used to persist consent. Control requires the exact active owner and fresh secure
coverage before and after a distinct one-use native owner-authentication purpose.
Enable and revoke have separate non-retained `auth_self` Polkit actions; neither
can consume manual-lock, unlock or power proof. The trusted presentation names
the login-scoped permission and failure-to-sleep tradeoff, never a generic unlock.

The separate LNRP schema version 1 journal retains the structured owner decision,
exact login/confirmation lock, stable request, approved intent, previous revision,
confirmation lineage and timestamp. A separately provisioned Control signer seals
only the two-second configuration update; its exact historical seal/deadline is
retained and re-verified without reconstructing a writable update. Possession of
the record-integrity key alone cannot fabricate owner approval. Persistence receives its verifier and
uses an independent integrity key. FULL-sync WAL, atomic revision compare-and-swap,
bounded append-only history and an authenticated global chain tip prevent a
historical enable retry or deleted revocation row from becoming current consent.
Every read authenticates schema, identity and complete bounded lineage. Unknown
schemas, write uncertainty, wrong keys, clock rollback/expiry and corruption fail
closed. Full-file/key rollback still requires protected filesystem recovery; no
HMAC or local timestamp is represented as an external anti-rollback oracle.
Migration `0006-s17-protective-lock-settings.json` preserves LNRT and LNRQ state.

Implementation status: canonical sleep identity, narrow protective policy, safety
predicates, native helper-attestation probe, durable settings journal and Control
enrollment/revocation controller are implemented with negative component tests.
Typed Authority1/SDK/CLI enrollment and owner-scoped historical queries are
composed with separately protected keys. Configuration is not a lock/sleep
request; receipts expose no seals, credentials or native protection claim.
Distinct native setting approval mechanisms are implemented; they are not real
PAM qualification. The ordinary runtime still selects the original manual policy.
The separate protective Control entry point now derives its exact request and
service actor internally and uses the same canonical managed lifecycle, registered
risk floor, request journal, durable handoff and independent verification. It
rebuilds fresh canonical native preconditions and re-reads current consent at both
prepare and handoff, without refreshing the original candidate's validity window.
Only this private context may consume the narrow protective policy's `Allow`;
ordinary managed effects still require their purpose-bound human approval.
Retained protective recovery validates the exact journal/transaction anchor and
can only observe completion, even after consent revocation or event completion.
An owner restart cannot substitute a new lock generation into the same request.

The native adapter has an exclusive, non-cloneable received-helper observation
scope. It freshly re-attests the live helper on every registered probe, rejects
resource/invocation substitution and removes availability when the scope ends.
This binding is not a native fact cache, execution grant, inhibitor or coverage
fence. Deterministic lifecycle and adapter tests exercise these boundaries; they
are not native qualification.

Production composition now registers the private `SleepGate1` object on the
same supervised Control connection. Its sole method takes no arguments; actual
received metadata selects the helper to independently re-attest, not a supplied
principal, event or operation. Bus policy denies the private interface and object
path to ordinary clients. Root admission is still not authentication or policy.
The fixed session-executor pre-start mode acquires no executor/control service
name and cannot choose another command. Its failure fails native service start.

Control owns the bounded session inventory, original suspend-inclusive aggregate
deadline, fresh canonical facts and coverage fan-out. Only an uncovered session
enters the same serialized protective managed lifecycle. Already-secure coverage
does not touch consent or that mutation mutex, avoiding a pre-start deadlock with
a managed suspend awaiting native completion. Busy protective mutation denies
continuation instead of waiting behind that suspend or creating a second Control.
Unknown/inactive/unqualified graphical sessions, inventory changes and missing
coverage fail closed; this is not general headless/multiseat support.

The native owner independently fences the exact boot/invocation/lock generation,
kernel suspend counter, unique supervisor and live helper launch. Concurrent
unlock remains denied until fresh native facts prove the exact job ended with no
queued work, or twice-read authenticated unit absence proves it was collected.
A counter change, timeout, Control acknowledgement or missing/failed observation
cannot retire the fence. Retirement only removes transition coverage bookkeeping;
ordinary purpose-bound owner authentication is still required to unlock.
If a fenced job terminates without an independently observed successful suspend
cycle, the protected presentation warns that sleep was not verified and the
computer may still be running, with a ventilation warning. It does not label a
missing observation as success or bypass ordinary unlock authentication. Failures
after received-helper attestation, including those before fencing, also reach
bounded process-retained Control diagnostics. The first-party session surface
polls the no-input `GetOwnNativeSleepGateStatus` query and displays a fixed
failure/ventilation warning; no raw errors or other session identities escape.
The query derives and independently checks the caller's current login, never
queues behind managed execution, and cannot execute, enroll or release a fence.
Restart, missing helper admission and unavailable diagnostics are explicitly not
proof of protection. Even `coverage-fenced` is historical entry bookkeeping, not
a successful-cycle/current-coverage claim. Native failure UX qualification remains
required; component rendering and read-only reporting do not supply that evidence.

The first-party session surface also requests explicit enable/revoke consent.
It secures the session through the ordinary managed lock, then requests the
distinct owner-authenticated setting purpose. Client tracking atomically retains
the setting request, exact confirmed lock and decision before that write; it
never becomes authority. On reload or uncertain response, consent recovery is
history lookup only, never a repeated write, resumed chain or substituted login.
Superseded history stays historical. Native consent interaction qualification is
still required; no model, shell password control or direct executor is introduced.

The production image stages the fixed suspend drop-in and explicitly disables
unqualified hibernate, hybrid-sleep and suspend-then-hibernate modes. It does not
change the development host or builders. This covers the declared native service
route, not root/kernel/direct sysfs bypasses or administrator configuration changes.
Deployment, positive PAM/power/lock recovery, accessibility and adversarial native
qualification remain pending on the pinned Arch/Hyprland substrate. Component
passes and installed assets alone cannot promote S17 from `planned`.

### Managed effects and recovery

Lock, unlock, suspend, logout, reboot and power-off use registered managed
semantics and the canonical eleven-stage lifecycle. No action is downgraded to
experience navigation or transient audio-style execution. Planning, policy,
approval, durable prepare, recovery, audit and reconciliation remain in
unprivileged Control. Native authentication and effectors expose bounded mechanisms
only; neither receives general orchestration or arbitrary privileged commands.

Suspend requires fresh independent secure-coverage evidence before dispatch.
Machine-wide power plans account for other sessions and native inhibitors; the
privileged caller must not silently bypass inhibitors.

An independently verified unlock retains its exact old native lock resource
until Control acknowledges the durable verified commit. No new effect is accepted
while this fence is outstanding. Recovery can therefore re-observe the old
resource after a crash-before-commit instead of losing it to immediate generation
rotation. Only the trusted Control bookkeeping acknowledgement advances the
generation; it neither requests an external effect nor creates permission. The
native authentication binding advances exactly one generation in the same
invocation and epoch, without outstanding confirmation or cooldown reset.

For S21 reuse, `session.power.observe` exposes bounded native availability,
transition flags, inhibitor counts/deadline and other user-session counts for an
exact epoch. `block-weak` is counted as blocking too; native execution must use
`SD_LOGIND_ROOT_CHECK_INHIBITORS` and never skip inhibitors. Availability is not
authorization. `SessionPowerSafetyReview` is non-authorizing and suspend coverage
returns the exact `SessionLockId`; S21 must not create a parallel power authority.

Native `CanSuspend`, `CanReboot` and `CanPowerOff` include permission checks for
their actual querying subject. A root or dedicated authority service's result is
not the session owner's permission snapshot. The direct logind adapter therefore
requires the native bus subject's UID and session epoch to equal the requested
owner/epoch before and after the probe. Canonical power evidence retains that
permission-query scope and Control rejects missing or substituted scope. A
standalone service outside that session must use a separately qualified, explicit
own-session native permission mechanism; it cannot relabel its direct `Can*`
reply or derive privileged execution authority from availability. That production
composition is provided by the distinct native-owner permission and logind
conditions mechanisms below; direct service-owned `Can*` results remain rejected.

The private native owner now exposes only a fixed, read-only power-permission
probe for the original compositor process. It runs as that process's UID, uses
official Polkit with no interaction and no custom details, and re-attests the
daemon, subject generation, Control and actual native session around the probe.
Control must not perform a cross-UID check on vendor login1 actions or change
vendor action ownership to obtain permission. The canonical permission envelope
binds the exact transition, principal and epoch and preserves the conservative
suspend-inclusive sample deadline. It is availability, not authentication proof.
Separate `session.power.conditions.observe` logind evidence carries inhibitors,
other sessions and transition flags without any caller-sensitive `Can*` result.
`SessionPowerSafetyReview::review_with_permission` combines these distinct facts
in Control and retains the earliest expiry; neither provider aggregates the other.
Managed execution and purpose-bound approval now consume these facts through the
same Control lifecycle. Native qualification remains required before acceptance.

Session/boot termination can destroy the request transport before a reply. Retain
durable ambiguity and recover using independent native session/boot facts rather
than declaring acknowledgement successful or blindly replaying. Suspend/resume
needs native transition evidence, not merely a later awake snapshot. Never
reconstruct permission from a digest or reuse proof for a new generation.

`SessionTransitionId` binds the distinct action to the complete `SessionLockId`.
Suspend also binds the pre-dispatch native successful-cycle baseline; other
actions have no interchangeable suspend baseline. The read-only logind transition
adapter emits canonical `ObservationEnvelope` evidence for the current boot and
presence of the original epoch, counting a recycled session name as a different
epoch. It reads the kernel's bounded sysfs suspend counter, rejects debug dry-run
modes and rechecks boot, service owner, epoch and suspend facts. Control's
non-authorizing postcondition review requires exactly one completed native cycle
and fresh secure coverage for the original lock before reporting secure resume.
A changed boot proves only that the original boot ended; it does not prove that
the currently observable machine remains powered off. Missing, changed, skipped,
rolled-back or substituted facts retain ambiguity. These read-only mechanisms
are not by themselves managed power execution, approval or qualification evidence.

The narrow root session executor exposes one fixed transition mechanism. Control
retains all planning, policy, approval, prepare, recovery and reconciliation.
The executor reattests its supervised Control sender and separate default-deny
service authorization, then uses the exact original native session and unique
root logind owner. Suspend/reboot/power-off call only the corresponding fixed
`*WithFlags` method with `SD_LOGIND_ROOT_CHECK_INHIBITORS`; logout terminates the
captured exact session object. Unknown methods fail closed, never falling back
to force, skip-inhibitors, ambient sessions or privileged shell commands.

Before queuing a native action, the executor asks the separately supervised
locker to fence its exact generation. No new unlock or authentication can race
a delayed transition. Suspend retires that fence only after durable Control
commit and the owner's independent exact successful-cycle/secure-coverage check.
Terminating transitions keep it until session/owner termination. An authenticated
definite pre-queue rejection may retire the executor's own undispatched fence,
after fresh identity/transition checks. Generic errors, lost replies, timeouts
and operation-in-progress do not prove rejection; ambiguity retains coverage and
never enables automatic replay. These failure semantics require real native
qualification, including late inhibitors, service loss and delayed operations.

The native lock screen retains only the nonsecret request/target correlation
from the consumed exact transition challenge. While suspend remains fenced it
can ask the same freshly attested Control service for historical status and
observe-only recovery, or acknowledge a committed suspend. Three bounded
automatic attempts are supplemented by explicit Enter-to-recheck interaction;
neither route starts an effect, extends approval or trusts a reply as coverage.
This closes recovery access when the ordinary shell is hidden behind the lock.

First-party shell controls compose two explicit typed requests: secure the own
session, then request the selected power action with native administrator
authentication. Local tracking is saved before each dispatch. Shell reload and
observe-only recovery never continue an abandoned power workflow. The shell has
no password input, native provider, policy or executor handle. Its completion
presentation validates the public managed receipt, without claiming current
power state or effect causation from historical completion.

Retain the approved canonical structured request before durable prepare in a
separate write-once request journal. The existing released transaction schema
remains unchanged; the journal uses its own versioned identity, bounded schema,
independent protected integrity key, FULL-sync WAL and per-record authentication.
The request codec preserves the exact existing desired-request digest framing,
including semantic provenance. Restart reads join the authenticated principal,
request identity and complete material to the validated transaction recovery
anchor. Missing, corrupted, substituted or noncanonical records fail closed.
An orphan record after prepare failure is not approval or authority; historical
retrieval cannot call an executor, mint approval or reprepare. Journal capacity,
write or integrity failure prevents new S17 prepare/dispatch. No historical
material is synthesized from a digest, and no existing v0.6 transaction is
silently migrated to a new recovery contract.

Locker death while secure must not expose the desktop. Provide deterministic
native-console/no-model recovery guidance, separate from normal approval paths.

## Required evidence before acceptance

The protected renderer deliberately uses Qt offscreen rendering and the one
explicitly owned Wayland connection. Qt metadata factories alone cannot establish
native screen-reader discovery. A separate bounded AT-SPI adapter inside the
security owner publishes only fixed first-party presentation metadata through
official GIO APIs. It receives neither an entry/response pointer nor a policy,
Control, authentication or executor handle. Own-runtime Unix routing and kernel
peer UID checks constrain transport, but do not make assistive peers trusted
authorities. Text/value/editable-text/action/geometry interfaces are absent; the
standard writable application ID is unused registry bookkeeping. Metadata loss
never unlocks. Native hardware input remains the separate protected path.
Component metadata/wire tests do not qualify screen-reader discovery or Orca.

Terminating native qualification uses the exact-source runtime contract's
explicit verified-private-disposable-persistent-copy disk mode. Power-off recovery
boots the SAME private copy, never the cacheable substrate. Owned single-link
private files, initial source/copy digests, final substrate immutability and the
two exact pinned launch commands are checked. The ordinary launcher still
defaults to snapshots. Runtime evidence retains its original boot identity;
partial terminating reports bind their distinct original/observed boots and
exact request/transaction/effect. Queue/host/QMP acknowledgements are not product
completion; recovery remains observe-only. These cases are not yet executed.

See [deterministic session recovery](../session-recovery.md) for original-request
lookup and explicit native-console break-glass boundaries. A replacement owner,
shell restart, lock hint or historical consent is not a recovery credential.

- Denial, cross-user/root substitution, generation reuse, stale/unsupported
  observations and operation-class downgrade tests.
- Native authentication success/denial, expired/locked accounts, cancellation,
  bounded attempts, protected-channel failure and proof substitution.
- Multi-output lock acknowledgement, hotplug, locker/shell crash, unavailable
  compositor and absence of unauthenticated unlock.
- Durable handoff, execution denial/loss, restart without replay, independent
  verification and reconciliation for each action.
- Real inhibitor handling and session/boot/resume transition evidence.
- Keyboard/pointer/accessibility and secret-safe visual qualification on the
  pinned Arch/Hyprland runtime, not just fixtures or environment readiness.
- Internal architecture/code/adversarial review and fixes; one clean final
  commit; full exact-head gates; then Codex review and genuinely new fixes;
  merge only when the complete slice is green.

## Current status

The branch composes managed lock/unlock through public `Authority1`, typed
SDK/CLI clients, unprivileged Control, the durable approved-request journal,
canonical prepare/revalidation and the narrow `Executor.Session1` root effector.
The concrete adapter shares each service's actual named connection and freshly
attests native systemd/process/session identities. Neither ordinary retries nor
explicit recovery replay an indeterminate S17 effect. Restart recovery joins the
authenticated retained request to its transaction and uses independent native
postconditions. Durable release acknowledgement is separately idempotent.

The private native runtime owns the actual Wayland connection and gated lock
protocol, protected input, official Polkit/PAM listener and fixed embedded
presentation. Pre-lock confirmation and unlock intent originate from actual
native keyboard input. Public receipts cannot release the lock or substitute
for PAM; bounded lost-reply handling retains the same operation identity and
uses observe-only recovery. Polkit authentication uses the original compositor
subject and daemon-injected caller/subject identity, not assumed forwarding of
custom authorization details. Ordinary exec, late dumpability repair, Qt key
injection, substituted generations and unguarded unlock cleanup are rejected.

Repository-owned deployment installs the secure entry point, fixed font policy,
root-supervised owner service/path and `user@.service` availability dependency.
The root image asset graph includes both executors and authority policies. A
fixed libcap post-transaction hook establishes `cap_ipc_lock=ep` only after final
root ownership. The owner drops its capability before accepting input. Its
service must not implicitly enable `NoNewPrivileges` through a seccomp sandbox
directive: that would disable the distribution's official setuid PAM helper.
Component build, install, contract and denial checks are not proof of deployed
PAM/helper behavior or first-login activation.

The existing exact-source pinned Arch/QEMU lane is being extended with a
separate genuine local PAM/logind Wayland fixture. Hyprland executes directly as
the session leader; a lingering manager or SSH shell cannot stand in for it.
The bootstrap probe requires unchanged production attestation and automatic
owner activation. Its report explicitly excludes authentication qualification,
S17 completion and support promotion. Existing shell-runtime cases remain
required independently. No retained real S17 native qualification exists yet.

Managed suspend/logout/reboot/power-off and first-party session/power controls are
implemented through the same typed authority and durable lifecycle. Native
pointer interaction now has guarded component coverage; assistive-technology,
full adversarial native cases and power transition/recovery qualification remain
unfinished, as does complete native inhibitor lifecycle. Availability observations
and component tests do not qualify those effects. This ADR
therefore remains Proposed and the S17 ledger remains planned until the complete
vertical slice, review and exact-head evidence satisfy the acceptance boundary.

This proposed record and unit tests do not complete S17, qualify a PlatformProfile,
or promote Experimental software to production-supported/Stable.
