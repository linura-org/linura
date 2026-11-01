# Security model

## Trust boundaries

Linura treats experience surfaces, models, local callers, the unprivileged authority runtime, durable Control authority and the root executor as distinct trust zones.

For the v0.6 bounded managed effect, the concrete trust path is:

```text
untrusted content / future model output
                  │
          IntentProposal/advice only
                  │
                  ▼
         local human/client caller
                  │
                  │ system-bus message
                  ▼
       org.linura.Authority1
                  │
      authenticated unique sender
                  │
      human Polkit authorization
                  ▼
       linura-authorityd
       (unprivileged,
    linura-authority identity)
                  │
       linura-control authority
       + durable SQLite/WAL state
                  │
       exact prepared handoff
                  ▼
      separately authorized root
      linura-executor-systemd
                  │
          native systemd API
                  ▼
              systemd
                  │
       fresh independent observation
                  ▼
        verifier / recovery logic
                  │
       commit → audit → reconcile
```

A compromised model provider or future agent is expected to be capable of proposing malicious intent. That must **not** be equivalent to compromise of the authority plane. v0.6 adds no agent mutation authority.

## v0.6 Authority1 caller boundary

The Experimental v0.6 public mutation entry point is:

- service `org.linura.Authority1`;
- path `/org/linura/Authority1`;
- interface `org.linura.Authority1`;
- method `ConvergeSystemdActiveState`.

The transport obtains the unique system-bus sender from the authenticated message metadata. Caller identity is not accepted as a caller-supplied method parameter. A sender must be a canonical D-Bus unique name before it can be translated into an OS principal.

The human authorization action is:

`org.linura.authority.manage-systemd-active-state`

Only after that authorization succeeds does `linura-dbus` construct human provenance for the exact request and delegate semantics inward to the authority runtime. D-Bus authentication and Polkit are therefore transport/OS authorization boundaries; they do not own planning, persistence or recovery policy.

“Local” is never equivalent to trusted. Root/administrator identity also does not mean the caller may bypass the canonical managed path.

## Operation-class boundary

Operation class is security-relevant authority metadata owned by trusted registered semantics and Linura Control. UI, CLI, configuration, agents, imported artifacts and providers cannot assert a weaker class to obtain a lighter execution path.

The only lightweight external-effect path is `TransientExternalEffect`, and it is deliberately constrained to qualified unprivileged effects whose trusted risk does not exceed `UserState` and whose outcome can be independently verified without durable indeterminate recovery. Privileged, system-level, security-sensitive, destructive, ambiguity-sensitive or durable desired-state work is a `ManagedExternalEffect` or unsupported and therefore cannot bypass the canonical durable lifecycle.

Unknown/ambiguous external effect semantics fail closed. See [ADR 0032](adr/0032-classify-operations-before-authority.md) and `contracts/operation-semantics.toml`.

## v0.10 Session1 caller boundary

The Experimental `org.linura.Session1` path is an unprivileged user-session authority surface for only qualified `TransientExternalEffect` operations. It does not inherit administrator semantics from `Authority1` and does not make every local session-bus peer trusted. The transport derives the caller from authenticated D-Bus metadata, derives the service connection's own Unix UID independently from the bus daemon, and rejects the call unless those UIDs are equal. This prevents an accidentally shared or misconfigured bus from using one user's `linurad` and PipeWire session as a cross-user confused deputy.

Session1 carries only narrow typed request material. Operation class, trusted risk, provider/resource binding, policy decision, durable audit reservation, executor dispatch and verification remain owned inward by registered semantics and Linura Control. The session-audio provider adapter invokes only the fixed `/usr/bin/wpexec` executable with a scrubbed process environment; the helper's Lua sandbox exposes no shell or arbitrary filesystem/process execution path. The Arch image and qualification contract pins `/usr/lib/linura/linura-session-audio.lua` to host `root:root` mode `0644` and proves that ownership outside the per-user service namespace. Because systemd filesystem sandboxing may obscure host UID 0 as overflow UID 65534 inside an unprivileged user namespace, `linurad` never treats that overflow identity as proof of root ownership and never executes the installed pathname directly. It opens the installed helper read-only with nonblocking, no-follow descriptor semantics before validating descriptor type/identity, then requires the regular single-link, non-writable helper bytes to match the exact helper compiled into `linurad`; it materializes those trusted bytes into a sealed anonymous file, verifies the write/grow/shrink/seal locks, and gives `wpexec` that immutable image through its standard input as `/dev/fd/0`. This keeps `ProtectSystem=strict` while eliminating both ambiguous-owner trust and the verify-then-reopen substitution race.

The first-party Control Center and Quick Settings surfaces are clients of this same boundary, not additional trust zones with mutation authority. They receive authoritative observation through the compiled ShellBridge and can request only the registered session-volume operation; neither QML surface receives provider handles, raw D-Bus mutation construction, operation-class/risk selection or executor authority. The exact-source shell development gate therefore qualifies the client-to-Session1 composition with real PipeWire/WirePlumber, exact-node verification and durable audit evidence while retaining Q11 as the separate real-workstation interaction/visual support gate.

The audio helper keeps its connection alive until a PipeWire synchronization
round trip completes after the identity-bound mixer update. A synchronization
error cannot produce the dispatch acknowledgement. This drains the asynchronous
request before process exit; it grants no additional authority and does not
replace Control's independent postcondition observation or existing process
deadline. Transport loss still fails closed and never triggers an effect retry.

## Human approval is not executor authority

The original caller's Polkit decision authorizes continuation of the exact Authority1 request. It is not a bearer token and is never forwarded as authority to the root executor.

The supported managed executor action is separately default-deny. Product policy grants the bounded managed executor path only to the dedicated `linura-authority` service identity. Ordinary users and administrators therefore cannot use `org.linura.Executor.Systemd1` as a shortcut around Control.

This separation prevents an OS approval check from collapsing:

- request validation;
- deterministic planning;
- policy/approval binding;
- durable prepare;
- pre-dispatch revalidation;
- recovery state;
- independent verification;
- verified commit and reconciliation.

Native session owner discovery, compound observation/arm/consume RPC and post-reply
identity revalidation share the original two-second probe deadline. `ObserveLock`
performs fresh session/peer attestation and an independent compositor sample;
like the arm/consume handshake, it may use only the remainder after discovery.
Primitive identity/mechanism calls retain their 500 ms cap. Reply arrival never
starts a new budget or freshens a proof. A late reply or failed revalidation fails
closed, and this allocation changes neither the human-interaction deadline nor executor
authority.

The S21 prepared display handoff uses that same separation. Only the independently
attested Control service can reach the root session executor's fixed
`apply-display-layout` action; ordinary users and root callers remain denied by
the system-bus policy. Service authorization cannot replace Control's sealed
managed effect, canonical complete intent or validated execution binding. The
root adapter preserves one original owner/boot/sample through strict native
validation, its single private owner call and final identity revalidation, all
within the original two-second probe clock. The owner rechecks the raw sample
digest, original boot timestamp, complete baseline, output frames and native
deadline before reserving one compositor apply. Another owner/connection cannot
adopt the attempt, and timeout, denied/unknown phase or a lost reply cannot cause
redelivery or assert verified success. The outer Control-to-root mechanism call
has its separate fixed ten-second cap for service policy and native handoff;
it never freshens native facts or extends the original confirmation deadline.

Production display status derives its original dispatch digest and deadline
from Control-validated durable history. Its native query is read-only, never a
permit or continuation, and reconciliation cannot apply/confirm/revert. Public
begin/confirm/revert remain unsupported until protected decisions, durable
compositor-loss restoration and required native qualification are complete.

The private Apply review handshake accepts the complete canonical material and
original principal/request/plan/digests from the supervised Control connection.
It shows bounded first-party review pages, requires a fresh native action and
presentation per revision, and presents fixed administrator/PAM metadata before
accepting input. Control owns bounded readiness polling; the original wall and
BOOTTIME deadlines cannot be renewed by polling, authentication or suspend.
The fixed Apply Polkit action uses `auth_admin`, never a retained grant. Its
positive result must still be followed by consumption of the exact native proof.
Expired, denied, replaced-owner and uncertain/late calls retire only their exact
scope. A separate scoped cancellation cannot cancel a newer conversation.

The owner's consumed Apply receipt remains process-local and one-use. Root's
separately admitted prepared dispatch must match its complete material, original
transaction and still-live native frame/input generations before redemption.
No client digest or positive Polkit reply is an executor credential. This private
composition is not production display support: continuous protected modeset,
Keep/Revert, replacement restoration and native adversarial acceptance remain
required before the public display effect can be enabled.

The private native apply request additionally binds the actual consumed protected
interaction resource on the same re-attested connection. The compositor retains
its opaque/input fence independently of protocol resources, separating the
expired human proof from the safety lifetime of an already started effect.
Only its reserved apply/restore stack permits expected geometry changes; static
output/rule/session/input drift cannot become new authority. Failure or owner
loss cancels continuation and reserves original compensation. Native restoration
requires original ownership, fresh baseline geometry, fresh per-enabled-output
hardware frames and accepted disable submissions before releasing protection.
Keep and explicit Revert consume a fresh purpose-bound scope within both original
attempt deadlines; the old Apply epoch cannot serve as that decision. The
Control-to-owner decision adapter preserves the sealed original dispatch,
principal, request, complete material and absolute deadline. A new native
Keep/Revert review consumes fresh physical input and per-output presentation;
the retained Apply receipt or positive Polkit result cannot substitute for it.
The root continuation must redeem this exact one-use owner receipt in addition
to its durable Control authorization. Scoped cancellation cannot retire an
unrelated conversation. Replacement restoration, S17/power preemption and native
acceptance remain incomplete, and public display mutation stays disabled.

The owner's native peer/session/unit inspectors queue at most 32 fixed
`Properties.Get` reads per interface before waiting. Each pending call retains
the existing 500 ms cap from admission, and all batches share their caller's
original probe clock (two seconds for peer/sleep probes, four for the existing
session inspector). Every reply is checked before a complete map can be used;
missing, malformed, substituted or late replies discard the entire batch.
Initial and revalidation batches are distinct fresh reads, never a cache.
All prior UID/PID, invocation, launch, session, immutable-asset, owner-continuity
and final deadline checks remain. Batching removes serial round trips from the
owner's event loop; it grants no observation authority or additional time.

Synchronous metadata inspection must not starve an already admitted native lock.
The immutable runtime binds a progress callback after the owned Wayland backend
and protocol are initialized. Between bounded metadata calls and batch waits,
it drains only already available events on that same attested connection.
Progress time consumes the existing probe clock; each remote call keeps its
original cap, and expired probes still fail without returning a partial map.
Nested native callbacks or painting skip a recursive pump. No Qt event loop,
D-Bus method dispatch, timer delivery, cache or effect retry is introduced.
Only the existing prepared gate sends lock/unlock effects; native acknowledgements
remain mechanism facts, with every peer/session/identity/scope/compositor and
final deadline check retained before accepting a result. Authentication's own
peer inspector uses the same bounded progress hook. A queued Qt callback is not
executed by this path, and a stalled acquisition still exits after five seconds.

Native owner discovery may acquire at most two complete connection snapshots
inside that same probe, with at most 256 listed names across both snapshots.
An exact typed missing-connection reply discards the entire snapshot; it never
turns the missing row into negative evidence. A fresh snapshot must retain the
original supervised UID, PID and invocation, and final supervision/credentials
are revalidated before use. Persistent churn, exhaustion, ambiguity, replacement,
malformed credentials and unknown/denied/timed-out introspection fail closed.
Only typed absence of the private object/interface/method excludes a separate
GLib connection from endpoint selection. This is native snapshot consistency,
not a second observation authority, cached fact or control-plane retry policy.

Post-dispatch lock and suspend-coverage verification distinguish a known native
acquisition/release transition from unavailable or inconsistent evidence. The owner first authenticates
Control and samples the compositor independently; it drains already available
Wayland events before comparing native acknowledgements. Only consistent in-flight
mechanism states produce the fixed typed pending reply. Control revalidates the
same owner and boot within the original probe deadline, then uses its existing
bounded verification loop. Pending creates no observation envelope or secure/unlocked
boolean, cannot authorize mutation, and cannot commit a postcondition. Other errors
still fail immediately. Native acquisition/release watchdogs remain unchanged.
Suspend still requires exactly one independently observed kernel cycle and the
same fresh secure lock generation. Pending coverage cannot substitute for either
fact; the existing canonical review remains inconclusive or unsatisfied until
both are proved, within Control's unchanged bounded verification loop.
The exact native `PreparingForSleep=true` fact is likewise inconclusive, never
completion: logind may acknowledge admission before the machine sleeps. Missing
or malformed preparation/counter facts and debug suspend modes remain errors.
Only fresh `PreparingForSleep=false`, exactly one completed kernel cycle and
the same verified secure generation can satisfy suspend. No additional effect
dispatch, observation budget or retry window follows from this classification.

The fixed pre-sleep helper starts under the root-owned native unit, then sets
`no_new_privs` and executes its one immutable image again with the same PID and
arguments as the fixed `linura-authority` UID and primary GID. It clears the
environment and supplementary groups before opening a bus connection, and checks
all real/effective/saved/filesystem IDs, empty capability sets and the privilege
gain restriction. The local account comes from one bounded descriptor-validated
`/etc/passwd` snapshot, never caller input or NSS.

This makes the live executable inspectable by unprivileged Control while
preserving the root-owned image inode, exact arguments, process generation,
systemd ControlPID, invocation, immutable configuration and live pre-kernel
phase checks. Neither root UID nor the service account alone qualifies an entry.
The native unit's main sleep operation retains its original root execution;
only the helper declines privilege. The helper carries no secret or reusable
executor authority. Security-owner and PAM protection remain separate boundaries.

The first independently verified release consumes its event once. Reconciliation
may reread only that same retained Released generation after fresh Control-peer,
compositor, coverage and sleep-fence checks. Ready/unlocked alone is insufficient;
replaced identities, relock and durable generation rotation invalidate that read.
It grants no dispatch authority and never repeats a release or rotates a generation.

Control and the native owner both authenticate the pinned Polkit 127 daemon as
the local `polkitd` account supervised by root-owned systemd. UID 0 is not its
daemon identity, and knowing the account UID is insufficient. The native adapter
requires the exact immutable unit fragment and executable, fixed live argv,
matching bus/kernel PID, nonzero invocation and absence of drop-ins. Two fresh
snapshots and service-owner rechecks share one original two-second probe budget;
the complete daemon identity must also survive the human interaction. A single
bounded local-account reader serves the fixed Control and Polkit identities. It
rejects root, aliases, duplicate/noncanonical rows, mutable/link-substituted files
and excessive input without consulting NSS or starting a process. These checks
establish a transport peer only; canonical approval and native proof consumption
remain independently required.

Protected keyboard delivery checks its actual configured Wayland surface and
current complete lock coverage on each fresh press. Focus can arrive before the
coverage acknowledgement, so an enter-time snapshot cannot permanently disable
later guarded input. Coverage changes synchronize focus before the first key,
including the protected accessibility projection. Focus/layout/device loss still wipes and cancels; neither
held keys nor generic Qt events can restore or submit native authentication.
Unchanged positive focus is not reannounced for each key; every loss still
cancels, including a prompt that has not yet received its first focused press.
Retiring consent refreshes presentation after both authentication and runtime
scopes are cleared. A denial returns to the locked retry presentation only when
the original native approval cooldown has reached Idle with no live conversation
or scope; presentation never resets that cooldown, approves input or unlocks.

Native transport errors expose fixed source-owned failure classes and mechanism
stages, never remote error names, messages, request bodies or addresses. Unknown
errors remain failures. Disposable qualification may retain bounded locker exit
facts only as failure diagnostics, independently of accepted native evidence.
Supervisor refusals distinguish only fixed process/user/unit/state/invocation/
launch/asset stages. No native field value enters the error. Failure-only owner
diagnostics compare the current invocation with the requested lock and discard
both identifiers. A separate three-second current-boot query reads at most 64
journal entries for that validated owner unit under the existing 16 KiB output
bound, selecting process exit fields and fixed watchdog labels only. Decoding
retains only known exit codes, numeric statuses and closed timeout stages.
Watchdogs make one allocation-free, nonblocking send to systemd's stderr socket
before their original exit 71. A full, closed or non-socket stderr cannot block,
allocate, retry, reset a deadline or invoke cleanup. Existing watchdog durations,
admission, cancellation and fail-closed exit remain unchanged.
The same nonblocking channel records only six closed Wayland milestones:
request marshalled, first lock surface configured, first frame flushed,
all currently announced lock surfaces flushed, actual locked acknowledgement
and release acknowledgement. At most one of each is emitted per acquisition.
These contain no input, identifiers, dimensions or
payload, and are discarded unless failure diagnostics are collected. A first
surface/frame is not proof of all-output coverage. Ordered milestones explain
where acquisition stopped; no log line changes admission, a deadline or native
state, and none can satisfy verification or recovery.
Failure-only compositor context uses fixed three-second read-only queries under
the disposable account with an explicit first-live-instance selector; it does not
depend on inheriting a compositor environment through SSH. Bounded parsers retain
only aggregate output counts and
closed upstream protocol/render-failure labels. Raw logs, names, identifiers and
dimensions are discarded. Ambient compositor discovery is not attestation of
the original invocation; these diagnostics cannot supply acceptance or recovery.
A replacement owner, successful native exit or empty
journal never repairs the original operation or constitutes acceptance evidence.
Sleep-gate denials carry only fixed stages and reasons in the private denial
reply and the helper's existing failure journal entry. Unknown errors map to `unclassified`; sender,
provider errors and response data are never copied into that diagnostic.
The native adapter accepts only the complete closed grammar on an access-denied
reply to the fixed private helper method, after the existing reply-size check.
Every such reply remains a hard failure; other error text stays redacted.
After a failed suspend submission, disposable qualification may read at most
64 current-boot journal entries from the fixed sleep/Control units and the
disposable fixture owner's fixed unit under
its existing shared 16 KiB output cap and a separate three-second diagnostic
budget. Only recognized failure categories leave the guest; raw journal text
is discarded. This context is not bound to an individual invocation and cannot
serve as execution, verification, recovery or support evidence. Diagnostic
failure preserves the original failed submission and cleanup.
The owner's fence refusal emits only immutable rejection labels through its
existing fixed-label diagnostic mechanism. Optional unit-probe diagnostics are
enabled only for this fence call; recovery remains quiet. They never print
native properties, peer identity, error text or authentication data, and do not
change admission, freshness, deadlines, coverage fencing or failure results.
The native unit probe sends every lookup/property request to the root-attested
supervisor's unique connection on the fixed, kernel-authenticated system bus.
The bus's requested-reply routing correlates the response to that destination;
Newer Qt deliberately returns an empty `QDBusMessage::service()` for reply/error
messages; older Qt exposes the sender, which must still match the pinned peer.
That accessor is therefore not portable sender evidence. Neither a replaceable
well-known destination nor an invented sender value substitutes for this binding.
Only a typed object-path reply or the exact native `NoSuchUnit` error can enter
lookup decoding. Absence requires a second identical error and unchanged owner;
present units require two matching complete snapshots and unchanged owner.
Local/broker failures, denial, timeout, malformed replies and replacement remain
refusals within the original shared two-second budget. Diagnostics retain only
closed error classes, never remote messages or a purported reply-sender category.
An independent two-second read of the fixed suspend unit's active/substate,
result and recorded main-PID presence uses separate property selectors and
the same output cap. Missing, duplicate, malformed or unknown fields produce
only an unavailable category. Even a native `Result=success` is failure context
here and cannot replace the failed managed verification or qualify a cycle.

## Privileged executor rules

Every privileged executor must:

- own one narrow effect domain;
- authenticate its operating-system caller at the transport boundary;
- independently authorize that caller for the exact executor action;
- validate identifiers, arguments and deterministic bindings again at the privilege boundary;
- receive only the bounded effect/correlation material required for dispatch;
- perform no general orchestration, planning, policy evaluation or natural-language interpretation;
- expose no arbitrary command/shell endpoint;
- expose no generic native-service proxy;
- use native system APIs where available;
- classify dispatch outcome conservatively;
- never claim that dispatch acknowledgement proves final machine state;
- remain separately sandboxed/hardened and security-reviewed.

For v0.6 the product effect is limited to canonical `linura-managed-*.service` units and exactly the desired states `active` or `inactive`, implemented with native systemd `StartUnit(..., "replace")` / `StopUnit(..., "replace")` calls.

The executor protocol may contain qualification/history operations in addition to the bounded product operation, but that does not widen the public Authority1 capability. Production D-Bus/Polkit policy remains part of the security boundary.

## IDs and digests are not capabilities

Operation IDs, request/transaction IDs, generation numbers and request/plan/effect/dispatch digests provide deterministic identity, correlation and anti-substitution evidence. Possession of those values does **not** grant execution authority.

For v0.6 a stable `operation_id` maps to `request:v06:<operation_id>`. The exact canonical request is independently checked against its durable `request_digest`.

- exact retry reuses the durable transaction;
- changed content under the same operation ID fails closed with `RecoveryRequestMismatch`;
- a changed request does not inherit prior approval or produce a second durable transaction for the same stable operation identity.

## Durable handoff and crash ambiguity

External execution is treated as potentially ambiguous. Before dispatch, Control durably crosses the prepared handoff boundary. If execution or transport becomes uncertain after that point, the transaction remains `Indeterminate`; restart must not reconstruct dispatch permission or blindly issue the effect again.

One-shot authority is process-local and exact-bound. Durable state is evidence/recovery state, not a serializable executor credential.

Recovery must acquire fresh authoritative evidence. `FreshRecoveryApproval` is minted only after constructing the exact fresh recovery candidate and is bound to that same candidate, preventing approval time-of-check/time-of-use substitution. Conflicting recovery evidence blocks progress instead of overwriting ambiguity.

## Verification is independent from execution

Executor acknowledgement proves at most dispatch classification. It is not authoritative post-state.

The v0.6 authority runtime composes a fresh native-systemd observation path for verification. The verifier consumes expected postcondition plus canonical observation; it does not consume the executor receipt as proof of success.

A transaction cannot reach durable `Committed` merely because the root service returned success. The intended postcondition must be independently observed/verified and the exact durable recovery/commit invariants must succeed first.

Post-commit reconciliation performs another independent check and deterministic planning to prove convergence (`NoChange`). It does not replay the original effect.

## Agent/model rules

- model output is untrusted data;
- agents emit typed `IntentProposal`/advice, not executable code;
- agent context is least-privilege and minimized;
- secrets use references/handles and are excluded from general prompts by default;
- prompt injection from web/files/repository content cannot create authority;
- tool/model/provider identity does not substitute for OS actor identity;
- sensitive mutations require Control policy/approval regardless of model confidence;
- agents never receive privileged executor handles;
- offline/no-model behavior remains a required security/recovery path.

`contracts/components.toml` additionally marks agent components as proposal-only future surfaces until their roadmap milestones. Workspace presence is not authority. See [ADR 0025](adr/0025-component-maturity-and-milestone-activation.md).

## State integrity

The v0.6 authority path uses durable SQLite/WAL transaction state with integrity/recovery checks. Durable storage is authoritative for Linura's control records, not for current Linux machine truth.

Observed state is always re-derived from authoritative Linux providers when truth matters for planning, execution eligibility, verification or recovery. Storage corruption, write uncertainty, stale evidence and conflicting machine state fail closed.

Broader intent/graph/provenance persistence remains subject to its own milestone/migration requirements; v0.6 does not claim every future persistence domain is complete merely because the authority transaction store is durable.

## D-Bus policy is part of the security boundary

The canonical interface XML, system-bus policy, Polkit actions/rules, runtime introspection and stability registry must agree.

v0.6 explicitly distinguishes:

- `Authority1`: public Experimental managed-authority entry point for the one bounded effect;
- `Executor.Systemd1`: privileged internal/qualification executor service, not a public general-purpose mutation authority;
- `Control1`: existing non-privileged planning/query lineage.

The obsolete broad root Polkit policy outside the canonical packaging path is removed; production authorization comes from the bounded packaged policy/rules reviewed with the corresponding service identity.

## v0.5 historical boundary and v0.6 integration

v0.5 qualified an isolated systemd executor and pure verifier without wiring product mutation authority. That release claim remains historically true. See [ADR 0021](adr/0021-v0.5-isolated-executor-verifier-qualification.md).

v0.6 is the first candidate to integrate the complete eleven-stage lifecycle for one bounded Experimental effect. The exact process, identity, approval, recovery and non-goal decisions are recorded in [ADR 0026](adr/0026-bounded-v0.6-managed-mutation-authority.md).

This integration does **not** convert v0.5's qualification-only user/rules or restart fixture namespace into production authority.

## Private qualification-evidence publication boundary

Private R2 evidence archival is separate from Linura runtime authority, deterministic
qualification and release support promotion. Selected successful exact-main Level A
evidence is admitted only after independent GitHub run/attempt verification,
complete canonical case and recording validation, explicit operator selection and
a recorded `qualification-archive` environment review. A separate credential-free admission job probes untrusted video, snapshots all verified files
and binds the canonical receipt to a trusted GitHub job-output digest. The distinct
protected publishing job receives bucket-scoped R2 credentials and checks the
admission receipt and exact bytes without invoking media decoders. Publication
reruns cannot reuse run-wide approval history and must use a fresh dispatch and
approval. Existing indexes with malformed original approval provenance are rejected.

The private index is a remote completion/inventory record, **not** an independent
signature, WORM guarantee, access authorization, proof that objects remain present
or a substitute for qualification. A compromised trusted publisher or R2
Read & Write token can potentially modify or delete evidence; digest checks do
not detect secrets in video frames or logs. Level B, Level C and release
publication remain disabled pending their own reviewed privacy/authority paths.
External GitHub environment and R2 access/lifecycle settings plus the first
approved real upload must be verified before operational activation. See
[ADR 0034](adr/0034-private-qualification-evidence-publication.md),
[ADR 0035](adr/0035-isolate-media-admission-from-r2-credentials.md) and the
[publication threat model](qualification/evidence-publication-threat-model.md).

## Remote/fleet security

A future fleet gateway is a separate process/service with mutual authentication, explicit enrollment, revocation, replay resistance, scoped device identity, staged rollout and its own threat model. No remote listener is added to `linurad` or `linura-authorityd` as a shortcut.

v0.6 makes no remote/fleet, supported-distribution or supported-hardware security claim.

## Security qualification requirement

The v0.6 claim requires both deterministic fault/recovery tests and a disposable real-system qualification using systemd, system D-Bus, Polkit and SQLite/WAL. Required negative evidence includes ordinary/direct-executor denial, wrong namespace/state rejection, request substitution rejection, stale/failed verification, executor loss/ambiguity, crash/restart without blind replay and conflict blocking.

Trusted Release Proof must rerun the exact-source v0.6 qualification before sealed release build/promotion. A green unit suite alone is insufficient security evidence for the managed effect.
