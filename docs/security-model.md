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
unrelated conversation. Replacement restoration and native acceptance remain
incomplete, and public display mutation stays disabled.

Native output identity now includes the actual retained Aquamarine DRM device
major/minor and connector object ID in its source-versioned identity witness.
Changing that binding invalidates the native output generation. The private
receiver rejects malformed, duplicated and unsupported bindings; non-DRM outputs
remain observable without mutation checkpoint qualification. These point-in-time
facts do not prove continuity after replacement or grant a restoration effect.
Independent retained kernel observation and durable restoration remain required.

The owner accepts a fresh native rule digest only after bounded canonical `LNRL:2`
decoding. Its source kind distinguishes an actual live wlr client from a retained
restored projection; the latter binds its original checkpoint hash and cannot
claim to recreate the client. Stored `LNRL:1` bytes retain their original live-client
meaning and exact encoding and cannot be advertised/reserved as fresh state. The actual selection point captures the selected index and ordered
selectors before wlr applies. Distinct underlying/effective `LNDR:2` records
and explicit wlr presence, owned-field mask and original integer refresh prevent
equal resolved geometry or lossy float projection from hiding source drift.
The preimage must reconstruct all owned display fields exactly,
including automatic placement/scaling and the full custom modeline, without
float rounding, integer truncation or alternate encodings. Reconstruction copies
those fields into the current native rule only if its resolved selector still
matches the original lineage; it preserves the current rule list/precedence and
unrelated settings. In-process rollback compares actual selected owned sources
and changes only the Linura overlay; it preserves unrelated selector-list edits.
Prepared native comparison binds rule, output-identity and ownership witnesses,
even when numeric geometry is unchanged. Schema-1 preimages containing older
`LNDR:1` or `LNDR:2` remain validated historical bytes, without migration,
admission to new reservations or complete restoration-source projection.
New private preimages use schema 2 without increasing existing size bounds.
This codec is not a store or an execution boundary:
durable preimage retention, authenticated continuity and independently verified
restoration are still required before any replacement compositor may use it.

Only the supervised root executor receives original native rule preimages in
its prepared observation. Rust matches their complete output/ownership/kernel
scope and checks their canonical representation independently. The executor transfers that same prepared preimage once to independent display
protection, which publishes an exclusive immutable private checkpoint and requires both file and
directory sync before it can call native apply. Root-owned safe ancestors,
0700/0600 scope, no-follow descriptor-relative access, serialized admission,
single-link regular files, bounded history and content digests prevent ordinary
callers from substituting records. Torn, corrupt, duplicate, unavailable or full
storage refuses dispatch without automatic cleanup. Persistence never renews
the original probe or confirmation clocks; both are revalidated before native
handoff. These are historical preimages, not policy, approval or executable
recovery authority. Replacement continuity, restoration and independent terminal
verification remain incomplete; public display mutations remain unavailable.

The pinned compositor starts behind a separate presentation fence, before any
ordinary frame or input. A one-use original descriptor from independent display
protection can admit ordinary startup only after the supervised protected owner
and protection service bind the actual native process, installed image, source
integration, active login epoch and seat. Startup publication shares the original
checkpoint admission mutex; pending subscriptions, retained in-memory witnesses
(including invalid/lost ones), or retained/unknown on-disk history keep it fenced.
An empty directory cannot override a retained original witness after record loss;
busy or poisoned memory also refuses admission. Only after all three sources are
clear may the service close ordinary startup leases whose original pidfds prove
process exit. It preserves current/live/unknown peers and every recovery lease,
checks invocation conflicts before retirement and keeps the same admission bound.
This retires no checkpoint, restoration reservation, witness or semantic intent.
Native rendering/scanout, focus, cursor and input paths enforce that fence, drain
suppressed held input and permanently refuse a lost or replaced lease. The new
private startup endpoint has one bounded authentication worker, independently
authenticates the supervised owner and grants no restoration or executor
permission. It neither acquires nor releases S17 state. Component checks do not
qualify the real first-frame and crash matrix; public mutations stay disabled.

First ordinary frames have a separate native tracker kind from protected owner
review/PAM content and opaque safety frames. Neither protected kind can satisfy
the ordinary-frame comparison. A comparison receipt retains the original wall
and BOOTTIME deadlines, including after read-only reconciliation.
Before the original finalization's native grant spend, Control additionally
revalidates the original canonical purpose, registered operation, current
policy/risk, exact durable binding and still-valid administrator approval. This
bounded process-local refusal material is removed before spend; neither restart
nor retained Root/Control records reconstructs it. These checks do not enable
the physical handoff, retire protection or certify terminal completion.

The startup RPC is addressed to the original independently attested unique bus
owner, never its replaceable well-known name. Qt 6.11 intentionally returns an
empty `QDBusMessage::service()` for reply messages; an exposed sender must match,
but absence of that API field is not proof of a substituted response. System-bus
requested-reply restrictions bind the response to the pending call. Independently,
the returned Unix socket must have kernel `SO_PEERCRED` for the original root
service MainPID. Exact reply signature/types, fresh service/session revalidation
and native single-use lease admission remain mandatory. A malformed response,
wrong socket/process, disappeared service or lost response fails closed; an
already consumed admission cannot be retried by restarting the owner.

The pinned compositor's package transaction uses the fixed
`linura-hyprland-install-secure-entry` helper to install mode 2755 with the
dedicated local `linura-display-entry` group. The group owns no Linura resources;
aliases, explicit members and primary-account membership are refused. This is
an exec-time loader boundary, not runtime execution authority. The kernel must
set `AT_SECURE=1` before constructors; the root guard independently reads that
marker from the admitted process's bounded auxiliary vector and requires the
installed file's exact dedicated group and setgid mode. A `nosuid` mount,
no-new-privileges suppression or an ordinary unqualified installation cannot
satisfy startup admission. The build omits build-directory library search paths.

The executable's bounded ELF preinit hook removes inherited environment keys
outside a fixed allowlist before ordinary dependency and C++ constructors. This
is separate from secure dynamic-loader entry: pinned libglvnd 1.7.0 checks current
UID/GID equality for EGL vendor overrides, so dropping the temporary group would
otherwise re-enable caller-selected vendor libraries. Software-renderer and
logind-backend flags accept only fixed values. Duplicate retained keys, malformed
entries or count/size exhaustion refuse startup before partially rewriting envp.
Legacy `env`/`envd` directives are refused to prevent later reintroduction of those
native-code selectors; application-specific variables belong to separately
launched application environments. This restriction changes the Experimental
pinned integration coherently; it is not a universal qualification of every
library/configuration loader. Constructor ordering, the pinned dependency graph
and actual native graphics startup still require adversarial qualification.

At the first statement of main, the native entry point requires a single thread,
drops real/effective/saved groups to the original login group, disables
dumpability and clears ambient, permitted, effective and inheritable
capabilities. A constructor-created thread is refused because `capset` cannot
clear another thread's retained capabilities. Information-only CLI exits remain
available to unprivileged builders; configuration and runtime require secure
entry. Native plugin loading is permanently refused, as is in-process Lua
configuration, whose standard libraries could otherwise execute native code.
The pinned integration retains its legacy Hyprlang configuration path.
Before changing groups it requires kernel `fs.suid_dumpable` policy 0 or 2;
policy 1 would reset dumpability during that transition and expose an attach
window before a later explicit reset. Unknown/unreadable policy refuses the
group drop. No code changes that host policy. See the kernel's
[credential-change dumpability rules](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html).
Removing PAM's local-seat ambient capabilities must
not leave the compositor inspectable by another same-UID process. It does not
set inherited no-new-privileges on applications or change host ptrace policy.
The capability-free protected owner hashes only the immutable installed image
as comparison data. After independent supervisor, logind, seat, leader and
original-pidfd checks, the root protection service opens that admitted leader's
actual executable and requires it to match the descriptor-walked immutable
`/usr/bin/Hyprland` inode and complete bounded SHA-256 bytes. It retains the image
descriptor and rechecks metadata and the actual executable throughout the
startup lease. Reauthentication shares the original admission deadline and
does not hash the image again. PID reuse, exec, mutation, unlink, missing access
or ambiguous facts refuse admission. Only this service has `CAP_SYS_PTRACE`,
bounded to its fixed executable inspection; no method accepts an arbitrary
path, memory address, ptrace operation or process target. The mutating executor
and protected owner remain capability-free. Compromise of this root service is
therefore a high-consequence boundary; this capability is not a caller grant.
Native qualification separately checks the kernel marker, dropped groups and
capabilities, unchanged application no-new-privileges behavior, a working loader
canary positive control and its rejection by the actual compositor, and
same-account process-access denial with guest Yama restrictions removed.
Implemented checks are not executed evidence: native startup, plugin/Lua denial
and the complete adversarial first-frame matrix still require qualification.

Independent display protection starts a read-only kernel subscription before
native sampling and binds it to that sample's actual DRM tuples. Real sysfs/kernfs descriptors and the
same kernel multicast socket remain outside executor/compositor memory. Every later check
consumes a bounded stream and compares the kernel sequence watermark; gaps,
overflows, truncation, bad source/data, DRM changes, changes to a bound bus/driver
ancestor and failed or changed retained attributes irreversibly poison it. It
never reopens an attribute after loss to discover a replacement. Original
continuation checks this witness before and after native dispatch. Protection-service
restart loses continuity and cannot reconstruct it from historical records.
The service adds AF_NETLINK reception while retaining PrivateDevices, read-only
kernel protections, no privilege acquisition and no IP socket
families. There are no DRM device opens, ioctls, master acquisition, sysfs writes
or privileged commands. This witness supplies comparison evidence only; it does
not authorize replacement startup/restoration or supply protected frame proof.
Real kernel hotplug/reset and modeset acceptance remain required.

The same fixed prepared-checkpoint callback acquires a separate original logind
`sleep:shutdown`/`block` inhibitor and retains its opaque FIFO in the independent
protection service. Executor/compositor death cannot release this descriptor. Acquisition and
later checks bind the exact current root logind owner and boot, observe only the
two fixed preparation properties, and require a live CLOEXEC FIFO with no input,
hangup or error. Failure permanently poisons the lease; no retry, replacement
owner or re-open can revive it. Power probes share bounded transport deadlines
and consume the original display sample/confirmation clocks; kernel evidence is
rechecked afterward. This protection neither requests a power transition nor
bypasses power policy/inhibitors. It adds no new credential or public method.
Retained kernel success/failure suspend counters bracket the original sample
and subsequent checks; a completed or failed sleep cannot be hidden by current
logind properties returning to false. Missing/reset/changed counters refuse.
Only qualified terminal recovery may release retained protection; replacement
startup supervision, terminal cleanup and real power-race qualification remain
incomplete, and public display mutation remains disabled.

The private `DisplayProtection1` peer is separately supervised with exact immutable
unit, MainPID, image, fixed `--display-protection` argv and bus-owner attestation.
`Begin`, `Reserve` and `Verify` accept only the current supervised executor,
including for root callers. They start an original subscription, consume it for
the same executor within the original two-second window and persist the
historical checkpoint, or verify retained original objects and stored payload
hash. `NativeStartup` separately authenticates the exact supervised native
owner; `ReadOriginal` and `ReadFinalization` require the exact supervised Control
process and share one bounded read worker. `ReserveRestoration` has the separate
prepared handoff boundary below.
It cannot write outputs, mint human approval, orchestrate recovery or reconstruct
lost protection. [ADR 0046](adr/0046-independent-original-display-protection.md)
records the boundary; public mutation activation still requires complete native
recovery qualification.

The private restoration endpoint producer requires the exact supervised
executor after a fresh Control prepare. It compares complete schema-2 original
source material, retains the original kernel/power witnesses and requires the
old compositor's actual pidfd exit plus the replacement's healthy fenced lease.
Exclusive typed reservation publication and both syncs precede endpoint creation.
A lost reply, malformed history, incomplete transfer or another binding for the
same unresolved original cannot renew admission. The bounded stream ends with a
marker only after fresh witness checks. `LNRG:2` projects only the same strictly
validated original preimage and exact canonical output bijection; durable
checkpoint/reservation bytes retain their original meaning. The native recipient
authenticates its kernel peer against its continuously held original Root lease,
bounds decoding and the original BOOTTIME transfer budget, and obtains fresh
strictly increasing witness acknowledgements on that endpoint. Its completed
transfer is not a reusable file credential. Root retains bounded worker slots;
idle loss, malformed/replayed/slow probes and witness loss close the endpoint.
The compositor's input/render lifetime checks remain nonblocking.

Before disclosing that endpoint, Root enables `SO_PASSCRED` on its receiving
side. Each probe fragment requires exactly one kernel `SCM_CREDENTIALS` record
matching the retained replacement's actual PID and session UID, followed by its
original pidfd/start-time and immutable-image checks. Socket-pair `SO_PEERCRED`
identifies its creator and cannot identify a process receiving a forwarded
descriptor. Ancillary truncation, extra controls/descriptors, missing credentials
or a foreign sender refuse acknowledgement; all received descriptors are closed.
One absolute partial-probe budget includes sender and witness checks; fragments
cannot renew it. These messages remain read-only continuity evidence and confer
no terminal release, cleanup or execution authority.

Control's separate original-restoration handoff reloads authenticated original
history, re-observes contributing facts after protected approval and uses the
existing canonical managed prepare/handoff CAS. Request and reservation/dispatch
records must be readable before the complete-material one-use port is called.
Native rejection, acknowledgement loss and restart cannot authorize replay or
commit restoration. Full native effect composition and independent terminal
verification/cleanup remain unfinished. Neither serialized binding nor file
digest is authority, and these mechanisms do not release outputs or power
blockers.

The separate protected original-restoration review uses private purpose 11
(native Recovery purpose 3), complete baseline-only `LNRI:1` comparison material
and fresh non-retained administrator authentication. It preserves both original
review deadlines and cannot enter Apply redemption, Keep/Revert or S17 approval.
The replacement's continuously retained original Root lease must be healthy in
recovery phase. Only its actual protected owner scene/input may appear; ordinary
content, scanout and lock release remain fenced. Native status, input, consume,
render and commit recheck the lease. These review proofs remain distinct from a
canonical prepared restoration handoff and from independent terminal evidence;
production restoration dispatch/cleanup remains unfinished.

Before lock/power review or native-sleep coverage coordination, Control's private
safety preparation cancels display continuation in the exact current owner/lock
generation. It polls restoration readiness within one two-second BOOTTIME budget,
including final reply revalidation. The compositor retains opaque/input/power
fences through the original baseline compensation; acknowledgement or numeric
geometry alone cannot release them. Unknown, expired or failed restoration
prevents S17 approval and prepared lock dispatch. Successful readiness grants no
lock, unlock, protective consent or power authority. Native overlap qualification
remains required.

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

SQLite validation may retain reference schemas derived solely from the compiled
migrations and reuse compiled read-only SQL statements. Current schema objects,
migration ledgers, identities, durability settings and authenticated record
histories are still read and validated on every required check; neither cache
retains a successful integrity result. A full transaction integrity check may
reuse current rows it has just authenticated under its existing `BEGIN IMMEDIATE`
write lock while it validates all generations, audit history and physical
reservations. Those rows are local to that check; subsequent calls load them
again, and no provider call or external effect occurs inside that read scope.
Fixed-key HMAC pads remain private to the
non-cloneable record-integrity key and are borrowed for fresh tag calculations.
They share the key's protected lifetime and are scrubbed with its original bytes
using sequentially consistent atomic stores before deallocation. Persisted HMAC
framing, key fingerprints and constant-time tag comparison are unchanged.

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

The separate private original-restoration executor action remains default deny
and checks the exact supervised Control sender before and after service policy.
Its one-use Root handoff binds the complete material, new execution binding,
absolute dispatch deadline and original native sample BOOTTIME. The owner and
compositor cannot renew that freshness by sampling again. Only the exact consumed
Recovery receipt, input/presentation generations and original Root endpoint admit
the write; Apply and Keep/Revert cannot redeem it. The compositor merges only
owned fields into current selected rules, preserves unrelated live settings,
restores selective original wlr fields and exact remapped prior overlays, and
latches every partial fault. It retains all startup/input/power/Root fences and
returns only nonterminal status. The independent proof path now derives expected
restored sources from the immutable Root checkpoint and separately observes actual
post-write opaque KMS frames or detached disabled connectors. Control joins those
fresh facts with native layout/source, logind, coverage and retained Root
continuity in the same canonical restoration recipe. Only the authenticated
already-dispatched verification context can yield NoChange and commit the new
restoration transaction without replay. A restart still needs fresh proof;
historical Committed state never releases a fence. Linked original authority
retirement is described below; qualified native/Root release and retention cleanup
remain unfinished. This
implementation does not activate public production display mutations.

Linked retirement separately persists and reads back an immutable authenticated
record of both exact requests and authority snapshots before closing original
authority as RecoveryBlocked. A fresh canonical restoration proof is required
again after persistence and on restart repair. The exact single-version CAS
invalidates old Verified commit capabilities without reporting the original
desired layout as committed. Missing/substituted link data, changed authority,
stale post-link evidence or a lost final readback cannot release a native/Root
fence or repeat the effect. The returned historical receipt is not permission
for the still-required qualified release and cleanup continuation.

Terminal finalization has a separate bounded `LNRF:1` comparison intent. It nests
unchanged nonterminal `LNRI:1` history and binds the restoration request/dispatch,
immutable link, restored source guard, post-write epoch and current login/lock.
Its purpose-separated SDK effect and adapter reservation cannot validate an old
Apply or restoration binding. A codec or reservation is never execution authority.
The separate registered terminal operation supports canonical planning and an
internal separately authorized/prepared Control handoff. Its native protected
terminal-purpose authentication and prepared quiescence adapters are implemented;
privileged/native retirement and release endpoints remain unavailable.

The compositor additionally implements a private held-scene terminal review
transition. It accepts complete `LNRF:1` only over the actual consumed original
Recovery scene with its continuously live Root grant, matching restoration
transaction/dispatch, exact nested source, current lock, restored source guard,
post-write epoch and completed native safety frames. The full material travels
in an immutable sealed descriptor bounded to 14 KiB; mutable, oversized or
non-file descriptors are rejected before reading. The native integration identity
includes both readers. A new scope has fresh bounded wall/BOOTTIME deadlines and
all outputs need new configure/presentation evidence. It cannot renew restoration
execution authority, start standalone, repeat output writes or release protection.
After consumption, native content/input returns to opaque safety frames while the
one-use consumed correlation stays fixed. Root/source/clock/device checks and
permanent loss latches remain. Existing Keep/Revert keep their original bounds.
Separate native terminal authentication and prepared quiescence dispatch are
implemented. Root retirement/release remain unfinished; this review mechanism
does not establish journal retirement or qualify native release.

The pinned scene additionally accepts a one-use `quiesce_finalization` request
only after actual terminal consumption. Its Root descriptor must authenticate
against the continuously retained original startup peer. The bounded `LNFT:1`
reader matches the complete reservation/material, transaction/effect/dispatch and
original clocks; old restoration grants cannot substitute. Native quiescence
requires the actual retained restoration source/epoch, no held input, and fresh
KMS state plus hardware-completed opaque safety frames before and after the Root
transition. The same original witnesses remain mandatory alongside the new live
terminal channel. Failure or replay poisons continuation and retains protection;
no unconditional health callback or historical-file admission replaces a witness.
This native mechanism releases no fence. Durable retirement/release and actual
native acceptance remain unfinished.

The prepared quiescence handoff consumes Control's sealed typed terminal
authorization, recomputes the distinct complete-material effect, and crosses the
actual supervised executor with a separate default-deny service action. Executor
and owner reattest their callers; no raw correlation grants authority. The
executor's fresh sample requires the restored desired layout and exact restored
source guard. Original Apply/restoration retain their pre-effect baseline checks.
Root reservation and owner transfer share the original two-second sample budget;
neither service-policy time nor a new query renews it. The protected owner spends
the consumed terminal receipt before the sole wire attempt, matching complete
material, canonical transaction, current epoch and the input generation captured
after terminal consumption retired focus. The pre-consumption PAM generation
cannot redeem it. A lost acknowledgement leaves ownership spent and fences held;
qualified lost-ack repair remains unfinished. Later continuity cannot rearm review,
repeat effects, retire witnesses or release protection.

Control's read-only `inspect_original_display_finalization` authenticates both
actual requests, exact committed restoration, reserved/dispatched history, link,
original checkpoint and exact linked original retirement before provider probes.
It separately queries Root's immutable restoration reservation through the bounded
`ReadFinalization` mechanism. Root checks the original live kernel/power witnesses,
exited original compositor and healthy replacement recovery admission before and
after reading strictly validated retained history. This producer reports
`protected`, or `reserved` only after matching this Root invocation's in-memory
reservation to the complete immutable terminal file and actual parent. The
separate actual-native channel can advance this to `quiesced`; files alone
cannot establish either lifetime or release.
Control matches the actual restoration transaction, effect, dispatch and checkpoint,
obtains the same independent fresh five-source canonical restoration proof,
then re-reads the durable anchors and checks every contributor's original expiry. It
cannot append a link, complete a CAS, prepare, dispatch, clean up or release any
protection. A missing readback still refuses the report. This initial query
requires fresh coverage for the restoration's exact lock identity; a replaced
owner/generation is unsupported until separately qualified current-lock admission.
Reports are expiring comparison data, never reusable terminal authority. Fresh
protected review, durable prepare/revalidation, native/Root quiescence and release,
independent completion proof and ownership-aware cleanup remain required.

Root's private terminal reservation mechanism admits only the actual supervised
executor, with the existing bounded worker/transfer slots and absolute dispatch
clock checks. It compares the complete nested restoration, parent dispatch,
canonical authenticated-UID/request transaction and exact current lock against
actual retained restoration history. Comparison bytes authenticate no caller and
cannot replace Control's prepared handoff. The immutable `LNRT:1` file uses the
existing private directory metadata, no-follow/inode, integrity, exclusive lock,
sync and 256-record limits. Its readback scans and validates the same complete
parent under the directory lock. A bounded one-use in-memory reservation is
retained before publication, including on publication, sync, readback or later
liveness failure. File loss therefore cannot reopen reservation or ordinary
startup. Neither matching disk history without live memory nor memory without
exact disk readback reports `reserved`. Parent/current-seat ownership cannot be
silently superseded, and no record is evicted to admit work. This mechanism
releases no witness, power blocker, input or output fence.

The private terminal channel is created only after exclusive synced reservation
and exact readback. Its purpose-separated transfer binds complete reservation
bytes and original dispatch/sample clocks, within the existing two-second
transfer and shared live-grant quota. Every native fragment requires kernel
credentials matched to the actual retained pidfd/start identity, immutable image
and original startup lease. A fixed 48-byte message binds the full reservation
digest and strictly increasing sequence. One `LNFQ:1` transition records held
native quiescence; only `LNFV:1` continuity follows. Authentication, fresh original
protection/readback and reply share one absolute one-second partial-message
budget. Initial quiescence remains inside the original dispatch/sample window;
later health checks cannot renew it. Worker/transfer/publication failure, EOF,
replay or clock regression permanently invalidates reports while ownership stays
reserved. No message offers durable retirement, release or current admission.
The native scene consumer and prepared quiescence dispatch are integrated but
remain unqualified; Root's protocol tests are component evidence only.

Canonical terminal planning accepts a restoration request reference and semantic
reason, never caller-selected original sources or terminal material. It reloads
authenticated linked history, inherits its provenance, and binds a private scoped
context to the exact principal and normalized request digest. The plan's single
`finalize_original` value is the purpose-separated material digest; complete
bounded `LNRF:1` stays private and is independently recomputed. The generic 4 KiB
planner attribute and 64 KiB normalized request limits remain unchanged. Generic
preview cannot create this context and refuses before probing. The canonical
recipe repeats Root and five-source native restoration probes, rejects source,
post-write epoch or lock drift, intersects original expiries, and re-reads linked
history afterward. Registration and trusted risk classification require a
SecuritySensitive ManagedExternalEffect; Apply, restoration, transient or local
operation classes cannot substitute. No planning result is approval or prepare.

The separate typed terminal authorizer receives Control's exact managed challenge
and complete material, which must recompute the canonical digest. Policy allow,
an unbound local approval or foreign principal cannot substitute for fresh exact
protected administrator proof. Control reloads linked history and independently
probes all facts after interaction, then compares the reviewed intent semantics.
Exact nested observation IDs and valid later KMS/frame counters stay in the fresh
observation binding; only their already-validated finding projections are kept
stable for human intent comparison. Native/source/binding/epoch/lock checks remain.

Before prepare, the existing authenticated journal immutably retains the canonical
request, complete bounded versioned material and a small per-restoration owner
record. Owner conflict prevents another operation ID from bypassing unresolved
terminal authority. Qualified supersession, never deletion or a renewed old grant,
is required to replace it. Material/owner and reserved/dispatched records must
read back exactly. Actual linked history, material, owner and original candidate
freshness are checked again before the sealed one-use handoff. Persistence loss,
conflict or stale proof refuses without delivering a port call. Once prepared,
duplicates are observation-only across restart; rejected/lost replies never mint
another authorization or cause redispatch. The qualified v0.6 startup abort of
never-dispatched Prepared authority remains intact; this API refuses to revive it.
Returned indeterminate receipts remain uncertainty;
no reply commits terminal completion or becomes native/Root release authority.

The initial ordinary-presentation attempt is separate from final fence retirement.
Only after the authenticated one-use Root/native spend and fresh native/KMS
checks may the retained scene render ordinary frames. It freezes the actual
submitted buffer identity and output-wide commit counters while retaining input,
S17, power, original Root and ordinary-startup fences. No later ordinary write,
buffer replacement or unrelated pending native state may satisfy the first-frame
comparison. Loss retains protection; a spent grant cannot be rearmed.

Its read-only `display.native-handoff.observe` capability is distinct from opaque
restoration presentation. The original absolute wall/BOOTTIME deadlines survive
Wayland, the attested native owner, private D-Bus and canonical projection. Closed
fields bind the original dispatch, checkpoint, complete restoration/terminal
correlations, source and epochs, and per-output connector/CRTC/plane/framebuffer
plus spend/completion counters. Unknown, truncated, duplicate, oversized, stale,
cross-scope or partial facts refuse; a read cannot mint another two-second window.

Control's separate post-effect inspection first authenticates all durable linked
history and original retirement/reservation/spend anchors. Fresh Root/protection,
native source/layout, logind, S17 coverage and ordinary-frame observations must
agree with the original ownership-derived restored source and complete mapping.
It reconciles a second independently sampled read of the same first frame,
rechecks Root/protection and durable anchors, and intersects all original
expiries. Opaque safety-frame evidence cannot replace ordinary presentation and
an ACK cannot replace either proof. Its separate verification route retains an
immutable `PhysicalReleaseVerified` Control record only after this independent
join. The record binds the exact signed terminal generation/version/binding,
request and spend ancestry, all contributor digests, complete first-frame/KMS
tuple and original wall/BOOTTIME deadlines. Retention failure or contradictory
history refuses; reconciliation preserves the first proof and cannot refresh its
time or create another spend. A missing spend reply can be reconciled by fresh
observation after restart, without reconstructing approval or effect authority.
The signed terminal remains Indeterminate: terminal durable
completion, final fence retirement, ordinary release, committed adoption,
authorized succession and reference-aware cleanup remain unimplemented. The
public production mutation prohibition and physical release gates remain intact.

Only direct successful native spend followed by independently retained first-frame
proof can move the original process-local finalization review into a completion
continuation. The separately durable completion preparation binds the canonical
request, signed terminal generation/version/binding, original spend and immutable
verification/frame identities. Control removes that review before any preparation
write or adapter call, revalidates current registered risk, policy and live
administrator approval, and checks the original deadline and clock ordering after
readback immediately before dispatch. Neither a missing reply nor fresh read-only
reconciliation recreates the continuation. An ACK-only adapter cannot commit the
terminal or retire protection. Actual authenticated Root/native completion,
post-retirement verification and ordered fence retirement remain required.

The original Root completion transfer now permits the native recipient's narrow
same-invocation protected-to-current handoff after its fresh first-frame/KMS and
output-history comparison. Current admission retains that same original Root
lifetime; it cannot admit a future compositor or fall back to recovery after
loss. Private input is quarantined until a fresh physical Escape and complete
native drain. S17 and Root/native power protection and Root's global barrier for
new startups remain held. The original terminal-review clocks are not extended.
Public production mutations remain disabled.

Current native scanout has a separate closed capability and actual producer;
it cannot be supplied by relabelling a first-frame receipt. Each enabled frame
must complete after the handoff boundary and match the actual retained ordinary
buffer, latest output commit and fresh KMS state. Disabled heads retain their
real detach boundary without a fabricated follow-up modeset. Counter rollback,
source/epoch drift, changed framebuffer at the same completed commit, stale
clocks, input ambiguity and lost Root continuity fail closed. The fresh Root
completion observation retains old first-frame data as comparison history only.
Control independently matches that history to its durable preparation and
verification, joins current Root/native/protection/source/logind/S17 facts, and
rechecks them afterward. Missing ACKs and restart permit read-only inspection;
they cannot replay execution, renew old proof or change the Indeterminate
terminal. Power/global-admission retirement, ReleasedCurrent and later ordinary
release/adoption/cleanup remain separate source requirements.

A separately prepared one-use continuation may now retire only native power.
The original canonical review, fresh independent current checkpoint and exclusive
Control before-effect record are required; a historical proof or restart cannot
mint this permit. Root records LNPP preparation and LNPS permission spend before
ACK on the original credential-bearing lifetime. The compositor checks the full
sealed comparison bytes and exact parent digest, both original producer clocks,
complete current KMS/commit inventory and drained input again after the reply.
It releases only its actual native inhibitor; Root's independent power blocker,
S17, startup admission and original recovery checkpoint remain retained.
A distinct Root power-grant observation cannot attest the physical effect:
Control independently joins current native power absence with Root's still-held
protection, source/layout, current KMS/input, logind and S17 before reporting the
post-native inspection. Storage failure, acknowledged-but-missing write, ambiguous
sync, denial, stale proof and lost ACK cannot cause redelivery. This native-only step leaves terminal history Indeterminate.
A further original-review continuation now durably prepares and closes Root's
own scope-specific blocker while retaining its kernel/checkpoint witnesses.
The separate retired-Root capability independently verifies logind processing;
it cannot be mistaken for held-power evidence. Control joins it with fresh
current native/source/layout/input/power, logind and S17 facts before its
canonical NoChange verification and signed Verified/Committed transitions.
Immutable pre-CAS comparison ancestry, verified material and CurrentCommitted
history support storage-failure and restart recovery without physical replay.
The inspection's actual signed terminal stays distinct from its old comparison
snapshot. The separate original-review committed-current and final-retirement
protocols below establish further native and durable postconditions. Ordered
successor admission remains a separate lifecycle operation.

Control's separate current-verification route retains the independently joined
current-state checkpoint under a purpose-separated immutable journal key. The
bounded record binds the complete current KMS/output inventory, original
Root/preparation/first-frame ancestry, signed terminal binding and all fresh
contributors. Storage ambiguity cannot yield a successful report; later fresh
inspection may reconcile the same persisted checkpoint without an effect call.
Advancing native frames cannot overwrite history or renew its original clocks.
Historical proof validity is separate from the new inspection's validity.
Synthetic, partial, stale, conflicting, rolled-back or corrupt evidence refuses.
This writes only Linura-owned evidence: no policy decision, recovered approval,
executor handle, final power/startup retirement or terminal commit is supplied.

Both earlier Root reservation writes also revalidate the original full canonical
finalization review, current registered risk/policy and live administrator
approval before journal preparation and immediately before the Root call. An
interactive caller plus durable history cannot reconstruct this process-local
review after restart. The read-only inspection and durable verification routes
remain available for already spent history; they cannot publish another Root
reservation or recreate a grant.

Control's separate read-only held-quiescence inspection loads the actual terminal
request, immutable complete intent/claim and prepared/dispatched history, requiring
its current Indeterminate snapshot before provider access. It matches Root's
Quiesced phase to that exact material/transaction/effect/dispatch and repeats the
independent five-source restoration proof. Reconstructed current source/epoch/lock
and linked material must remain identical. A second Root query detects loss or
phase change during the join; exact terminal and linked snapshots/history are read
again afterward. Validity is the intersection of the original contributors, never
renewed by readback. This report neither changes durable state nor supplies
retirement/current admission authority.

The native owner and Rust transport additionally implement a separate terminal
approval purpose (12) and fresh non-retained administrator action. The owner can
transition only its actual retained original Recovery flow on the same authenticated
Control connection, current login/lock and exact original material/request/dispatch.
It cannot create a terminal scene from historical bytes or a new owner connection.
The new review retains both fresh absolute clocks, complete material and canonical
request/observation/review binding, and needs fresh pages, frames and administrator
proof. The original spent Recovery receipt remains non-redeemable. Healthy consumed
Recovery retention no longer expires with the old output-write window; actual
native/Root continuity, original connection, monotonic clocks and bounded status
probes still govern that held lifetime. Loss never reconstructs or renews authority.
The typed Control finalization authorizer recomputes material's SDK payload and
resource, checks the exact principal/administrator class, and consumes that separate
native proof. Generic approval cannot substitute. Permanent native-current and final Root/global-admission
retirement remain unimplemented; the
same-invocation pending handoff and its read-only current inspection cannot
substitute for those requirements.

## Original display final retirement and the early Committed boundary

Control's signed `CurrentCommitted` transition intentionally precedes the native
committed-current port. It records desired state, not final release, successor
admission or cleanup authority. Before new display preparation or dispatch,
Control loads bounded, MAC-checked restoration/finalization ownership across the
seat, including Committed and RecoveryBlocked transactions. An idle native
provider, changed compositor invocation, missing reply or Control restart cannot
skip this ownership barrier. The actual retained canonical recovery bytes must
remain unchanged when competing operations are refused.

After independent committed-current qualification, only the still-retained
original canonical finalization review can prepare final retirement. Control
revalidates its purpose, authenticated principal, generation, exact signed-state
version/binding, registered risk, current policy and protected approval before
retention and immediately before dispatch. The immutable preparation binds the
signed commit, first qualified-current proof, original Root grant and fresh
physical observation. Losing process-local review at restart prevents dispatch.

Root retains exclusive LNCT preparation and LNCE spend records. The actual
original credential-bearing completion channel accepts the distinct LNCA purpose
only after its committed-current phase, with exact digest and sequence. The
spend is durable before ACK; neither an ACK nor these comparison bytes asserts a
physical effect. Native code compares the complete sealed preparation and parent
grant, both clocks, source, KMS/commit inventory and drained input before and
after the exchange. Only that successful exchange constructs its non-cloneable
retired-current lifetime. Obsolete display-review input/device and S17-epoch
bindings may then retire; native session-lock authority remains separate. Source
ownership, frame tracking, original Root lifetime and recovery provenance remain.

Control independently joins fresh current native frames and its existing eight
sources between two authenticated Root final-retirement observations. It requires
the exact native final-retirement marker and every durable parent before retaining
an immutable post-effect proof. Root then records LNCZ ReleasedCurrent metadata;
Control completes its own purpose-separated ReleasedCurrent record only after
matching Root readback and another fresh independent join. A lost physical ACK
permits read-only verification. Metadata-only retry preserves the original proof
and producer clocks and cannot call the native effect, reconstruct approval or
renew a grant. Missing, corrupt, foreign, stale or conflicting evidence refuses.

Only actual final completion moves Root's already-retired power witness into a
separate released-lifetime state. That state preserves original kernel,
checkpoint, boot and logind identity continuity without claiming pending power
protection. Pending paths retain their original strict power-transition checks.
The complete Root power and final metadata reply shapes have exact schema-sized
transport bounds only for authenticated Control calls to their specific private
endpoint/interface/method. All other replies retain the ordinary bounded limit.
Final records do not clear global startup ownership, admit a successor, delete
recovery files, or authorize shared-reference cleanup. Those require the separate
qualified lifecycle protocol. Public display mutations remain unsupported.

Ordinary terminal release preparation uses a distinct managed purpose and fresh
plan-bound protected approval. Neither the original Keep approval nor signed
Committed state authorizes it. Control durably claims a single release owner for
the original request and retains complete canonical LNOR material before prepare
and one-use dispatch. Restart/lost-ACK retries are read-only; unresolved ordinary
release also blocks competing seat mutations. The private Root
`ReserveOrdinaryRelease` endpoint accepts only the exact supervised Control
transport, validates the distinct execution binding against complete LNOR
material, and rechecks the live original ordinary startup/kernel/power witnesses
and both absolute clocks around immutable `LNOP:1` publication/readback. The
complete actual original checkpoint must match, and missing/corrupt ancestry
fences all subsequent writes. Root preparation never releases native coverage,
input, S17, power, startup admission or evidence. Native grant/spend, physical
handoff and independent completion remain required and unavailable in this
increment; public production display mutation remains prohibited.

A checked request-history read scope is a synchronous storage lifetime, never a
current-provider observation or execution capability. SQLite fully validates
live identity/schema/durability and all authenticated history at scope entry,
then authenticates individual loads in that same read transaction. Nested
integrity checks revalidate live identity/durability settings and require the
same still-open, unmodified transaction; the complete history was authenticated
at entry and every selected row is authenticated again on load. A shared borrow and
read-only contract prohibit carrying it across Control's mutable provider/effect
boundary; fresh scopes obtain fresh snapshots. Neither forgetting the guard nor
a failed rollback permits writes or a new inspection. Unknown rollback state or
an invalid scoped MAC poisons the journal lifetime. No validation result or row
is reused as current authority after the scope ends, and the original native
spend/first-frame deadlines are unchanged.
