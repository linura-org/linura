# ADR 0047: Original display restoration is a fresh managed effect

- Status: Proposed
- Refines: ADR 0012, ADR 0032, ADR 0045 and ADR 0046
- Scope: S21-2 replacement compositor recovery; implementation and native qualification in progress

## Context

An original immutable checkpoint is historical data. Its old Apply approval,
confirmation clock, compositor handles and owner connection cannot authorize a
replacement invocation. Startup admission deliberately retains opaque output
and ordinary-input fencing while any unresolved history exists. Neither a new
login nor an expired confirmation window may bypass that fence.

## Decision

Startup executable attestation belongs to the independent root protection
boundary after exact supervised-owner and logind leader admission. The native
entry point first disables dumpability and relinquishes all process capability
sets, preventing capability removal from exposing the compositor to same-user
inspection. The owner supplies only an immutable installed-image digest. The
root guard uses exactly `CAP_SYS_PTRACE` to open the admitted nondumpable
leader's executable, independently compares the fixed root-immutable installed
inode and complete bounded hash, and retains the descriptor for ongoing
metadata/executable checks. It offers no arbitrary inspection interface. The
mutating executor and protected owner retain no capabilities. Reauthentication
shares the original startup deadline and retained image; it cannot refresh
that deadline or hash a second image. This strengthens startup attestation but
does not replace secure-loader/plugin review or native attack qualification.

Control derives a separate original-restoration candidate from the authenticated
original request, durable authority/phase chain and immutable native checkpoint.
It independently obtains current native/logind/coverage and original-protection
evidence. The original protection service must retain the original kernel
subscription, connector descriptors and power blocker; loss cannot be repaired
by reopening them or loading their identities from disk.

The candidate contains a complete bijection between historical output identities
and the replacement output identities. The adapter must establish that bijection
from original retained kernel continuity and a fresh native sample, not connector
names, EDID, enumeration order, equal geometry or equal numeric handles. Pure
domain validation checks the same boot, UID and seat, a different compositor
invocation, exact complete inventories and a fresh replacement lock scope. A new
logind epoch is permitted because killing a compositor that leads its login can
end the original login. The original lock identity and approval never move to
that new epoch.

The bounded `hyprland-recovery` provider emits only a fresh
`display.original-protection.observe` envelope for an exact `display:recovery:`
resource. It preserves the old sample/confirmation clocks, complete historical
intent and hashed rule/ownership/native identities. It does not query or aggregate
current outputs. Control joins it to a separate fresh Hyprland observation using
the complete native identity digest, which includes the original kernel DRM
tuple. Original retained kernel continuity and a complete unique digest match
are both required; EDID or connector-name equality alone is insufficient.

Control's restoration recipe also receives comparison-only historical facts
loaded from its authenticated original request/baseline/phase journal. That
private planning context must match the exact new request and original lineage;
it cannot refresh an observation or survive as an execution permit. Public
generic preview without that context fails closed. The same canonical recipe
is reused for authority review, fresh prepare and pre-dispatch revalidation.

Deterministic derivation remaps **only the original baseline**, including disabled
heads, mirroring, scale, transform, exact mode/refresh and position. It validates
the result against all replacement native capabilities. It cannot replay the
original desired layout, omit an inconvenient output, round a mode or manufacture
a visible independent root. Native rule selection/precedence and prior overlay
ownership require separate exact preimage comparison and restoration; geometry
alone is insufficient.

Private `LNRI:1` candidate material binds the original request, dispatch and exact
checkpoint digest to the original complete intent, replacement complete intent,
replacement native baseline/ownership guard and ordered output bijection. A
same-geometry change in replacement rule/overlay lineage also refuses dispatch.
Bounded canonical length framing preserves all
resource punctuation as data. These fields are not credentials or proof of live
continuity. Historical capability validation checks original shape at the
original timestamp; it does not refresh that evidence.

The protected owner's private native comparison decoder independently checks the
complete `LNRI:1` framing and old-to-new bijection, including reordered output
handles, mirrors, disabled heads and a new login epoch on the same boot/user/seat.
It requires the replacement target to equal the remapped original baseline and
rechecks the current geometry, capabilities and native baseline guard before a
future Recovery presentation. A shared canonical vector is validated by both
Rust's native-capability derivation and the C++ decoder. It now supplies the
private Recovery review, but is not an execution capability or native effect.

The restoration operation is `ManagedExternalEffect` with a trusted
`SecuritySensitive` floor. Its fresh canonical `ReconciliationPlan` includes the
original lineage, current scope, complete target and contributing evidence.
Purpose-bound protected review and authentication cannot satisfy Apply, Keep,
unlock or power purposes. Policy approval remains review evidence; a new durable
prepare and fresh revalidation must precede a one-use executor handoff. The root
mechanism authenticates the supervised caller and reserves the exact original
checkpoint/new prepared binding once before any native write. Lost replies,
partial mutation and repeated requests do not renew or redeliver that admission.
Control owns orchestration; the root protection process does not choose a plan,
ask for approval, run a recovery loop or write display rules.

## Native source lineage

The private schema-2 native preimage now captures `LNRL:2` at the actual native
selection point. It binds the selected index and ordered selectors, distinct
underlying/effective `LNDR:2` owned fields, wlr presence and committed owned-field
mask, and the original integer refresh before float-Hz projection. Geometry and
an effective rule alone cannot reconstruct that source. Existing per-head and
whole-payload bounds remain unchanged. Historical schema-1 records retain their
original interpretation and cannot qualify a new complete recovery source.
In-process overlay compensation compares actual selected owned sources and
preserves unrelated live selector edits; it never writes native config or wlr.

## One-use original-root handoff

The restoration reservation must bind the original dispatch/checkpoint hash,
complete canonical restoration material, new prepared execution binding and
replacement invocation. Exclusive durable creation and file/directory sync
precede disclosure of a grant. A lost reply never redelivers that binding. A
further replacement requires another fresh reviewed/prepared request; it cannot
inherit the interrupted restoration's authority.

Native handoff uses a distinct original-root-created Unix endpoint. Its kernel
peer PID/UID must match the peer of the compositor's retained original startup
lease, which must remain continuously healthy. Reopened files, root-looking
metadata, serialized PIDs, hashes and a replacement protection service are not
grant authentication. The original startup lease remains silent; unexpected
bytes still poison it. Grant bytes have separate bounded canonical framing and
must match the exact protected Recovery purpose, native scope and prepared
binding before any output write. Duplicated endpoint descriptors share the
consumed stream; they do not recreate an unread authorization.

The root mechanism retains reservation and original witnesses on incomplete
transfer, cancellation, timeout or partial mutation. The protected compositor
must retain opaque/input fencing independently of the human-review lifetime.
The private Guard now accepts `ReserveRestoration` only from the exact supervised
executor. `LNRR:1` stores the complete fresh execution binding and `LNRI:1`
material before disclosure of an `LNRG:2` endpoint. It uses the same exclusive,
synced, strictly validated bounded history directory as original checkpoints;
original `LNRJ:1` records retain their bytes and meaning. Another binding for the
same unresolved original cannot supersede it. Failed replies/transfers retain
that reservation. Transfer has one retained worker slot, a two-second absolute
budget and a final marker following fresh witness checks. Those mechanisms
perform no display write, release or recovery orchestration.

The protected owner now admits the separate original-restoration approval
purpose 11 and native Recovery presentation purpose 3. Its canonical comparison
scope includes the complete `LNRI:1` material, reviewed bindings, reason and
original absolute wall/BOOTTIME bounds. Fresh administrator authentication uses
`org.linura.authority.restore-original-display-layout`, never a retained Polkit
grant or the original Apply proof. Both review clocks remain bounded to sixty
seconds; native focus, input, configure or first-frame changes invalidate the
proof. Legacy S17 approval, ordinary Apply redemption and retained Keep/Revert
cannot consume it.

Only a replacement with a continuously healthy original Root lease in recovery
phase admits this private scene. The compositor rechecks that original lease on
fresh status, input, consume, render and commit paths; unknown/lost state keeps
opaque/input fencing. Ordinary scene rendering and scanout stay blocked. Native
input callbacks do not start nested owner snapshot queries: the compositor's
actual private status/consume paths revalidate the lease independently.

Control now exposes a separate nonterminal original-restoration handoff. It
reloads authenticated original history and fresh contributing evidence after the
protected interaction, requires unchanged material/authority semantics, issues
purpose-bound approval evidence and uses the existing durable prepare/handoff
CAS. It retains and reads back the exact request, reservation and dispatch
correlation before calling the narrow restoration port. That sealed handoff
carries the complete private material and the original fixed dispatch deadline;
a digest-only descriptor cannot select or reconstruct native intent. Duplicate
requests, including after restart or a lost/rejected reply, cannot hand off again.
A native reply cannot commit, verify or release this nonterminal transaction.

The unconsumed Experimental `LNRG:1` producer format is replaced coherently by
`LNRG:2`: the complete reservation plus a bounded native-only projection derived
from the same strictly validated immutable schema-2 source. The projection binds
the exact canonical old-to-new output bijection, original rule/wlr lineage, prior
overlay and kernel/native identities. It is neither another observation nor an
alternative durable history; original `LNRJ:1` and `LNRR:1` records retain their
bytes and meaning. Serialized projections and old transfer bytes grant no effect.

The bounded native recipient authenticates its actual Root peer against the
continuously retained startup lease, consumes its descriptor on every path,
checks framing/correlation and the exact canonical bijection, and shares one
two-second BOOTTIME budget across transfer and its first fresh witness probe.
After the final marker, the original Root endpoint remains a live witness
channel. Fixed 16-byte `LNRV:1` probes have strictly increasing sequence numbers;
Root acknowledges only after fresh retained protection checks. Idle endpoints
also check original protection, and malformed, replayed, slow or lost probes
close the endpoint. Worker retention is bounded by the existing startup quota;
the transfer slot is released after transfer without redelivering authority.
Input/render lifetime checks do not perform blocking witness queries.

Original native wlr projection restores only the committed owned fields plus
its enabled state, retaining the original integer refresh. It never recreates
a historical Wayland client or freezes uncommitted native fields. New live wlr
ownership, a changed selected rule or changed selector ordering refuses import.
Unrelated live color, ICC, VRR and other settings remain current.

`LNRL:2` explicitly distinguishes no wlr source, a real live wlr client and a
retained restored projection. Only the last kind carries its original checkpoint
digest. The actual native selected source remains separate; reconstructing old
committed fields never claims a historical Wayland client is live. The expected
post-write source is the new explicit restored-projection lineage, rather than
counterfeiting the old live-client witness. Same numeric geometry cannot equate
those source kinds. A new actual wlr owner refuses import or, after qualified
terminal retirement, replaces the retained projection normally. Original
`LNRL:1` history retains its exact bytes and live-client interpretation; historical
decoding neither advertises it as current nor permits a new reservation.

The private `Executor.Session1.RestoreOriginalDisplayLayout` method accepts only
the complete fresh material and execution binding from the exact supervised
Control owner, with a distinct default-deny service policy action checked between
two fresh Control identity checks. The concrete Control adapter consumes its
sealed one-use authorization. The native session adapter validates a fresh
replacement sample/guard, reserves the original Root endpoint once and carries
the exact sample digest and original BOOTTIME to the private owner. All adapters
refuse late, changed-owner or wrong-purpose state without retry or rediscovery.

`ReserveRestoration` also binds the exact absolute dispatch deadline and original
native sample BOOTTIME into the Root-produced `LNRG:2` transfer. They remain
single-handoff data: immutable `LNRR:1` history retains its existing bytes and
meaning and is never redelivered after restart. Root rechecks the original
sample/deadline before reservation and after witness checks before its final
marker. The compositor checks the Root-bound deadline against its correlation
and the original sample age again immediately before the first write. A newer
owner/native snapshot cannot renew the original two-second freshness window.

The owner separately redeems only its exact consumed Recovery material,
transaction and input/presentation generations. Apply and Keep/Revert cannot
consume that receipt. Its original boot deadline remains fixed. The native
`restore_original` request consumes its descriptor on every path and retains a
wire tombstone before entering the effect mechanism; a new wire object cannot
redeliver even an ambiguous callback. The compositor authenticates the original
Root peer, compares the complete native source and current baseline guard,
acquires current power protection and retains its grant/protected fence before
any possible write. It stages only owned rule fields, remerges those fields into
the actual live selected rules at the write point and restores the selective wlr
projection and exact remapped prior overlays. Shared rules, new wlr ownership,
selector/inventory/identity drift or any partial failure remain unresolved.
A failed write permanently latches the fault; no successful return clears it.

The native mechanism returns only nonterminal Restoring or RecoveryFailed.
Opaque rendering, input, original Root witnesses and power remain fenced;
there is no terminal release or cleanup here. Qualified supersession and the
linked terminal workflow remain unfinished. Component checks and code composition
do not establish pinned SDK/native qualification.

## Independent restoration observation

Original-protection observation schema 2 adds the complete expected restored
source digest for each historical output. Root derives these digests from its
immutable original checkpoint, projecting a historical wlr source into an explicit
restored projection anchored to that checkpoint. It does not copy the replacement
compositor's claimed post-write digest. Control derives the complete expected
replacement source/ownership guard from those digests and the authenticated
baseline/bijection. Current numeric layout, native identity, original prior overlay
ownership and source lineage must all agree. Historical checkpoint bytes and their
version remain unchanged.

The compositor separately samples actual atomic KMS properties through its
already-owned DRM descriptor. Every enabled connector must have an active exact
mode and one primary plane scanning the retained immutable opaque buffer from the
current restoration write epoch. The current frame must have completed through
the native hardware-presentation path; a queued commit, an old protected review
frame, a reused buffer identity or an acknowledgement is insufficient. Active
cursor/overlay planes refuse evidence. Disabled outputs require an actually
detached connector, rather than a cached desired disable. Enumeration and property
counts are bounded, with one absolute two-second probe budget and no retries,
device reopen, import, modeset or cached-state fallback. Original Root witnesses
are checked before and after the native probe, and source/layout snapshots must
remain identical around it.

The optional private Wayland snapshot event and the supervised-Control-only
`SecurityOwner1.ObserveOriginalDisplayPresentation` method carry this bounded
sample. Its typed projection uses the existing authoritative
`ObservationEnvelope`, provider `hyprland`, capability
`display.original-presentation.observe` and the exact recovery resource. It binds
the checkpoint, transaction, effect, dispatch, complete output/frame inventory,
post-write epoch and actual source guard. The Linux adapter validates the exact
attested owner and both clocks without renewing the original probe lifetime.
This is an observation, never an execution or release credential.

Only an authenticated, already-dispatched restoration can enter Control's private
verification context. The same canonical recipe then joins fresh original Root,
native source/layout, logind, coverage and presentation envelopes. It produces
`NoChange` only for that exact retained restoration material and dispatch after
all comparisons succeed. A pre-effect context cannot use this mode to skip
approval or prepare. `reconcile_original_display_restoration` uses the existing
observe-only durable recovery path and commits only the restoration transaction;
it cannot replay a write, retire the original transaction/checkpoint or release a
fence. Restart after Verified or Committed still requires the same fresh canonical
proof. The separate linked terminal continuation described below remains required.

## Terminal sequencing

An original transaction can be Verified but not Committed when its compositor
dies. Ordinary Indeterminate recovery must not acquire permission to mutate
Verified or Committed state. A distinct Control-signed `VerifiedCompensated`
resolution therefore permits only Verified → RecoveryBlocked after independently
proven compensation and a durable linked terminal result. Its exact generation,
version and binding use the same persistence CAS; nonzero observation/link digests
and a fixed window of at most two seconds are mandatory. It creates no execution,
reprepare or commit authority. Ordinary `authorize_recovery` cannot mint this
resolution, and the distinct signer method cannot authorize any other state.

SQLite retains the original verified desired/graph/provenance material and appends
the explicit `verified-compensated-v1` audit kind. Validation accepts that retained
material only with this authenticated terminal kind following the exact same
generation's Verified audit event. Existing blocked histories keep their previous
shape and meaning. Old readers fail closed on the new audit kind; no old row or
audit event is relabeled. The prior commit request loses its CAS, and replay,
expired/foreign authority and changed generation/version/binding refuse mutation.
This mechanism is bookkeeping only: Control's linked terminal workflow and native
finalization must still consume it through the qualified path below. It is not yet
used to release any fence.

Control's linked bookkeeping path first independently reconciles the restoration
transaction to Committed, then records a bounded immutable
`linura.display.original-restoration-link.v1` payload in its existing authenticated
request journal. It binds both complete authority snapshots and request digests,
the original dispatch/checkpoint, the restoration dispatch and the independently
verified combined observation digest. Its meaning is qualified historical
compensation correlation; original retirement may still be pending. Original
source/intent records retain their bytes and meaning.

The exact journal key, principal, canonical bytes and committed restoration anchor
are read back before original retirement. Control then runs the same fresh
canonical five-source proof again. The original must equal the retained pre-retire
snapshot or its exact single-version RecoveryBlocked successor. Indeterminate
authority closes through the existing conflicting-state recovery; Verified
authority uses the distinct compensation resolution above. An already completed
retirement returns only after the same fresh proof. Original Committed state,
changed anchors or unavailable proof cannot be converted into compensation.

This ordering permits observe-only repair after a crash between link persistence
and retirement or a lost final readback. Missing link persistence cannot retire
authority; fresh proof cannot rewrite an existing link with new timestamps or
bindings. The returned terminal receipt describes durable historical bookkeeping,
not current native state, a release credential or another effect. The separate
qualified native/Root continuation and retention workflow remain unfinished.

Restoration acknowledgement is not success. Native opaque/input protection,
original witnesses and power blockers must remain retained until independent
fresh evidence proves the original rule/overlay semantics, kernel continuity,
complete restored layout and each output's terminal presentation or verified
disable. Control then commits the linked terminal result durably before the
qualified one-use finalization releases the fence and retires active checkpoint
retention. Original desired-state authority never becomes a successful desired
commit merely because compensation succeeded. Unknown or conflicting state
remains unresolved without replay or automatic cleanup.

## Compatibility and qualification

Root terminal reservation is a separate narrow mechanism. It admits the actual
supervised executor, compares the complete retained restoration and its canonical
UID/request transaction, parent dispatch and exact lock, and uses the existing
absolute dispatch bounds and shared worker/transfer slots. A bounded one-use
in-memory reservation precedes exclusive synced `LNRT:1` publication under the
unchanged private 256-record quota. Failed publication, sync, readback or liveness
checks retain ownership; neither missing files nor a new operation ID permit a
second attempt or ordinary startup. Readback requires the exact parent during
the same locked scan. `ReadFinalization` reports `reserved` only when the complete
file matches this Root invocation's memory and current original protection;
files alone cannot reconstruct that lifetime. Existing `LNRJ:1` and `LNRR:1`
remain immutable and unchanged. This reservation acknowledgement releases no
protection and supplies no quiescence, retirement or current-admission proof.

Experimental wire changes update all in-repository consumers together. Original
durable checkpoints and Control history remain immutable and retain their
original version/meaning. A legacy record that cannot establish complete native
lineage remains fenced; it is not silently migrated, deleted or authorized.

Pure mapping/material tests establish deterministic candidate validation only.
They do not qualify authenticated restoration, native writes, independent
terminal proof, cleanup, production mutation activation or actual multi-output
compositor-loss/lock/power/input/first-frame behavior. Those remain required in
the sequential implementation and exact-head native acceptance gates.
