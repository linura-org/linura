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

The private schema-2 native preimage captures `LNRL:1` at the actual native
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
material before disclosure of an `LNRG:1` endpoint. It uses the same exclusive,
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

Authenticated native grant consumption/writes, fresh Control prepared handoff
and qualified supersession/terminal workflow remain unfinished. Component checks
of the review and endpoint producer do not establish that required composition
or native qualification.

## Terminal sequencing

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

Experimental wire changes update all in-repository consumers together. Original
durable checkpoints and Control history remain immutable and retain their
original version/meaning. A legacy record that cannot establish complete native
lineage remains fenced; it is not silently migrated, deleted or authorized.

Pure mapping/material tests establish deterministic candidate validation only.
They do not qualify authenticated restoration, native writes, independent
terminal proof, cleanup, production mutation activation or actual multi-output
compositor-loss/lock/power/input/first-frame behavior. Those remain required in
the sequential implementation and exact-head native acceptance gates.
