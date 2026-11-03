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
