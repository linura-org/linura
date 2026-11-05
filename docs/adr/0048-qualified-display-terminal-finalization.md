# ADR 0048: Authorize display terminal finalization separately

- Status: Proposed
- Refines: ADR 0012, ADR 0018, ADR 0032, ADR 0046 and ADR 0047
- Scope: S21-2 terminal workflow; production display mutation remains unavailable

## Context

The original-restoration `LNRI:1` operation deliberately returns nonterminal
status with startup, input, opaque presentation, kernel and power protection
retained. Independent restoration proof and linked authority retirement do not
turn its old approval, committed snapshots or comparison receipt into permission
to release protection. Normal native Keep/Revert also require fence retention
through independent Control verification and layout commit.

## Decision

Introduce an explicit terminal managed operation with a separate fresh protected
authorization and canonical plan-bound durable prepare/revalidation. Its trusted
risk floor is SecuritySensitive. It is not a query, transient effect or mere
Linura-local cleanup. Root/native mechanisms remain narrow; Control owns planning,
policy, history, verification, recovery, dependency and retention decisions.

The private Experimental `LNRF:1` comparison material binds the restoration
request and dispatch, immutable original/restoration link, exact current restored
source guard, post-write epoch, current lock identity and unchanged complete
`LNRI:1` source material. Byte bounds, length framing, nonzero canonical digests,
complete original/replacement mapping and native capabilities remain mandatory.
The current lock must belong to the same replacement login. A newly authenticated
current owner/lock generation does not inherit approval from an older one.

The material is data. Its parser cannot certify a commit, authenticate a caller,
issue approval or release a fence. Old durable bytes retain their meaning; neither
an old restoration nor a historical receipt is a terminal execution credential.
The terminal path must load and authenticate both actual transactions and their
link, prove exact original retirement, and independently verify the complete
current native/source, Root, logind, coverage and physical frame facts.

The canonical terminal desired-state value is the existing purpose-separated
`LNRF-SHA256:1` digest payload. Complete bounded material remains in Control's
private authenticated context and must be recomputed against the digest before
planning and any later prepared handoff. This preserves the generic planner's
4 KiB attribute limit and avoids platform-specific validation in the planner.
A digest alone establishes neither historical context nor current proof.

The terminal operation follows the restoration layout commit and linked original
retirement. Its own effect handoff requires fresh protected approval, canonical
review, durable prepare, reservation/readback, current revalidation and a sealed
one-use adapter port. The protected purpose must be distinct from Apply, Keep,
Revert, original restoration, unlock and power. Generic preview or an untrusted
caller cannot supply its authenticated history context.

Native callbacks quiesce while all fences stay held. Root authenticates the exact
native sender on every acknowledgement fragment, verifies original protection,
and durably records qualified retirement before ordinary admission can change.
Intentional witness closure cannot poison an already quiesced native state. The
real S17 lock remains intact; held input is quarantined/drained before ordinary
focus. Fresh native source/frame checks remain necessary at the release boundary.

Historical completion cannot replace current admission. Lost acknowledgement,
spent-record repair, expiry, service loss and replacement races need explicit
qualified states, with no display-write replay, reconstructed witness or renewed
old window. A genuinely new effect needs a fresh managed authorization; it cannot
be reconstructed from the previous receipt. Committed original desired state needs
its own preserving adoption/continuation, never failed-baseline compensation.

Control analyzes shared ownership/dependencies before retention cleanup. Retain
unknown or still-referenced preimages and semantic why-chains; bound active,
retired and spent state with explicit full-storage refusal. No delete-to-retry,
unbounded retention or loss of provenance is permitted.

## Implementation and qualification limits

The initial implementation includes bounded core/SDK/adapter comparison codecs
and a read-only Control prerequisite inspection. The query authenticates both
actual requests, exact linked snapshots, phase records and original checkpoint
before provider probes, joins the same fresh five-source canonical restoration
proof, and reads the durable anchors again before returning an expiring report.
It performs no durable transition and cannot repair missing linked retirement.
An additional bounded Root query reads the actual immutable restoration
reservation while checking original live witnesses and current recovery admission
before and after readback. It shares the existing original-read worker and emits
only protected state. Control independently matches transaction/effect/dispatch
and checkpoint to authenticated history, joins the fresh canonical restoration
proof and preserves both original expiries. Closed future terminal comparison
states do not activate a Root completion producer or supply release authority.
This initial inspection requires the exact restoration lock identity; current
owner/generation replacement fails closed. A fresh lock in the codec alone does
not qualify that path.

The separate operation registration has ManagedExternalEffect semantics and a
trusted SecuritySensitive floor. Non-executable canonical planning requires a
private principal/request-bound context built from actual linked history; generic
previews refuse before provider probing. Planning re-observes Root reservation and
the same independent five-source restoration proof, checks exact current source,
post-write epoch and lock against complete material, then re-reads durable anchors.
It preserves the original provenance and performs no durable transition. Failed
planning retires the private context just as successful planning does.

Control additionally implements a separate typed terminal challenge/authorizer and
prepared one-use handoff. Full material must recompute the canonical digest before
protected review; actual linked history and independent facts are reloaded after
interaction. Exact fresh evidence remains bound into the refreshed candidate and
durable prepare. Volatile nested observation IDs and valid later physical frame
counters are evidence, not new human intent; only those already-validated finding
projections are normalized, with exact complete evidence retained in the terminal
observation digest. Source, post-write epoch, lock and lineage must remain equal.

Complete material is retained in a bounded versioned opaque journal record before
prepare. A separate small immutable owner record binds the restoration to one
terminal request/digest/material. Another operation ID cannot silently supersede
it; explicit qualified supersession remains separate. Request, material, owner,
reservation and dispatch readback precede the one-use port. Prepared/dispatched
duplicates never repeat approval or effects. Qualified v0.6 startup behavior still
aborts never-dispatched Prepared authority; this API cannot revive it.
Indeterminate duplicates return retained uncertainty, including after lost replies
or native refusal. No reply commits completion.

No native protected terminal purpose, production executor endpoint, Root retirement
or native release is activated. The remaining terminal managed workflow, native/Root quiescence and
finalization, normal Keep/Revert ordering, Committed adoption, safe supersession
and reference-aware cleanup still require coherent implementation.

Before activation, qualify the complete exact-source native failure matrix:
multi-output rules/overlays/modes/frames, compositor loss at each phase, stale or
lost proof, partial effect/lost replies, deadline/storage failure, current lock,
power/suspend/hotplug/focus/protected input and zero/one/multiple administrators.
Portable fixtures, compilation and historical green gates do not supply that
evidence. The PR remains draft until all remaining required work is complete.
