# ADR 0046: Retain original display protection outside executor lifetime

- Status: Proposed
- Refines: ADR 0002, ADR 0012, ADR 0032, ADR 0042 and ADR 0045
- Scope: S21-2 private original-witness mechanisms; public mutations remain unsupported

## Context

An immutable display checkpoint preserves historical native rules, original
ownership, scope and clocks. It cannot reconstruct the live kernel subscription,
connector descriptors or original logind inhibitor. Keeping these objects in the
executor loses them on executor replacement even if the compositor survives.
Reopening descriptors or acquiring another inhibitor would erase the evidence
gap instead of recovering the original protection.

## Decision

Retain these bounded mechanisms in the independently supervised root service
`linura-display-protection.service`. Its fixed process entry is the existing
session executor image with the sole argument `--display-protection`; systemd
attestation requires that exact argv, immutable image and unit, current MainPID,
invocation, service account, unique system-bus sender and absence of drop-ins.
It has no display-write, session-lock, power-transition or approval endpoint.
This is not a privileged recovery coordinator: Control retains all planning,
policy, prepare, revalidation, verification, durable phase and retirement work.

The private Experimental `DisplayProtection1` interface has five
bounded mechanisms. `Begin` opens the original bounded kernel subscription before native
sampling. `Reserve` consumes that subscription once, within its original two
seconds and in the same authenticated executor invocation. It validates the
historical binding and native preimage, compares the original sample clock with
the subscription, acquires the fixed original power blocker and durably reserves
the original preimage before returning. `Verify` revalidates the retained
original objects and exact stored bytes. A dispatch digest is only correlation,
never caller authentication or an executor permit.

`ReadOriginal` is a separate bounded read for the exact supervised Control
invocation. It authenticates the replacement recovery scope, requires the
original retained compositor pidfd to prove exit, and requires the original
healthy startup lease of a recovery-fenced replacement with the same boot, UID,
seat and integration. Both sides authenticate the current protection service.
The same retained kernel/power witnesses verify before and after the immutable
read. Only typed historical intent/metadata/digests enter the canonical
`hyprland-recovery` observation; native rule bytes remain adapter-private.
Control owns the separate current-output/session/coverage probes and their join.
Neither reading history nor constructing this observation authorizes restoration.

The system bus denies ordinary callers for the original-witness methods.
`Begin`, `Reserve` and `Verify` independently authenticate the current supervised
executor before and after their mechanism; `ReadOriginal` admits only Control.
The separately bounded `NativeStartup` entry
requires the current supervised protected owner and independently bound login. Root UID alone
is insufficient. The executor authenticates the protection service before and
after each bounded call. Lost replies are not retried. Pending subscriptions are
bounded to 32 and expire only before dispatch; retained protections are bounded
to 256 and have no automatic TTL or cleanup. Native confirmation deadlines and
freshness limits do not widen across this extra process boundary.

### Serialized native startup admission

`NativeStartup` accepts only the current root-supervised protected owner, not an
ordinary same-UID caller or arbitrary root process. It uses supervisor properties
without calling the owner's not-yet-registered endpoint. The owner independently
attests its actual Wayland peer, the installed immutable executing compositor
image and the compiled native integration identity. Protection independently
checks the caller's kernel credentials, exact owner invocation, boot, active
local Wayland login leader, session creation epoch and seat twice. Its retained
pidfd rejects a live overlapping invocation in that login and compositor UUID
reuse; independent logins keep separate leases across normal VT switching.

One admission mutex serializes startup publication with original subscription
creation, consumption and checkpoint publication. A descriptor-relative locked
history scan never caches an empty result. Pending original probes or any retained
or unknown history keep startup recovery-fenced. Until qualified terminal
retirement exists, history fencing is deliberately conservative across logins.
The service retains at most 64 startup leases, with no replacement or implicit
cleanup. Only one startup authentication worker may run; dropping an RPC future
does not release its worker slot early or create an unbounded admission queue.

The same authenticated protected owner transfers the original root-created Unix
socket through the private native protocol. Native admission compares the exact
compositor invocation and the socket's kernel root/PID peer with the attested
service. This descriptor is a presentation lease, never a credential, executor
permit or restoration grant. Startup defaults to opaque output and blocked
ordinary input before initialization of the backend or first frame. Every startup
submission initializes the actual scanout buffer opaque; unavailable rendering
refuses a commit. Normal rendering, direct scanout, late callbacks, hardware
cursors, focus and all ordinary input paths retain the fence. Admission drains
suppressed physical keys/buttons before ordinary focus; it cannot clear private
or quarantined protected-input state.

The lease is installed once. Unexpected bytes, EOF, loss, an invalid descriptor
or failed event registration remain fenced for the invocation; reconnecting to a
new service cannot repair it. Native lease-loss events clear focus, suppress
cursors and damage outputs. Native Apply and Keep refuse startup-fenced/lost
state; original in-process safety compensation remains bounded by its retained
checkpoint. Native snapshots expose startup phase privately and consistently
with the existing fence. No startup operation acquires/releases S17 lock state,
reopens original recovery witnesses, changes output rules, renews an old display
confirmation deadline or admits a restoration effect.

The service's lifetime does not depend on the executor. Restarting the executor
does not restart protection. Protection service death, logind replacement, boot
change, lost original descriptors, event gaps or failed checks cannot be repaired
by loading identities from disk. They fail closed, and the original durable
checkpoint remains unresolved. This decision does not claim protection survives
loss of the protection service itself.

## Persistence and compatibility

The existing `LNRJ:1` checkpoint encoding is unchanged. Bounded descriptor-relative
readback requires the same owner, permissions, single link, exact filename to
dispatch correlation and checksum; it never creates a missing record. Each live
protection additionally retains the hash of its original payload and rejects
substitution. Historical parsing is comparison data, not fresh observation,
restoration admission, a recovered approval or authority to execute a plan.

New prepared rule preimages use `LNDR:2`, adding the resolved native selector as
bounded canonical comparison data. Reconstruction and in-process rollback
require matching live selector lineage; neither rewrites selectors or the live
rule list/precedence. All rule, output-identity and ownership witnesses participate
in prepared native comparison, including equal-geometry drift. Existing nested
`LNDR:1` preimages retain their exact historical validation and dispatch binding;
they are never implicitly migrated, deleted, reconstructed or admitted to a new
reservation. This is explicit nested-payload versioning, not recovered authority.

Existing S17 executor methods retain their original admission and Polkit paths.
The added service is deployed alongside the same executor artifact. Public SDKs,
agents, UI and semantic domain crates receive no transport or protection handle.

## Qualification and remaining boundary

Component tests exercise exact private introspection, transport-sender denial,
nonzero canonical correlation, original subscription consumption, time/epoch
refusal and immutable checkpoint readback. The v0.6 disposable native lane adds
ordinary/root denial and independent service-invocation survival across executor
restart, with exact contract, policy and unit artifact bindings. That lane does
not acquire a real DRM witness or qualify display recovery.

The startup mechanism has component coverage, not accepted native first-frame
or compositor-crash qualification. Canonical purpose-bound single-use
restoration, native rule/overlay reconstruction, independent terminal evidence,
retirement and the real S21-2 multi-output crash matrix remain required before
public mutation activation. This decision does not replace those requirements.
