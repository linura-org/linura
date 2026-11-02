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

The private Experimental `DisplayProtection1` interface has exactly three
mechanisms. `Begin` opens the original bounded kernel subscription before native
sampling. `Reserve` consumes that subscription once, within its original two
seconds and in the same authenticated executor invocation. It validates the
historical binding and native preimage, compares the original sample clock with
the subscription, acquires the fixed original power blocker and durably reserves
the original preimage before returning. `Verify` revalidates the retained
original objects and exact stored bytes. A dispatch digest is only correlation,
never caller authentication or an executor permit.

The system bus denies ordinary callers. Every method independently authenticates
the current supervised executor before and after the mechanism. Root UID alone
is insufficient. The executor authenticates the protection service before and
after each bounded call. Lost replies are not retried. Pending subscriptions are
bounded to 32 and expire only before dispatch; retained protections are bounded
to 256 and have no automatic TTL or cleanup. Native confirmation deadlines and
freshness limits do not widen across this extra process boundary.

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

Serialized replacement startup fencing, canonical purpose-bound single-use
restoration, native rule/overlay reconstruction, independent terminal evidence,
retirement and the real S21-2 multi-output crash matrix remain required before
public mutation activation. This decision does not replace those requirements.
