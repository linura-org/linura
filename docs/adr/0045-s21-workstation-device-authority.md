# ADR 0045: S21 device effects share one Control authority and verified recovery

- Status: Proposed
- Refines: ADR 0003, ADR 0012, ADR 0024, ADR 0031, ADR 0032, ADR 0033 and ADR 0042
- Scope: v0.10 S21, `arch-hyprland-v1`; depends on accepted S17 security/power authority

## Context and decision

S21 adds display topology, native brightness and UDisks2 removable-media effects to the reference workstation experience while reusing S17 managed session power. Native provider *discovery* is not mutation authority. Control Center, Quick Settings, OSD, keyboard, CLI/SDK and agent proposals are invocation/presentation paths over the **same trusted Control-owned operation semantics**, not competing executors or policy planes.

Each supported effect must use a registered trusted operation whose class, risk floor, provider, observation capability, exact resource identity, material keys, authenticated principal, postcondition and failure/recovery semantics are independently reviewed. Providers return bounded authoritative observations; they cannot supply operation classes, approvals, grants or executable plans. Unknown, unqualified, substituted or stale effects fail closed.

The companion `contracts/v010-s21-design.toml` is **inert proposed design data**, not a runtime operation registry. Candidate names and risk classifications require separate implementation/native security review before registration or activation. A proposed ADR, a passing component fixture and implementation code do not qualify a native effect, S21 completion, Q11 physical evidence or release support.

Native session/seat/boot/provider generation must be freshly attested; connector names, EDID, D-Bus paths, disk labels, `/dev/sdX`, UID strings and correlation IDs are not authorization evidence. All privileged, durable, security-sensitive or ambiguity-sensitive effects use the canonical managed lifecycle; transient effects require an independently proven, unprivileged and at-most-`UserState` envelope. ShellBridge remains an unprivileged presentation client. No arbitrary privileged shell, Hyprland command construction, unchecked sysfs writes, Polkit bypass, raw D-Bus forwarding or arbitrary mount options are allowed.

## Scope and existing ownership

The existing Linura Shell has a power plugin, Control Center, Quick Settings, and the presentation-only compiled `org.linura.ShellBridge`. Existing S17 managed session power and native locked-session coverage must be reused. Platform discovery can identify the Hyprland compositor and UDisks2 provider, but these are not authoritative S21 effect adapters. The current source has no first-party display/storage shell plugins, typed display-layout authority, qualified physical brightness provider, or removable-storage mutation provider.

The S21 contract fixes shared boundaries before the domain implementations. Domain-specific positive/negative qualification is in `docs/qualification/v0.10.0-s21.md` and adversarial security requirements in `docs/qualification/v0.10.0-s21-security.md`. No candidate operation is executable until later trust-boundary and qualification review.

## Trust invariant

Every effect has exactly one *trusted* operation descriptor, risk floor, provider/observation scope, exact resource identity, allowed change keys, principal binding, and verification strategy. The client, plugin, policy proposal, imported config, agent, or provider cannot change the operation class or authorize privileged execution. An unknown operation, stale/ambiguous evidence, changed actor/seat, lost provider or missing compatible profile yields explicit unsupported/blocked/indeterminate state rather than a fallback effect. Never expose generic shell commands, unrestricted D-Bus method forwarding, arbitrary `hyprctl` expressions, sysfs paths, mount options or systemd commands as a Linura authority API.

For `ManagedExternalEffect`: request/observe/plan/validate/authorize/prepare/execute/independently verify/commit/audit/reconcile; retain exact plan/approval/generation through restart; no blind replay of indeterminate effects. `TransientExternalEffect` is eligible **only** after the domain proves unprivileged, at-most-UserState, nondurable semantics with Control-mediation, fresh post-effect evidence and durable attempt audit. Classifications here are conservative *candidate* floors, never runtime registrations. Versioned typed observations are authoritative only for the exact provider, resource and freshness window.

## Candidate provider/resource boundaries

### Display topology

Authoritative Hyprland output observation must bind the exact compositor instance, selected logind session, a complete active-output topology and individual connector generations. Connector names, enumeration indices and EDID strings can be useful correlation but are not unique authorization identities by themselves. A typed complete-layout plan includes enablement, chosen native mode/refresh, scale, transform, position and supported mirroring. Reject unsupported mode tuples, stale hotplug topology, duplicate/ambiguous connectors and any plan that could eliminate the only recoverable visible/secure output.

Treat topology changes as managed and **recovery-critical**. Prepare a bounded last-known-good recovery path independent of the potentially invisible QML interface; distinguish proposed, dispatched, independently verified, committed and indeterminate state. Where Hyprland lacks an atomic backend transaction, do not claim one; partial apply and lost acknowledgement require independent re-observation, and a timeout cannot finalize success. Native `ext-session-lock` coverage of every active output and exact lock generation must be preserved across hotplug and layout changes or the effect must fail closed. Freeze the actual pinned Hyprland version and its supported API before implementing the executor.

The implemented component boundary uses a typed `DisplayObservationFacts`
projection of the existing `linura-observation::ObservationEnvelope`; it adds
no second observation envelope or source authority. Its closed versioned fields
bind the complete output-generation inventory, exact advertised mode tuples,
enablement, geometry, scale, transform, mirroring and powered enabled outputs.
Canonical `LNDL:1` layout data is bounded, contains no control characters and is
validated against the complete native inventory before use as planner material.
It is not a compositor command, durable recovery journal or execution credential.
Unknown schema versions, extra/missing fields, aliases and unsupported native
precision fail closed. The read-only JSON adapter retains disabled-output mode
advertisements, mirroring and DPMS state, and rejects duplicate known fields.
Hyprland's rounded available-mode strings do not establish exact native mode
support when the current refresh tuple differs; do not round it into eligibility.

Read-only client discovery is the separate `AuthoritativeQuery`
`Authority1.GetOwnDisplaySnapshot`, surfaced through the SDK and no-model CLI.
It has no target/principal input and binds native owner/output evidence to the
authenticated caller's independent current local active logind epoch and seat.
Control schedules one probe of each mechanism, with their existing two-second
bounds and a four-second aggregate cap. Projection preserves the original
earlier sample time and earliest expiry; the report remains valid for at most
two seconds and may expire before it reaches the client. No cached fallback,
retry or partial report is returned. A complete report may have no powered
outputs and cannot satisfy mutation safety, secure coverage, approval or durable
recovery. The client receives typed generation-bound layouts and exact bounded
mode inventories, never a native handle, command or executable plan.

`PlanPreviewControl::plan_display_layout` coordinates separate display, logind
and security-owner observations and derives the canonical non-executable
`ReconciliationPlan`. Existing preview request limits, principal namespacing,
idempotency and retention bounds apply; the native lock target is part of the
normalized request. `DisplayLayoutSafetyReview` shares existing active-session
checks, requires the exact seat and independently bound topology/output coverage,
and retains only a last-known-good **candidate**. The earliest native expiry
bounds the review. Pure postcondition review requires newer timestamps and
sequences from every source, the retained lock generation, matching complete
layout and a powered independent output. It neither commits nor replays effects.

The private native owner now has a read-only `ObserveDisplay` probe. It retains
head/mode lifetimes on the same attested Wayland connection, gives recycled head
names new identities, and synchronizes bounded reads before and after the fixed
peer-checked Hyprland metadata query. A changed snapshot is rejected. Exact native
mode tuples and identities come from the pinned private integration, with live
upstream/source identity validation. A new owner adopts the same compositor UUID
and native output lifetimes for observation; reconnecting never acquires an old
attempt's apply or continuation right. Independent wlr inventory/geometry and
Hyprland metadata corroborate the sample. Rounded JSON mode strings cannot
manufacture support. Exact native thousandth scales require their original float
bits and matching independent 24.8 projection. Unknown precision fails closed.
Independent `ext-session-lock` acknowledgement and per-output committed
configure generations supply coverage facts; screen counts and diagnostic
acquisition milestones supply no coverage authority.

The Linux adapter projects these facts into the existing display envelope and a
distinct `session.display-coverage.observe` capability. Existing S17 lock-wire
semantics remain unchanged. Control registers the bounded observers and checks
independent logind/coverage facts for each display candidate. The complete typed
`LNDI:1` request binds the exact lock generation, last-good baseline and desired
layout. Generic canonical preview and durable authority candidate derivation use
the same display factory; there is no alternate provider-owned plan. Contributing
native deadlines are narrowed and their exact evidence digests enter Control's
authority binding. A changed baseline or loss of the final currently powered
independent output rejects mutation planning.

The trusted registry registers `operation:display.layout.apply` with managed,
security-sensitive semantics. The native transaction port consumes Control's
sealed effect, recomputes its descriptor from the retained complete intent and
hands the exact binding to the separately supervised root session executor.
Its fixed display action is default-deny; the dedicated authority identity must
also pass fresh service attestation before and after that policy check. Root
strictly validates native metadata and retains the same owner, boot, original
sample timestamp and digest through its single prepared owner handoff. The
owner independently rechecks the raw sample, native scope, per-output frames
and original deadline, then reserves one private compositor apply. Neither
correlation hashes nor a native reply are approval or postcondition evidence.

Typed Authority1 begin/confirm/revert, SDK and CLI contracts remain explicitly
unsupported until protected decisions, durable compositor-loss restoration and
native qualification are complete. Authority1 status is connected for retained
requests only: Control supplies the exact original dispatch digest and deadline
from validated durable history, independently observes and reconciles without
any apply or continuation. An adapter restart cannot guess correlation from a
transaction name or recreate an executor permit. Public display mutation stays
disabled until the complete execution/recovery contract passes pinned-runtime
and adversarial qualification.

The managed controller validates the entire reserved/dispatch/decision/terminal
chain before either status classification or continuation. Native attempt facts
cannot renew their freshness while independent verification runs. Verified
restoration uses a fresh invocation of the same canonical display planner to
prove the exact retained baseline, then closes the original desired-state
transaction in its existing `RecoveryBlocked` state. The desired layout did not
commit and cannot reprepare/replay; an immutable display `Restored` phase records
the compensated baseline separately. A crash between these writes reconciles
fresh facts and finishes bookkeeping without any apply. No released transaction
schema/state is reinterpreted as successful execution.

New display requests first enumerate a bounded, authenticated durable recovery
inventory. An unresolved Indeterminate or Verified display transaction fences its
seat across Control, owner or compositor replacement; a new request ID, native
idle state, missing reservation, elapsed client timeout, changed login owner or
new compositor invocation cannot release it. Scope comparison deliberately uses
the seat rather than the old volatile compositor/output handles. The historical
principal/request are joined to their exact durable anchor and validated phase
chain; they are data for observation, never a recovered approval or permit.

One prior request may be reconciled read-only before a new request seeks human
approval. Only existing fresh native-attempt, independent layout/coverage and
canonical verification can retire that prior authority. Unknown state stays
fenced. The new request then undergoes its own normal fresh review and prepare;
strict exclusion checks run again before handoff and dispatch. No unbounded
startup worker, effect retry or automatic Keep is introduced. Committed and
RecoveryBlocked authority is terminal: restoration retirement already required
independent proof before RecoveryBlocked, even if final journal bookkeeping was
interrupted. Observing those terminal facts does not assert current native state.

The persistence namespace query authenticates the complete store, then selects
bounded matching rows in the same BEGIN IMMEDIATE snapshot. Literal prefix
matching is not a caller-selected authority route; Control owns namespace and
recovery classification. Overflow, tampered excluded rows, malformed history or
inconsistent identity fail closed. This query adds no schema migration or new
persistent transaction state.

Before dispatch, Control captures an immutable, purpose-versioned
`linura.display.native-baseline.v1` record in the same authenticated request
journal. It binds the original request, transaction/generation, authority binding,
exact contributing observation digest and original native sample to the complete
baseline, prior overlay ownership and bounded native rule/identity digests. The
record is read back and validated before a permit is spent; missing, substituted,
oversized or inconsistent recovery data cannot reach the native effect. Its
historical timestamp is preserved: reading it after restart never refreshes an
observation, reconstructs approval or authorizes replay.

The ORIGINAL checkpoint's comparison digest travels with the one-use
`AuthorizedDisplayApplication` from Control to the admitted root executor and
original native owner. It covers the complete canonical baseline, sorted output
lifetimes, overlay ownership, base/identity digests and prior owned targets. These
facts already belong to the canonical plan's native findings and observation
binding; the digest is a refusal-only precondition, not a second executable plan,
approval or credential. Root's fresh strict projection must match it, and the
owner compares it again on its last retained snapshot before compositor apply.
The compositor validates that entire immutable snapshot before reservation and
continues fencing underlying rule/identity drift. A later native sample cannot
silently replace the original LKG ownership/configuration. Service/principal,
policy and managed handoff requirements are unchanged.
Independent restoration verification receives the ORIGINAL baseline guard, not
just numeric geometry. Control rechecks it against another fresh canonical
observation before durable retirement; even a verifier's satisfied flag cannot
override ownership/rule drift. Desired-layout verification separately requires
complete current Linura overlay ownership. These comparisons create no recovery
execution authority and cannot retarget a replacement compositor.

The pinned private native schema3 supplies mandatory ownership comparison data;
the protected owner hashes native rule and identity preimages before projecting
them into canonical observations. Canonical display schema2 has complete typed
recovery metadata for every exact output. Schema1 remains the independently
useful generic read-only monitor projection; it cannot qualify mutation capture.
Well-formed partial native geometry remains observable as read-only evidence
when a retained overlay target differs from actual state. Unknown or malformed
metadata is rejected. Automatic placement/scale and custom timing participate in
the rule digest; unrelated ICC/color/VRR/reservation fields do not. Digests and
EDID/connector facts do not prove authenticated physical continuity across
compositor replacement. This durable checkpoint alone cannot execute restoration
in a new compositor; that continuity and recovery path still require qualification.

Keep/revert is a separate protected human interaction over the already prepared
canonical display transaction. Control creates a sealed `DisplayDecisionChallenge`
from the retained request, authenticated principal, durable authority binding and
generation, dispatch record, fresh pending-attempt evidence, exact decision and
original deadline. It is a continuation projection, not another executable plan
or policy subject. Original apply approval, human caller provenance, a UID and
ordinary client confirmation cannot satisfy it. A non-cloneable consumed proof
must match that exact challenge. After interaction, Control acquires a newer
attempt sample and independently rechecks the desired layout before keeping it.
Changed facts, cancellation, proof substitution and expiration prevent dispatch.

Keep also revalidates the **original ChangeProposed canonical plan**, its trusted
operation registration, registered risk floor and source classifier revision,
current policy review, and live original administrator approval. This check runs
before interaction, after fresh native/layout verification, and after the durable
decision append before continuation. Planning against the already applied layout
would produce NoChange and cannot substitute for the original mutation review.
The bounded process-local review retains no observation envelope, executor handle,
permit or signer; it cannot issue another apply. Expired/revoked approval, changed
principal/policy/risk/review, missing retention or clock rollback deny Keep.
Losing this review or its approval state at Control restart leaves observation
and independently scoped restoration available; it cannot reconstruct Keep
authority from durable journal data. Native timeout restoration is still required.
The display risk binding records both the registered-floor and source classifier
revision. Existing persisted bindings are not rewritten or silently adopted.

Decision phases with consumed protected proof use the explicitly versioned
`linura.display.recovery-protected-decision.v2` framing around the unchanged v1
phase bytes and challenge digest. Other phases retain their existing encoding.
Legacy v1 decisions remain readable as retained data, but cannot be promoted to
protected decision authority: lifecycle admission reports independent recovery
required without rewriting, deleting or replaying them. Neither journal format
contains a reusable native proof or executor credential. A late durable append
cannot extend the native deadline.

The production continuation adapter consumes that sealed Control value and
retains the original deadline through `Executor.Session1.ContinueDisplayLayout`
and private `SecurityOwner1.ContinuePreparedDisplay`. It cannot choose another
layout, principal, reservation or new apply. The executor requires the current
independently supervised Control sender before and after the same default-deny
display service policy; the protected owner independently requires the current
supervised executor. Decision/challenge hashes are bounded comparison data, not
transport credentials or substitutes for protected human input. Ordinary/root
bus callers cannot reach either privileged effect path merely by copying them.

The owner rechecks the current session, settled independent lock state, exact
topology, input/surface coverage and original mechanism deadline. Keep additionally
requires the complete current desired layout, including mirror/disabled targets.
The original Wayland connection must still own its single decision reservation;
replacement owners may observe but cannot adopt it. Final wire admission checks
both wall and suspend-inclusive clocks against the ORIGINAL native dispatch, so
clock rollback, suspend or late IPC cannot extend it. Reservation is consumed
before writing. Denial, unknown phase and lost replies stay ambiguous; Control
only observes thereafter and requires independent verification before retirement.

This connected continuation is not activation evidence. Production mutation and
public Keep/Revert remain unsupported until actual native protected interaction,
compositor-loss restoration and full native qualification are complete. There is
no fallback from missing protected input to Polkit, original approval, ordinary
client confirmation or a local/root identity.

The native attempt gate and Qt watchdog are component mechanisms. They reserve
apply and baseline restoration separately before write construction, compare
both suspend-inclusive and wall-clock deadlines, retain fences on uncertainty,
and require fresh full-layout/coverage proof to clear recovery. An acknowledged
restore remains `Restoring`; an uncertain acknowledgement can be resolved by
independent baseline evidence without retry. Ordinary watchdog teardown cannot
silently remove an armed timer. These components remain unconnected to production
dispatch. A timer in one process does not establish recovery after that process
or compositor dies: independent recovery-owner integration and real crash
qualification remain mandatory before activation.

The candidate `keyword monitor` writer was removed before activation after
review of pinned upstream v0.56.2. Legacy `handleMonitor` constructs a new monitor
rule and `CMonitorRuleManager::add` replaces the prior named rule. Consequently
an apparently bounded layout write can also reset color, VRR, ICC or reserved
area settings outside the reviewed `LNDI:1` intent. The standard output-management
override preserves unrelated rule fields but supplies no mirroring request.
Finishing the native executor therefore requires a qualified typed mechanism
that preserves unmanaged fields while supporting every required layout effect;
merely restoring the string writer or treating mirrored geometry as mirroring is
not an acceptable activation path.

The S21-2 candidate therefore uses an exact-source integration into Hyprland
v0.56.2, pinned by `contracts/hyprland-display-integration.toml`. It introduces a
bounded private typed adapter, a compositor-owned BOOTTIME restoration timer and
a monitor-rule overlay preserving unmanaged fields. This is a static integration,
not a dynamically loaded plugin ABI. Component fixtures and source staging do
not qualify the integration. Actual private-header compilation, whole-compositor
linking, live build/protocol identity, native mutation/restoration and S17 coverage
must pass before activation or merge.

In-process compensation reserves the previous overlay ownership, underlying
owned-rule semantics and exact numeric baseline before its first native write.
It establishes a baseline independent root, revalidates native scope/rules, then
resumes the prior overlay or the native automatic rules. It does not synthesize
new explicit baseline overlays as the final restored state. A changed underlying
owned rule or replaced output refuses compensation; unrelated current rule
settings are preserved. Fresh numeric baseline geometry and native ownership
must both match before retiring the inhibitor/checkpoint. This volatile
checkpoint does not satisfy durable compositor-death recovery requirements.

The exact upstream hook transformations live in the native integration source
tree as `source_integration.py`. The shared owner/compositor CMake identity hashes
that recipe alongside the native implementation and protocol. Changing only a
hook therefore changes the live identity; matching the upstream commit alone is
insufficient. The stager executes this one repository-owned recipe, checks that
its bytes remain unchanged and retains its digest with the exact patched-file
manifest. Archive admission and build orchestration remain tooling. This source
binding is not a substitute for qualifying the actual immutable compositor
binary and its pinned SDK in the runtime guest.

The private native endpoint admits effects only from the kernel PID/UID of the
exact root-supervised protected owner launch. One 250 ms fixed system-bus probe
requires a root unique systemd owner, the immutable packaged service/image, no
drop-ins, exact numeric User/MainPID/ExecStart, active running state and a nonzero
InvocationID. A retained pidfd and repeated service/daemon evidence reject process
exit, PID reuse and replacement during the probe. Every explicit confirmation or
revert reattests the original invocation as well as the original connection.
Private-global binding checks the same admission before allocating a client
slot; ordinary same-UID clients cannot exhaust the protected-owner slots. An
admitted replacement owner can observe old reservations without acquiring any
continuation. No user service,
environment-selected bus, local/root caller exemption or POSIX SID assumption can
replace this evidence. Admission loss cannot stop automatic compositor recovery;
admission itself never substitutes for prepared canonical Control authority.

The compositor mechanism owns a native logind block inhibitor for both sleep and
shutdown before its first layout write. It verifies the canonical system bus,
root logind owner and both preparation facts under one 250 ms probe budget,
retains the CLOEXEC descriptor independently of clients, and rechecks the entire
captured snapshot and original clocks after acquisition. Native confirmation or
independently observed restoration can retire the inhibitor; an acknowledgement,
failed compensation or client loss cannot. This coordinates the pending mechanism
with native power without adding another power authority or force path. Compositor
death still requires durable Control reconciliation and cannot count as restored.

S17 release and power admission also observe the compositor-owned display fence
on the original attested connection. Fresh pending/restoring/failed reservations,
unknown coverage, source mismatch or a previously advertised integration becoming
unavailable refuse protected approval, lock release, transition fencing and the
pre-kernel sleep gate. A replacement owner has no local attempt object but still
observes that native fence. A compositor which never advertised the display
integration preserves the established S17 path; it has no supported Linura display
mutation mechanism. Probes run before final protected-input/proof-generation
checks because draining Wayland may deliver hotplug/configure events. They grant
no approval and never restore or replay effects. After that read, a secure owner
also requires every current lock surface's configured, committed and flushed
frame generation; the global acknowledgement alone cannot admit a transition
while a hotplugged output is awaiting configure. No keyboard focus is required
for this frame-only automatic-sleep check. Independently, both the normal
protocol unlock and forced-unlock hooks refuse to clear native locked state or
advance its security epoch while the compositor display reservation is fenced.
That compositor-thread guard closes the interval after the owner's last read.
The reservation becomes fenced before entering initial inhibition/modeset
callbacks, including the interval before the transaction object is published;
reentrant admission cannot see a false idle state during the first write.
These exclusions still require native overlap qualification and do not establish
per-output scanout/first-frame protection or compositor-death durability.

The native owner separately binds protected interactions to output configuration
and keyboard generations. Every active output needs a configured, committed and
flushed lock frame before input becomes eligible. Hotplug/resize cancels pending
text/compose/click state, and focus/keymap/capability replacement invalidates a
completed unconsumed proof. The existing Level A native authentication runner
exercises output hotplug during a real pending PAM unlock, requires denial and
the same retained lock generation, then requires successful fresh authentication.
The runner preserves distro lockout behavior and never enters a response into the
cancelled prompt. Implementing that case is not evidence that it has run.

Development readiness reuses `core`/`shell`/`editor`; `shell` already covers the
security-owner prerequisites, with full native CMake/CTest required separately.
The standalone `hyprland-build` inventory checks the source-pinned Arch SDK and
does not require Rust or QML editor tooling inside it. The SDK driver reuses the
existing disposable Arch substrate builder, native pacman signature protection
and guarded storage. A missing GLES3/library/ABI prerequisite belongs to S21-2,
not S21-7. No generic host installer may replace these pins with rolling packages
or downgrade a maintained host to satisfy the SDK check.

These are three build-readiness contexts, not a new environment or acceptance
hierarchy. Extend existing Level A for display execution, rollback, process loss,
hotplug and S17 lock coverage in S21-2. Preserve optional Level B and maintained
physical Level C/Q11 as defined by the existing acceptance contract. Full display
UI convergence remains S21-6; cross-domain and physical qualification remain
S21-7/release. General S17 historical-acceptance reconciliation is separate work.

### Native backlight

Bind a physical kernel/logind backlight device to exact active session, seat and device generation, plus native max/current values and qualified minimum. Favor the reviewed logind `Session.SetBrightness` route for the actual owner when the target profile and device permit it; a caller-supplied sysfs path or ambient privileged helper is never authority. Percentages, hotkeys and OSD are presentation mappings and must be verified against independent native state after effect. Lack of a physical backlight is `unsupported`, not permission to substitute software gamma or external DDC/CI. The proposed `SecuritySensitive` risk floor conservatively includes loss of visible access and does **not** permit a transient shortcut. The eventual executor requires reviewed owner permissions, managed authorization and recovery. Unsupported hardware remains read-only. Prevent sole-output blackout with a qualified minimum and recovery path.

### UDisks2 removable media

UDisks2 observation must identify drive, block, partition and filesystem relationships, actual mount state, physical children/siblings, D-Bus owner generation, supported functions and authenticated seat/session context. D-Bus paths, `/dev/sdX`, filesystem labels and serial numbers alone are not stable mutation identities. Native `Filesystem.Mount`, `Filesystem.Unmount`, `Drive.Eject` and `Drive.PowerOff` are distinct reviewed operations with independent availability, authorization, postconditions and recovery. Eject does not imply power-off; power-off does not imply physical ejection. Authorization uses the actual UDisks2/Polkit invoking subject, not an assumed privilege from Linura or root's `Can*` observations. Eject/power-off must account for other filesystems on a shared drive. No formatting, partitioning, forced/busy unmount, untrusted mount paths/options, break-glass bypass or data erasure is introduced.

Treat all privileged effects as managed. A successful D-Bus reply is not a verified mount or safe-eject state. Busy-device denial, device replacement/removal, service loss, delayed reply, partial cleanup and restart require bounded independent observation and no duplicate replay. No data-loss-prone recovery without explicit new authorization.

### Power and idle

S17 **already owns** registered lock/suspend/logout/reboot/power-off, native logind permissions, inhibitors, other sessions, secure suspend fence and durable indeterminate recovery. S21 must reuse those exact operation identities and authority routes, including subject-sensitive permission sampling; a new power executor, direct `systemctl` shortcut, root-origin permission substitution or inhibition bypass is prohibited. `block-weak` is a blocker. Idle configuration, observation, UX and shortcut policy may be added only as separately reviewed Linura-owned or managed semantics. Auto-destructive idle dispatch requires its own independently justified authorization and safety contract and is otherwise unsupported.

## Multi-interface convergence

ShellBridge and QML are unprivileged presentation only; typed queries, plans and receipts converge through Control. Quick Settings, Control Center, keyboard/OSD, supported CLI/SDK and accepted agent proposals must resolve identical operation IDs, resources and risk floors. Stale/unknown/blocked/pending/indeterminate/verified states must remain distinguishable. No optimistic success on timeout. Qualification must cover focus/keyboard/pointer, screen reader, reduced motion, overlay input regions, multioutput/HiDPI, offline provider and restart/reconnect, including no-AI mode.

## Qualification and release gates

Before S21 activation: review contracts and native API versions; build negative tests for stale session/seat/output/device identities, hotplug, screen blackout, failed rollback, ext-session-lock coverage, privilege substitution, malicious mount options, sibling-drive removal, busy media, lost dispatch reply and restart with uncertain effects. Use exact-source Level A Arch/Hyprland runtime and real UDisks2 guest observation/transactions. VM fixtures prove only their declared scope; simulated brightness is not real backlight hardware and virtual disks do not prove physical USB eject. Physical Q11 acceptance separately binds supported monitors/GPU/driver, actual backlight and removable media where claimed, input/accessibility, provider identities, and recovery. Video is supporting evidence, never the sole oracle.

Preserve inherited v0.4, v0.6, v0.9, S17/v0.10 CI and evidence gates. Never set S17 or S21 to complete, alter `interactive_workstation.evidence_ready`, promote release support, or mark physical cases passed on the basis of documentation, candidate contract, mocked adapter or completed implementation alone.

## Implementation sequencing and acceptance

S21 architecture/contracts -> S21-2 display -> S21-3 brightness -> S21-4 UDisks2 -> S21-5 power UX/idle -> S21-6 workstation convergence -> S21-7 native integration and qualification. Independent backend PRs can be developed in parallel after the trusted contract is stable, but integration/merge follows the S17 dependency and reviewed backend requirements.

S21 integration remains dependent on independently accepted S17 session security and power, exact-source negative qualification, recovery proof and protected merged-PR evidence. Proposed contracts and individual domain PRs cannot assert slice acceptance.

### Candidate protected display presentation

An unlocked display change must not acquire `ext-session-lock` merely to display
its authentication prompt. The pinned compositor candidate therefore provides a
separate, private `linura_protected_display_manager_v1` surface role and input
lifetime. Binding and every retained conversation step independently reattest the
same supervised native owner invocation. The role supplies no approval, principal,
policy decision, managed permit or display effect; Control remains the sole
canonical authority. S17's actual lock state remains independent.

The compositor candidate renders an opaque full-output scene containing only the
owned configured surface, excludes ordinary windows, IME, overlays, direct scanout
and the ordinary cursor, and gates physical input before capture/keybinding paths.
Existing plugins or a custom screen shader make protected presentation unsupported.
Virtual injection and unsupported absolute-pointer input do not become physical
confirmation. Hotplug, keymap/device replacement, native snapshot drift, foreign
focus, scope substitution, suspension or either original deadline invalidate the
conversation. Closing or losing its owner preserves S17 state and drains physical
held input before ordinary focus can return.

A buffer commit, configure acknowledgement or flushed frame cannot establish
readiness. The candidate uses accepted Aquamarine queued-commit IDs, separately
requires successful backend submission, and correlates an actual presented event
with hardware-completion evidence for every required output. Reused/wrapped IDs
fail closed across configure generations. Repaint cannot renew the original
scope, input epoch or deadline. Consumption is one-use comparison data; human
PAM authentication and final managed dispatch still require their independent
purpose-bound proof and revalidation.

This candidate scene is not yet connected to the production owner's protected
Apply/Keep/Revert conversations. Its component/wire tests and fresh private-header
compilation do not prove native presentation, modeset first-frame safety, durable
compositor replacement restoration or complete display acceptance. Production
mutations remain unsupported until those paths and their actual native tests are
complete. No S21-2 or release support is promoted by this implementation.

The owner-side candidate now binds that private global on its original exclusive
connection and creates separate configured opaque surfaces for each currently
enabled exact native output. It retains the original two-clock window, decodes
bounded scope/status generations, polls without renewing that window, fences
pending status replies before reserving one consumption, and denies foreign or
stale epochs. Its input guard uses private readiness while a display conversation
exists, independently of real S17 coverage. Cancellation destroys only the private
roles; an existing lock remains acquired until its established managed release.
The public display methods, PAM purpose binding and final execution receipt are
still not activated. Real client/server component cases exercise rendering and
one-use consumption both unlocked and already locked, using an explicitly
non-authoritative scene fixture; they do not qualify physical presentation or
human authentication. S21-2 still requires failure-input isolation, production
composition, native modeset/recovery and adversarial acceptance before enabling it.
