# API and contract stability

Linura treats **contract version** and **contract stability** as independent axes. A name such as `Control1`, `Authority1` or `*.v1.schema.json` identifies a contract generation; it does not, by itself, make that contract Stable or frozen.

`contracts/stability.toml` is the machine-readable source of truth. Public machine-readable artifacts also embed lifecycle metadata where appropriate so contributors, tooling, SDK authors and automated reviewers see the same status where the contract is defined.

## Stability levels

### Experimental

Experimental is the default while Linura is pre-1.0 unless a contract is explicitly promoted.

- Breaking changes are allowed when they improve architecture or remove an obsolete design.
- No overlap window or deprecation shim is required.
- A breaking change must update implementation, checked-in contract, schemas, in-repository clients/SDKs, tests, documentation and stability registry coherently in the same change.
- Compatibility shims must not be retained merely because an earlier development commit or Experimental release exposed a shape.
- Security, authority, provenance, validation, resource bounds and fail-closed behavior remain mandatory; Experimental does not mean careless.
- Experimental generation numbers such as `Authority1`/`Control1` must never be described as Stable solely because they contain `1`.

### Preview

Preview is for contracts intentionally exposed to named early adopters/design partners.

- Breaking changes remain possible but require a migration note and explicit release-note disclosure.
- Avoid gratuitous churn and preserve compatibility when inexpensive.
- Promotion is explicit in `contracts/stability.toml`; it is never inferred.

### Stable

Stable is a deliberate compatibility commitment.

- Existing semantics and wire shapes are preserved within the same contract major generation.
- Breaking changes require a new major contract/interface, overlap window, migration documentation and compatibility tests.
- Promotion requires an ADR or equivalent design record, a supported release, compatibility coverage and explicit registry metadata (`since` and `compatibility`).
- Stability is never inferred from a `v1` filename, `Control1`/`Authority1` suffix, public visibility, age or prior inclusion in an Experimental release.

## Historical enforcement

Stable compatibility is checked against an accepted historical tree, not only metadata in the current checkout. The canonical validator selects the pull-request merge base (or previous protected-main commit) and enforces that a Stable contract cannot be removed, downgraded or rewritten in place under the same generation.

D-Bus validation permits additive members but preserves every previously published method, signal, property, interface annotation, argument shape and member annotation. JSON Schema, CLI, Rust SDK and Python SDK contracts currently use a conservative same-generation comparison: once Stable, their checked contract artifact is immutable until a typed compatibility checker can prove a change is backward-compatible.

Protected CI fetches full Git history so historical comparison cannot silently degrade into current-tree-only checking. Source archives/specialized tooling can provide an explicit prior tree with `--baseline-root`; CI/local Git workflows can override baseline discovery with `--baseline-ref` or `LINURA_CONTRACT_BASELINE_REF`.

## Product SemVer and contract generations

Product versions and contract generations solve different problems. Linura may ship `v0.x` releases containing `Control1`, `Authority1` and `*.v1.schema.json` contracts that remain Experimental. A contract may later be promoted independently without renaming it merely because its stability changed.

## Durable state is different

Experimental wire APIs may be replaced, but persisted authority/user state, migration records, audit/provenance records and durable evidence must never be silently reinterpreted or discarded. Persisted-format changes require explicit versioning, migration handling, validation and recovery semantics regardless of wire/API stability.

A wire breaking change also must not make old durable rows become executable credentials or alter the meaning of already-audited authority history.

## Promotion procedure

1. Identify the exact registry entry in `contracts/stability.toml`.
2. Document real consumers and compatibility requirements.
3. Add migration/compatibility tests appropriate to the target level.
4. Record promotion rationale in an ADR or release contract.
5. Update registry and artifact-local lifecycle metadata atomically.
6. Run `cargo xtask check` plus applicable integration/acceptance evidence.
7. For mutation/authority contracts, include privilege-boundary and recovery compatibility analysis; wire compatibility alone is insufficient.

Downgrading a Stable contract is not an acceptable substitute for versioning a breaking change.

## Contract families and authority meaning

### Control1

`org.linura.Control1` is the established Experimental non-privileged local control/planning/query lineage. Its generation number does not imply mutation authority.

### Python package

The `linura` PyPI distribution is an Experimental non-privileged client-package
surface. Package SemVer and Linura D-Bus contract generations are independent axes.
The initial `0.0.1` Python surface exposes project/Control1 metadata and local
`linuractl` discovery only; it does not connect to D-Bus, execute the CLI, or add
mutation authority. Its source contract is registered as `python.linura` so any
future Stable promotion requires the same explicit compatibility process as other SDKs.

### Authority1

`org.linura.Authority1` is a distinct Experimental **system-bus managed-authority** contract introduced for the bounded v0.6 effect. Its registry entry is:

- ID: `dbus.org.linura.Authority1`;
- kind: `dbus-interface`;
- version: `1`;
- stability: `experimental`;
- canonical ABI: `interfaces/dbus/org.linura.Authority1.xml`.

The v0.6 method `ConvergeSystemdActiveState` is deliberately narrower than the internal executor protocol. It accepts the exact bounded active-state request and returns one structured receipt. `Authority1` does not expose generic `Apply`, shell execution, arbitrary systemd methods or an executor-forwarding surface.

Any later widening to new mutation domains requires an explicit architecture/contract decision and must not be smuggled into generation 1 merely because an internal executor gains a new method.

The in-progress S17 decision is recorded in ADR 0042. Its distinct
`ConfigureProtectiveLock` method changes only owner-authenticated Linura-local
consent, not external session/power state. Its epoch and request-status queries
return retained provenance only; they expose no policy/executor credential or
native protection assertion. The method is not a generic configuration/apply
surface, does not activate automatic locking, and remains Experimental pending
completion of S17's managed protective route and native qualification.

### Executor.Systemd1

`org.linura.Executor.Systemd1` is Experimental but is a privileged internal/executor contract, not the public policy authority surface. Its stability entry permits coherent pre-1.0 evolution, subject to privilege/security review and live-introspection/checked-XML consistency.

## Milestone contract posture

### v0.1.0

Linura v0.1.0 is Experimental. `org.linura.Control1`, Rust SDK/CLI and checked-in JSON Schemas may evolve coherently until explicitly promoted. The Control1 contract is authenticated read-only observation; obsolete pre-stable mutation compatibility stubs are not part of it.

### v0.2.0

v0.2.0 remains Experimental. `Control1` adds deterministic, evidence-bound plan-preview operations. `execution_authorized=false` is part of that boundary and there is no public apply operation or Stable compatibility promise.

### v0.3.0

v0.3.0 remains Experimental. `Control1` extends the observation/non-executable planning lineage with plan-review/explanation operations. Risk, policy outcome, approval requirement and semantic provenance are authority evidence only; they do not create an executable token.

D-Bus caller authentication does not make UID 0 or another local identity equivalent to trusted human/admin approval.

### v0.4.0

v0.4.0 remains Experimental. Durable authority transaction/recovery structures become real local persisted state, but no supported external mutation API is introduced. Process-local one-shot handoff semantics are deliberately not serialized into the public wire contract.

Persisted-state changes have stronger migration/recovery obligations than the Experimental API label alone would imply.

### v0.5.0

v0.5.0 remains Experimental. `Executor.Systemd1` is qualified as a separately privileged component with a qualification-only restart operation and independent verifier. That does **not** add product mutation semantics to `Control1` or make the executor a public general-purpose API. See ADR 0021.

### v0.6.0

v0.6 remains Experimental. It introduces `Authority1` generation 1 as the first bounded public managed-mutation transport, limited to converging canonical `linura-managed-*.service` units to `active`/`inactive` through the complete authority lifecycle.

The released milestone makes no Stable compatibility promise for:

- `Authority1` wire shape;
- `Executor.Systemd1` wire shape;
- CLI/SDK mutation helpers if/when exposed;
- component maturity contract schema;
- internal durable implementation details beyond their documented persistence/migration safety obligations.

The existence of a successful v0.6 managed effect does not authorize broadening `Control1`, `Authority1` or the SDK into generic Linux apply surfaces. Any later Stable promotion requires the normal registry/compatibility process and evidence appropriate to the promoted scope.

### Private native security owner

`org.linura.SecurityOwner1` is an Experimental private system-bus adapter for the
S17 security-owning process, not a public client apply/authentication API. It
separates exact-scoped approval interaction/consumption, independent native lock
observation, prepared session-executor dispatch, verified release and Control's
durable commit acknowledgement. It exports on the owner's authenticated unique
connection; there is no caller-preclaimable per-user well-known service name.
Callers are freshly checked against supervised Control/session-executor identity,
not a supplied principal or a root UID alone. Its canonical XML, compiled Qt
metadata and typed codecs are checked together. Production composition and native
qualification remain required before S17 activation; the interface's generation
does not establish support or a Stable compatibility obligation.

Native connection discovery has no public API change. At most two whole
snapshots share the original two-second probe and aggregate 256-name limit.
Typed disappearance invalidates a whole snapshot; fresh discovery must retain
the original supervised UID/PID/invocation and final attestation. Unknown errors,
ambiguous endpoints and persistent churn remain failures, never partial authority.

`ObserveLock` returns a boolean only for settled native state. A consistent native
acquisition/release may return the fixed private `NativeTransitionPending` error;
ordinary authoritative queries still fail without a settled observation. Only
post-dispatch lock and suspend-coverage verification may await that typed state within Control's existing
bound. Other errors remain failures. `RetainedVerifiedRelease` rereads only the
same independently verified Released generation with fresh peer/compositor checks;
it cannot consume another release event, rotate a generation or authorize dispatch.
The canonical suspend postcondition also keeps a fresh typed
`PreparingForSleep=true` snapshot inconclusive within that existing bound.
It cannot complete or replay the transition. Unknown preparation/counter facts,
debug modes, changed identities and invalid freshness still fail closed; success
requires preparation to end, one completed native cycle and exact secure coverage.
Managed verification and planning's retained-completion review classify the
complete fresh native transition before requesting completion coverage. Known
pending preparation or an unchanged counter does not request that `ObserveLock`.
Only canonical `SecureCoverageRequired` requests an independent sample after an
exact completed cycle; that intermediate result is neither completion nor authority. Both original
envelopes are reviewed again at the current time after sampling. The existing
observation bounds remain unchanged, and required coverage errors remain failures.
Ordinary pre-dispatch safety review still requires its own fresh secure coverage.

The Linux transition adapter can also discard one mixed suspend sample when its
counter moves from the exact retained baseline to baseline+1 during the read.
Both debug-mode reads must be `none`, the original epoch must remain present,
and the final boot, root-attested logind owner and original two-second deadline
must all validate first. This internal `None` result contains no envelope,
sequence, timestamp or completion evidence. Only post-dispatch verification may
await a fresh sample within Control's existing settle bound. The ordinary
`Observer` query/planning contract still rejects the mixed sample. Transport
errors, extra cycles, malformed facts and identity or clock changes remain hard
failures; no failure-string matching authorizes a retry.

## Coherent-change requirement

The private `SleepGate1` wire shape remains unchanged. Its fixed helper now
irreversibly enters the local `linura-authority` UID/GID before connecting;
transport admission and native attestation require that effective identity.
Control still verifies the same root-supervised pre-start PID/invocation, current
immutable executable and arguments. The explicit root allow rule is removed,
and the handler independently rejects a root kernel UID. No compatibility
exception is retained for this Experimental route. This grants no lock/power
permission or executor credential and changes no persisted authority meaning.

For Experimental D-Bus changes, these must remain coherent in the same candidate:

- implementation-generated/live introspection;
- checked-in `interfaces/dbus/*.xml`;
- `contracts/stability.toml`;
- D-Bus contract tests;
- security/architecture documentation;
- packaging D-Bus policy where access semantics change;
- release notes when the change is user/integrator relevant.

A live method not represented in canonical XML, or XML that does not match live signatures, is contract drift and fails qualification rather than being explained away as Experimental flexibility.

The private Experimental `SecurityOwner1.ObserveDisplay` method is a read-only
native display probe, separate from `ObserveLock`. Its `(ssstssb)` structure binds
the exact native lock resource, compositor connection generation, seat,
suspend-inclusive sample time, bounded typed topology JSON, bounded native
monitor metadata and settled independently observed secure state. The Linux
adapter retains the original two-second probe deadline and projects canonical
`display.outputs.observe` and `session.display-coverage.observe` evidence.
The larger reply cap applies only to this exact private method for supervised
Control; existing methods and error replies retain their previous bounds.
Unknown schemas, incomplete inventories and mismatched independent facts fail
closed. This method creates no output configuration or execution authority.

The public Experimental display contract adds `BeginDisplayLayout`,
`GetDisplayLayoutStatus`, `ConfirmDisplayLayout` and `RevertDisplayLayout` on
Authority1. The begin request contains only a bounded operation label, complete
`LNDI:1` intent and semantic reason. The transport derives the principal and
rejects a foreign-session intent; clients cannot choose policy, trusted risk,
executor handles or a prepared plan. The single `(sssst)` receipt binds request,
transaction, topology, closed lifecycle state and the original confirmation
deadline. Unknown states, substituted requests and different wire shapes fail
client decoding. Pending, restored and confirmed remain distinct; historical
reports never assert current native layout or protection. Compositions without
the complete native admission/execution/recovery ports explicitly refuse these
methods. The current production composition remains unsupported; publishing the
contract is not activation or S21-2 completion.

The separate Experimental `GetOwnDisplaySnapshot` is an `AuthoritativeQuery`
with no input arguments. Its `(sstta(ttba(uuu)b))` report carries the lock
resource, complete canonical layout, original acquisition time/validity and
ordered output capability rows (handle, generation, disable capability, exact
mode tuples, power state). Control binds the native sample to the caller's
independent active local logind epoch/seat; the client validates the closed
shape, complete inventory and original expiry. Only this method has a 64 KiB
client reply budget; existing replies retain their 16 KiB limit. Discovery may
report no powered outputs and grants no mutation, coverage or approval authority.

The owner display projection uses private schema 4, binding the exact native
thousandth scale and its IEEE float bits to the independent wlr 24.8 projection,
with generation-bound ownership/identity digests and actual DRM device/connector
comparison data. Non-DRM outputs remain read-only for mutation qualification.
The pinned compositor's UUID/output lifetimes replace owner-generated display
identities. A missing/mismatched live source integration or inconsistent complete
inventory is unsupported. No schema-1 compatibility path supplies authority.

The separate private `ObservePreparedDisplay` method admits only the supervised
session executor and returns `((ssstssb)ss)`: the same bounded sample, a
length-framed SHA-256 content correlation and a separate private original-rule
preimage. This replaces the Experimental shape coherently; no old-shape shim
grants preparation. Rust checks the digest, typed complete
native inventory, original baseline, available desired options, visible recovery
output and independent per-output coverage before retaining this precondition.
The digest excludes probe time because it correlates two distinct native probes;
each conservative boot-clock deadline is checked independently. Neither a sample
nor its digest is approval or prepared dispatch authority. Only this exact
method/role pair receives the larger reply cap; errors and other endpoints retain
their existing limits. This read-only addition does not activate a display write.

The preimage has its own schema, exact upstream/integration identity, complete
native output/kernel bindings, original owned-rule bytes and prior overlays.
Private preimage schema 2 now uses `LNRL:2`: exact native selection index/order,
underlying and effective `LNDR:2` owned rules, explicit source kind (no wlr,
actual live wlr client or retained restored projection), committed fields and
the original integer refresh. A restored projection binds its original checkpoint
digest and never claims a live historical client. Fresh receivers/reservations
require version 2. Stored `LNRL:1` bytes retain their exact original interpretation
and bytes: its wlr flag means actual live-client presence, never a restored
projection. Historical reading cannot promote it to a new current observation or
reservation. Schema-1 rule-only durable preimages also retain their original
meaning and cannot qualify a complete new restoration observation.
The outer `LNRJ:1` framing and all existing byte limits remain unchanged.
Rust independently validates its canonical rule encoding and matches every row
against the sampled topology's hashes/ownership before retention. It stays out
of ordinary observations. The root executor reserves an immutable private
`LNRJ:1` checkpoint before native apply; file and directory durability must both
succeed. Storage work consumes the original probe/confirmation clocks, followed
by fresh revalidation. No stored bytes, digest or successful sync grants
restoration authority. Independent continuity, replacement recovery, terminal
verification and production activation remain incomplete.

`SecurityOwner1.ObserveDisplayAttempt` is a separate read-only Control probe.
Its `(sssst)` query carries the retained canonical intent and exact native
transaction/effect/dispatch/deadline correlation. The `(sssttub)` response binds
the current lock and topology, original transaction/deadline, conservative
BOOTTIME sample, closed native phase and settled lock state. Discovery, peer and
boot revalidation and the reply share the original two-second deadline. This
small reply retains the existing reply cap. No configure/keep/restore request is
sent, and reconnecting acquires no continuation right. The Rust adapter projects
only `display.layout-attempt.observe` into the canonical envelope; native phase
is neither independent layout verification, protected approval nor permission to
replay. Production dispatch and full recovery remain unqualified and unsupported.

The private Experimental `SecurityOwner1` display handshake additionally exposes
`ArmDisplayApproval`, `DisplayApprovalReady`, `ConsumeDisplayApproval` and
`CancelDisplayApproval`. Each takes the original `(sssssssu)` comparison scope,
complete material, bounded reason and original wall/BOOTTIME deadlines as `(sssssssu)sstt`, and
returns one boolean. Purpose 8 admits Apply; distinct purpose 11 admits a fresh
original-restoration review using complete bounded `LNRI:1` material. The latter
requires the separate non-retained administrator action
`org.linura.authority.restore-original-display-layout`. Legacy S17 methods
continue rejecting both display scopes. A retired readiness conversation returns the
fixed unavailable error rather than indefinite pending. Cancellation compares
the exact scope even after its deadline and cannot adopt another native owner or
cancel a newer conversation. These private methods create neither public mutation
support nor an executor credential. Keep/Revert must continue a retained original
transaction; they cannot enter through this initial display handshake. The native
protected protocol uses distinct Recovery purpose 3, with its original absolute
wall/BOOTTIME review bounds. Only the replacement's continuously healthy original
Root lease in recovery phase permits that private scene. Ordinary rendering,
scanout, lock release and Apply redemption stay fenced. Protected approval is
not a prepared restoration dispatch, terminal proof or release permission.

The private Experimental `DisplayProtection1.ReserveRestoration` takes one
bounded 16 KiB `ay` reservation, the exact absolute dispatch deadline (`t`) and
original native sample BOOTTIME (`t`), and returns one original-root-created Unix
endpoint (`h`). Runtime admission requires the exact supervised executor; Control
retains member-specific read access, including the bounded `ReadFinalization`
query described below. The reservation binds a
fresh execution binding and complete `LNRI:1` material, not an old Apply/Keep
approval. Typed `LNRR:1` files share the existing private quota and strict history
checks; original `LNRJ:1` and `LNRR:1` files are unchanged. The unconsumed
Experimental `LNRG:1` transfer is replaced by `LNRG:2`, containing the exact
reservation and a native-only projection of the same strictly validated original
source, the exact dispatch deadline and original sample BOOTTIME. A later native
sample cannot refresh that original admission window. Complete framing and a
final fresh-check marker precede fixed-size,
strictly increasing `LNRV:1` witness probes on that original Root endpoint. Both
the Root worker count and transfer/probe budgets are bounded. Serialized bytes,
old transfers or a replacement service cannot reconstruct the original endpoint.
The native recipient requires its kernel Root peer to match the continuously
held startup lease; input/render lifetime checks never block on a witness query.

Control's nonterminal restoration handoff uses canonical purpose-bound approval,
fresh prepare and one-use durable CAS, and reads back request/dispatch history
before calling its sealed complete-material restoration port. Repeated requests
never transparently dispatch again. No reply verifies/commits restoration or
releases a fence. Distinct private `Executor.Session1.RestoreOriginalDisplayLayout`
and `SecurityOwner1.RestoreOriginalDisplay` methods carry the fresh full material,
execution/sample bindings and one-use Root endpoint through consumed Recovery
redemption to the compositor's `restore_original` request. All in-repository
introspection, generated protocol clients and denial fixtures change together.
The native writer restores only owned source fields and exact prior overlays;
partial faults remain latched and every recovery fence remains held. Independent
terminal composition and native qualification remain unfinished; these private
changes create no public mutation support or qualification claim.

Original-protection observation schema 2 additionally carries a complete map of
expected restored source digests derived from the same immutable original
checkpoint; it does not rewrite durable checkpoint history. The optional
`original_restoration_presentation` event on the private display snapshot and
supervised-Control-only `SecurityOwner1.ObserveOriginalDisplayPresentation` method
expose a bounded post-write KMS/frame sample. The Linux adapter projects that
sample into the canonical `display.original-presentation.observe` envelope for
the exact recovery resource, including its complete output inventory and exact
checkpoint/transaction/effect/dispatch/source bindings. All in-repository native,
Rust, generated-protocol and introspection consumers change together. These
Experimental observations are neither execution credentials nor terminal release
permission. The observe-only Control reconciliation API commits the restoration
only after the same fresh canonical proof, including after restart; linked
original retirement and native/Root finalization remain separate required work.

The internal transaction signer adds a distinct terminal-only Verified compensation
resolution for the replacement-recovery crash gap. It preserves ordinary
Indeterminate-only recovery and all existing persistence formats. New SQLite
history explicitly uses `verified-compensated-v1`, retaining the prior verified
provenance while closing authority as RecoveryBlocked. Old readers reject the new
audit kind instead of misinterpreting it. No schema migration, historical event
rewrite, desired-state commit, public method or executor credential is introduced.
The linked Control/native terminal workflow remains required before activation.

The internal `retire_original_display_restoration` bookkeeping API joins the
restoration commit to its original authority through an immutable purpose-versioned
`linura.display.original-restoration-link.v1` journal record. It binds exact
principal, requests, snapshots, dispatches and checkpoint, preserves original
non-success/provenance and requires fresh canonical proof again before its CAS or
restart repair. Its returned receipt is historical correlation, with no public
D-Bus/SDK mutation activation or native/Root release authority. This additional
opaque journal payload does not reinterpret prior phase records or checkpoints.

The separate private Experimental `LNRF:1` material preserves the complete original
`LNRI:1` bytes and adds bounded terminal comparison bindings. Its purpose-separated
`finalize-original-display-restoration` SDK descriptor and
`linura.native-display.finalization-reservation.v1` adapter codec accept neither
old Apply nor restoration bindings. Complete material and its digest are
comparison data, not execution authority; they change no durable record.

The owner has a bounded private `LNRF:1` reader with a shared canonical core
fixture. It preserves complete nested restoration bytes, rejects original-purpose
correlations and foreign login epochs, and compares the restored layout/source
guard, exact current lock and post-write epoch against supplied current native
facts. Public aggregate encoding is bounded before allocation. This comparison
does not attest Root continuity or physical frames, arm a protected purpose or
release any protection. Existing Apply/Recovery scope parsers refuse these bytes.

The internal read-only `inspect_original_display_finalization` API returns an
expiring material/evidence report only after exact authenticated linked retirement
and a new independent canonical restoration proof. It reads history again after
probing, never repairs or appends history, and cannot issue a release credential.
Its initial same-lock scope refuses owner/generation changes. There is no new
public D-Bus/SDK method, production mutation support or native qualification claim.

The private Experimental `DisplayProtection1.ReadFinalization` takes a recovery
scope (`s`) and returns the complete immutable restoration reservation (`ay`),
closed phase (`u`) and optional terminal reservation (`ay`). It admits only the
freshly attested supervised Control process, shares the existing original-read
worker limit, and uses the ordinary 64 KiB reply limit and original two-second
probe budget. The current Root producer returns only phase 0 (`protected`) with
empty terminal bytes after checking live original witnesses and replacement
recovery admission before and after strict history readback. Unknown, duplicate,
corrupt or unsafe history refuses without repair or deletion.

The adapter emits the canonical `display.original-finalization.observe`
`ObservationEnvelope`; full restoration/terminal codecs and unchanged nested
restoration bytes are mandatory for future terminal phases. Reserved, quiesced,
retired and released-current are comparison states only, with no current Root
producer. A historical spent record cannot supply released-current admission.
Control's inspection matches these new Root facts to actual authenticated history
and joins the independent five-source proof without extending either expiry.
The report includes the canonical restoration postcondition digest, not a permit.

The internal `plan_original_display_finalization` API takes an operation ID,
authenticated restoration request reference and semantic reason. A separate
registered SecuritySensitive ManagedExternalEffect binds the single
`finalize_original` desired-state key to `display.original-finalization.observe`.
The desired value is the canonical `LNRF-SHA256:1` payload, with the existing
4 KiB generic attribute and 64 KiB normalized request bounds unchanged. Complete
bounded material is private context and must recompute that exact payload; the
SDK descriptor-from-payload helper validates only comparison syntax and scope.
Neither a client-authored digest nor raw material can establish the authenticated
history context. Planning repeats all independent probes and durable readback,
preserves provenance, returns a non-executable canonical plan and retires context
on every exit. Generic preview cannot establish its private context.

The internal `begin_original_display_finalization` API adds a separate typed
terminal authorizer/challenge and one-use prepared port. The challenge carries the
complete bounded material alongside its exact managed canonical digest binding;
old restoration/Apply/Keep/Revert/unlock/power approval cannot substitute. Fresh
history and all independent observations are reloaded after interaction, with
unchanged intent semantics and original contributor expiries required. Nested
observation IDs and later valid frame counters remain exact evidence in the
observation binding; they do not become different human intent.

The existing authenticated opaque journal retains complete material under
`linura.display.original-finalization-material.v1` (16 KiB maximum). A separate
`linura.display.original-finalization-owner.v1` record (1 KiB maximum) binds one
restoration to its terminal request/digest/material. Existing formats, quotas and
immutability remain unchanged. Exact readback of request/material/owner and
reserved/dispatched phases is required before the sealed port; history, owner and
the candidate's original freshness are checked again at handoff. Another operation
ID requires qualified supersession, which this API does not implement.

An existing prepared/dispatched request is observation-only, including after
persistence failure, rejected or lost native replies. Its receipt is retained
uncertainty, never independent completion or release authority. No native terminal
purpose, production executor/native release endpoint, public D-Bus/SDK facade or
production mutation support is activated by this Control component.
Never-dispatched Prepared authority still becomes Aborted at startup under the
qualified v0.6 recovery rule; this API refuses revival or redispatch.

### Session1 bounded transient-effect contract

`org.linura.Session1` is a distinct Experimental **session-bus transient-effect** contract introduced for the v0.10 workstation line. It is hosted by the same unprivileged `linurad` process and well-known session-bus service as Control1, but it is a separate object/interface and does not widen the historical non-executable Control1 method surface.

- ID: `dbus.org.linura.Session1`;
- kind: `dbus-interface`;
- version: `1`;
- stability: `experimental`;
- canonical ABI: `interfaces/dbus/org.linura.Session1.xml`.

The first method, `SetAudioOutputVolume`, accepts only a caller request identity, an exact numeric PipeWire output-node ID, an integer percentage in the bounded 0–100 range and a bounded semantic reason. The transport authenticates the session-bus sender and requires the sender's Unix UID to equal the UID owning the service connection. It delegates to `linura_control::TransientEffectControl`; Session1 owns no risk downgrade, policy decision, executor permit or verification shortcut. The default-output alias remains discovery-only so a moving default cannot become mutation authority. The concrete provider adapter binds the numeric resource to pre-effect `object.serial` and `node.name` evidence, and WirePlumber resolves and mutates that exact object in one helper event-loop callback before Control independently re-observes the postcondition.
