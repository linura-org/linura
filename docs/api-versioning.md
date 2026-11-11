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

The Experimental `GetOwnNativeBacklightCandidate` method is a read-only
own-session diagnostic with no request arguments and one `(ssuuu)` reply:
session resource, native device name, maximum, requested and actual native
brightness. Its transport retains the original unique sender and PID separately
from provenance, with the authenticated bus GUID. A bus restart cannot reuse
that sender on a different bus generation. The native probe requires broker-provided live `ProcessFD`,
matching UID/PID and the exact active local Wayland session epoch; unsupported
broker/kernel evidence fails closed. The acquisition, native reads and final
identity checks share one original suspend-inclusive two-second deadline.
This reply has no timestamp, approval, protected worker proof or executable
brightness permission. No wire compatibility shim or production write is added.

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


### Session1 bounded transient-effect contract

`org.linura.Session1` is a distinct Experimental **session-bus transient-effect** contract introduced for the v0.10 workstation line. It is hosted by the same unprivileged `linurad` process and well-known session-bus service as Control1, but it is a separate object/interface and does not widen the historical non-executable Control1 method surface.

- ID: `dbus.org.linura.Session1`;
- kind: `dbus-interface`;
- version: `1`;
- stability: `experimental`;
- canonical ABI: `interfaces/dbus/org.linura.Session1.xml`.

The first method, `SetAudioOutputVolume`, accepts only a caller request identity, an exact numeric PipeWire output-node ID, an integer percentage in the bounded 0–100 range and a bounded semantic reason. The transport authenticates the session-bus sender and requires the sender's Unix UID to equal the UID owning the service connection. It delegates to `linura_control::TransientEffectControl`; Session1 owns no risk downgrade, policy decision, executor permit or verification shortcut. The default-output alias remains discovery-only so a moving default cannot become mutation authority. The concrete provider adapter binds the numeric resource to pre-effect `object.serial` and `node.name` evidence, and WirePlumber resolves and mutates that exact object in one helper event-loop callback before Control independently re-observes the postcondition.

### Proposed physical backlight resource

The Experimental, unregistered S21-3 backlight contract uses one exact resource
shape: `backlight:physical:<boot-uuid>:<uid>:<session>:<created-monotonic-us>:<device-generation-uuid>`.
`BacklightResourceId` validates the existing canonical `SessionEpoch`, a valid
non-root UID and a nonzero canonical generation UUID. Earlier development
examples with an arbitrary suffix were never qualified executable resources and
receive no compatibility alias. A syntactically valid UUID does not attest a
physical device; the future trusted inventory must independently establish
non-reused lineage and bind seat, provider invocation, qualification revision
and native bounds in canonical observation/plan evidence.

The proposed fixed effect data contains only the exact resource and native value.
Risk review, administrator approval and a descriptor grant no dispatch authority:
the live registry and sealed managed route remain disabled. Backlight durable
recovery permits only observe-only resolution; approval-based reprepare is
rejected without resetting the consumed attempt. No existing persisted format,
registered operation, public D-Bus shape or Stable contract changes.
