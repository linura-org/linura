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

D-Bus validation permits additive members but preserves every previously published method, signal, property, interface annotation, argument shape and member annotation. JSON Schema, CLI and Rust SDK contracts currently use a conservative same-generation comparison: once Stable, their checked contract artifact is immutable until a typed compatibility checker can prove a change is backward-compatible.

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

### Authority1

`org.linura.Authority1` is a distinct Experimental **system-bus managed-authority** contract introduced for the bounded v0.6 effect. Its registry entry is:

- ID: `dbus.org.linura.Authority1`;
- kind: `dbus-interface`;
- version: `1`;
- stability: `experimental`;
- canonical ABI: `interfaces/dbus/org.linura.Authority1.xml`.

The v0.6 method `ConvergeSystemdActiveState` is deliberately narrower than the internal executor protocol. It accepts the exact bounded active-state request and returns one structured receipt. `Authority1` does not expose generic `Apply`, shell execution, arbitrary systemd methods or an executor-forwarding surface.

Any later widening to new mutation domains requires an explicit architecture/contract decision and must not be smuggled into generation 1 merely because an internal executor gains a new method.

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

## Coherent-change requirement

For Experimental D-Bus changes, these must remain coherent in the same candidate:

- implementation-generated/live introspection;
- checked-in `interfaces/dbus/*.xml`;
- `contracts/stability.toml`;
- D-Bus contract tests;
- security/architecture documentation;
- packaging D-Bus policy where access semantics change;
- release notes when the change is user/integrator relevant.

A live method not represented in canonical XML, or XML that does not match live signatures, is contract drift and fails qualification rather than being explained away as Experimental flexibility.
