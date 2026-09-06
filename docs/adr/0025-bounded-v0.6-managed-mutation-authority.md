# ADR 0025 — Bounded v0.6 managed mutation authority and Authority1 boundary

- Status: Accepted
- Date: 2026-09-06
- Refines: ADR 0012, ADR 0019, ADR 0020, ADR 0021

## Context

ADR 0012 established one canonical eleven-stage mutation lifecycle. ADRs 0019 and 0020 established durable SQLite/WAL authority, exact reviewed bindings, fail-closed recovery and a sealed process-local handoff. ADR 0021 then qualified an isolated root systemd executor and an independent verifier without connecting them to product mutation authority.

v0.6 is the first milestone permitted to compose those pieces into one real external effect. The integration must not turn a narrow qualification component into a generic root service, must not make Polkit approval or deterministic digests into bearer authority, and must not allow executor acknowledgement to become proof of machine state.

The principal architectural question is therefore where caller authentication, human approval, durable Control authority, privileged execution and independent verification live once the complete lifecycle becomes real.

## Decision

v0.6 introduces exactly one bounded Experimental managed mutation capability: converging the active state of canonical `linura-managed-*.service` systemd units to exactly `active` or `inactive`.

A successful request follows the canonical sequence without reordering or skipping stages:

```text
request / intent
→ observe
→ plan
→ validate
→ authorize
→ prepare
→ execute
→ verify
→ commit
→ audit
→ reconcile
```

Failure or denial may stop the sequence early. Ambiguous execution is preserved durably and is never converted into success or automatically replayed merely because the caller retries.

### Public authority boundary

The v0.6 mutation entry point is the Experimental system-bus contract:

- service: `org.linura.Authority1`
- object path: `/org/linura/Authority1`
- interface: `org.linura.Authority1`
- stability contract: `dbus.org.linura.Authority1`, version `1`, Experimental
- method: `ConvergeSystemdActiveState`
- request: four strings carrying operation identity, canonical unit, desired active state and human reason
- response: one structured receipt with D-Bus signature `(sssssssssbas)`

`Authority1` is deliberately not a generic `Apply`, shell, command, file, package or arbitrary systemd-method interface.

### Transport, authority and process ownership

Responsibilities are split deliberately:

- `linura-dbus` owns the system-bus transport boundary: canonical unique-sender binding, OS caller identity lookup, the `Authority1` Polkit interaction, conversion to human provenance only after authorization, wire receipt encoding and service hosting. It does not own planning, persistence, systemd execution or mutation semantics.
- `linura-control` owns policy/query orchestration, lifecycle semantics, durable authority transitions and recovery rules. It remains the semantic authority rather than the D-Bus adapter or executor.
- `linura-authorityd` is the unprivileged v0.6 composition/runtime process. It owns protected local authority state/secrets, composes SQLite/WAL persistence, authoritative observation, `ManagedLifecycleControl`, the narrow executor client and the independent verifier, and hosts `Authority1` through `linura-dbus`.
- `linura-executor-systemd` remains a separately hardened root service. It performs only the exact bounded native systemd effect after its own authorization and argument/binding validation.
- `linura-linux-observation` remains the source of canonical native-systemd observation used for planning and verification. Executor output is never machine truth.

The `linura-authorityd` binary is intentionally a thin composition root; moving planner/policy/persistence semantics into it or systemd execution semantics into `linura-dbus` would create a second authority/domain layer and is rejected.

### Human approval and executor authorization are separate

An original human caller is authenticated from the system-bus sender and must pass the Polkit action:

`org.linura.authority.manage-systemd-active-state`

Successful human approval authorizes the authority service to continue evaluating the exact request; it is not a credential that can be presented directly to the root executor.

The managed executor action is separately default-deny and production policy grants the bounded executor path only to the dedicated `linura-authority` service identity. Ordinary users and administrators therefore cannot bypass Control by calling the supported managed executor operation directly.

Transaction IDs, generation numbers and request/plan/effect/dispatch digests remain correlation and anti-substitution evidence. None is bearer authority.

### Stable operation identity and request substitution

A stable v0.6 `operation_id` maps to the durable request namespace:

`request:v06:<operation_id>`

The canonical request body is independently checked against the durable `request_digest`. An exact retry reuses the durable transaction and must not dispatch the effect again. Reusing the same operation ID with changed request content fails closed with `RecoveryRequestMismatch`; it does not allocate a second transaction or inherit authority from the earlier request.

### Freshness, verification and commit

Planning and verification require authoritative current observation. The authority runtime composes verification independently from execution and does not feed an executor receipt into the verifier.

The root executor may prove only dispatch classification. Durable `Committed` state is reachable only after the intended postcondition has been independently observed and verified, the exact durable generation has progressed through recovery/verification correctly, signer-authorized commit succeeds, and audit/reconciliation invariants are satisfied.

Reconciliation after commit performs fresh verification/planning and proves that the managed state converges to `NoChange`; it does not replay the original effect.

### Indeterminate execution and recovery

A durable handoff moves the transaction into an execution-ambiguous state before external dispatch. If process loss, transport loss or ambiguous executor behavior occurs after handoff, restart must not reconstruct one-shot dispatch authority or blindly execute again.

Recovery constructs one exact fresh candidate and only then mints `FreshRecoveryApproval` against that same candidate. Approval must not be generated for one observation and consumed against a different recovery candidate. This closes the recovery approval time-of-check/time-of-use gap without relaxing freshness or binding requirements.

Conflicting recovery evidence blocks progress. Intended-effect-absent recovery may make the transaction eligible for a newly prepared attempt, but a new explicit invocation and a newly minted one-shot handoff are required before another dispatch.

## Exact v0.6 capability boundary

The supported v0.6 external effect is limited to:

- provider: systemd;
- canonical resource namespace: `systemd:unit:linura-managed-*.service`;
- operation: set active state;
- desired states: exactly `active` or `inactive`;
- native effect: systemd `StartUnit(unit, "replace")` or `StopUnit(unit, "replace")`.

No shell command, arbitrary executable, environment, filesystem path, package operation, network/storage mutation, arbitrary unit type, generic D-Bus call or caller-selected systemd method crosses the executor boundary.

## Release and qualification consequence

The complete lifecycle claim requires both deterministic fault qualification and disposable-system qualification. Unit/in-process tests are not substitutes for a real systemd/D-Bus/Polkit/SQLite guest, and a real guest happy path is not a substitute for deterministic recovery/fault coverage.

Trusted Release Proof must require the permanent v0.6 qualification before sealed build/promotion. `linura-authorityd` is therefore a release artifact covered by checksums, SBOM, byte reproduction and published-release verification.

## Explicit non-claims

This decision does not introduce:

- generic Linux mutation authority;
- generic systemd administration;
- arbitrary shell/command execution;
- package, file, network or storage authority;
- agent/model execution authority;
- unattended agent mutation;
- multi-resource atomicity;
- a supported Linux distribution, machine class or hardware profile;
- a Stable mutation API.

v0.6 remains Experimental.

## Consequences

### Positive

- The first real effect uses the same canonical authority lineage that was previously qualified in pieces.
- Human approval, durable Control authority, root execution and independent verification remain distinct trust decisions.
- Stable operation identity becomes restart-safe without allowing request substitution.
- Crash/ambiguity handling is conservative and cannot create duplicate effects by replaying stale authority.
- The public mutation surface is smaller than the internal executor protocol and cannot be widened accidentally by adding executor methods.

### Costs

- The authority path is intentionally more complex than a direct privileged RPC.
- Exact-source VM qualification and recovery testing are mandatory for the bounded claim.
- New mutation domains require their own bounded contracts, policy and verification evidence rather than reusing `Authority1` as a generic apply surface.

## Rejected alternatives

### Put the managed method on Control1/linurad

Rejected for v0.6. The existing Control1 lineage is non-privileged planning/query transport. The first real managed effect requires a separately reviewable system-bus authority runtime and OS authorization boundary without silently converting the older client surface into privileged mutation authority.

### Let Polkit approval authorize the executor directly

Rejected. Human approval and executor dispatch are different decisions. Directly passing human approval to the root service would collapse Control policy/revalidation/recovery into an OS authorization check.

### Put systemd execution in linura-dbus or linura-control

Rejected. Transport must remain adapter-only and semantic Control must remain independent of concrete privileged subsystem adapters.

### Retry indeterminate execution automatically

Rejected. Once external dispatch may have occurred, replay can duplicate effects. Recovery must re-observe, preserve ambiguity and require a new exact authority path when another dispatch is actually safe.
