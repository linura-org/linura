# Security model

## Trust boundaries

Linura treats experience surfaces, models, local callers, the unprivileged authority runtime, durable Control authority and the root executor as distinct trust zones.

For the v0.6 bounded managed effect, the concrete trust path is:

```text
untrusted content / future model output
                  │
          IntentProposal/advice only
                  │
                  ▼
         local human/client caller
                  │
                  │ system-bus message
                  ▼
       org.linura.Authority1
                  │
      authenticated unique sender
                  │
      human Polkit authorization
                  ▼
       linura-authorityd
       (unprivileged,
    linura-authority identity)
                  │
       linura-control authority
       + durable SQLite/WAL state
                  │
       exact prepared handoff
                  ▼
      separately authorized root
      linura-executor-systemd
                  │
          native systemd API
                  ▼
              systemd
                  │
       fresh independent observation
                  ▼
        verifier / recovery logic
                  │
       commit → audit → reconcile
```

A compromised model provider or future agent is expected to be capable of proposing malicious intent. That must **not** be equivalent to compromise of the authority plane. v0.6 adds no agent mutation authority.

## v0.6 Authority1 caller boundary

The Experimental v0.6 public mutation entry point is:

- service `org.linura.Authority1`;
- path `/org/linura/Authority1`;
- interface `org.linura.Authority1`;
- method `ConvergeSystemdActiveState`.

The transport obtains the unique system-bus sender from the authenticated message metadata. Caller identity is not accepted as a caller-supplied method parameter. A sender must be a canonical D-Bus unique name before it can be translated into an OS principal.

The human authorization action is:

`org.linura.authority.manage-systemd-active-state`

Only after that authorization succeeds does `linura-dbus` construct human provenance for the exact request and delegate semantics inward to the authority runtime. D-Bus authentication and Polkit are therefore transport/OS authorization boundaries; they do not own planning, persistence or recovery policy.

“Local” is never equivalent to trusted. Root/administrator identity also does not mean the caller may bypass the canonical managed path.

## Human approval is not executor authority

The original caller's Polkit decision authorizes continuation of the exact Authority1 request. It is not a bearer token and is never forwarded as authority to the root executor.

The supported managed executor action is separately default-deny. Product policy grants the bounded managed executor path only to the dedicated `linura-authority` service identity. Ordinary users and administrators therefore cannot use `org.linura.Executor.Systemd1` as a shortcut around Control.

This separation prevents an OS approval check from collapsing:

- request validation;
- deterministic planning;
- policy/approval binding;
- durable prepare;
- pre-dispatch revalidation;
- recovery state;
- independent verification;
- verified commit and reconciliation.

## Privileged executor rules

Every privileged executor must:

- own one narrow effect domain;
- authenticate its operating-system caller at the transport boundary;
- independently authorize that caller for the exact executor action;
- validate identifiers, arguments and deterministic bindings again at the privilege boundary;
- receive only the bounded effect/correlation material required for dispatch;
- perform no general orchestration, planning, policy evaluation or natural-language interpretation;
- expose no arbitrary command/shell endpoint;
- expose no generic native-service proxy;
- use native system APIs where available;
- classify dispatch outcome conservatively;
- never claim that dispatch acknowledgement proves final machine state;
- remain separately sandboxed/hardened and security-reviewed.

For v0.6 the product effect is limited to canonical `linura-managed-*.service` units and exactly the desired states `active` or `inactive`, implemented with native systemd `StartUnit(..., "replace")` / `StopUnit(..., "replace")` calls.

The executor protocol may contain qualification/history operations in addition to the bounded product operation, but that does not widen the public Authority1 capability. Production D-Bus/Polkit policy remains part of the security boundary.

## IDs and digests are not capabilities

Operation IDs, request/transaction IDs, generation numbers and request/plan/effect/dispatch digests provide deterministic identity, correlation and anti-substitution evidence. Possession of those values does **not** grant execution authority.

For v0.6 a stable `operation_id` maps to `request:v06:<operation_id>`. The exact canonical request is independently checked against its durable `request_digest`.

- exact retry reuses the durable transaction;
- changed content under the same operation ID fails closed with `RecoveryRequestMismatch`;
- a changed request does not inherit prior approval or produce a second durable transaction for the same stable operation identity.

## Durable handoff and crash ambiguity

External execution is treated as potentially ambiguous. Before dispatch, Control durably crosses the prepared handoff boundary. If execution or transport becomes uncertain after that point, the transaction remains `Indeterminate`; restart must not reconstruct dispatch permission or blindly issue the effect again.

One-shot authority is process-local and exact-bound. Durable state is evidence/recovery state, not a serializable executor credential.

Recovery must acquire fresh authoritative evidence. `FreshRecoveryApproval` is minted only after constructing the exact fresh recovery candidate and is bound to that same candidate, preventing approval time-of-check/time-of-use substitution. Conflicting recovery evidence blocks progress instead of overwriting ambiguity.

## Verification is independent from execution

Executor acknowledgement proves at most dispatch classification. It is not authoritative post-state.

The v0.6 authority runtime composes a fresh native-systemd observation path for verification. The verifier consumes expected postcondition plus canonical observation; it does not consume the executor receipt as proof of success.

A transaction cannot reach durable `Committed` merely because the root service returned success. The intended postcondition must be independently observed/verified and the exact durable recovery/commit invariants must succeed first.

Post-commit reconciliation performs another independent check and deterministic planning to prove convergence (`NoChange`). It does not replay the original effect.

## Agent/model rules

- model output is untrusted data;
- agents emit typed `IntentProposal`/advice, not executable code;
- agent context is least-privilege and minimized;
- secrets use references/handles and are excluded from general prompts by default;
- prompt injection from web/files/repository content cannot create authority;
- tool/model/provider identity does not substitute for OS actor identity;
- sensitive mutations require Control policy/approval regardless of model confidence;
- agents never receive privileged executor handles;
- offline/no-model behavior remains a required security/recovery path.

`contracts/components.toml` additionally marks agent components as proposal-only future surfaces until their roadmap milestones. Workspace presence is not authority. See [ADR 0025](adr/0025-component-maturity-and-milestone-activation.md).

## State integrity

The v0.6 authority path uses durable SQLite/WAL transaction state with integrity/recovery checks. Durable storage is authoritative for Linura's control records, not for current Linux machine truth.

Observed state is always re-derived from authoritative Linux providers when truth matters for planning, execution eligibility, verification or recovery. Storage corruption, write uncertainty, stale evidence and conflicting machine state fail closed.

Broader intent/graph/provenance persistence remains subject to its own milestone/migration requirements; v0.6 does not claim every future persistence domain is complete merely because the authority transaction store is durable.

## D-Bus policy is part of the security boundary

The canonical interface XML, system-bus policy, Polkit actions/rules, runtime introspection and stability registry must agree.

v0.6 explicitly distinguishes:

- `Authority1`: public Experimental managed-authority entry point for the one bounded effect;
- `Executor.Systemd1`: privileged internal/qualification executor service, not a public general-purpose mutation authority;
- `Control1`: existing non-privileged planning/query lineage.

The obsolete broad root Polkit policy outside the canonical packaging path is removed; production authorization comes from the bounded packaged policy/rules reviewed with the corresponding service identity.

## v0.5 historical boundary and v0.6 integration

v0.5 qualified an isolated systemd executor and pure verifier without wiring product mutation authority. That release claim remains historically true. See [ADR 0021](adr/0021-v0.5-isolated-executor-verifier-qualification.md).

v0.6 is the first candidate to integrate the complete eleven-stage lifecycle for one bounded Experimental effect. The exact process, identity, approval, recovery and non-goal decisions are recorded in [ADR 0026](adr/0026-bounded-v0.6-managed-mutation-authority.md).

This integration does **not** convert v0.5's qualification-only user/rules or restart fixture namespace into production authority.

## Remote/fleet security

A future fleet gateway is a separate process/service with mutual authentication, explicit enrollment, revocation, replay resistance, scoped device identity, staged rollout and its own threat model. No remote listener is added to `linurad` or `linura-authorityd` as a shortcut.

v0.6 makes no remote/fleet, supported-distribution or supported-hardware security claim.

## Security qualification requirement

The v0.6 claim requires both deterministic fault/recovery tests and a disposable real-system qualification using systemd, system D-Bus, Polkit and SQLite/WAL. Required negative evidence includes ordinary/direct-executor denial, wrong namespace/state rejection, request substitution rejection, stale/failed verification, executor loss/ambiguity, crash/restart without blind replay and conflict blocking.

Trusted Release Proof must rerun the exact-source v0.6 qualification before sealed release build/promotion. A green unit suite alone is insufficient security evidence for the managed effect.
