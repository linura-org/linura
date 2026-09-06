# Policy and identity

Linura separates authenticated authority identity, human approval, service-to-executor authorization and request provenance. None of those concepts substitutes for the others.

## Principal

The **principal** is the authenticated authority identity used to namespace and bind policy, review and approval state. A transport derives it from trusted credentials; clients, agents and imported artifacts cannot self-assert it.

A change of principal creates a different review subject even when the plan contents are otherwise identical.

For local D-Bus authority surfaces, the system-bus sender is obtained from authenticated message metadata and resolved to the operating-system principal. Caller-supplied method fields never replace that binding.

## Actor provenance

The **actor** is immutable request provenance carried into the canonical plan:

- `Human`: human-initiated request.
- `Service`: local service/automation request.
- `Agent`: AI/agent-originated proposal or request.
- `Remote`: authenticated remote-origin provenance for future remote surfaces.

Actor kind does not itself grant authority. In particular, `Human` does not mean approved, `Service` does not mean trusted to mutate, and `Agent` can never self-authorize.

## Policy subject

Policy evaluation consumes a review subject derived by Linura Control from the canonical `linura-planner::ReconciliationPlan`. It binds at least:

- authenticated principal;
- request and plan identity;
- actor provenance;
- provider, resource and capability;
- semantic provenance;
- exact authoritative evidence identity and material;
- prospective/trusted risk classification;
- deterministic changes/findings and blocked state;
- policy identity and revision through the evaluation binding.

Clients and transports do not construct a second policy-specific plan.

## Decisions

Policy produces one deterministic outcome:

- `Allow`;
- `Deny(reason)`;
- `RequireApproval(class, reason)`;
- `Blocked(reason)`.

Unknown, malformed, unsupported or structurally blocked state fails closed. `Blocked` is distinct from a policy denial: it means the plan is not valid review material and cannot become approvable merely by selecting a more privileged approver.

## Approval binding

Approval evidence must be usable only for the exact review binding that produced the requirement. A different principal, plan, request, authoritative evidence material, provider/resource/capability, risk-policy provenance or policy revision invalidates reuse. Expiry and revocation are checked by Linura Control using trusted current authority state/time.

Most importantly:

```text
policy allow       != execution authority
valid approval     != execution authority
reviewed plan      != prepared mutation
prepared mutation  != reusable executor credential
executor receipt   != verified machine state
```

The milestone progression preserves that separation: v0.3 established review-only policy/approval, v0.4 durable prepare/recovery authority, v0.5 isolated executor/verifier qualification, and v0.6 integrates the first bounded Experimental managed external effect through the complete lifecycle.

## v0.6 Authority1 human approval

The Experimental `org.linura.Authority1.ConvergeSystemdActiveState` path authenticates the original system-bus caller and requires the fixed human Polkit action:

`org.linura.authority.manage-systemd-active-state`

That decision answers only whether the original caller may submit the exact bounded managed request into Linura's authority lifecycle. Human approval is converted into exact Control-owned review/approval provenance inside the trusted authority service; it is not forwarded as a root-executor credential.

A stable v0.6 `operation_id` maps to one durable request identity, and the exact canonical request body is independently bound by a durable request digest. Reusing the operation ID with changed content fails closed rather than inheriting prior approval or transaction authority.

## v0.6 executor authorization

The root `linura-executor-systemd` service performs a separate authorization decision for the managed action:

`org.linura.executor.systemd.set-active-state`

Product policy defaults that action to deny and grants it only to the dedicated unprivileged `linura-authority` service identity. An ordinary user or direct root/admin caller does not become authorized merely by being local, privileged, or previously approved by Authority1.

This executor authorization proves only that the dedicated service identity may invoke the already-bounded privileged mechanism. It does not prove that a request was freshly observed, planned, policy-approved, durably prepared or safe to replay; those remain Control lifecycle responsibilities.

## Durable authority and handoff

Before external dispatch can occur, Linura Control revalidates the exact current principal/review/evidence/policy/approval material and crosses the current durable generation from `Prepared` to `Indeterminate`. The winning in-process handoff authority is generation-bound, one-shot, non-serializable and non-reconstructible.

Durable identifiers, generation numbers, state versions and digests are correlation/integrity material. They cannot be used as bearer authority by a restarted process or a different caller. Recovery from `Indeterminate` therefore requires fresh authoritative observation and never blindly recreates a prior dispatch permit.

## Grants

Future grants are scoped authority associated with authenticated principals, for example read or proposal capabilities. A scope such as `package.plan` must never imply `package.apply`. Grants require explicit policy treatment, bounded lifetime/revocation semantics where applicable, and cannot bypass exact plan/evidence review binding or the canonical managed-mutation lifecycle.

Agents/models remain proposal-only and cannot receive a grant that silently turns model output into privileged execution authority.
