# Capability composition

Users request capabilities, not implementation trivia. A capability blueprint describes what a machine can provide and how that capability composes with others.

Relations include `requires`, `provides`, `conflicts`, `replaces`, `recommends`, and `optional`.

Example:

```text
development.ai
 ├─ requires development.python
 ├─ requires compute.gpu
 ├─ recommends containers
 └─ optional notebooks
```

The solver produces a deterministic resolution. Missing requirements and conflicts are explicit blockers rather than invitations to guess.

## Declarative resource contributions

Resolved capabilities contribute **typed desired resources**, not command strings. Each resource contribution names:

- the authoritative observation provider;
- the resource identity;
- the observation capability used to establish current state;
- a normalized map of desired state attributes.

Multiple capabilities may contribute compatible attributes to the same resource. If two selected capabilities demand different values for the same resource attribute, deterministic desired-state compilation fails closed instead of selecting one implicitly.

Semantic origin is added when a capability contribution is compiled for an intent, so desired resources retain the intent, requirement and contributing-capability identities that explain why the state is wanted.

## Authority boundary

Capability composition and planning remain non-authorizing. The v0.2 planner contract still produces a canonical non-executable `ReconciliationPlan`; later releases add authority **around that exact plan** rather than teaching blueprints to execute.

Since v0.6, Linura has one narrowly qualified managed external effect through the canonical authority lifecycle. v0.10 adds trusted `OperationClass` semantics and requires public effect operations to resolve through registered typed operation descriptors. A capability blueprint therefore cannot:

- carry arbitrary privileged shell text;
- grant executor or policy authority;
- self-declare a weaker operation class or risk;
- bypass fresh authoritative observation or deterministic planning.

The trusted operation registry/domain contract plus Linura Control decide which class-specific authority path is valid after planning. Capability composition describes **what should exist**; it never becomes an alternate execution backend.
