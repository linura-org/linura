# ADR 0028 — Proposal-only agent interpretation

**Status:** Accepted

## Context

v0.8 introduces natural-language and agent-assisted interpretation. The model/provider boundary is useful only if it remains structurally incapable of bypassing Linura's existing deterministic authority chain. Model output is probabilistic, may be malformed or adversarial, can be based on stale context, and may contain instructions that falsely claim approval or executable authority.

v0.7 already provides durable intent and Library state. v0.6 already provides the bounded managed-mutation lifecycle. v0.8 therefore needs an interpretation layer that feeds those existing contracts instead of creating a second planning, policy, approval or execution path.

## Decision

Linura represents model-assisted interpretation as a typed, versioned `IntentProposal` that is always untrusted until deterministic validation and explicit acceptance.

### Canonical proposal envelope

The canonical proposal carries only proposal-domain data:

- schema version and stable proposal identity;
- the actor on whose behalf interpretation was requested;
- normalized requested outcome and typed requirements;
- explicit capability references, assumptions and unresolved questions;
- bounded confidence/uncertainty metadata;
- provider, model and adapter identity without credentials;
- a digest-bound interpretation context containing the authoritative-context revision and semantic input digest;
- non-authoritative explanation/advisory material;
- a canonical digest computed from the complete authority-relevant proposal representation.

The proposal cannot carry an approval record, dispatch permit, privileged executor handle, policy decision or unrestricted command/tool request. Text that claims any of those things remains ordinary untrusted text.

### Context binding and staleness

Interpretation is requested against an explicit `InterpretationContextBinding`. The binding contains a caller-supplied context revision plus a canonical digest over the semantic context projection that was provided to the interpreter. Acceptance must re-prove the same context binding, or reject the proposal as stale.

A context revision is an opaque Linura-owned token. Providers may echo it but cannot create authoritative freshness. Provider-local timestamps or confidence scores are not substitutes for the caller-owned binding.

### Provider-neutral contract

Provider adapters implement a transport-neutral interpretation interface. The request contains bounded semantic input, actor identity, context binding and explicit resource/output budgets. The response contains a structured proposal candidate and provider metadata. Provider-specific HTTP, RPC, model, streaming, tool-call and authentication details do not enter the canonical intent model.

Adapters declare whether they require network access and which interpretation protocol/schema versions they support. Offline mode must never invoke a network-required adapter.

### Bounded execution and failure semantics

The runtime owns provider selection, timeout/cancellation policy, retry admission and aggregate budgets. A provider receives no implicit retry authority. Provider failure, timeout, cancellation, malformed output or budget exhaustion produces no authoritative intent mutation.

The runtime validates the complete provider result before exposing it as a validated proposal. Partial/streaming fragments never become proposals.

### Manual operation

Agent-native does not mean agent-dependent. A deterministic manual interpreter path accepts already-typed user input and constructs the same validated `IntentProposal` contract without a model provider or network dependency.

### Advice and disagreement

Specialists/advisors return separately attributed advisory records. Advice is never silently merged into authority-bearing proposal fields. If multiple advisors disagree, the conflict remains explicit and reviewable. Agreement between providers is not authorization.

### Acceptance boundary

Acceptance is a separate deterministic operation. It:

1. validates proposal schema and canonical digest;
2. re-proves actor and context binding;
3. validates referenced capabilities against a caller-supplied local capability set;
4. rejects unsupported, contradictory or stale proposal material;
5. converts the proposal into a normal `Intent` in `Proposed` state;
6. hands that typed intent to the existing durable v0.7 persistence/idempotency path.

Acceptance itself grants no approval or execution authority. Any machine mutation still traverses the existing observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile lifecycle.

### Secret and diagnostic boundary

Provider credentials remain adapter-private. Canonical requests/proposals and public errors contain no credential material. The runtime bounds diagnostics and may expose stable error categories without copying arbitrary provider response bodies into audit/state surfaces.

## Consequences

- `linura-intent` owns the canonical proposal types, validation and digest semantics.
- `linura-agent-runtime` owns deterministic interpretation orchestration and manual operation.
- `linura-provider-sdk` owns provider-neutral adapter contracts, not model authority.
- provider implementations may be local, hosted or enterprise-managed without changing the canonical proposal/authority model.
- v0.8 can be qualified with deterministic mock/replay adapters without depending on a live external model service.
- adding autonomous tool or executor authority in a future release requires a new explicit authority decision; it cannot be inferred from this ADR.

## Non-goals

This decision does not add autonomous execution, generic tool use, policy administration, approval authority, a privileged agent daemon, hosted synchronization or a supported machine/platform profile.
