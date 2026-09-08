# ADR 0028 — Proposal-only agent interpretation

**Status:** Accepted

## Context

v0.8 introduces natural-language and agent-assisted interpretation. The model/provider boundary is useful only if it remains structurally incapable of bypassing Linura's existing deterministic authority chain. Model output is probabilistic, may be malformed or adversarial, can be based on stale context, and may contain instructions that falsely claim approval or executable authority.

v0.7 already provides durable intent and Library state. v0.6 already provides the bounded managed-mutation lifecycle. v0.8 therefore needs an interpretation layer that feeds those existing contracts instead of creating a second planning, policy, approval or execution path.

## Decision

Linura represents model-assisted interpretation as a typed, versioned `IntentProposal` that is always untrusted until deterministic validation and an independently authenticated and authorized acceptance operation.

### Canonical proposal envelope

The canonical proposal carries only proposal-domain data:

- schema version and stable proposal identity;
- the actor on whose behalf interpretation was requested as provenance, never authentication authority;
- normalized requested outcome and typed requirements;
- explicit capability references, assumptions and unresolved questions;
- bounded confidence/uncertainty metadata;
- provider, model and adapter identity without credentials;
- a digest-bound interpretation context containing a Control-minted authority-context revision and semantic input digest;
- non-authoritative explanation/advisory material;
- a canonical digest computed from the complete authority-relevant proposal representation.

The proposal cannot carry an authenticated principal, approval record, dispatch permit, privileged executor handle, policy decision or unrestricted command/tool request. Text that claims any of those things remains ordinary untrusted text.

### Context binding and staleness

Interpretation is requested against an explicit `InterpretationContextBinding` minted by trusted Linura Control from the authoritative state used to construct the semantic context projection. The binding contains an opaque Control-owned context revision plus a canonical digest over the minimized semantic projection supplied to the interpreter.

Trusted Control, not the agent runtime, constructs that projection. Before the projection crosses into the agent runtime, Control resolves the allowed semantic inputs, removes secret-bearing fields and values, and records the authority sources/revisions and observation identities required to later revalidate acceptance.

The agent runtime, client and provider may transport or echo that binding, but none of them may mint or advance authoritative freshness. At acceptance, Linura Control must:

1. re-read or re-resolve every authority-bearing observation, policy, Library object, capability-registry entry and existing-intent dependency relevant to the proposal;
2. re-check time-based observation freshness with trusted Control time, including provider/resource/capability validity windows that may expire even when no revision changes;
3. reacquire authoritative observation where required freshness has expired, or fail closed if fresh authoritative evidence cannot be established;
4. derive the current authority-context binding from that fresh/current material; and
5. require an exact match with the proposal binding.

An unchanged revision/digest is therefore insufficient when an observation has aged outside its validity window. Replaying an old but internally consistent binding fails closed when any authority-bearing dependency changed or when required observation freshness expired.

Provider-local timestamps, model confidence, caller-generated revisions and client assertions are not substitutes for the Control-owned binding or Control-owned freshness evaluation.

### Provider-neutral contract

Provider adapters implement a transport-neutral interpretation interface. The request contains bounded, data-minimized semantic input, actor provenance, the Control-minted context binding and explicit resource/output budgets. The response contains a structured proposal candidate and provider metadata. Provider-specific HTTP, RPC, model, streaming, tool-call and authentication details do not enter the canonical intent model.

The untrusted agent runtime never receives raw secret-bearing Library, observation, retrieval or user context for the purpose of filtering it itself. Trusted Linura Control constructs the complete provider/runtime projection first and excludes secret values, privileged tokens, authority credentials and other protected secret-bearing fields before that projection crosses into the agent runtime. Where semantics require a secret dependency, only a protected reference/handle or explicitly non-secret metadata may cross the runtime/provider boundary. A hosted adapter must never receive a secret merely because the caller included it in retrieved context or Library data.

Adapters declare whether they require network access and which interpretation protocol/schema versions they support. Offline mode must never invoke a network-required adapter.

### Bounded execution and failure semantics

The runtime owns provider selection, timeout/cancellation policy, retry admission and aggregate budgets over the already-minimized request. A provider receives no implicit retry authority. Provider failure, timeout, cancellation, malformed output or budget exhaustion produces no authoritative intent mutation.

The runtime validates the complete provider result before exposing it as a validated proposal. Partial/streaming fragments never become proposals.

### Manual operation

Agent-native does not mean agent-dependent. A deterministic manual interpreter path accepts already-typed user input and constructs the same validated `IntentProposal` contract without a model provider or network dependency. Manual construction does not weaken the later authenticated-principal, Control-context, registry or authorization checks.

### Advice and disagreement

Specialists/advisors return separately attributed advisory records. Advice is never silently merged into authority-bearing proposal fields. If multiple advisors disagree, the conflict remains explicit and reviewable. Agreement between providers is not authorization.

### Acceptance boundary

Acceptance is a separate trusted Control operation. Proposal fields are evidence/input only; they do not authenticate or authorize the caller. Acceptance must:

1. validate proposal schema, version and canonical digest;
2. obtain the authenticated `Principal` from the trusted transport/session boundary and verify that principal independently of the proposal's actor provenance;
3. validate the claimed actor provenance against the authenticated request context without treating actor equality as authorization;
4. re-establish all required current authority material and time-based observation freshness inside Control, reacquiring authoritative observations where freshness expired;
5. derive the current authority-context binding inside Control and require an exact match with the proposal binding;
6. resolve every capability reference against the current Control-owned local capability registry, failing closed if the registry, capability or support state is unavailable or unsupported;
7. reject contradictory, ambiguous, stale, substituted or otherwise unsupported proposal material;
8. require the applicable Control-owned human/policy acceptance decision and prove that the decision is exact-bound to the authenticated principal, canonical proposal ID/digest, accepted Control context binding, durable operation identity, requested create/revise action, and exact create/revise target identity/revision expectation;
9. convert the accepted proposal into a normal `Intent` in `Proposed` state; and
10. atomically persist the intent transition together with an exact proposal-acceptance record before reporting success.

The acceptance decision cannot be reused for a different proposal, context, operation or target merely because the principal and high-level action are the same. Changed proposal digest, context binding, operation identity, create/revise target or expected revision requires a new applicable acceptance decision.

The durable acceptance record must bind at least the authenticated principal, acceptance-decision identity and decision-binding digest, proposal ID, canonical proposal digest, accepted Control context binding, durable operation identity, create/revise action and target identity/revision expectation, resulting `IntentId`, and resulting intent revision. Exact retry of the same acceptance is idempotent and returns the same result. Reuse of the same proposal/operation/decision identity with different bound material fails closed as a conflict. A lost response after commit therefore cannot create a second intent, replay authorization onto substituted proposal content, or erase proposal-to-intent provenance.

This requires a dedicated v0.8 acceptance transaction/path built on the v0.7 durable Library/idempotency substrate; calling the pre-existing `create_intent` operation alone is not sufficient evidence of proposal acceptance.

Acceptance itself grants no machine-mutation approval or execution authority. Any later machine mutation still traverses the existing observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile lifecycle.

### Secret and diagnostic boundary

Provider credentials remain adapter-private. Trusted Control excludes secret values, privileged tokens, authority credentials and protected Library/observation/retrieval/user fields before an interpretation projection crosses into the agent runtime. Only protected references/handles or deliberately non-secret projections may be supplied when needed for semantics.

Canonical requests/proposals and public errors contain no credential material. The runtime bounds diagnostics and exposes stable error categories without copying arbitrary provider response bodies, prompts or secret-bearing context into audit/state surfaces.

## Consequences

- `linura-intent` owns the canonical proposal types, validation and digest semantics.
- `linura-agent-runtime` owns deterministic interpretation orchestration and manual operation over an already-minimized Control-produced projection, but not projection minimization, freshness, capability-registry or acceptance authority.
- `linura-provider-sdk` owns provider-neutral adapter contracts, not model authority.
- Linura Control owns authenticated-principal binding, trusted projection construction/minimization, current authority-context derivation, time-based observation-freshness revalidation, capability-registry resolution and the applicable exact-bound acceptance authorization decision.
- the durable Library acceptance path owns the atomic exact proposal/decision-to-intent idempotency/provenance record while preserving the v0.7 durability model.
- provider implementations may be local, hosted or enterprise-managed without changing the canonical proposal/authority model.
- v0.8 can be qualified with deterministic mock/replay adapters without depending on a live external model service.
- adding autonomous tool or executor authority in a future release requires a new explicit authority decision; it cannot be inferred from this ADR.

## Non-goals

This decision does not add autonomous execution, generic tool use, policy administration, approval authority, a privileged agent daemon, hosted synchronization or a supported machine/platform profile.
