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
- a digest-bound interpretation context containing a Linura Control-minted authority-context revision and semantic input digest;
- non-authoritative explanation/advisory material;
- a canonical digest computed from the complete authority-relevant proposal representation.

The proposal cannot carry an authenticated principal, approval record, dispatch permit, privileged executor handle, policy decision or unrestricted command/tool request. Text that claims any of those things remains ordinary untrusted text.

### Context binding and staleness

Interpretation is requested against an explicit `InterpretationContextBinding` minted by trusted Linura Control from the authoritative state used to construct the semantic context projection. The binding contains an opaque Control-owned context revision plus a canonical digest over the minimized semantic projection supplied to the interpreter.

Linura Control, not the agent runtime, constructs that projection. Before the projection crosses into the agent runtime, Control resolves the allowed semantic inputs, removes secret-bearing fields and values, and records the authority sources/revisions and observation identities required to later revalidate acceptance.

The agent runtime, client and provider may transport or echo that binding, but none of them may mint or advance authoritative freshness. At acceptance, Linura Control must:

1. re-read or re-resolve every authority-bearing observation, policy, Library object, capability-registry entry and existing-intent dependency relevant to the proposal;
2. re-check time-based observation freshness using trusted Control time, including provider/resource/capability validity windows that may expire even when no revision changes;
3. reacquire authoritative observation where required freshness has expired, or fail closed if fresh authoritative evidence cannot be established;
4. derive the current authority-context binding from that fresh/current material; and
5. require an exact match with the proposal binding.

An unchanged revision/digest is therefore insufficient when an observation has aged outside its validity window. Replaying an old but internally consistent binding fails closed when any authority-bearing dependency changed or when required observation freshness expired.

Provider-local timestamps, model confidence, caller-generated revisions and client assertions are not substitutes for the Control-owned binding or Control-owned freshness evaluation.

### Provider-neutral contract

Provider adapters implement a transport-neutral interpretation interface. The request contains bounded, data-minimized semantic input, actor provenance, the Control-minted context binding and explicit resource/output budgets. The response contains a structured proposal candidate and provider metadata. Provider-specific HTTP, RPC, model, streaming, tool-call and authentication details do not enter the canonical intent model.

The untrusted agent runtime never receives raw secret-bearing Library, observation, retrieval or user context for the purpose of filtering it itself. Linura Control constructs the complete provider/runtime projection first and excludes secret values, privileged tokens, authority credentials and other protected secret-bearing fields before that projection crosses into the agent runtime. Where semantics require a secret dependency, only a protected reference/handle or explicitly non-secret metadata may cross the runtime/provider boundary. A hosted adapter must never receive a secret merely because the caller included it in retrieved context or Library data.

Adapters declare whether they require network access and which interpretation protocol/schema versions they support. Offline mode must reject a selected or registered network-required adapter **before adapter invocation or transport initialization**. Provider discovery, selection, health checks or fallback logic must not make a network-required adapter observable in offline mode through connection attempts, authentication, DNS, socket setup or provider callbacks. Deterministic qualification must be able to prove zero adapter invocations for this case.

### Bounded execution and failure semantics

Linura Control owns provider discovery/eligibility, provider selection, cross-adapter scheduling, aggregate deadlines and budgets, timeout/cancellation policy, retry admission, fallback/advisor scheduling, caching/coalescing and cross-provider aggregation over the already-minimized request. Control issues one bounded per-attempt invocation to the runtime. The runtime may mechanically enforce only that Control-supplied attempt deadline/cancellation/budget, invoke only the Control-selected adapter, and return that attempt's result; it must not autonomously select another adapter, retry, fallback, reset or widen budgets, cache/coalesce across providers, or aggregate provider/advisor results.

An adapter owns only the transport mechanics needed to carry that single admitted provider invocation. It must not internally retry, reissue or start a replacement/resume provider request after timeout, rate limit, transport failure or partial response. It returns the bounded failure to Control, and every repeated provider invocation requires a fresh Control admission against the still-authoritative aggregate budget and deadline. A provider receives no implicit retry authority. Provider failure, timeout, cancellation, malformed output or budget exhaustion produces no authoritative intent mutation.

Within one Control-admitted attempt, the runtime validates the complete provider result before returning a proposal candidate. Partial/streaming fragments never become proposals. Canonical proposal validation remains owned by `linura-intent` and trusted admission/aggregation decisions remain owned by Control.

### Manual operation

Agent-native does not mean agent-dependent. A deterministic manual interpreter path accepts already-typed user input and constructs the same validated `IntentProposal` contract without a model provider or network dependency. Manual construction does not weaken the later authenticated-principal, Control-context, registry or authorization checks.

### Advice and disagreement

Specialists/advisors return separately attributed advisory records. Linura Control owns cross-advisor scheduling, selection, aggregate budgets and deterministic combine/select/reject policy; the runtime returns bounded per-attempt advisory results and cannot silently initiate or aggregate additional advisors. Advice is never silently merged into authority-bearing proposal fields. If multiple advisors disagree, the conflict remains explicit and reviewable. Agreement between providers is not authorization.

### Acceptance boundary

Acceptance is a separate trusted Linura Control operation. Proposal fields are evidence/input only; they do not authenticate or authorize the caller. Acceptance must:

1. validate proposal schema, version and canonical digest;
2. obtain the authenticated `Principal` from the trusted transport/session boundary and verify that principal independently of the proposal's actor provenance;
3. validate the claimed actor provenance against the authenticated request context without treating actor equality as authorization;
4. re-establish all required current authority material and time-based observation freshness inside Linura Control, reacquiring authoritative observations where freshness expired;
5. derive the current authority-context binding inside Control and require an exact match with the proposal binding;
6. resolve every capability reference against the current Control-owned local capability registry, failing closed if the registry, capability or support state is unavailable or unsupported;
7. reject contradictory, ambiguous, stale, substituted or otherwise unsupported proposal material;
8. require the applicable Control-owned human/policy acceptance decision and prove that the decision is exact-bound to the authenticated principal, canonical proposal ID/digest, accepted Control context binding, durable operation identity, requested create/revise action, and exact create/revise target identity/revision expectation;
9. enter the authority-internal durable acceptance transaction and acquire its write/CAS serialization guard before the final authority check;
10. while that durable guard is held, revalidate the complete current context/freshness/capability/decision binding using monotonic fail-closed trusted Control time, normalize every time-limited authority input to its exclusive first-invalid Control instant, compute the earliest normalized authority-validity deadline, capture the current trusted-time sample as the sealed authority-time floor, and fail closed if any authority generation, target revision, freshness requirement, decision applicability or time-bounded authority has drifted or expired;
11. mint a transaction-scoped sealed acceptance-commit capability exact-bound to the acceptance material, durable transaction identity, authority generation, trusted-time floor and normalized exclusive authority-validity deadline;
12. consume that capability through the authority-internal Library acceptance primitive without releasing or reacquiring the durable guard; immediately at the intent+acceptance-record write/CAS linearization, mechanically sample trusted Control time and abort/roll back unless `time_floor <= now < deadline`; any backward/rollback sample below the sealed floor is an authority-clock failure and must never revive otherwise expired authority; and
13. atomically persist the resulting normal `Intent` in `Proposed` state together with the exact proposal-acceptance record before reporting success.

#### Authority-validity deadline normalization and monotonic time

The sealed authority-validity deadline has one canonical meaning: it is an **exclusive first-invalid instant** in trusted Linura Control time. The acceptance write/CAS is valid only when the sampled linearization time satisfies `now < deadline`; `now == deadline` is invalid and must fail closed.

Every time-limited authority contributor must be normalized to that meaning before the minimum deadline is chosen. Normalization preserves the contributor's own validity predicate rather than assuming all sources share the same endpoint convention or clock unit. In particular:

- an acceptance decision/approval that is invalid when `now >= expires_at` contributes `expires_at` itself as its exclusive deadline;
- an observation whose freshness predicate remains current at its inclusive expiration timestamp contributes the first representable trusted-Control instant after that inclusive endpoint as its exclusive deadline;
- any other time-bounded authority input contributes the first trusted-Control instant at which its own authoritative validity predicate becomes false.

Clock units/resolution must be normalized before comparison. Unit-conversion overflow, successor/endpoint overflow, an unknown endpoint convention, or inability to derive a deterministic first-invalid instant is a release-blocking fail-closed condition for acceptance; such a contributor must never be silently omitted from the aggregate deadline.

Trusted Control time used by the acceptance transaction is monotonic/fail-closed. Final revalidation records a trusted-time floor in the sealed capability. The persistence-time sample must be greater than or equal to that floor as well as strictly earlier than the exclusive validity deadline. If the clock source moves backward, is reset, cannot prove monotonic continuity for the in-flight transaction, or returns a sample earlier than the sealed floor, the acceptance attempt aborts with no durable intent or acceptance record. A crash/restart never attempts to reconstruct the transient capability or its time continuity; it re-enters Linura Control and establishes fresh authority instead.

The durable acceptance transaction must cover every locally mutable authority input whose concurrent change could invalidate acceptance. Such changes either participate in the same Control-owned guard or advance a monotonic authority generation checked at linearization. Time-bounded authority is not considered preserved merely because it was valid before capability minting: the sealed capability carries the earliest normalized exclusive authority-validity deadline across all time-limited authority inputs, including observation freshness and decision/approval applicability, and the authority-internal persistence path must enforce `time_floor <= now < deadline` at the actual durable write/CAS linearization. There must be no user-controlled wait or second lock acquisition between that final trusted-time check and the atomic write. If internal blocking or retry reaches/passes the deadline or trusted Control time rolls backward below the sealed floor, the transaction must abort rather than commit stale or unauthorized acceptance.

The acceptance decision cannot be reused for a different proposal, context, operation or target merely because the principal and high-level action are the same. Changed proposal digest, context binding, operation identity, create/revise target or expected revision requires a new applicable acceptance decision.

### Sealed durable acceptance

The durable Library acceptance primitive is an authority-internal persistence surface, not a new public `LocalLibrary`/SDK mutation API. It must require a sealed acceptance-commit capability minted only by Linura Control after the final exact-bound revalidation above.

The sealed capability is non-user-constructible, non-deserializable from client/provider input, non-cloneable/replayable as a general credential, exact-bound to the acceptance material and durable transaction, carries the sealed trusted-time floor plus earliest normalized exclusive authority-validity deadline, and is consumed by value for one durable linearization attempt. Public SDK clients, providers and the agent runtime cannot fabricate it or invoke proposal acceptance by supplying a structurally similar request.

The durable acceptance record must bind at least the authenticated principal, acceptance-decision identity and decision-binding digest, proposal ID, canonical proposal digest, accepted Control context binding, durable operation identity, create/revise action and target identity/revision expectation, authority generation/freshness evidence, decision/approval validity evidence, the sealed trusted-time floor, normalized exclusive authority-validity deadline and endpoint-normalization evidence enforced at linearization, resulting `IntentId`, and resulting intent revision. Exact retry of an already-committed acceptance is idempotent and returns the same result. Reuse of the same proposal/operation/decision identity with different bound material fails closed as a conflict.

If the process fails before commit, no sealed capability is recoverable or reconstructible from public/durable identifiers; the caller must re-enter Linura Control and re-establish current authority. If the commit succeeds but the response is lost, recovery reads the exact durable acceptance record and returns the same result without creating a second intent or replaying authorization over changed material.

Calling the pre-existing public `LocalLibrary::create_intent` operation alone is not sufficient evidence of proposal acceptance and cannot substitute for the sealed authority-internal path.

Acceptance itself grants no machine-mutation approval or execution authority. Any later machine mutation still traverses the existing observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile lifecycle.

### Secret and diagnostic boundary

Provider credentials remain adapter-private. Linura Control excludes secret values, privileged tokens, authority credentials and protected Library/observation/retrieval/user fields before an interpretation projection crosses into the agent runtime. Only protected references/handles or deliberately non-secret projections may be supplied when needed for semantics.

Canonical requests/proposals and public errors contain no credential material. The runtime bounds diagnostics and exposes stable error categories without copying arbitrary provider response bodies, prompts or secret-bearing context into audit/state surfaces.

## Consequences

- `linura-intent` owns the canonical proposal types, validation and digest semantics.
- `linura-agent-runtime` owns bounded single-attempt interpretation execution and manual interpretation over an already-minimized Control-produced projection. It does not own cross-provider discovery/selection/scheduling, deadlines or aggregate budgets, retry/fallback admission, caching/coalescing, aggregation, projection minimization, freshness, capability-registry or acceptance authority.
- `linura-provider-sdk` owns provider-neutral single-invocation adapter contracts and transport mechanics, not retry admission, model authority or orchestration policy.
- Linura Control owns provider discovery/eligibility, cross-provider selection/scheduling, deadlines and aggregate budgets, retry/fallback/advisor admission, caching/coalescing and aggregation, plus authenticated-principal binding, trusted projection construction/minimization, current authority-context derivation, time-based observation-freshness revalidation, capability-registry resolution, exact-bound acceptance authorization, durable acceptance serialization, monotonic trusted-time authority-validity normalization/evaluation and sealed acceptance-capability minting.
- the Linura Library durable path owns atomic storage of the accepted intent + exact acceptance record and mechanically enforces the sealed trusted-time floor plus normalized exclusive authority-validity deadline at durable linearization, but the proposal-acceptance primitive is authority-internal, requires the sealed Control-minted capability, and is not exposed as a public SDK mutation surface.
- provider implementations may be local, hosted or enterprise-managed without changing the canonical proposal/authority model.
- v0.8 can be qualified with deterministic mock/replay adapters without depending on a live external model service.
- adding autonomous tool or executor authority in a future release requires a new explicit authority decision; it cannot be inferred from this ADR.

## Non-goals

This decision does not add autonomous execution, generic tool use, policy administration, approval authority, a privileged agent daemon, hosted synchronization or a supported machine/platform profile.
