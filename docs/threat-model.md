# Threat model

## Assets

- host integrity/availability and bootability;
- user data, credentials and secret references;
- network/security configuration;
- approved intent and desired state;
- reusable Setup/Profile definitions and Library history;
- system graph and semantic provenance;
- audit/policy/grant state;
- durable authority transaction/idempotency/recovery state;
- trusted risk-policy state and classification provenance;
- update/release trust roots;
- user understanding at approval time.

## Adversaries

- malicious/compromised local application;
- malicious extension/workflow/capability package;
- compromised hosted/local AI model or agent runtime;
- prompt injection embedded in web/files/repositories/messages;
- malicious package/update artifact;
- unprivileged local user on multi-user machine;
- remote attacker against an intentionally exposed service;
- accidental administrator/model/automation mistakes;
- malicious or malformed imported/synchronized Setup or MachineProfile.

## Primary threats and mitigations

### Confused deputy / privilege laundering
Low-privilege client or agent convinces Linura to perform privileged work.
- authenticated OS principal binding distinct from client-supplied provenance;
- explicit grants + policy evaluation;
- plan/approval before privilege;
- strict executor revalidation.

### Risk downgrade, under-classification or classifier substitution
A caller, model, provider or configuration change attempts to make a dangerous canonical plan look like a lower-risk mutation, or relies on an unknown mutation shape receiving the ordinary mutation approval class.
- planner `prospective_risk` is a lower bound and cannot be reduced by authority classification;
- trusted deterministic risk classification is owned by Linura Control, not client/model/provider payloads;
- classification uses exact typed canonical plan material such as provider/resource/capability/change keys;
- no matching trusted rule means unclassified mutation risk and the review fails closed as `blocked`;
- classification below the planner floor is rejected and the review fails closed as `blocked`;
- overlapping rules choose the highest risk deterministically rather than the first/lowest match;
- risk-policy revision and matched rule identities are retained as material review findings/provenance;
- approval/review reuse across changed risk-policy provenance or resulting risk is rejected;
- the initial v0.3 rule set is deliberately narrow rather than guessing risk for future mutation domains.

### Approval replay, theft or policy substitution
A caller attempts to reuse approval for a different principal, plan, evidence snapshot, resource/capability, risk classification or policy revision, or to preserve approval after expiry/revocation.
- policy review is derived from the canonical `ReconciliationPlan`, not a client-authored executable plan;
- review binds authenticated principal + request/plan identity + complete authoritative observation digest + provider/resource/capability + material risk-classification provenance + policy ID/revision;
- material planned changes/findings and semantic provenance are revalidated against the reviewed subject before approval evidence is accepted;
- `PlanId` alone is never sufficient authority evidence;
- approval evidence is authenticated, scoped to an explicit approval requirement, and checked for approver constraints, expiry and revocation at use time;
- approval issuance/validation/revocation and replay-tombstone pruning obtain current time inside Linura Control; callers cannot supply the authority clock used to keep evidence current or reopen replay IDs;
- authority time is monotonic within the process: a backward host wall-clock sample fails closed, so expired evidence cannot revive and replay-tombstone decisions cannot be reversed by clock rollback;
- cross-principal approval reuse and changed policy/risk-policy revision reuse fail closed;
- agents/models cannot mint approval evidence or satisfy their own protected human/admin approval requirement;
- durable prepare revalidates the exact current review, full fresh authoritative observation and approval binding instead of trusting a prior UI/review result;
- handoff-time dispatch eligibility revalidates the same full current authority again immediately before the durable ambiguity transition, so a long-lived `Prepared` row cannot preserve expired/revoked/stale authority;
- approval or a durable prepare record never becomes executor authority by itself.

### Authoritative observation substitution or expiry at prepare/handoff
A caller preserves an observation/evidence identifier while changing authority, freshness or observed attributes, or attempts to prepare or cross the dispatch handoff from evidence that became stale after planning/review.
- v0.4 binds a deterministic digest of the complete validated authoritative observation envelope, including authority/freshness material and canonical attributes;
- Control-owned prepare-time validation checks the complete retained observation binding and current freshness using trusted current time;
- Control-owned handoff-time validation repeats current observation freshness/material checks immediately before the `Prepared` → `Indeterminate` CAS;
- changed authority, validity/freshness window, attributes, provider/resource/capability or other material observation content changes the binding or invalidates the handoff;
- stale/expired observation cannot prepare or mint a dispatch permit and instead requires fresh authoritative observation followed by replan/review/current authority establishment;
- evidence ID alone is never sufficient prepare or handoff evidence.

### Durable prepare substitution, idempotency rebinding or generation aliasing
A caller attempts to reuse a durable request/transaction identifier with changed authority material after process restart, substitute plan/observation/policy/risk/approval content behind a retained identifier, or rewrite a prior generation when recovery needs fresh authority material.
- durable idempotency is namespaced by authenticated principal + request ID;
- one stable transaction retains an append-only sequence of immutable per-generation bindings;
- the durable prepare generation binds a deterministic domain-separated digest of exact trusted review, complete observation and authorization material;
- same idempotency namespace + changed binding through ordinary prepare fails as conflict, including after database reopen;
- changed authority material may create generation N+1 only through the typed Control-owned no-effect recovery path from the exact current `Indeterminate` predecessor after full current authority re-establishment;
- recovery append atomically retires generation N, creates exactly one N+1, advances the transaction current-generation/state-version pointer and appends audit evidence;
- SQLite uniqueness/foreign-key constraints backstop in-process checks and prevent duplicate generation identities;
- transaction ID, request ID, plan ID, evidence ID, approval ID and generation number are references, not sufficient authority evidence;
- immutable authority-binding fields cannot be silently rewritten after prepare.

### Dispatch-before-indeterminate, stale dispatch authority or duplicate dispatch capability
A future executor is called while the transaction is still durably `Prepared`, a long-lived prepared generation crosses the handoff after its authority became stale, or multiple callers reconstruct/obtain dispatch permission for one non-idempotent generation.
- `Prepared` carries no dispatch capability;
- immediately before the handoff, Linura Control revalidates current authenticated principal, complete observation freshness/material, canonical review, policy/risk-policy provenance and any required approval using Control-owned trusted authority state/time;
- mutable local authority invalidation such as approval revocation is serialized with the handoff-time validation/mint critical section so revocation cannot race between successful validation and permit issuance;
- invalid/stale/expired/revoked handoff authority cannot transition to `Indeterminate` or mint a permit;
- the exact current transaction generation + state-version + binding must atomically CAS `Prepared` → `Indeterminate` plus its audit event before any executor call;
- exactly one caller can win that CAS;
- only that winning caller may receive the corresponding process-local generation-bound dispatch permit;
- the permit constructor is sealed to the trusted Control/transaction handoff and the permit is non-cloneable, non-serializable, non-persistable and non-reconstructible from an `Indeterminate` row, transaction ID or generation ID;
- any future executor-dispatch API consumes the permit by value, so one successful permit is usable at most once;
- callers that merely observe an already-`Indeterminate` generation receive no permit;
- a crash after durable `Indeterminate` commit but before permit consumption permanently loses that generation's permit; restart cannot recreate/reissue it and must enter authoritative recovery;
- durable storage records that the ambiguity boundary was crossed, not a reusable executor credential;
- v0.4 qualifies this handoff without invoking an executor so v0.5/v0.6 cannot introduce weaker stale-authority, crash or duplicate-dispatch windows.

### Blind replay or contradictory recovery after crash / ambiguous external effect
A crash occurs around a future effect boundary and restart incorrectly assumes the effect did or did not happen, or concurrent recovery observers commit contradictory outcomes for the same generation.
- `Indeterminate` is an explicit durable transaction state and survives restart;
- restart, duplicate delivery, a retained prepare row, a lost dispatch permit, executor self-report or local database state never implies retry permission;
- fresh authoritative re-observation is required to resolve ambiguity;
- each stable transaction carries one durable `current_generation` pointer and monotonic `state_version`;
- every recovery resolution and generation append CAS the same exact current-generation/state-version serialization point;
- proof that intended state already exists may CAS only the exact current `Indeterminate` generation to `Verified`;
- proof that the intended effect did not occur permits only current-authority revalidation/re-prepare eligibility and, if successful, one atomic recovery transaction that retires N to `Aborted`, appends exactly one N+1 `Prepared`, advances current generation/version and appends audit events;
- conflicting state may CAS only the exact current `Indeterminate` generation to `RecoveryBlocked`;
- stale/insufficient/ambiguous evidence keeps the transaction `Indeterminate`; any durable recovery-observation audit append must itself serialize on/increment the same state-version;
- once any recovery result commits, concurrent losers must reload state and cannot later transition the now-historical predecessor or create a sibling N+1 generation;
- current observation freshness, policy and required approval must be re-established before a new prepared generation, so recovery cannot revive expired/revoked authority;
- recovery decisions and generation changes are append-only audited;
- v0.4 exposes no executor/managed effect, so these semantics are qualified before privileged execution is introduced.

### Durable state schema substitution or corruption
Local authority persistence is malformed, partially corrupted, migrated incorrectly, or replaced by an unsupported future schema.
- repository-owned SQLite application ID and explicit supported schema/user version;
- migration IDs/checksums are verified transactionally;
- SQLite integrity and foreign-key checks are part of store integrity validation;
- unsupported newer schema and migration checksum mismatch fail closed;
- exact binding digests, immutable generation continuity, current-generation/state-version consistency and retained audit-chain/state consistency are validated;
- automatic recovery does not silently rewrite corrupted authority history.

### Coherent whole-database rollback / snapshot restore
An attacker or operator replaces the complete authority database with an older internally consistent copy, or restores a VM/filesystem snapshot containing older authority history.
- v0.4 explicitly does **not** claim that SQLite integrity checks, migration checksums or an unkeyed internal audit hash chain can detect this case;
- transparent authority-database restore/rollback and host/VM snapshot rollback are unsupported v0.4 authority states;
- v0.4 idempotency/audit guarantees assume monotonic continuity of the qualified local authority database;
- a future supported restore protocol must use an independently protected monotonic epoch/anchor or otherwise invalidate retained authority and require fresh re-establishment;
- release qualification and documentation must not describe internal hash chaining as an anti-rollback anchor.

### Persistence crash/power/I/O failure
The process or guest loses power around a SQLite transaction boundary, or storage rejects/fails writes.
- WAL + `synchronous=FULL` are required within the qualified local filesystem/storage assumptions;
- state transition and its audit append are one SQLite transaction;
- multi-record recovery-generation append/retire/current-pointer/audit changes are one SQLite transaction;
- release qualification injects process `SIGKILL`, abrupt disposable-guest power loss and representative write/I/O failures around transaction boundaries;
- reopen must either show the complete committed transition/audit pair (or complete recovery-generation transaction) or the prior complete state, never a half semantic transition;
- failed commits do not authorize state advancement;
- filesystem/storage/hypervisor assumptions are named explicitly; storage that violates required locking/sync semantics is unsupported;
- `synchronous=FULL` is not represented as a universal hardware durability guarantee.

### Prompt injection / model compromise
External content manipulates an agent into dangerous proposals.
- model output has proposal authority only;
- trusted structured validation/solver/policy/risk-classification boundaries;
- no executor/tool handle in model runtime;
- context/source provenance and user-visible material effects;
- negative tests for escalation attempts.

### Malicious reusable setup/profile
An imported or synchronized artifact attempts to smuggle commands, unsafe state, authority or credentials onto the target machine.
- setup/profile formats are declarative and contain no executor command transcript;
- imported artifacts carry no grants/approvals;
- schema/composition/cycle validation before adoption;
- secret values prohibited; only secret refs are portable;
- fresh target observation + capability resolution + plan/risk classification/policy/approval;
- unsupported/ambiguous requirements fail closed;
- provenance distinguishes imported definitions from locally approved/adopted lineage.

### Machine-class spoofing / cross-class adoption confusion
A malicious or malformed portable profile lies about its source machine class, or attempts to use a workstation/server/edge label to obtain capabilities, support status, weaker policy, or unsafe cross-class replay on the target machine.
- imported `machine_class` is untrusted declarative source metadata and never an authority, grant, executor selector, risk override, or support assertion;
- the Experimental portable-profile schema accepts only the canonical `workstation`, `server`, and `edge` values and rejects missing/unknown values;
- the target machine is independently observed and its local capabilities/platform support are resolved from authoritative local evidence rather than trusted from the imported class label;
- source/target class differences are compatibility inputs that require fresh resolution and a fresh reviewable plan; historical executor effects are never replayed;
- unsupported, ambiguous, or unsafe cross-class compatibility fails closed rather than coercing one class into another;
- policy/approval remains bound to the fresh target plan and authenticated local authority context, so changing a class label cannot preserve or manufacture prior approval;
- release-qualified platform support is established only by release evidence for the exact local class + platform/profile + architecture/hardware boundary, never by a portable artifact declaring a class;
- provenance retains imported origin so later explanation/audit can distinguish source metadata from locally observed and approved facts.

### Secret leakage through portability/sync
A setup/profile export or Library sync accidentally contains credentials.
- portable domain types expose secret-reference fields only;
- export validation/redaction tests;
- secret stores remain local/provider-specific;
- synchronized artifacts are treated as potentially public/untrusted unless explicitly protected by a future storage provider.

### Semantic-provenance spoofing
A client invents a false "why" chain to make dangerous state look legitimate.
- provenance creation is authority-owned;
- lineage links approved intent/setup/plan/effect IDs;
- clients cannot rewrite history;
- imported setup/profile provenance remains distinguishable from locally approved lineage.

### Unsafe intent/setup retirement
Removing one goal or reusable setup breaks another because resources are shared.
- system-graph ownership/dependency analysis;
- removal impact plan;
- shared resources retained;
- verification and rollback/snapshot where applicable.

### Dependency/conflict/setup composition manipulation
Malformed capability/setup definitions cause cycles, hidden conflicts or unsafe alternatives.
- schema validation;
- deterministic solver/composition resolution;
- explicit unsatisfied/conflict results;
- bounded resource usage/cycle detection;
- signed/trusted catalogs before supported third-party distribution.

### Command/injection attacks
- no generic shell interface;
- native APIs preferred;
- fixed executable + structured argv only where subprocesses are unavoidable;
- secret values never in argv.

### TOCTOU/stale plan or authority at effect handoff
- observed-state freshness and preconditions;
- review is bound to the exact authoritative observation digest, material plan and trusted risk classification being approved;
- policy/risk-policy/approval changes invalidate stale review evidence;
- durable prepare revalidates exact full observation/review/approval material immediately before crossing the prepare boundary;
- a long-lived `Prepared` generation is revalidated again by Control immediately before the durable handoff; stale observation, changed policy/risk provenance, expired/revoked approval or changed principal blocks `Indeterminate` and permit minting;
- mutable local authority invalidation is serialized with the handoff validation/mint critical section;
- a future executor remains unavailable until that fresh authority check succeeds and the exact generation-bound indeterminate CAS commits;
- future executor qualification must still enforce executor-local preconditions appropriate to the concrete effect;
- plan expiry/replan rules;
- setup/profile adoption always plans against current target state.

### Approval fatigue/deception
- aggregate material effect/change summary;
- dedicated destructive/security approval classes;
- no model-generated UI allowed to disguise authoritative approval controls;
- policy can require step-up authentication.

### Tampered releases/extensions/library catalogs
- protected release pipeline, immutable tags, SBOM, signing/attestation and asset verification before supported releases;
- extension capability expansion requires approval;
- future shared catalogs need content identity/signature policy before being considered trusted distribution channels.

### Audit/provenance tampering
- append-only transaction audit design;
- transaction transition + audit append are one local database transaction;
- recovery generation retirement/append/current-pointer changes and their audit events are one local database transaction;
- ordinary audit UPDATE/DELETE is rejected by the v0.4 SQLite schema;
- deterministic event sequencing and chained integrity digests detect non-coherent deletion/reordering/tampering within the retained database history;
- store integrity validation cross-checks retained audit continuity against immutable generation history and current durable transaction generation/state-version;
- an internal unkeyed hash chain does not detect replacement by an older complete internally consistent database and is not claimed to;
- detected corruption fails closed rather than being silently repaired;
- optional external export/signing/monotonic anchoring remains future enterprise/hardening work.

### Persistence resource exhaustion
A local client tries to consume unbounded disk/memory with authority or audit records, or maintenance silently discards old authority to make room.
- per-record and aggregate durable authority/audit bounds;
- bounded lock/busy waiting;
- oversized inputs rejected before avoidable retained cloning/serialization;
- capacity exhaustion fails closed;
- no silent eviction of authority/audit history in v0.4;
- WAL checkpoint/maintenance may reclaim physical space without changing semantic history.

## v0.8 proposal interpretation and acceptance threats

### Proposal actor spoofing or acceptance-authority laundering
A compromised client, provider or agent runtime supplies actor fields that appear to identify an authorized user and attempts to convert that provenance directly into durable intent.
- proposal `Actor` fields are provenance only and never authenticate a caller;
- the acceptance operation obtains the authenticated `Principal` independently from the trusted transport/session boundary;
- Linura Control requires the applicable human/policy acceptance decision for that authenticated principal before durable intent creation/revision;
- that decision is exact-bound to the authenticated principal, proposal ID/digest, accepted Control context binding, durable operation identity, create/revise action and exact target identity/revision expectation;
- actor/principal relationships are revalidated by Linura Control, and self-asserted proposal data cannot create grants or authorization;
- acceptance grants no machine-mutation approval, dispatch permit or executor authority.

### Proposal context TOCTOU, expiry or stale-binding replay
A caller replays an old but internally consistent context revision/digest after observation, policy, Library state, capability registry or relevant existing intent has changed, after an observation validity window expires without a revision change, or while one of those authority inputs changes concurrently with acceptance.
- the authority-context revision is minted by trusted Linura Control from the authoritative state used for interpretation;
- the client/runtime/provider may transport the binding but cannot mint or advance it;
- acceptance re-reads/re-resolves relevant authoritative dependencies inside Linura Control;
- time-based observation freshness is re-evaluated using trusted Control time independently of revision equality;
- expired required observation is reacquired before acceptance, or acceptance fails closed when fresh evidence cannot be established;
- immediately before durable acceptance, Linura Control revalidates the full context/freshness/capability/decision binding under a Control-owned serialization/CAS boundary;
- authority-generation, target-revision, freshness or decision drift at that linearization point fails closed rather than committing stale authorization;
- Linura Control derives the current authoritative binding from that fresh/current material and requires an exact match;
- provider timestamps, caller-generated revision tokens and model confidence are never freshness authority.

### Capability-registry substitution or expansion
A provider/client supplies a matching invented capability definition so an otherwise unknown proposal reference appears supported.
- proposals carry capability references, not authoritative registry entries;
- acceptance resolves every reference against the current Control-owned local capability registry;
- unavailability, unknown capability, unsupported support state or registry revision change fails closed;
- providers, model output and agent runtimes cannot expand the trusted registry through proposal content.

### Secret exfiltration through interpretation context or diagnostics
Retrieved context, Library state, observations or user input contain secret values and a compromised agent runtime or hosted/local adapter attempts to receive or log them.
- Linura Control constructs and data-minimizes the semantic projection before it crosses into the untrusted agent runtime;
- raw secret-bearing Library, observation, retrieval or user context is never delegated to the runtime for filtering;
- secret values, privileged tokens, authority credentials and protected secret-bearing fields are excluded before the runtime/provider boundary;
- only protected references/handles or explicitly non-secret metadata may represent a secret dependency;
- provider credentials remain adapter-private;
- public errors/audit use bounded stable categories and do not copy arbitrary provider response bodies, prompts or secret-bearing source context;
- qualification injects secret canaries into source context and proves they do not reach runtime/provider input, proposal state, diagnostics or audit surfaces.

### Proposal substitution, authorization replay, direct persistence bypass or lost-response replay
Acceptance commits durable intent but the response is lost, a caller reuses a proposal/operation/decision identity with changed principal, digest, context, action, target or resulting intent, or an untrusted caller attempts to bypass Linura Control by invoking the Library persistence surface directly.
- Linura Control exact-binds the acceptance decision to authenticated principal + proposal ID/digest + accepted context + durable operation identity + create/revise action + exact target identity/revision expectation;
- final authority revalidation and sealed capability minting occur under the Control-owned acceptance serialization boundary at the durable linearization point;
- the authority-internal Library acceptance primitive requires a sealed exact-bound Control-minted commit capability and is not exposed as a public `LocalLibrary`/SDK proposal-acceptance mutation accepting caller-constructible authority fields;
- the sealed capability is non-user-constructible, non-deserializable from client/provider input and consumed for one durable linearization attempt;
- the durable record binds authenticated principal + acceptance-decision identity/binding + proposal ID/digest + accepted Control context binding + durable operation identity + create/revise action + exact target expectation + authority-generation/freshness evidence + resulting `IntentId`/revision;
- exact retry returns the same durable result after process restart;
- a crash before commit cannot reconstruct the transient sealed capability from public or durable identifiers and must re-enter Linura Control for fresh authority establishment;
- semantic substitution or conflicting reuse of any bound identity/material fails closed;
- an acceptance decision for one proposal/context/operation/target cannot authorize another merely because the principal or high-level action is the same;
- direct public Library/SDK attempts to fabricate proposal acceptance are rejected without durable mutation;
- the proposal-to-intent lineage remains durable for explanation/audit and cannot be reconstructed from mutable conversation text;
- the pre-v0.8 generic `create_intent` call alone is not treated as proof of authenticated/authorized proposal acceptance.

### Compromised adapter/runtime or malicious model output
A provider or agent runtime emits malformed typed data, authority claims, hidden tool requests or misleading explanations.
- model/provider/runtime output remains proposal-only and cannot carry authenticated principal, approval evidence, policy decisions, grants, dispatch permits or executor handles;
- complete structured output is schema/version/bounds/digest validated before it can become a proposal;
- partial streaming fragments never become accepted proposal state;
- prompt/tool/authorization claims embedded in text remain untrusted data;
- no executor/tool handle exists in the interpretation runtime;
- deterministic Linura Control acceptance independently re-establishes authenticated principal, current authority context/freshness, capability-registry resolution and the exact-bound acceptance decision;
- negative qualification covers escalation, malformed/oversized output and provider/runtime failure paths.

## Deferred threats

Fleet/remote orchestration and hosted/shared Library services receive dedicated threat-model extensions before any network control plane or trusted shared catalog is enabled.

## v0.5 privileged component threats

### Sender spoofing, Polkit bypass, or qualification-authority leakage
- the executor derives the unique sender from the system D-Bus message rather than trusting a caller-supplied identity;
- one fixed Polkit action gates the qualification method; production policy remains deny-by-default and the permissive qualification principal exists only in disposable test fixtures;
- serialized transaction IDs, generations, digests, receipts, and an `Indeterminate` durable row cannot independently authorize execution;
- no Control1, CLI, SDK, agent, or other public mutation surface exposes the qualification action.

### Effect substitution or generic-root expansion
- the privilege boundary accepts only a canonical `.service` name in the dedicated `linura-v05-qualification-*` namespace;
- exact effect/binding correlation is re-derived and validated inside the executor;
- no shell, arbitrary executable, file-write primitive, arbitrary systemd method, or generic D-Bus forwarding surface exists;
- dispatch errors after the native ambiguity boundary are classified conservatively as indeterminate.

### Executor self-attestation or stale verification
- `Dispatched` is not state proof;
- canonical systemd observation independently records `ActiveEnterTimestampMonotonic`;
- the verifier consumes only fresh native canonical observation and is structurally forbidden from depending on the executor or native D-Bus transport;
- stale, future, missing, wrong-resource, wrong-capability, non-native, inactive, or unchanged-timestamp evidence cannot verify success.
