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

### Developer preparation confused with runtime authority or qualification

A stale saved preparation plan, interrupted native transaction, substituted
cached tool or diagnostic success is treated as permission to mutate a host or as
application acceptance evidence.

- Native development preparation is an explicit operator command over a reviewed
  checkout, not a runtime/model/provider interface. Only fixed package-manager
  entrypoints use native sudo authorization; the Python process stays unprivileged.
- Saved developer plans bind source inputs, user/home/host and native package
  state; short expiry and complete rederivation reject stale or tampered inputs.
  They are not product ReconciliationPlans, authorization credentials or a security
  boundary against the same developer changing repository code.
- Native authenticated repositories/configuration, package-manager locks/hooks
  and administrator maintenance remain trusted. No key import, insecure install,
  removal, downgrade, partial Arch upgrade or protection bypass is automated.
- Digest-verified archives precede extraction/execution; private generation
  manifests precede cached executable probes. Unmanaged paths are not overwritten.
- Interrupted package phases retain original ownership and transaction receipts;
  changed state requires operator review before acceptance of a new observation.
  Shared dependencies are retained and no rollback/database repair is improvised.
- Doctor/preflight never install. Receipts explicitly deny qualification authority;
  native package transactions and application A/B/C evidence require their own
  actual execution. See [ADR 0044](adr/0044-explicit-native-development-preparation.md).

### Native session identity laundering, stale lock generation or forged sleep source
A caller or process substitutes a syntactically valid native session, lock, owner invocation, power transition, permission observation or sleep identifier to affect another login, release a later lock or replay a previous power request.
- Canonical IDs in `linura-core` are untrusted correlation material, even when parsing succeeds; a caller may construct them without possessing an OS credential.
- Bind every session epoch to freshly attested kernel boot identity, authenticated logind owner UID, exact session ID and nonzero session creation generation, not PID, user name, ambient `self` or a stale session handle.
- Bind a native lock to an independently attested security-owner service invocation and nonzero lock generation. Replacement owner, compositor, transport or generation invalidates old approval and unlock proofs.
- Bind transitions to the exact lock and operation kind; a suspend-cycle baseline and a permission observation cannot prove real sleep/resume, logout, shutdown or reboot.
- Bind a protective-lock request to an independently attested native pre-sleep invocation plus full login epoch. Neither this ID, a parsed request nor a transport receipt approves pre-sleep locking or sleep.
- Keep caller identity, native observation, policy approval, human/PAM/Polkit authentication, prepared execution authority and independent postcondition verification separate. Freshly revalidate before dispatch; uncertainty, replacement and replay fail closed.
- See proposed [ADR 0042](adr/0042-s17-session-security-and-power-authority.md); native proof and qualification remain mandatory.

### Confused deputy / privilege laundering
Low-privilege client or agent convinces Linura to perform privileged work.
- authenticated OS principal binding distinct from client-supplied provenance;
- explicit grants + policy evaluation;
- plan/approval before privilege;
- strict executor revalidation.

### Operation-class downgrade or lifecycle bypass
A caller, model, UI, configuration file, provider or extension attempts to label an external effect as ephemeral/query/local/transient so it can avoid the authority path required by its semantics.
- operation class is bound by a trusted registered operation/domain contract and validated by Linura Control, not accepted as caller authority;
- unknown or ambiguous external effect semantics fail closed rather than defaulting to the transient path;
- `TransientExternalEffect` is limited to qualified unprivileged effects with trusted risk no higher than `UserState` and bounded verification/audit semantics;
- privilege, stronger trusted risk, durable desired state, ambiguity/recovery requirements or unsupported transient semantics promote the operation to `ManagedExternalEffect` or block it;
- only `ManagedExternalEffect` may cross a privileged executor boundary;
- interface equivalence tests ensure GUI/config/shortcut/CLI/agent requests resolve to the same trusted operation class;
- machine-readable operation semantics and tooling tests reject contract drift.

### Transient executor self-report, stale verification or hidden ambiguity
A bounded transient mechanism reports success/failure inaccurately, post-effect evidence is stale/reused/substituted, or a transport failure creates ambiguity that the lightweight path cannot safely resolve.
- the transient executor is unprivileged and receives only a Control-minted typed `AuthorizedTransientEffect`; it receives no durable dispatch permit, privileged executor handle or generic shell authority;
- executor return status is never postcondition evidence;
- Control always performs a fresh authoritative post-effect observation after an execution attempt, including executor failure;
- post-effect evidence must carry a provider observation timestamp **strictly later** than Control's executor-dispatch lower bound; equal/older timestamps are ordering-ambiguous and fail closed even when the evidence ID differs and the envelope is otherwise current;
- no-change outcomes pass the same authenticated-principal policy review before audited success, so a denied actor cannot use the no-change branch as an authorization bypass or state oracle;
- registration validation, executor input and post-effect verification bind the complete requested postcondition, including attributes that were already satisfied before execution and therefore absent from the initial plan diff;
- transient audit records include provider/resource/capability identity plus independent SHA-256 bindings of the complete canonical plan and complete requested postcondition, so request/plan ID reuse cannot alias changed effect material;
- reused pre-effect evidence, non-current evidence, wrong provider/resource/capability or a postcondition mismatch cannot produce a verified receipt;
- every planned material change must match fresh authoritative post-effect attributes before success is reported;
- the audit record binds authenticated principal, operation/plan/request identities, trusted semantic risk, exact policy ID/revision, reviewed policy-subject risk, trusted risk-classification revision/rule IDs and pre/post evidence identities;
- a durable audit attempt reservation is accepted before executor dispatch; reservation failure prevents execution, while terminal records are linked to the same deterministic attempt binding so a terminal audit failure cannot erase evidence that dispatch was attempted;
- arbitrary executor/provider diagnostic text is never persisted in transient audit records; stable typed failure codes preserve forensic category without copying credentials, tokens or provider error payloads into durable audit;
- inability to obtain/interpret bounded fresh post-effect evidence fails the transient attempt; if the domain can require durable indeterminate recovery, that operation is `ManagedExternalEffect` or unsupported rather than transient.

### Registered-operation substitution or risk-floor weakening
A caller, provider, extension, recovery path or compromised composition attempts to substitute a different registered operation, broaden its resource/effect binding, lower its trusted risk floor, or reuse authority produced before registered semantics changed.
- the trusted operation registry is constructed inside Control and is not supplied by clients, providers, agents or imported configuration;
- external-effect authorization begins from a canonical `ReconciliationPlan` that must match the registered provider, observation capability, resource scope and allowed material change keys;
- the registered risk floor is applied before policy review, so the policy subject, approval class, review digest and durable `AuthorityBinding.trusted_risk` all carry the strengthened risk;
- changing or raising the registered floor cannot reuse weaker prior review/approval/prepared authority; current authority must be reconstructed and rebound;
- managed restart and `Indeterminate` recovery re-establish authority from current registration, fresh authoritative observation and a fresh canonical plan instead of inheriting permission from the predecessor generation;
- immediately before every privileged handoff, Control re-resolves the prepared plan through the trusted registry and requires current resolved risk to equal the reviewed/durable bound risk;
- missing registration, plan-shape mismatch, stale/weaker bound risk or registry inconsistency fails closed before permit minting or executor dispatch;
- operation-semantics contract checks and adversarial tests cover candidate creation, approval refresh, recovery/reprepare and privileged handoff so one alternate path cannot silently omit the registry/risk-floor binding.

### Risk downgrade, under-classification or classifier substitution
A caller, model, provider or configuration change attempts to make a dangerous canonical plan look like a lower-risk mutation, or relies on an unknown mutation shape receiving the ordinary mutation approval class.
- planner `prospective_risk` remains a conservative lower-bound guard for ordinary/unregistered and managed classification;
- the sole downward-refinement exception is the trusted exact registered transient path, entered only after Control has matched the canonical plan to a trusted `TransientExternalEffect` descriptor's provider, observation capability, resource scope and allowed material change keys;
- the complete requested postcondition must be covered by the trusted transient risk rule before any downward refinement; attributes already satisfied in the pre-effect observation cannot bypass classification merely because they are absent from the initial plan diff;
- the ordinary classifier continues to reject downward classification, while the registered transient refinement must resolve to at most `UserState`; unknown rules, shape mismatch, privilege, stronger risk or durable/ambiguity requirements fail closed rather than entering the lightweight path;
- callers, providers, UI/configuration and models cannot request or supply the refinement flag/classification;
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

### Proposal context TOCTOU, pre/post-mint authority expiry or stale-binding replay
A caller replays an old but internally consistent context revision/digest after observation, policy, Library state, capability registry or relevant existing intent has changed; an observation validity window expires without a revision change; a time-bounded human/policy acceptance decision or approval expires without any authority-generation change; trusted Control time rolls backward, resets/rebinds, or loses monotonic continuity after capability minting; or execution is delayed after final validation/capability minting but before the actual durable write/CAS so previously valid evidence or authorization becomes invalid.
- the authority-context revision is minted by trusted Linura Control from the authoritative state used for interpretation;
- the client/runtime/provider may transport the binding but cannot mint or advance it;
- acceptance re-reads/re-resolves relevant authoritative dependencies inside Linura Control;
- time-based observation freshness and decision/approval applicability are re-evaluated using trusted Control time independently of revision equality;
- expired required observation is reacquired before acceptance, while expired decision/approval authority requires fresh applicable authorization; otherwise acceptance fails closed;
- Linura Control enters the authority-internal durable acceptance transaction and acquires the write/CAS serialization guard before final context/freshness/capability/decision revalidation;
- while that guard remains held, Linura Control revalidates current authority, samples trusted Control time for the final-revalidation authority-time floor, normalizes every time-limited authority contributor to the same **exclusive first-invalid Linura Control instant** according to that contributor's own validity predicate and clock unit, then computes the earliest normalized authority-validity deadline; observation freshness that remains current at an inclusive expiration endpoint contributes the first representable Control instant after that endpoint, while a decision/approval invalid for `now >= expires_at` contributes `expires_at` itself;
- unknown endpoint semantics, incompatible/unknown clock units, unit-conversion overflow, successor/endpoint overflow or any inability to derive a deterministic first-invalid Control instant fails closed; such a contributor is never dropped from the deadline set;
- the sealed transaction-scoped acceptance capability is exact-bound to the durable transaction and carries the final-revalidation authority-time floor, earliest normalized exclusive authority-validity deadline and endpoint/unit-normalization evidence for every contributing time-bounded authority input;
- the authority-internal Library path consumes the sealed capability without releasing/reacquiring the durable guard and mechanically rechecks trusted Control time at the actual intent+acceptance-record write/CAS linearization, permitting the write only when `time_floor <= now < deadline`;
- a post-mint sample with `now < time_floor`, a detected clock reset/rollback/rebind, or unknown monotonic continuity fails closed and aborts/rolls back with no durable intent or acceptance record, even if the sampled wall-clock value otherwise satisfies `time_floor <= now < deadline`;
- any database-lock, scheduling, internal-I/O or retry delay that reaches or passes the sealed normalized deadline aborts/rolls back with no durable intent or acceptance record, regardless of which time-limited authority input expired;
- Linura Control derives the current authoritative binding from fresh/current material and requires an exact match;
- provider timestamps, caller-generated revision tokens and model confidence are never freshness or authorization authority.

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
- provider credentials and reusable transport handles remain private to the trusted invocation gate/credential resolver and never enter untrusted runtime/adapter logic;
- public errors/audit use bounded stable categories and do not copy arbitrary provider response bodies, prompts or secret-bearing source context;
- qualification injects secret canaries into source context and proves they do not reach runtime/provider input, proposal state, diagnostics or audit surfaces.

### Proposal substitution, authorization replay, direct persistence bypass or lost-response replay
Acceptance commits durable intent but the response is lost, a caller reuses a proposal/operation/decision identity with changed principal, digest, context, action, target or resulting intent, an untrusted caller attempts to bypass Linura Control by invoking the Library persistence surface directly, a sealed capability is held across blocking long enough for observation freshness or decision/approval applicability to expire before persistence linearizes, or trusted Control time rolls backward, resets/rebinds, or loses monotonic continuity after the capability was minted.
- Linura Control exact-binds the acceptance decision to authenticated principal + proposal ID/digest + accepted context + durable operation identity + create/revise action + exact target identity/revision expectation;
- the durable write/CAS serialization guard is acquired before final authority revalidation; sealed capability minting then occurs while that guard remains held, rather than being treated as the durable linearization point itself;
- the authority-internal Library acceptance primitive requires a sealed exact-bound Control-minted commit capability and is not exposed as a public `LocalLibrary`/SDK proposal-acceptance mutation accepting caller-constructible authority fields;
- the sealed capability is non-user-constructible, non-deserializable from client/provider input, exact-bound to the durable transaction, final-revalidation authority-time floor, earliest normalized exclusive authority-validity deadline and endpoint/unit-normalization evidence, and consumed for one durable linearization attempt;
- immediately at the actual intent+acceptance-record write/CAS, the Library path rechecks trusted Control time and permits persistence only when `time_floor <= now < deadline`; rollback/reset/rebind/unknown time continuity, invalid/missing normalization evidence or deadline expiry rolls the transaction back;
- the durable record binds authenticated principal + acceptance-decision identity/binding + proposal ID/digest + accepted Control context binding + durable operation identity + create/revise action + exact target expectation + authority-generation/freshness evidence + decision/approval validity evidence + enforced authority-time floor + normalized exclusive authority-validity deadline + endpoint/unit-normalization evidence + resulting `IntentId`/revision;
- exact retry returns the same durable result after process restart;
- a crash before commit cannot reconstruct the transient sealed capability from public or durable identifiers and must re-enter Linura Control for fresh authority establishment;
- semantic substitution or conflicting reuse of any bound identity/material fails closed;
- an acceptance decision for one proposal/context/operation/target cannot authorize another merely because the principal or high-level action are the same;
- direct public Library/SDK attempts to fabricate proposal acceptance are rejected without durable mutation;
- the proposal-to-intent lineage remains durable for explanation/audit and cannot be reconstructed from mutable conversation text;
- the pre-v0.8 generic `create_intent` call alone is not treated as proof of authenticated/authorized proposal acceptance;
- qualification independently injects inclusive-observation endpoint normalization, decision/approval exact-expiry normalization, normalization overflow/unknown-semantics failure, post-mint observation expiry, post-mint decision/approval expiry, numeric trusted-time rollback, trusted-time reset/rebind and continuity-unknown cases so one case cannot mask another.

### Runtime/adapter orchestration takeover, invocation-gate bypass or aggregate-budget escape
A compromised agent runtime receives one bounded interpretation attempt and tries to become a second orchestration owner by selecting another provider, self-retrying, activating fallback, initiating advisors, resetting aggregate deadlines/budgets, or aggregating/caching/coalescing cross-provider results. Compromised adapter logic tries to obtain reusable credentials, open direct network/process/session transport, substitute the prepared provider invocation, forge/replay an invocation permit, or hide adapter/transport-library retries, request-producing redirects/authentication replay, uncertain-write replay or stream reconnect/resume inside that single admitted attempt after timeout, rate limit, transport failure, cancellation or partial response.
- Linura Control exclusively owns provider eligibility/discovery, selection, cross-adapter scheduling, aggregate deadlines/budgets, timeout/cancellation policy, retry/fallback/advisor admission, caching/coalescing and aggregation;
- the runtime receives an exact Control-admitted attempt descriptor for one selected adapter and may enforce only its bounded attempt-local mechanics;
- the runtime cannot mint another attempt descriptor, select a second adapter, reset/re-base aggregate budget/deadline state, or turn provider failure into retry/fallback/advisor admission;
- runtime/adapter logic runs in a production-enforced sandbox without ambient provider network/process/session egress, raw/reusable credentials or dereferenceable credential/transport handles;
- adapter logic first emits a bounded credential-free `PreparedProviderInvocation`; Control validates it against the selected provider/adapter/endpoint profile and attempt bounds and records its exact canonical digest;
- every side-effecting hosted/local provider call crosses a separate trusted invocation gate; Control mints an unforgeable single-use permit exact-bound to the canonical interpretation request and prepared-invocation digests plus attempt/provider/adapter/endpoint/network classification/per-attempt bounds and aggregate orchestration state, and only the gate receives that permit through its protected capability channel;
- the gate verifies the exact prepared invocation and atomically consumes the permit before credential resolution, authentication, DNS, socket, process/session or provider transport initialization; request substitution plus forged, mismatched, expired, replayed or already-used permits fail before any such side effect;
- one permit authorizes at most one provider invocation and is spent on success, timeout, rate limit, transport failure, cancellation or partial response; adapter logic returns the bounded outcome without internally retrying, reissuing or starting a replacement/resume request;
- transport-library automatic retries, redirects that initiate a request, authentication-challenge replay, uncertain-write replay and stream reconnect/resume are disabled and each is treated as another provider invocation requiring fresh Control admission;
- every extra or repeated provider invocation requires a fresh Control admission/permit against the original aggregate budget/deadline; adapter/runtime isolation prevents bypassing the gate;
- multi-advisor scheduling and deterministic select/combine/reject policy remain in Control while runtime results stay separately attributed;
- qualification uses the production-equivalent sandbox plus credential/network/process/session/transport traps to exercise runtime self-selection/self-retry, direct-egress and credential access, prepared-invocation substitution, permit forgery/replay/second consumption, adapter/transport-library repeat invocation, fallback/advisor initiation, budget/deadline reset and aggregation takeover; zero forbidden side-effect counters are required.

### Offline-mode network adapter escape
Offline mode is enabled while a network-required adapter is installed, discovered, selected, health-checked, chosen as fallback or otherwise considered by orchestration, and adapter lifecycle code attempts network-side effects before Linura Control admits a provider attempt.
- adapter metadata declares network requirement before any adapter callback or transport initialization that could perform I/O;
- Linura Control evaluates offline policy before provider admission and before adapter invocation, provider discovery callbacks, health-check callbacks, fallback activation, provider authentication, DNS resolution, socket creation/connect or transport/client initialization; the runtime cannot override that decision;
- a network-required adapter selected in offline mode is rejected locally with zero adapter-callback, authentication, DNS, socket and transport-initialization side effects;
- discovery or fallback cannot opportunistically probe a network-required provider while offline merely to decide whether it is usable;
- deterministic qualification independently exercises explicit selection, provider discovery, health checking and fallback with trap-backed network-required adapters and requires all invocation/authentication/DNS/socket/transport-initialization counters to remain exactly zero for every path;
- manual/no-provider operation remains a separate complete path and does not weaken this pre-invocation isolation rule.

### Compromised adapter/runtime or malicious model output
A provider or agent runtime emits malformed typed data, authority claims, hidden tool requests or misleading explanations.
- model/provider/runtime output remains proposal-only and cannot carry authenticated principal, approval evidence, policy decisions, grants, dispatch permits or executor handles;
- complete structured output is schema/version/bounds/digest validated before it can become a proposal;
- partial streaming fragments never become accepted proposal state;
- prompt/tool/authorization claims embedded in text remain untrusted data;
- no executor/tool handle or cross-provider orchestration authority exists in the interpretation runtime;
- deterministic Linura Control acceptance independently re-establishes authenticated principal, current authority context/freshness, capability-registry resolution and the exact-bound acceptance decision;
- negative qualification covers escalation, malformed/oversized output and provider/runtime failure paths.

## S17 native session-security threats (implementation in progress)

- A dispatched lock transition can race its Wayland acknowledgement. Pending is
  admitted only from the attested observation endpoint after a fresh compositor
  sample and a consistent in-flight native mechanism. It is no security boolean
  or observation envelope. Control revalidates the owner/boot and preserves its
  existing bounded settle loop; all other errors abort and native watchdogs remain.
- Repeated postcondition verification must not consume a release event twice or
  confuse Ready/unlocked with verified Released. Read-only retained verification
  requires that exact Released generation plus fresh authenticated peer/compositor,
  absent coverage and clear sleep fence. Relock, owner replacement and generation
  rotation invalidate it; neither a retained flag nor a receipt authorizes dispatch.

These are required boundaries, not completed native qualification or a production
support claim. See proposed [ADR 0042](adr/0042-s17-session-security-and-power-authority.md)
for the current implementation status.

- Session-id/PID/UID reuse cannot inherit approval: bind kernel boot, session
  creation generation, attested security-owner invocation and native lock
  generation in typed resource identity. Counter reset after owner restart does
  not recreate an old approval target.
- A logind hint, cached observation, client boolean, PAM/agent success signal or
  executor acknowledgement cannot prove secure compositor coverage or completion.
- Protective locking is an explicit, login-scoped, revocable owner policy, not
  an implicit root/service exemption. Separate enable/revoke owner-authentication
  purposes bind the exact lock, request, desired setting, previous revision and
  evidence. Wrong-owner PAM identities, manual/unlock/power proof substitution,
  lost coverage and policy drift during interaction cannot enroll a grant.
  Configuration is security-sensitive Linura-owned state with no privileged
  effect. Its separate keyed FULL-sync WAL journal authenticates bounded immutable
  history and the global tip; atomic CAS and read-only historic receipts prevent
  a retried enable from undoing revocation. Missing/corrupt/expired/unknown state
  denies use, and full storage rollback remains a separate recovery assumption.
  Fresh authenticated current consent must be re-read at every managed prepare
  and handoff; a stored record or constructed policy value is not a credential.
- A protective sleep initiator must be attested as the exact root-supervised
  pre-start helper of the current native suspend invocation, including immutable
  configuration/image/argv, live PID generation and not-yet-started kernel entry.
  Root UID, service Actor text and `PrepareForSleep` alone prove neither this gate
  nor a physical lid event. The initiating principal must remain the protective
  service, distinct from approved owner-intent provenance. Canonical managed lock
  risk and durable recovery are unchanged; the exception never unlocks or requests
  power. Event identity is stable across retries/owner restarts. Revocation,
  stale/other invocation and owner generation changes invalidate new authority.
  Observe-only crash recovery cannot reconstruct dispatch permission.
  The protective managed entry point derives the fixed actor/request internally;
  neither manual mutation nor public planning can select its private policy
  context. Fresh canonical preconditions are rebuilt at prepare and handoff,
  while the original observation deadline still bounds dispatch. Current-store
  failure, revocation, seat/generation drift or event loss stops before execution.
  Recovery authenticates the retained service namespace and exact transaction
  anchor without consulting consent or recreating a live event credential.
  A concrete exclusive received-helper scope re-attests each native probe;
  cleanup cannot clear a later binding, and sequence/scope exhaustion fails closed.
- Delay inhibitors expire and cannot be claimed as sleep-denial enforcement.
  Native entry must refuse continuation without fresh verified coverage and fence
  it against concurrent unlock. Already-secured managed suspend must not require
  automatic-lock enrollment. Unsupported native paths require coverage or denial;
  root/kernel bypasses have no universal prevention claim. Protection failure may
  leave a closed laptop awake, with a visible battery/heat tradeoff. The private
  no-argument `SleepGate1` route uses actual received-helper metadata and separate
  bounded coverage coordination; service-account bus admission is never policy.
  The root-launched fixed helper uses one same-PID self-exec to drop all user/group
  identities to the fixed local service account, clear environment/groups and
  usable capabilities, and prohibit privilege gain before opening transport.
  The root-owned executable inode, exact argv, live root-supervised pre-start
  PID/invocation and native phase remain independently attested. This preserves
  live-image checking without adding inspection capability to Control. Untrusted
  account selection, saved root IDs, supplementary groups, retained capabilities,
  missing credential facts and root-only caller substitution fail closed.
  Already-secure
  coverage does not wait on the managed mutation mutex or require protective
  enrollment. Uncovered sessions still enter the single durable managed lifecycle;
  busy/poisoned admission denies, never creates parallel authority. The owner's
  independent native fence denies concurrent unlock until exact job completion or
  freshly authenticated native unit absence. Counters/timeouts/Control replies
  alone cannot clear it. Sanitized bounded diagnostics are published only after
  native received-helper attestation; early error/unwind records denial. A
  no-input own-login query independently checks current native identity and never
  waits behind managed execution. Unknown, busy, restart and invalid replies
  cannot become cached protection claims. The shell warns of failed sleep and
  ventilation risk without exposing raw errors, other owners, event IDs or an
  authentication/action interface. Historical fenced coverage is never evidence
  of current security or a successful sleep cycle. Missing initial helper admission
  cannot be inferred from process-local reporting; native qualification remains
  required. The image disables unqualified hibernation modes rather
  than accepting an uncovered alternative entry. Native deployment, recovery and
  real qualification remain unfinished. The owner-authenticated setting endpoint and owner-scoped historical
  queries expose consent provenance only. No seal/permit is returned; stale
  receipts cannot reenroll, and latest-in-epoch history is not active-session or
  native protection evidence. These routes do not activate automatic locking.
- Unlock uses a purpose-scoped session-owner class. It cannot authorize another
  owner, a later lock, administrator work, destructive actions, or agent approval.
  General baseline protected approval strength remains actor-invariant.
- Raw PAM questions may themselves contain sensitive/provider-controlled text.
  Only a bounded closed prompt kind, step and official native authentication UID
  become fixed presentation labels; unknown/localized questions stay generic.
  Response echo remains masked irrespective of the native echo flag. Cancellation
  or visibility loss during response delivery defers teardown until the protected
  buffer's borrowed pointer has returned and been wiped, then denies completion.
  Accessibility exposes fixed names and password-field/focus/availability metadata
  only: no text, editable-text, value or action interface, response contents,
  selection, cursor or response length. Offscreen Qt coordinates are not native
  multi-monitor geometry. Real AT-SPI traversal/input qualification is still due.
- Suspend, logout, reboot and power-off have distinct transition identities and
  native authentication purposes. Only the exact canonical challenge can consume
  its fresh one-use proof. Power authentication uses separate non-retained admin
  actions, not session-owner unlock permission, and leaves secure coverage intact.
  Control alone derives completion; provider-supplied `completed`, dispatch
  acknowledgement, reply loss and idle/awake snapshots cannot prove a transition.
  Retained S17 transition recovery is observe-only and cannot reprepare or replay.
- Native owner authentication must come from the trusted system authentication
  boundary for the exact canonical challenge. Fixed non-retained Polkit actions
  are checked through a scrubbed environment on the canonical system bus; raw
  authorization-process diagnostics and credentials are not logged or forwarded.
  Control's Polkit transport must bind the local non-root `polkitd` account to
  the exact immutable `polkit.service` launch, current bus/kernel PID and nonzero
  invocation under root systemd supervision. UID-only and root-owner shortcuts,
  duplicate account records, unit drop-ins, substituted argv, finished launches
  and changed generations fail. The original bounded probe covers two fresh
  snapshots and owner rechecks; the identity is revalidated after authentication.
- Control freshly checks native active-session facts and binds their predicates
  in the canonical plan. Fresh locker evidence cannot refresh expired ownership.
  Native adapters must attest the security-owner process and revalidate the same
  epoch/generation at dispatch; an ordinary shell/plugin cannot forge that owner.
- Native peer checks bind named service ownership to the root-supervised main PID
  and service invocation plus exact native launch record/image/argv, not just a
  local/root UID, text service name or unrelated root-owned executable. Native
  Polkit registration/conversation remains separate from privileged dispatch.
  Neither a native PAM completion signal nor a consumed confirmation releases the
  compositor lock. Password input has no QML property, transport payload, clipboard
  or debug formatter; bounded storage must be locked, non-dumpable and wiped.
- Unlock verification retains the old lock identity until Control's durable
  verified commit acknowledgement; no new effects cross that fence. Authentication
  binding rotates exactly one generation, with no outstanding proof or cooldown
  bypass. Independent compositor release uses one bounded native query with the
  connected kernel peer bound to the original compositor, not a client boolean
  or an unlock acknowledgement. Its runtime/canonical-evidence integration and
  native positive qualification remain required.
- Startup protection must precede a large UI runtime. The proposed private runtime
  uses a single memory-lock file capability for secure-exec entry, verifies the
  kernel's `AT_SECURE` marker, rejects user-dumpable/unknown startup states and
  saved-user/group identity escapes, and immediately forces and verifies
  dumpability zero before capability use, memory locking, input or toolkit code,
  drops the capability before input and refuses unexpected privilege/dumpability.
  Its own bootstrap binds the current executable inode and exact root-systemd
  launch, then rechecks active session/service facts rather than trusting PID
  continuity alone. The actual
  connected Wayland peer, not another pathname probe, must bind the qualified
  native session leader. A first-socket path notification may precede Hyprland's
  control socket; startup therefore uses bounded filesystem events and periodic
  listener probes within the same five-second monotonic deadline. Complete
  ownership/type/link route checks remain required. Stale socket inodes do not
  establish availability: nonblocking connections must reach a listener of each
  class. At most one connection per candidate is retained without requests while
  waiting for the other class; inode replacement and closed peers invalidate it.
  Every probe closes before the runtime connects and attests its actual peers;
  liveness never becomes native session identity or authorization. Only relevant
  topology events consume the unchanged 256-event budget; unrelated runtime
  traffic cannot grant readiness or renew the clock. Watch failure, event
  overflow, excessive relevant churn, partial/dead routes and expiry fail closed.
  `Restart=no` remains. Deployment, reload, ptrace and helper behavior still need
  native qualification; component tests do not prove these operating-system facts.
- Native owner metadata reads use fixed, read-only property batches of at most
  32 requests per interface. Each pending request retains its original 500 ms
  timeout and the enclosing caller's unchanged aggregate clock. A partial,
  malformed, substituted or late batch is unavailable, never a negative fact.
  Revalidation issues a separate fresh batch and preserves every existing
  session/launch/identity comparison. No `GetAll`, shared cache, retry, effect or
  new authority path is introduced. The component wire barrier requires every
  read to arrive before any reply, and checks changing samples and failed/late
  members; native qualification still independently decides acceptance.
- Control's repeated native-owner supervision checks request exactly the five
  unit fields and three service fields consumed by the existing immutable
  launch binding. Unrelated systemd accounting getters are not queried. Each
  read-only interface batch shares one 500 ms primitive/remainder deadline and
  one 64 KiB aggregate payload bound, within the original two-second probe.
  Replies must come from the attested unique systemd peer. Missing, malformed,
  failed, substituted, oversized and late members reject the complete batch;
  neither partial maps nor cached results become evidence. Supervisor, kernel
  credentials, invocation, launch, image, session and final boot/owner checks
  retain their original comparisons and fresh revalidation points.
- A compound native lock observation includes fresh peer/session attestation and
  independent compositor sampling. Its RPC, like approval arm/consume, may use
  only the remainder of the original two-second probe after discovery. Reply
  arrival cannot restart that clock; late replies and failed final owner/boot
  revalidation remain hard failures, and pending transitions create no evidence.
  Primitive metadata calls retain their 500 ms cap. This allocation introduces
  no retry, cached authority, effect, or additional verification window.
- Native keyboard input goes directly from a wiped bounded UTF-8 temporary into
  protected storage. Malformed encodings and capacity overflow leave no partial
  edit. An exclusively bound entry rejects generic Qt key-event injection; typed
  response data never traverses Qt/QML input filters. Layout/focus/keyboard loss
  cancels and wipes. Compose data is a source-pinned, digest-checked embedded
  resource without runtime filesystem or user include lookup.
  A focus-before-coverage ordering cannot strand the protected entry: each fresh
  press revalidates the retained native surface and current complete coverage
  before synchronizing entry focus. Leave, layout/device loss and held-key
  rejection remain mandatory; an old focus flag cannot authorize input.
  The native coverage event also synchronizes focus before any keypress, so a
  read-only accessibility readiness probe cannot depend on secret input to focus.
  An unchanged positive focus cannot announce a new focus event per key.
  Retired consent and completed cooldown must not strand the native retry UI.
  Visual denial retirement requires actual Idle approval state and no live scope
  or conversation, without resetting failure state or creating authentication.
  Native call diagnostics use closed classes/stages without remote error text;
  failure-only guest service diagnostics cannot become current-state evidence
  or replace the original failure and ephemeral-account cleanup.
  Owner failure diagnostics compare invocation identity without retaining it
  and read only bounded exit fields/closed watchdog labels from the fixed unit's current-boot
  journal. A later running replacement must never be described as proof that
  the original invocation survived. Closed supervisor refusal stages retain
  every original identity, launch, immutable-asset and lifecycle check.
  A watchdog's fixed diagnostic uses one nonblocking socket send; journal
  backpressure, closure or a non-socket stderr cannot delay the original exit,
  create a retry or invoke lock/Qt cleanup. Durations remain unchanged.
  Blocking peer/session inspection must not starve a prepared lock's Wayland
  acknowledgement. Factory-owned progress drains only the already attested
  native connection between bounded reads, inside the original probe clock.
  It must not dispatch Qt/D-Bus/timer events, recurse through native callbacks
  or painting, cache evidence, renew deadlines or bypass the prepared effect
  gate. Peer/session/scope/generation/compositor and final deadline checks must
  still validate the post-progress result; the acquisition watchdog is unchanged.
  Sleep-gate denial diagnostics select only source-owned stages/reasons and map
  unknown error text to `unclassified`. The disposable suspend failure reader
  bounds current-boot queries to the fixed sleep/Control and disposable owner
  units, 64 entries, 16 KiB and three
  seconds, discards raw journal text and exports only closed failure labels.
  Those labels are diagnostic context, never invocation-bound authority or
  verification evidence; unavailable diagnostics cannot erase a failed effect.
  AT-SPI failure diagnostics retain only a fixed failure family and probe stage;
  numeric exits cannot become accepted unsupported-interface or authentication
  evidence. Correlated call timeouts still abort the probe within the original
  call and aggregate bounds. Native observation errors retain only source-owned
  rejection labels, never raw provider responses or credentials.
  Owner fence/probe failures emit only immutable rejection labels, never native
  properties, peer identifiers, authentication data or remote error text. Probe
  diagnostics are enabled only for the fence call, never recovery; all original
  admission, revalidation, timeout and coverage checks still fail closed.
  Unit/property requests pin the root-attested unique supervisor connection on
  the fixed authenticated system bus. Requested-reply routing rejects foreign
  connection replies. Newer Qt hides reply/error `service()`; older Qt exposes
  the sender, which must still match the pinned peer. The accessor is not portable
  received-sender evidence. Fresh owner revalidation and
  two complete matching snapshots remain required; absence requires two exact
  native `NoSuchUnit` errors. Broker/local errors, non-replies, malformed fields,
  denial, timeout and replacement fail closed under the original probe budget.
  Unit-lookup diagnostics retain only closed failure classes, never remote
  messages, native identifiers or invented empty-sender categories. The private-bus
  component regression sends forged success/absence replies from a separate
  connection before the genuine response; it is not native acceptance evidence.
  A separate bounded two-second read retains only closed unit state/result
  categories and main-PID presence. Unknown fields stay unavailable, and a
  native success result never becomes managed completion or cycle evidence.
  Embedded first-party rendering imports no user/network scene
  and never receives response text. Pre-lock confirmation uses the same exclusive
  connection's fixed private xdg-shell surface. It accepts only a fresh
  unmodified native Enter/Escape press or bounded native primary-button click,
  never Qt/QML synthetic input, text,
  held/repeated keys or an effect. Close, focus/keymap/device loss and
  suspend-inclusive expiry deny it. The private native runtime creates the
  backend after secure startup/session attestation; received system-bus metadata
  selects the freshly supervised Control or executor caller. The XML/Qt wire
  contract exposes separate approval, observation, prepared dispatch and durable
  commit acknowledgements, with no preclaimable per-user service name. Toolkit,
  import, compose, font and bus overrides are removed before GUI initialization;
  user QML disk caches and font configuration are not imported. Positive native
  deployment, pointer/accessibility, production Control/executor/recovery and
  visual qualification remain unfinished; component tests are not that evidence.
- Native pointer events use the same exclusive seat and configured owned
  surfaces. Press and release must hit the same enabled presentation target and
  interaction revision within one suspend-inclusive second. Drag-away, duplicate
  press, unmatched release, focus/device loss, changed prompt/state, wrong button
  and out-of-bounds coordinates cannot migrate a click into authentication.
  Submission still requires native keyboard focus and secure coverage; an unlock
  request is typed intent, not authentication or effect authority. No generic Qt
  mouse event can focus or submit protected input. A fixed software cursor is
  painted in opaque owned buffers without loading a user cursor theme. Native
  pointer and assistive-technology qualification remain required.
- Offscreen Qt metadata factories alone do not export a native screen-reader
  tree. S17's dedicated AT-SPI adapter uses fixed own-runtime Unix routes and
  kernel peer UID checks, but still treats assistive bus peers as untrusted
  presentation readers. Its bounded metadata projection has no response bytes,
  length, cursor, selection, raw PAM question or effect/security fact. Standard
  text/value/editable-text/action/geometry interfaces are absent. The sole
  writable registry ID is unused bookkeeping, never approval or input. Bounded
  worker dispatch and cancellable original connection/registration budgets keep
  those peers off native keyboard dispatch. Transport/registry loss retires the
  export; read-only reconnection cannot release coverage, recreate authority or
  replay effects. Real discovery, announcements and denial still require native
  qualification. Local metadata availability is not authentication evidence.
- Power availability is not policy or OS execution authority. Unknown inhibitors,
  another user session or in-flight transitions fail closed. Root must respect
  both regular and weak blocking inhibitors; suspend also requires exact native
  secure-lock coverage and bounded native delay-inhibitor coordination.
- Session/boot-ending effects retain durable ambiguity; acknowledgement is not
  verified success and restart cannot blindly repeat a one-shot power action.
- Post-dispatch suspend verification first classifies the complete fresh native
  transition.
  Known preparation or an unchanged cycle must not start a lock probe that could
  cross kernel sleep. Only an exact completed cycle requests fresh secure coverage;
  that intermediate requirement proves no completion. Final canonical review
  revalidates both original envelopes at the current time, without extending
  either lifetime, retrying failed required observations or replaying an effect.
  A native read crossed by exactly the retained baseline-to-baseline+1 suspend
  cycle may be discarded only after both disabled debug-mode reads, original
  epoch presence, boot, root logind owner and original probe deadline validate.
  The discarded sample has no authoritative envelope or new sequence. Only the
  post-dispatch verifier may await another independent sample within Control's
  unchanged bound; planning still rejects it. Transport errors, unknown facts,
  extra cycles, changed identities and expired probes remain hard failures.
- Digest-only transactions cannot reconstruct approved intent on restart. S17
  retains canonical structured requests, including provenance, before prepare
  in an independently authenticated, bounded, write-once FULL-sync WAL journal.
  Recovery checks the exact principal/request namespace, canonical codec and
  transaction anchor. Missing/corrupt/substituted material denies recovery;
  journal failure denies new prepare/dispatch. Orphan records grant nothing,
  and historical request retrieval cannot approve, reprepare or execute. An
  internally consistent rollback of all storage still requires the separate
  recovery/rollback trust assumptions; the journal is not a trusted clock or
  anti-rollback oracle. No raw request bytes enter diagnostics or audit payloads.
- Security-owner crash must leave conformant native compositor coverage closed;
  ordinary shell reload/dismissal must never own an unlock path. Native recovery,
  multi-output/hotplug, authentication/account denial and visual/interaction
  evidence are required before activation or final review.

### S21 device identity substitution, insecure output topology and media loss

- Native attempt status is obtained only through the independently supervised
  Control caller and the owner's retained attested compositor connection. Exact
  canonical intent, current lock/topology and original effect/dispatch/deadline
  scope must match around the native get_status read. The adapter preserves the
  conservative sample time and original probe deadline; unknown phases, changed
  owner/boot/output inventory and substituted wire scope fail closed. Native
  terminal flags remain separate from independent layout verification and
  protected human decisions. Querying or reconnecting grants no continuation or
  effect-replay right.

- A client can authenticate as the session owner and still be unable to prove a
  new protected keep/revert decision. Control requires a separate consumed human
  proof bound to the already prepared canonical request, durable authority
  generation/binding, dispatch record, exact action, fresh native attempt and
  original deadline. Original apply approval, cached proof, opposite-action
  proof and ordinary caller provenance do not satisfy this boundary. A newer
  attempt probe follows interaction, and keeping also requires a new independent
  layout check. Protected decisions retain their challenge correlation in an
  explicit v2 journal frame; legacy v1 decisions are retained but rejected for
  protected authority rather than silently upgraded. Lost replies and durable
  reservations remain observe-only. Native interaction and end-to-end recovery
  qualification remain required before production activation.

- A same-UID Wayland client must not reach display writes by constructing private
  protocol messages or exhaust all protected-owner slots. Private-global binding
  attests the owner before allocating any slot; apply reattests the bound
  invocation. Admission requires the exact immutable root-systemd-supervised
  owner PID/UID, service image/arguments and live InvocationID through the fixed
  root-peer bus. Each original-connection confirm/revert reattests that same
  invocation under one 250 ms budget and retained pidfd. Root service/daemon
  replacement, PID reuse, non-running state, drop-ins, malformed evidence or an
  unavailable bus deny the explicit effect; they do not disarm automatic native
  recovery. Component substitutions and real-wire denial/timer tests do not
  qualify the actual root-supervised positive path. That native path remains
  required before production activation.

- A source-pinned compositor integration is a bounded native mechanism, never
  policy or privileged execution authority. The production caller must retain
  canonical Rust planning, authenticated principal binding, managed durable
  prepare/revalidation and fresh independent verification. Correlation fields
  cannot authorize a display change or let another connection confirm one.
- A pending attempt's BOOTTIME timer belongs to the compositor, survives native
  client disconnect, and reserves baseline compensation once before dispatch.
  Acknowledgements cannot establish restoration. Compositor loss, stale native
  lifetimes, coverage gaps and failed compensation remain indeterminate until
  independently reconciled; they cannot silently replay or renew authority.
- Compensation must restore original ownership and automatic rule behavior,
  not leave numeric baseline overlays installed. The compositor reserves its
  prior overlay/rule checkpoint before its first write; a different baseline,
  replaced output or changed underlying owned rule refuses restoration. Current
  unrelated rule settings are retained. Independent numeric geometry cannot
  retire the recovery fence unless the native ownership check also passes.
  This in-process checkpoint cannot survive compositor death or substitute for
  the still-required durable last-known-good/restart reconciliation path.
- Keep cannot downgrade the original layout mutation to a NoChange policy
  subject after the desired layout is visible. Control retains a bounded
  historical canonical review with no observation or execution capability and
  rechecks current operation registration, exact original risk/source revision,
  policy and approval revocation/expiry before interaction, after independent
  verification and after durable decision I/O. Lost review/approval at restart
  denies Keep rather than reconstructing authority from the journal; observation
  and independently scoped restoration remain available. A denied post-journal
  decision is observe-only and cannot be replayed as a continuation.
- Prepared display transport accepts only the independently supervised Control
  sender and separate default-deny executor action. The complete intent must
  reproduce the sealed effect/binding. Root's strict native decoder and the
  owner's immediate raw-sample recheck retain the same owner, boot and original
  sample deadline through one apply; copied digests are correlation, not grants.
  Native unknown/denied/lost replies remain ambiguity, never verified success or
  permission to retry. Status uses the original validated durable dispatch scope
  without requiring adapter memory, creating another effect or adopting a prior
  connection's continuation. Component fixtures and live bus-denial cases do not
  establish complete native display execution, recovery or support.
- The compositor acquires the fixed native logind sleep/shutdown block inhibitor
  before any display write, independently checks the root service and current
  preparation state, and revalidates captured output facts and deadlines after
  acquisition. Denial, service loss or a preparing transition refuses admission.
  Its descriptor outlives clients and remains held through ambiguous/failed
  restoration. Only native full-layout verification retires it; this does not
  establish recovery after compositor termination or bypass S17's power policy.
- S17 approval/release/power/pre-kernel admission re-reads the native display
  fence, including attempts created by a prior owner. Pending/restoring/failed,
  unknown or mismatched native state cannot authorize a security transition.
  Wayland draining precedes final proof/input-generation checks so a hotplug
  callback during the probe cannot leave old eligibility intact. The secure
  owner's per-output configured/committed/flushed predicate is rechecked after
  the read, including outputs awaiting configure despite a global lock ack.
  The exact
  pinned normal and forced unlock paths also reject release while fenced before
  clearing locked state or changing the security epoch. Exclusion is published
  before initial inhibition/modeset callbacks, before the transaction object has
  returned to its supervisor. Reentrant admission cannot use that interval to
  acquire a second reservation. Component tests are not proof of real first-frame
  safety, overlap or restart reconciliation.
- Protected input requires committed and flushed frames for every current lock
  surface, not merely the global lock acknowledgement. Output add/remove/resize
  cancels the old prompt and invalidates unconsumed proofs. A completed proof is
  also bound to the native keyboard focus/keymap/capability generation. Held keys,
  compose state and clicks cannot migrate a response into a reconfigured prompt.
  Wire fixtures are not native authentication/hotplug qualification; the existing
  Level A runner must additionally execute its new real pending-PAM/hotplug denial
  and independently authenticate the same retained lock again afterwards.
- Compile against the exact reviewed Hyprland source/API and preserve unrelated
  monitor-rule fields. Reject mismatched integration identities, missing
  GLES3/EGL/SDK dependencies, unsupported environments and unverified native
  outcomes. Preserve the upstream security-context global filter: sandboxed
  clients must not acquire the new privileged display global. Native negative
  qualification must exercise this boundary, beyond generic protocol fixtures.
- SDK/package inventories and development caches are not native or physical
  evidence. Reuse the existing Level A/B/C contracts, with display execution,
  restoration and S17 lock coverage required in S21-2 and physical Q11 separately
  maintained. No build profile, self-reported phase or old-head result promotes
  readiness to runtime acceptance or release support.
- The native runtime consumes a compositor build candidate only from the same
  exact-source workflow attempt. Its closed file inventory, streamed size/hash
  checks and source/recipe/contract/SDK bindings are checked again inside the
  root-immutable disposable Arch guest. Its freshly configured protected owner
  must have the same integration identity. The stopped reference executable is
  replaced atomically only inside that guest, and bootstrap checks the running
  inode against the retained binary digest. This fixture cannot install on a
  host, supply a public updater, cache Linura outputs as a substrate, grant
  execution authority or promote the candidate to display/recovery/S17 support.
- Candidate handoff binds the canonical runtime package contract as well as the
  build SDK. Require the runtime's declared package set and exact SDK versions
  for every installed package; do not require build-only tools to be installed
  in a runtime guest. Wrong snapshot/base/architecture, missing runtime packages,
  version drift and unbound additional providers all remain unsupported.
- The native owner binds the private output protocol on its existing attested
  Wayland connection and requires the live pinned upstream/source identities.
  Stable compositor/output lifetimes survive owner reconnection for observation;
  replacement clients cannot acquire old apply/confirmation rights. Complete
  inventory, geometry, original timestamps and exact float/fixed scale evidence
  must agree independently. Retiring terminal wire objects preserves one-use
  correlation tombstones; resource reclamation is not permission to replay.
- Read-only own-display discovery has no UID/session/target input. Control
  binds one native display/owner sample to independent active local logind
  evidence for the transport principal and exact seat/epoch. Original sample
  time and earliest expiry survive projection and client decoding. Deny stale,
  unsupported, duplicate, incomplete and replaced-generation reports; no cached
  fallback or retry. A report of powered-off outputs is diagnostic state, not
  a visible recovery guarantee, lock coverage, approval or execution authority.
  Its bounded 16-output/128-mode inventory uses a dedicated 64 KiB reply cap;
  existing Authority1 methods retain their 16 KiB cap.
- The public display mutation methods accept only bounded typed intent or a same-request
  lifecycle decision. Principal identity remains transport-derived. Receipt
  decoding requires the exact structure, request namespace, canonical topology,
  transaction and closed state; history is never current layout or protection.
  Unsupported authority compositions refuse before prepare. The current
  production composition remains unsupported until native prepared admission,
  protected display decisions, execution and recovery are fully connected and
  qualified. A transport method or an SDK command cannot stand in for that proof.

A client, provider or stale resource alias may retarget approved operations to
another compositor output, physical backlight, removable drive or login session;
a partial write or lost reply may be misrepresented as verified completion.
- Bind each effect to freshly observed boot/session/seat/provider and exact
  resource generation. Connector labels, EDID, native object paths and
  `/dev/sdX` alone do not confer authority.
- Reject unsafe/partially applied display layouts unless independently
  recoverable, and preserve native S17 `ext-session-lock` coverage for
  every active output during hotplug and compositor restart.
- The display component projection rejects incomplete or aliased output/mode
  inventories, wrong native envelope identity/authority and expired evidence.
  Native JSON cannot round an ambiguous refresh tuple into supported state;
  duplicate known fields, invalid scale/transform and mirror chains are rejected.
- Display preview uses the canonical planner and existing bounded retention;
  changing the layout, reason or native lock target under one retained request
  identity fails closed. Separate fresh logind and lock observations must bind
  the exact seat, compositor topology and complete active-output generations.
  A generic secure bit, screen count or discovery-only IPC result is insufficient.
- Pure display postcondition review requires strictly post-dispatch timestamps
  and advancing observation sequences from all sources, unchanged lock identity
  and state, exact full layout and a powered independent output. Neither this
  review nor a retained last-known-good candidate grants dispatch, durable
  restoration, commit or replay authority. Native binding/activation remains pending.
- Deny foreign-seat/unknown backlight, unsafe physical brightness bounds,
  implicit software-gamma substitutions and arbitrary privileged sysfs writes.
- Keep UDisks2/Polkit subject authentication, drive/partition/filesystem
  topology, busy or sibling-volume denial, no arbitrary mount options,
  and no replay after unplug or ambiguous eject.
- Reuse S17 secure suspend, native inhibitors including `block-weak`,
  principal and non-replayable power recovery, without force shortcuts.
- Final success requires independent post-effect observation; synthetic
  fixtures and video do not substitute for required native/physical proof.
- See proposed [ADR 0045](adr/0045-s21-workstation-device-authority.md) and
  [S21 security qualification](qualification/v0.10.0-s21-security.md).

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


### PipeWire numeric-node reuse, moving-default substitution or unaudited session dispatch
A session audio client supplies the moving default alias as mutation authority, or a concrete PipeWire numeric object ID is destroyed and reused for a different sink between authoritative planning and executor dispatch. A local persistence failure could otherwise allow an external effect without durable attempt evidence.
- the default-output alias is observation/discovery-only and is outside the registered mutation resource scope;
- the trusted pre-effect observation records exact `node_id`, `object_serial`, `node_name` and `media_class` material;
- observation and execution use a root-owned packaged WirePlumber helper rather than `wpctl` text/ID command composition;
- the helper's `ObjectManager` resolves exactly one `Audio/Sink` whose bound node ID, `object.serial` and `node.name` all match the trusted pre-effect evidence, then invokes `mixer-api` on that matched object in the same event-loop callback without yielding; there is no second external numeric-ID target lookup between identity match and mutation;
- volume execution accepts only the registered operation/provider, one exact numeric output resource and one canonical integer `volume_percent` in 0..100; the mixer uses cubic user-volume scale and the helper rejects values above 100%;
- `/usr/bin/wpexec` and the helper path are fixed, the helper must be a root-owned single-link regular file that is not group/world writable, execution has a bounded deadline and scrubbed environment, and raw helper stderr is consumed under the output bound but is not surfaced as public/provider diagnostic text;
- the per-user SQLite audit runs in WAL + FULL synchronous mode with bounded retained records and bounded database/WAL growth; opening rejects symlinks, hard-link aliases, oversized files, unexpected schema objects and any column/STRICT-schema drift;
- Control requires the durable attempt reservation before dispatch, and terminal records are finalized only against the same attempt binding; a non-no-change terminal record without a prior reservation fails closed;
- Session1 carries typed request material only, requires the authenticated sender UID to match the UID owning the service's session-bus connection, and owns no shell, provider forwarding, policy decision or privileged execution authority.
