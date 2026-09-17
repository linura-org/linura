# v0.9 durable bootstrap and provisioning threat model

## Status and scope

This document defines the next bounded v0.9 slice after durable update/migration recovery. It covers persistent bootstrap state, crash/restart recovery, the bounded Provisioning Manifest, restart-safe provisioning modes, deferred owner enrollment, and the authority boundary between a preparer and the eventual owner.

This slice remains **Experimental** and does not itself create a v0.9 platform-support or release-readiness claim. Disposable-system qualification and the dedicated v0.9 adversarial security qualification remain required before release closure.

## Core security rule

Bootstrap persistence is **state/evidence, never authority**. A durable bootstrap ledger, provisioning-mode record, Provisioning Manifest, manifest digest, restart checkpoint, preparer session, or `owner-enrollment-pending` record must never grant executor permission, policy approval, shell access, model authority, or replay authority.

A restart may recover what has been durably and safely observed, but it must not recreate historical authority or blindly replay an external effect.

## Durable bootstrap ledger v1

The persistent bootstrap ledger must be versioned, bounded, integrity-checked, and fail closed.

Required properties:

- canonical stage order matches the v0.9 `BootstrapStage::ORDERED` contract;
- persisted state represents only a canonical completed prefix plus the first incomplete stage;
- skipped, duplicated, unknown, out-of-order, corrupt, truncated, or unsupported-newer records fail closed;
- ledger size, field count, identifier length, and serialized nesting are explicitly bounded;
- persistence uses a same-directory temporary file, `fsync`, atomic rename, and parent-directory `fsync`;
- post-rename durability ambiguity is distinct from definite pre-rename failure;
- concurrent writers are serialized and protected by durable generation/CAS identity;
- restart reopens and re-observes durable state before any next-stage decision;
- completed stages are never blindly replayed merely because an in-memory caller asks to run them again;
- a crash before a commit leaves the stage incomplete; a crash after an ambiguous commit requires reopen/reconciliation rather than guessing.

The ledger must not contain bearer credentials, approval tokens, generic commands, shell snippets, model output transcripts, or executor capabilities.

## Rollback-protection boundary

The v0.9 generation anchor is deliberately stored outside the mutable bootstrap state root and is machine-scoped. Within this bounded threat model it detects replacement or restoration of an older ledger/state-root copy while the machine-scoped anchor remains trustworthy, and a copied disk is additionally bound to protected machine identity plus the DMI hardware UUID so cross-machine continuation fails closed.

v0.9 does **not** claim cryptographic rollback resistance against a privileged actor that can rewind the entire trusted storage domain on the same hardware, including both the bootstrap ledger and its generation anchor in one whole-filesystem or whole-disk snapshot. Defending that stronger rollback class requires a trust anchor outside the rewound storage domain, such as TPM-backed monotonic/NV state, a hardware-backed counter, or an authenticated remote monotonic service. That stronger hardware/remote anti-rollback guarantee is outside this Experimental v0.9 slice and must not be inferred from the local generation anchor.

Accordingly, “ledger rollback” qualification in this slice means rollback/substitution of the ledger or bootstrap state root against a non-rolled-back machine-scoped anchor, plus cross-machine clone rejection. Evidence and release language must not describe the local anchor as protection against privileged same-machine whole-disk rollback.

## Provisioning Manifest v1

The Provisioning Manifest is **untrusted declarative input** delivered through a qualified local transport. It is not a script and is not an authorization artifact.

The manifest must have:

- an explicit schema/version identifier;
- a strict maximum byte size;
- explicit maximum collection counts and string lengths;
- bounded structural depth;
- a canonical serialization used to compute an exact manifest identity/digest;
- fail-closed rejection of unknown critical fields, duplicate keys after canonicalization, malformed encodings, path traversal, control characters, and unsupported versions;
- exact binding between the parsed manifest and the durable bootstrap/provisioning state that consumes it.

Permitted declarative domains are bounded to the v0.9 contract, including provisioning mode, source/profile selection, bounded bootstrap networking, non-secret references, deferred owner enrollment, and bounded host identity.

The manifest must reject and must never carry:

- shell snippets or generic commands;
- executable scripts or package-manager command text;
- executor permits or dispatch authority;
- policy overrides or approval decisions;
- historical action/replay transcripts;
- passwords, private keys, recovery secrets, bearer tokens, or owner credentials;
- model/provider authority or instructions that can bypass canonical Control authorization.

## Restart-safe provisioning modes

The durable provisioning state machine must encode exactly the supported v0.9 modes:

1. `interactive-owner` — the eventual owner is present and enrollment may be completed through the qualified path;
2. `prepare-for-another-owner` — the preparer may bring the machine to a safe handoff boundary but cannot invent or retain final-owner authority;
3. `unattended-local` — bounded declarative provisioning driven by a validated local Provisioning Manifest;
4. recovery — native recovery path, not a hidden normal provisioning shortcut.

Every mode transition must be explicit, monotonic, restart-safe, and exact-bound to the current bootstrap session and manifest identity when a manifest is involved.

## `owner-enrollment-pending`

`owner-enrollment-pending` is a first-class durable state, not an implicit absence of an owner.

Entering this state means:

- the machine is prepared for handoff but has no final-owner authority yet;
- preparer-local temporary credentials and sessions are revoked or scrubbed from the handoff boundary;
- preparer approvals, permits, decisions, model conversations, and executor capabilities are not portable into owner enrollment;
- ordinary provenance may record that a preparation event occurred, but must not retain credentials or reconstruct authorization;
- restart returns to the same pending state without replaying preparer actions.

Leaving `owner-enrollment-pending` requires a fresh owner-enrollment transaction that creates a **new authority generation**. The eventual owner cannot inherit the preparer's credential material, approval generation, authenticated session, executor permit, or prior Control decision.

## Authority-generation separation

The implementation must keep these identities distinct:

- machine identity;
- bootstrap/provisioning session identity;
- preparer/operator identity;
- eventual owner identity;
- manifest identity;
- authority generation.

No equality or reuse of caller-visible names may collapse these boundaries. Durable records may correlate identities for audit/recovery, but correlation is not authorization.

## Crash and restart semantics

Every stage that may cause an externally visible effect follows the same fail-closed pattern used by the durable update/migration slice:

1. establish exact input/target identity;
2. durably record the prepared transition if needed;
3. perform the bounded external effect;
4. re-observe authoritative postconditions;
5. durably commit the stage only after verification.

Crash injection must cover before and after every durable boundary. If an effect may have started but completion cannot be proven, restart must re-observe/reconcile or enter recovery; it must not infer success from a later stage and must not blindly replay.

## Production preparer-revocation evidence

The v0.9 production bootstrap includes a narrowly scoped preparer-revocation signer. It is not an owner-enrollment signer and cannot create policy approval, executor permits or final-owner authority. It becomes usable only in the active `OwnerEnrollmentResolution` effect-started state, under effective UID 0, after First Boot has terminated the fixed `linura-preparer` processes, removed supplementary-group/SSH/sudo authority, locked the password when the account exists, validated sudoers, synchronized the filesystem and re-observed those postconditions. The authenticated receipt binds session, machine, operation, stage, effect state, scope, postcondition digest and freshness. An already-valid externally produced qualification receipt remains consumable, preserving independent adversarial verification.

## Required adversarial qualification

The dedicated v0.9 security qualification must cover at least:

- malformed, truncated, oversized, deeply nested, duplicate-key, and unsupported-version manifests;
- forbidden command/script/approval/policy/credential fields;
- path traversal, symlink, hard-link, and permission attacks on ledger/manifest state;
- stale or cross-machine/cross-session manifest replay;
- concurrent bootstrap writers and stale generation/CAS attempts;
- ledger rollback, substitution, corruption, gap, duplicate-stage, and out-of-order stage attacks within the rollback-protection boundary defined above;
- crash windows before/after every persistent bootstrap transition;
- TOCTOU between manifest validation, durable binding, and effect execution;
- attempts to preserve or restore preparer credentials after entering `owner-enrollment-pending`;
- attempts to reuse preparer approvals, permits, sessions, or authority generation for final-owner enrollment;
- ownership takeover attempts after restart;
- diagnostics/provenance checks proving secrets and bearer authority are not leaked.

## Disposable-system evidence

Before release readiness, the exact Ubuntu 24.04 / amd64 / QEMU TCG QualificationEnvironment must prove:

- bootstrap ledger persistence across real process/system restart;
- resume from every stage boundary at the first incomplete stage;
- no completed effect is blindly replayed;
- all three normal provisioning modes survive restart;
- `prepare-for-another-owner` reaches durable `owner-enrollment-pending`;
- eventual owner enrollment after restart creates a fresh authority generation;
- preparer credentials/approvals/permits are unavailable to the eventual owner;
- invalid/corrupt/newer persistent state fails closed into recovery;
- Q11 migration/restore/update-interruption/native-recovery cases remain green on the same exact source;
- native recovery remains usable with First Boot, model/provider, and network unavailable.

Evidence must bind exact source SHA, scenario revision/digest, base-image digest, machine environment, relevant binary hashes/sizes, toolchain/QEMU identity, and immutable workflow/run identity. Source-level unit tests alone must not advance release support.

## Security conclusion for this slice

The acceptance boundary is: **restart may recover durable bootstrap facts, but it may not recover historical authority**. A Provisioning Manifest is bounded declarative input, `owner-enrollment-pending` is explicit durable state, and final-owner enrollment must mint fresh authority that cannot inherit preparer credentials, approvals, permits, sessions, or replay capability.
