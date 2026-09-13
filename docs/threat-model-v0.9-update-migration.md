# v0.9 update and migration recovery threat model

## Status and scope

This document covers the v0.9 durability boundary introduced for migration ledgers, migration backups, and update restart/recovery state. It supplements the main security model and the v0.9 First Boot recovery model.

These records are **evidence and recovery state, not authority**. A durable migration ledger, backup record, prepared package transaction, update journal, transaction ID, snapshot ID, verification receipt, dispatch generation, or recovery reason cannot authorize a privileged effect, substitute for policy/approval, or become a bearer capability.

This slice does not claim that Q11 is complete. It establishes source-level durability and fail-closed restart contracts that must still be exercised end-to-end on the exact v0.9 QualificationEnvironment before release readiness.

## Assets and trust boundaries

Protected assets:

- the set of migrations known to have been verified and durably committed;
- exact-target recovery backups used to make a risky migration reversible;
- update stage and exact package-transaction correlation identity;
- the prepare/dispatch/verification boundary for an external package effect;
- trusted producer provenance and freshness of update verification evidence;
- explicit recovery-required state;
- native recovery availability independent of First Boot, models, and hosted services.

Untrusted or non-authoritative inputs include callers, model output, imported configuration, caller-selected evidence roots, filenames supplied outside repository-owned paths, stale process memory, old/replayed receipts, and any persisted state that fails integrity/shape/permission validation.

The v0.9 production update-evidence trust anchor is fixed at `/var/lib/linura-update/v0.9`. Its qualified producer identity is `linura-update-evidence-v09`, and the reference-environment producer files are root-owned (UID 0). A caller-selected directory is never promoted into a production trust anchor merely because it is mode `0700` or self-consistent.

## Threats and required controls

### Persisted-state corruption or substitution

Threat: an attacker, crash, partial write, downgrade, or unrelated process changes a migration ledger or update journal so Linura skips work, repeats effects, or assumes success.

Controls:

- versioned, bounded on-disk formats;
- deterministic integrity tags that detect accidental/corrupt substitution but are **not** treated as cryptographic authentication or authority;
- regular-file and non-symlink requirements;
- group/other-writable state files rejected;
- unknown/newer format versions fail closed;
- invalid identifiers, stages, effect states, or impossible state combinations fail closed;
- atomic same-directory create-new temporary writes, file `fsync`, rename, and parent-directory `fsync`;
- the ledger rename is an explicit commit point: failures before rename are definitely uncommitted, while failures after rename are durability-ambiguous and enter recovery instead of triggering rollback or replay;
- update coordinators compare both durable state and the durable journal generation before replacement, so an independently replaced same-content journal is treated as stale rather than silently accepted.

Release qualification must additionally prove corruption/newer-schema rejection on the exact reference environment.

### Backup aliasing, wrong-target use, substitution, and TOCTOU drift

Threat: a migration is declared recoverable using the source file itself, a hard link to it, a stale backup, different bytes, a perfectly valid backup of an unrelated resource, or a source/backup pair that changes after validation but before `apply()`.

Controls:

- source and backup must be regular non-symlink files;
- canonical paths must differ;
- device/inode identity must differ, rejecting hard-link aliases;
- source and backup device/inode identities are retained and must remain unchanged during revalidation;
- backup must be non-empty and byte-for-byte equal when validated;
- the backup artifact and its parent directory are durably flushed before the checkpoint is accepted;
- size and deterministic integrity evidence are retained and revalidated immediately before a risky migration applies;
- every risky file-backed migration declares its exact recovery target;
- the validated backup source must match the migration target by canonical path and retained device/inode identity before `apply()` is permitted;
- for the Linura-managed migration path, the exact source and backup are opened with no-symlink semantics and held under exclusive advisory locks from checkpoint acquisition through migration execution;
- after the durable recovery marker is written and immediately before `apply()`, Linura rechecks the held descriptors, path/device/inode bindings, lengths, permissions, and byte-level checkpoint integrity; any drift fails closed;
- a migration marked as requiring a snapshot/backup cannot start without both an exact target binding and validated recovery evidence.

The file locks serialize cooperating Linura participants; they are not claimed to prevent a privileged non-cooperating process from writing. The immediate post-marker path/inode/content recheck is therefore also required and release qualification must inject checkpoint drift to prove fail-closed behavior.

End-to-end qualification must still prove restoration of a validated backup after injected migration/update failure.

### Verification or ledger failure after migration effect

Threat: a migration mutates state but verification or durable ledger commit fails and Linura records, rolls back, or retries the wrong state.

Controls:

- migration verification occurs before the durable applied-ledger commit;
- reversible migrations attempt rollback on verification failure;
- rollback failure escalates to explicit manual recovery rather than surfacing as an ordinary retryable operation error;
- failed verification never marks the migration applied;
- non-reversible failure enters explicit manual-recovery state rather than fabricating success;
- a ledger write failure **before** rename is definitely uncommitted; reversible work may roll back and a rollback failure escalates to manual recovery;
- a ledger failure **after** rename is `DurabilityUncertain`: the migration is not rolled back because the durable ledger may already contain the applied ID;
- after such an ambiguous commit, the in-process runner becomes recovery-required and refuses additional migrations until durable state is reopened/reconciled.

A durable ledger is therefore evidence of a verified migration, not permission to run one.

### Trusted update evidence provenance

Threat: a caller chooses its own evidence directory, writes self-consistent integrity-tagged receipts, and presents them as trusted provider evidence.

Controls:

- production verification does not accept a caller-supplied evidence root;
- the production verifier opens only `/var/lib/linura-update/v0.9`;
- the root is inspected before canonicalization and again afterward, must remain the same directory identity, must not be a symlink, must not be group/other writable, and must be owned by the qualified producer UID;
- individual receipts must be single-link regular non-symlink files, non-group/other-writable, and owned by the same trusted producer identity;
- receipt `source` must equal the qualified producer identity `linura-update-evidence-v09`;
- deterministic receipt integrity tags detect corruption but are not the source of trust; trust comes from the preconfigured producer path/identity plus exact receipt binding.

Test-only alternate roots exist only behind Rust `cfg(test)` and are not part of the production API.

### Crash before package dispatch

Threat: Linura restarts after selecting a package transaction but before an external effect begins and loses the exact transaction identity.

Controls:

- package dispatch is preceded by a durable `Prepared` state bound to an exact transaction ID;
- snapshot policy is checked before the prepare boundary;
- a restart from `Prepared` may continue only with that exact prepared transaction;
- no generic command text or executor credential is persisted.

### Crash, replay, or transport loss after dispatch begins

Threat: an external package effect may have happened, may be in progress, or may have failed; a restart blindly replays it, or an old successful verification receipt is replayed against a new dispatch that reused the same caller-visible IDs.

Controls:

- `DispatchStarted` is durably recorded at the dispatch boundary;
- a restart from `DispatchStarted` returns `ReobserveBeforeContinuing`;
- each durable journal replacement has an observed generation identity derived from the exact journal file identity and commit timestamp;
- package verification evidence must bind the update ID, target ID, transaction ID, **and the exact current durable dispatch generation**;
- package verification evidence carries an issuance timestamp, must not predate the current dispatch generation, must not be implausibly future-dated, and is accepted only within the bounded verification freshness window;
- the coordinator rechecks dispatch generation and freshness immediately before moving the package transaction to `Verified`;
- a receipt from another durable dispatch generation is rejected even if update/target/transaction IDs are reused;
- the package transaction cannot advance to migrations merely because dispatch was acknowledged;
- independent trusted-producer verification must move the transaction to `Verified` first;
- no blind replay permission is reconstructed from the journal.

This mirrors Linura's broader rule that durable recovery state is not serialized execution authority.

### Bypassing native recovery or direct-upgrade policy

Threat: a broken Linura path prevents native recovery, or an ordinary direct package upgrade silently bypasses Linura's coordinated update lifecycle.

Controls:

- direct-upgrade decisions remain fail-closed unless the operation is explicitly coordinator-owned or explicit break-glass context is present;
- break-glass is recovery policy, not a hidden normal path;
- model/network/First Boot availability is never required for native recovery.

The v0.9 release must still qualify the native recovery path and interruption recovery inside the exact Ubuntu/QEMU reference environment.

### Path and permission attacks

Threat: symlinks, writable state files, path aliasing, caller-selected trust roots, or malformed identifiers redirect durable evidence or recovery artifacts.

Controls:

- migration IDs and update correlation IDs are bounded and path-safe;
- persisted ledger/journal files reject symlinks and group/other write access;
- backup files reject symlink and same-inode aliasing;
- exact migration-target path/inode binding prevents unrelated backup substitution;
- production update evidence is anchored to a fixed root-owned producer path, not a caller-selected directory;
- temporary durable-state files use `create_new` and mode `0600`.

Further production integration must create and preserve these state/evidence directories under packaging/service identities appropriate to the final process boundary.

## Adversarial qualification matrix

Before v0.9 release readiness, exact-source qualification must cover at least:

- corrupt/truncated migration ledger;
- unsupported-newer migration ledger version;
- corrupt/truncated update journal;
- unsupported-newer update journal version;
- symlink or writable persistent-state substitution;
- caller-selected/self-owned update-evidence root substitution;
- evidence-root symlink/ownership substitution;
- hard-linked backup substitution;
- unrelated valid backup presented for a different migration target;
- stale/changed/replaced backup source before migration;
- source/backup drift after initial checkpoint validation but before migration apply;
- migration verification failure and rollback;
- rollback failure/manual-recovery escalation;
- pre-rename ledger failure with safe rollback;
- post-rename ledger durability ambiguity with **no rollback and no in-process replay**;
- crash/restart before dispatch;
- crash/restart after dispatch started;
- replay of a package-verification receipt from a previous dispatch generation;
- stale or future-dated package-verification evidence;
- verification failure after package dispatch;
- update interruption at deterministic checkpoints;
- validated backup restoration after injected failure;
- native recovery with First Boot/model/network unavailable;
- proof that no persisted recovery record grants executor/policy/approval authority.

## Security conclusion for this slice

The source-level design now fails closed at the dangerous ambiguity and substitution boundaries: **once an external update effect may have started, restart requires re-observation rather than blind replay; package success evidence must come from the fixed trusted producer and bind the exact current dispatch generation within a freshness window; once a migration ledger rename may have committed, recovery/reopen is required rather than rollback or replay; and a risky migration holds and rechecks its exact recovery checkpoint through the validation-to-apply boundary**.

This is necessary but not sufficient for the v0.9 support claim. Disposable-system Q11 acceptance, native recovery, restore execution, persistent First Boot/provisioning state, packaging of the trusted update-evidence producer path, and final security/release review remain release blockers until separately qualified and bound into Trusted Release Proof.
