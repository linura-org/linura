# v0.9 update and migration recovery threat model

## Status and scope

This document covers the v0.9 durability boundary introduced for migration ledgers, migration backups, and update restart/recovery state. It supplements the main security model and the v0.9 First Boot recovery model.

These records are **evidence and recovery state, not authority**. A durable migration ledger, backup record, prepared package transaction, update journal, transaction ID, snapshot ID, or recovery reason cannot authorize a privileged effect, substitute for policy/approval, or become a bearer capability.

This slice does not claim that Q11 is complete. It establishes source-level durability and fail-closed restart contracts that must still be exercised end-to-end on the exact v0.9 QualificationEnvironment before release readiness.

## Assets and trust boundaries

Protected assets:

- the set of migrations known to have been verified and durably committed;
- exact-target recovery backups used to make a risky migration reversible;
- update stage and exact package-transaction correlation identity;
- the prepare/dispatch/verification boundary for an external package effect;
- explicit recovery-required state;
- native recovery availability independent of First Boot, models, and hosted services.

Untrusted or non-authoritative inputs include callers, model output, imported configuration, filenames supplied outside repository-owned paths, stale process memory, and any persisted state that fails integrity/shape/permission validation.

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
- the ledger rename is an explicit commit point: failures before rename are definitely uncommitted, while failures after rename are durability-ambiguous and enter recovery instead of triggering rollback or replay.

Release qualification must additionally prove corruption/newer-schema rejection on the exact reference environment.

### Backup aliasing, wrong-target use, and substitution

Threat: a migration is declared recoverable using the source file itself, a hard link to it, a stale backup, different bytes, or a perfectly valid backup of an unrelated resource.

Controls:

- source and backup must be regular non-symlink files;
- canonical paths must differ;
- device/inode identity must differ, rejecting hard-link aliases;
- source and backup device/inode identities are retained and must remain unchanged during revalidation;
- backup must be non-empty and byte-for-byte equal when validated;
- size and deterministic integrity evidence are retained and revalidated immediately before a risky migration applies;
- every risky file-backed migration declares its exact recovery target;
- the validated backup source must match the migration target by canonical path and retained device/inode identity before `apply()` is permitted;
- a migration marked as requiring a snapshot/backup cannot start without both an exact target binding and validated recovery evidence.

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

### Crash before package dispatch

Threat: Linura restarts after selecting a package transaction but before an external effect begins and loses the exact transaction identity.

Controls:

- package dispatch is preceded by a durable `Prepared` state bound to an exact transaction ID;
- snapshot policy is checked before the prepare boundary;
- a restart from `Prepared` may continue only with that exact prepared transaction;
- no generic command text or executor credential is persisted.

### Crash or transport loss after dispatch begins

Threat: an external package effect may have happened, may be in progress, or may have failed, and a restart blindly replays it.

Controls:

- `DispatchStarted` is durably recorded at the dispatch boundary;
- a restart from `DispatchStarted` returns `ReobserveBeforeContinuing`;
- the package transaction cannot advance to migrations merely because dispatch was acknowledged;
- independent verification must move the transaction to `Verified` first;
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

Threat: symlinks, writable state files, path aliasing, or malformed identifiers redirect durable evidence or recovery artifacts.

Controls:

- migration IDs and update correlation IDs are bounded and path-safe;
- persisted ledger/journal files reject symlinks and group/other write access;
- backup files reject symlink and same-inode aliasing;
- exact migration-target path/inode binding prevents unrelated backup substitution;
- temporary durable-state files use `create_new` and mode `0600`.

Further production integration must place the state directories under repository-owned service identities and packaging permissions appropriate to the final process boundary.

## Adversarial qualification matrix

Before v0.9 release readiness, exact-source qualification must cover at least:

- corrupt/truncated migration ledger;
- unsupported-newer migration ledger version;
- corrupt/truncated update journal;
- unsupported-newer update journal version;
- symlink or writable persistent-state substitution;
- hard-linked backup substitution;
- unrelated valid backup presented for a different migration target;
- stale/changed/replaced backup source before migration;
- migration verification failure and rollback;
- rollback failure/manual-recovery escalation;
- pre-rename ledger failure with safe rollback;
- post-rename ledger durability ambiguity with **no rollback and no in-process replay**;
- crash/restart before dispatch;
- crash/restart after dispatch started;
- verification failure after package dispatch;
- update interruption at deterministic checkpoints;
- validated backup restoration after injected failure;
- native recovery with First Boot/model/network unavailable;
- proof that no persisted recovery record grants executor/policy/approval authority.

## Security conclusion for this slice

The source-level design now fails closed at both dangerous ambiguity boundaries: **once an external update effect may have started, restart requires re-observation rather than blind replay; once a migration ledger rename may have committed, recovery/reopen is required rather than rollback or replay**. Risky file-backed migrations also cannot borrow recovery evidence from an unrelated resource.

This is necessary but not sufficient for the v0.9 support claim. Disposable-system Q11 acceptance, native recovery, restore execution, persistent First Boot/provisioning state, and final security/release review remain release blockers until separately qualified and bound into Trusted Release Proof.
