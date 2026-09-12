# v0.9 recovery-evidence threat model

**Status:** v0.9 candidate boundary; not a release or broad recovery-support claim  
**Scope:** `linura-bootstrap` recovery evidence consumed by the pre-authority First Boot path

## Security objective

First Boot may advance to a non-authorizing Control submission only when recovery readiness was produced by the qualified recovery producer for the exact First Boot session and canonical plan. A local caller must not be able to manufacture recovery readiness by creating arbitrary files, copying bytes, choosing a digest, or reusing evidence from another session or plan.

This boundary establishes trusted recovery **evidence provenance**. It does not by itself complete v0.9 installation/update/migration/backup/restore qualification; those end-to-end release gates remain separately required.

## Trust zones

The relevant zones are:

1. **untrusted First Boot caller/input** — may choose a checkpoint identifier and may attempt path/digest substitution;
2. **qualified recovery producer storage** — fixed v0.9 evidence root owned by the trusted system side and not writable by group/other principals;
3. **producer restore receipt** — bounded machine-readable evidence binding the restore result to producer identity, session, plan, checkpoint identity, checkpoint digest and restored digest;
4. **`linura-bootstrap` verifier** — validates producer storage, receipt and byte identity and emits opaque `RecoveryCheckpointEvidence`;
5. **First Boot session** — can consume opaque recovery evidence but cannot construct or mutate it into authority;
6. **Linura Control** — independently owns later review/authorization and must not treat recovery evidence as execution authority.

The v0.9 production evidence root is `/var/lib/linura-recovery/v0.9`. The qualified producer identity is `linura-recovery-v09`.

## Threats and mitigations

### Caller-created equal files

**Threat:** an unprivileged caller creates two separate files containing identical arbitrary bytes and asks the verifier to treat equality as proof that a checkpoint was restored.

**Mitigation:** production verification requires the exact checkpoint and restored-artifact paths derived from the bounded checkpoint identifier under the protected producer root. Equality of caller-owned files outside that root is rejected. The expected digest is corroborated by the trusted producer receipt rather than accepted as authority from the caller.

### Path, symlink and traversal substitution

**Threat:** path traversal, symlinks, alternate directory entries or unrelated files are substituted for producer artifacts.

**Mitigation:** checkpoint identifiers are bounded to a path-safe character set; `..` is rejected. Producer root/subdirectories must be real directories rather than symlinks, artifacts must be regular non-symlink files, canonical parents must match the expected producer directories, and supplied paths must canonicalize to the exact producer artifacts.

### Writable producer storage

**Threat:** an untrusted local principal modifies checkpoint, restored-copy or receipt material after it is considered trusted.

**Mitigation:** the production producer root, child directories and artifacts are required to be root-owned and must not be group- or other-writable. Verification fails closed when ownership or permission constraints are weaker. This prevents an ordinary First Boot caller from seeding or replacing trusted recovery evidence.

A host with arbitrary root compromise is outside the ability of an in-host verifier to defend cryptographically; Linura still does not convert local/root caller identity into Control authorization through any public API.

### Fake restore through the same inode

**Threat:** the checkpoint itself, a symlink, or a hard link is reused as the alleged restored copy.

**Mitigation:** checkpoint and restored artifact must be distinct canonical paths and distinct `(device, inode)` identities. Symlinks are rejected.

### Receipt replay or lineage substitution

**Threat:** a valid restore receipt from another First Boot session, plan or checkpoint is replayed.

**Mitigation:** the receipt is schema-bounded and binds `producer`, `session_id`, `plan_id`, `checkpoint_id`, `checkpoint_sha256`, `restored_sha256`, and `result=restored`. Any mismatch fails closed before opaque recovery evidence is created. The receipt itself is hashed into `RecoveryCheckpointEvidence` for retained provenance.

### Digest substitution

**Threat:** the caller supplies a digest for different bytes or changes one artifact after receipt production.

**Mitigation:** the caller digest is only a redundant assertion. The verifier hashes both trusted artifacts, validates the receipt digests, requires checkpoint/restored digest and size equality, and rejects zero-length evidence.

### Native recovery disappearance

**Threat:** First Boot reports recoverability while the native recovery escape hatch is absent or replaced.

**Mitigation:** the bounded v0.9 verifier continues to require the qualified root-owned executable native shell and package-manager paths before recovery evidence is accepted. End-to-end native-recovery behavior remains a separate disposable-system v0.9 qualification gate.

### Test-fixture leakage

**Threat:** cross-crate unit-test fixture support becomes a production bypass.

**Mitigation:** synthetic local-file fallback is an explicit `linura-bootstrap/test-support` feature used only by test dependencies. Optimized builds fail compilation when that feature is enabled. Normal production dependencies do not enable it. The trusted producer verification path has dedicated adversarial tests independent of the synthetic fixture path.

## Residual and deferred risks

This change closes caller-forgeable recovery evidence in the v0.9 foundation, but it does **not** declare the complete recovery system release-qualified. v0.9 still requires the trusted producer to be integrated with real persistent-state checkpoint/restore operations and qualified across installation, migration, backup/restore, update interruption, crash/restart, indeterminate outcomes and native recovery in the exact disposable QualificationEnvironment.

Until those release gates, Trusted Release Proof, immutable publication and independent verification complete, the recovery producer contract and exact Ubuntu/QEMU environment remain Experimental candidate boundaries only.
