#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "crates/linura-migrations/src/lib.rs"
UPDATE = ROOT / "crates/linura-update/src/lib.rs"
THREAT = ROOT / "docs/threat-model-v0.9-update-migration.md"
QUAL_TEST = ROOT / "tests/tooling/test_v09_recovery_qualification.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_update() -> None:
    text = UPDATE.read_text(encoding="utf-8")

    # Apply the exact rustfmt changes reported by canonical CI. The semantic
    # snapshot-attempt and policy-revalidation hardening is already present.
    text = replace_once(
        text,
        "        (self.state.stage == UpdateStage::Snapshot).then_some(self.journal_generation.token.as_str())\n",
        "        (self.state.stage == UpdateStage::Snapshot)\n            .then_some(self.journal_generation.token.as_str())\n",
        "format snapshot_generation",
    )
    text = replace_once(
        text,
        "    fn coordinator_with_policy(\n        label: &str,\n        policy: UpdatePolicy,\n    ) -> (TestDir, UpdateCoordinator) {\n",
        "    fn coordinator_with_policy(label: &str, policy: UpdatePolicy) -> (TestDir, UpdateCoordinator) {\n",
        "format coordinator_with_policy",
    )
    text = replace_once(
        text,
        "        assert_eq!(reopened.mark_dispatch_started(), Err(UpdateError::SnapshotRequired));\n",
        "        assert_eq!(\n            reopened.mark_dispatch_started(),\n            Err(UpdateError::SnapshotRequired)\n        );\n",
        "format snapshot policy assertion",
    )
    text = replace_once(
        text,
        "            verifier.verify_snapshot(\n                \"forged-snapshot\",\n                UPDATE_ID,\n                TARGET_ID,\n                generation,\n                started,\n            ),\n",
        "            verifier.verify_snapshot(\"forged-snapshot\", UPDATE_ID, TARGET_ID, generation, started,),\n",
        "format forged snapshot verification",
    )

    UPDATE.write_text(text, encoding="utf-8")


def patch_migrations() -> None:
    text = MIGRATIONS.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "use std::collections::BTreeSet;\n",
        "use std::collections::BTreeSet;\nuse std::ffi::OsString;\n",
        "import OsString",
    )
    text = replace_once(
        text,
        "use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};\n",
        "use std::os::unix::ffi::{OsStrExt, OsStringExt};\nuse std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};\n",
        "import unix path encoding",
    )
    text = replace_once(
        text,
        'const RECOVERY_MAGIC: &str = "linura-migration-recovery-v1";\n',
        'const RECOVERY_MAGIC: &str = "linura-migration-recovery-v2";\n',
        "bump recovery marker version",
    )
    text = replace_once(
        text,
        "const MAX_RECOVERY_MARKER_BYTES: u64 = 16 * 1024;\n",
        "const MAX_RECOVERY_MARKER_BYTES: u64 = 16 * 1024;\nconst MAX_RECOVERY_PATH_BYTES: usize = 4096;\n",
        "recovery path bound",
    )

    recovery_types = r'''
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRecoveryRecord {
    migration_id: String,
    checkpoint: Option<MigrationRecoveryCheckpoint>,
}

impl MigrationRecoveryRecord {
    fn new(migration_id: impl Into<String>, checkpoint: Option<MigrationRecoveryCheckpoint>) -> Result<Self, MigrationError> {
        let migration_id = migration_id.into();
        if !valid_identifier(&migration_id, 128) {
            return Err(MigrationError::CorruptRecoveryMarker(
                "recovery record contains an invalid migration id".into(),
            ));
        }
        if let Some(checkpoint) = &checkpoint {
            checkpoint.validate_descriptor()?;
        }
        Ok(Self {
            migration_id,
            checkpoint,
        })
    }

    #[must_use]
    pub fn migration_id(&self) -> &str {
        &self.migration_id
    }

    #[must_use]
    pub fn checkpoint(&self) -> Option<&MigrationRecoveryCheckpoint> {
        self.checkpoint.as_ref()
    }

    /// Revalidates only the durable recovery artifact. The migration target is
    /// intentionally not required to retain its pre-migration bytes after a
    /// crash because the purpose of this record is to recover from that case.
    pub fn revalidate_recovery_backup(&self) -> Result<(), MigrationError> {
        let checkpoint = self.checkpoint.as_ref().ok_or_else(|| {
            MigrationError::RecoveryCheckpointUnavailable(self.migration_id.clone())
        })?;
        checkpoint.revalidate_backup()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRecoveryCheckpoint {
    target_path: PathBuf,
    backup_path: PathBuf,
    target_device: u64,
    target_inode: u64,
    backup_device: u64,
    backup_inode: u64,
    size: u64,
    integrity_tag: u64,
}

impl MigrationRecoveryCheckpoint {
    fn from_validated_backup(backup: &ValidatedBackup) -> Result<Self, MigrationError> {
        let checkpoint = Self {
            target_path: backup.source_path.clone(),
            backup_path: backup.backup_path.clone(),
            target_device: backup.source_device,
            target_inode: backup.source_inode,
            backup_device: backup.backup_device,
            backup_inode: backup.backup_inode,
            size: backup.size,
            integrity_tag: backup.integrity_tag,
        };
        checkpoint.validate_descriptor()?;
        Ok(checkpoint)
    }

    fn validate_descriptor(&self) -> Result<(), MigrationError> {
        if self.target_path == self.backup_path
            || !self.target_path.is_absolute()
            || !self.backup_path.is_absolute()
            || self.target_path.as_os_str().as_bytes().is_empty()
            || self.backup_path.as_os_str().as_bytes().is_empty()
            || self.target_path.as_os_str().as_bytes().len() > MAX_RECOVERY_PATH_BYTES
            || self.backup_path.as_os_str().as_bytes().len() > MAX_RECOVERY_PATH_BYTES
            || self.size == 0
        {
            return Err(MigrationError::CorruptRecoveryMarker(
                "recovery checkpoint descriptor is invalid".into(),
            ));
        }
        Ok(())
    }

    fn revalidate_backup(&self) -> Result<(), MigrationError> {
        self.validate_descriptor()?;
        let path_metadata = fs::symlink_metadata(&self.backup_path).map_err(io_error)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || path_metadata.dev() != self.backup_device
            || path_metadata.ino() != self.backup_inode
            || path_metadata.len() != self.size
            || path_metadata.nlink() != 1
            || path_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedBackupArtifact);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&self.backup_path)
            .map_err(io_error)?;
        let opened_metadata = file.metadata().map_err(io_error)?;
        if opened_metadata.dev() != self.backup_device
            || opened_metadata.ino() != self.backup_inode
            || opened_metadata.len() != self.size
            || opened_metadata.nlink() != 1
        {
            return Err(MigrationError::UntrustedBackupArtifact);
        }
        let (size, integrity_tag) = file_integrity(&mut file)?;
        if size != self.size || integrity_tag != self.integrity_tag {
            return Err(MigrationError::BackupMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    #[must_use]
    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    #[must_use]
    pub const fn target_device(&self) -> u64 {
        self.target_device
    }

    #[must_use]
    pub const fn target_inode(&self) -> u64 {
        self.target_inode
    }

    #[must_use]
    pub const fn backup_device(&self) -> u64 {
        self.backup_device
    }

    #[must_use]
    pub const fn backup_inode(&self) -> u64 {
        self.backup_inode
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn integrity_tag(&self) -> u64 {
        self.integrity_tag
    }
}
'''.strip("\n")

    text = replace_once(
        text,
        "}\n\n#[derive(Debug)]\nstruct BackupStabilityGuard<'a> {\n",
        "}\n\n" + recovery_types + "\n\n#[derive(Debug)]\nstruct BackupStabilityGuard<'a> {\n",
        "insert durable recovery record types",
    )

    store_old = r'''    fn load_recovery_marker(&self) -> Result<Option<String>, MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        if metadata.len() > MAX_RECOVERY_MARKER_BYTES {
            return Err(MigrationError::CorruptRecoveryMarker(
                "migration recovery marker exceeds the supported size bound".into(),
            ));
        }
        parse_recovery_marker(&fs::read(path).map_err(io_error)?).map(Some)
    }

    fn reconcile_recovery_marker(
        &self,
        ledger: &MigrationLedger,
    ) -> Result<Option<String>, MigrationError> {
        let Some(migration_id) = self.load_recovery_marker()? else {
            return Ok(None);
        };
        if ledger.is_applied(&migration_id) {
            self.clear_recovery_marker()?;
            return Ok(None);
        }
        Ok(Some(migration_id))
    }

    fn persist_recovery_marker(&self, migration_id: &str) -> Result<(), MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        atomic_write(
            &path,
            &serialize_recovery_marker(migration_id),
            "migration recovery marker",
        )
    }
'''
    store_new = r'''    pub fn load_recovery_record(&self) -> Result<Option<MigrationRecoveryRecord>, MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        if metadata.len() > MAX_RECOVERY_MARKER_BYTES {
            return Err(MigrationError::CorruptRecoveryMarker(
                "migration recovery marker exceeds the supported size bound".into(),
            ));
        }
        parse_recovery_record(&fs::read(path).map_err(io_error)?).map(Some)
    }

    fn reconcile_recovery_marker(
        &self,
        ledger: &MigrationLedger,
    ) -> Result<Option<MigrationRecoveryRecord>, MigrationError> {
        let Some(record) = self.load_recovery_record()? else {
            return Ok(None);
        };
        if ledger.is_applied(record.migration_id()) {
            self.clear_recovery_marker()?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn persist_recovery_record(
        &self,
        record: &MigrationRecoveryRecord,
    ) -> Result<(), MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        atomic_write(
            &path,
            &serialize_recovery_record(record),
            "migration recovery marker",
        )
    }
'''
    text = replace_once(text, store_old, store_new, "upgrade recovery store")

    text = replace_once(
        text,
        "pub struct MigrationRunner {\n    ledger: MigrationLedger,\n    store: Option<MigrationLedgerStore>,\n    recovery_required: Option<String>,\n}\n",
        "pub struct MigrationRunner {\n    ledger: MigrationLedger,\n    store: Option<MigrationLedgerStore>,\n    recovery_required: Option<String>,\n    recovery_record: Option<MigrationRecoveryRecord>,\n}\n",
        "runner recovery record field",
    )
    text = replace_once(
        text,
        "            store: None,\n            recovery_required: None,\n",
        "            store: None,\n            recovery_required: None,\n            recovery_record: None,\n",
        "initialize recovery record",
    )

    open_old = r'''        let ledger = store.load()?;
        let recovery_required = store
            .reconcile_recovery_marker(&ledger)?
            .map(|id| format!("persisted recovery marker for migration {id}"));
        Ok(Self {
            ledger,
            store: Some(store),
            recovery_required,
        })
'''
    open_new = r'''        let ledger = store.load()?;
        let recovery_record = store.reconcile_recovery_marker(&ledger)?;
        let recovery_required = recovery_record.as_ref().map(|record| {
            format!(
                "persisted recovery record for migration {}",
                record.migration_id()
            )
        });
        Ok(Self {
            ledger,
            store: Some(store),
            recovery_required,
            recovery_record,
        })
'''
    text = replace_once(text, open_old, open_new, "runner open recovery record")

    text = replace_once(
        text,
        '''                Ok(Some(id)) => {
                    let reason = format!("persisted recovery marker for migration {id}");
                    self.recovery_required = Some(reason.clone());
                    return Err(MigrationError::RecoveryRequired(reason));
                }
''',
        '''                Ok(Some(record)) => {
                    let reason = format!(
                        "persisted recovery record for migration {}",
                        record.migration_id()
                    );
                    self.recovery_record = Some(record);
                    self.recovery_required = Some(reason.clone());
                    return Err(MigrationError::RecoveryRequired(reason));
                }
''',
        "reload durable recovery record",
    )

    marker_old = r'''        if let Some(store) = &store
            && let Err(error) = store.persist_recovery_marker(&descriptor.id)
        {
            if matches!(error, MigrationError::DurabilityUncertain(_)) {
                self.latch_recovery(format!(
                    "{}: durable in-progress marker is uncertain",
                    descriptor.id
                ));
            }
            return Err(error);
        }

        if let Some(guard) = &checkpoint_guard {
            guard.assert_stable()?;
        }
'''
    marker_new = r'''        let recovery_checkpoint = checkpoint_guard
            .as_ref()
            .map(|guard| MigrationRecoveryCheckpoint::from_validated_backup(guard.evidence))
            .transpose()?;
        let recovery_record =
            MigrationRecoveryRecord::new(descriptor.id.clone(), recovery_checkpoint)?;

        if let Some(store) = &store {
            if let Err(error) = store.persist_recovery_record(&recovery_record) {
                if matches!(error, MigrationError::DurabilityUncertain(_)) {
                    self.latch_recovery(format!(
                        "{}: durable in-progress recovery record is uncertain",
                        descriptor.id
                    ));
                }
                return Err(error);
            }
            self.recovery_record = Some(recovery_record);
        }

        if let Some(guard) = &checkpoint_guard {
            guard.assert_stable()?;
        }
'''
    text = replace_once(text, marker_old, marker_new, "persist checkpoint in recovery record")

    # Clear in-memory checkpoint evidence whenever durable marker cleanup is
    # known to have completed safely.
    text = replace_once(
        text,
        "        if let Some(store) = &store\n            && let Err(error) = store.clear_recovery_marker()\n        {\n            return self.handle_cleanup_failure(error);\n        }\n        Ok(MigrationOutcome::Applied)\n",
        "        if let Some(store) = &store\n            && let Err(error) = store.clear_recovery_marker()\n        {\n            return self.handle_cleanup_failure(error);\n        }\n        self.recovery_record = None;\n        Ok(MigrationOutcome::Applied)\n",
        "clear recovery record on success",
    )
    text = text.replace(
        "        if let Some(store) = store\n            && let Err(cleanup_error) = store.clear_recovery_marker()\n        {\n            return self.handle_cleanup_failure(cleanup_error);\n        }\n",
        "        if let Some(store) = store\n            && let Err(cleanup_error) = store.clear_recovery_marker()\n        {\n            return self.handle_cleanup_failure(cleanup_error);\n        }\n        self.recovery_record = None;\n",
    )
    if text.count("self.recovery_record = None;") < 3:
        raise SystemExit("expected recovery record cleanup in success + rollback paths")

    text = replace_once(
        text,
        "    #[must_use]\n    pub const fn requires_recovery(&self) -> bool {\n        self.recovery_required.is_some()\n    }\n",
        "    #[must_use]\n    pub const fn requires_recovery(&self) -> bool {\n        self.recovery_required.is_some()\n    }\n\n    #[must_use]\n    pub fn recovery_record(&self) -> Option<&MigrationRecoveryRecord> {\n        self.recovery_record.as_ref()\n    }\n",
        "expose recovery record",
    )

    text = replace_once(
        text,
        "    RecoveryTargetRequired(String),\n",
        "    RecoveryTargetRequired(String),\n    RecoveryCheckpointUnavailable(String),\n",
        "recovery checkpoint unavailable error",
    )
    text = replace_once(
        text,
        "            Self::RecoveryTargetRequired(id) => {\n                write!(f, \"migration {id} requires an exact recovery target binding\")\n            }\n",
        "            Self::RecoveryTargetRequired(id) => {\n                write!(f, \"migration {id} requires an exact recovery target binding\")\n            }\n            Self::RecoveryCheckpointUnavailable(id) => write!(\n                f,\n                \"migration {id} has no persisted recovery checkpoint to revalidate\"\n            ),\n",
        "display checkpoint unavailable",
    )

    # Add backup-only integrity helper used after a crash when the target may
    # already have changed.
    text = replace_once(
        text,
        "fn fnv1a_update(mut state: u64, bytes: &[u8]) -> u64 {\n",
        '''fn file_integrity(file: &mut fs::File) -> Result<(u64, u64), MigrationError> {
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    let mut integrity = FNV_OFFSET;
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            return Ok((size, integrity));
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| MigrationError::Io("recovery backup size overflow".into()))?;
        integrity = fnv1a_update(integrity, &buffer[..read]);
    }
}

fn fnv1a_update(mut state: u64, bytes: &[u8]) -> u64 {
''',
        "file integrity helper",
    )

    recovery_serializers_old = r'''fn serialize_recovery_marker(migration_id: &str) -> Vec<u8> {
    let mut payload = format!("{RECOVERY_MAGIC}\nmigration={migration_id}\n");
    let tag = integrity_tag(payload.as_bytes());
    payload.push_str(&format!("integrity={tag:016x}\n"));
    payload.into_bytes()
}

fn parse_recovery_marker(bytes: &[u8]) -> Result<String, MigrationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        MigrationError::CorruptRecoveryMarker("recovery marker is not UTF-8".into())
    })?;
    let integrity_start = text.rfind("integrity=").ok_or_else(|| {
        MigrationError::CorruptRecoveryMarker("integrity record is missing".into())
    })?;
    let (payload, integrity_line) = text.split_at(integrity_start);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| MigrationError::CorruptRecoveryMarker("invalid integrity record".into()))?;
    if expected.len() != 16 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "invalid integrity tag".into(),
        ));
    }
    let expected = u64::from_str_radix(expected, 16)
        .map_err(|_| MigrationError::CorruptRecoveryMarker("invalid integrity tag".into()))?;
    if integrity_tag(payload.as_bytes()) != expected {
        return Err(MigrationError::CorruptRecoveryMarker(
            "integrity tag mismatch".into(),
        ));
    }
    let mut lines = payload.lines();
    if lines.next() != Some(RECOVERY_MAGIC) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "unsupported recovery marker version".into(),
        ));
    }
    let migration_id = lines
        .next()
        .and_then(|line| line.strip_prefix("migration="))
        .ok_or_else(|| MigrationError::CorruptRecoveryMarker("missing migration field".into()))?;
    if lines.next().is_some() || !valid_identifier(migration_id, 128) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "invalid migration field".into(),
        ));
    }
    Ok(migration_id.to_owned())
}
'''
    recovery_serializers_new = r'''fn path_hex(path: Option<&Path>) -> String {
    match path {
        None => "-".into(),
        Some(path) => path
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn parse_recovery_path(value: &str, label: &str) -> Result<PathBuf, MigrationError> {
    if value == "-"
        || value.len() > MAX_RECOVERY_PATH_BYTES * 2
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(MigrationError::CorruptRecoveryMarker(format!(
            "invalid {label}"
        )));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| {
            MigrationError::CorruptRecoveryMarker(format!("invalid {label}"))
        })?;
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| {
            MigrationError::CorruptRecoveryMarker(format!("invalid {label}"))
        })?);
    }
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_PATH_BYTES {
        return Err(MigrationError::CorruptRecoveryMarker(format!(
            "invalid {label}"
        )));
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(MigrationError::CorruptRecoveryMarker(format!(
            "{label} is not absolute"
        )));
    }
    Ok(path)
}

fn recovery_field<'a>(line: Option<&'a str>, name: &str) -> Result<&'a str, MigrationError> {
    let line = line.ok_or_else(|| {
        MigrationError::CorruptRecoveryMarker(format!("missing {name} field"))
    })?;
    line.strip_prefix(&format!("{name}=")).ok_or_else(|| {
        MigrationError::CorruptRecoveryMarker(format!("invalid {name} field"))
    })
}

fn parse_recovery_u64(value: &str, label: &str) -> Result<u64, MigrationError> {
    value.parse::<u64>().map_err(|_| {
        MigrationError::CorruptRecoveryMarker(format!("invalid {label}"))
    })
}

fn serialize_recovery_record(record: &MigrationRecoveryRecord) -> Vec<u8> {
    let (
        checkpoint_kind,
        target_path,
        backup_path,
        target_device,
        target_inode,
        backup_device,
        backup_inode,
        size,
        checkpoint_integrity,
    ) = match record.checkpoint() {
        Some(checkpoint) => (
            "file",
            path_hex(Some(checkpoint.target_path())),
            path_hex(Some(checkpoint.backup_path())),
            checkpoint.target_device().to_string(),
            checkpoint.target_inode().to_string(),
            checkpoint.backup_device().to_string(),
            checkpoint.backup_inode().to_string(),
            checkpoint.size().to_string(),
            format!("{:016x}", checkpoint.integrity_tag()),
        ),
        None => (
            "none",
            "-".into(),
            "-".into(),
            "-".into(),
            "-".into(),
            "-".into(),
            "-".into(),
            "-".into(),
            "-".into(),
        ),
    };
    let mut payload = format!(
        "{RECOVERY_MAGIC}\nmigration={}\ncheckpoint={checkpoint_kind}\ntarget_path={target_path}\nbackup_path={backup_path}\ntarget_device={target_device}\ntarget_inode={target_inode}\nbackup_device={backup_device}\nbackup_inode={backup_inode}\nsize={size}\ncheckpoint_integrity={checkpoint_integrity}\n",
        record.migration_id()
    );
    let tag = integrity_tag(payload.as_bytes());
    payload.push_str(&format!("integrity={tag:016x}\n"));
    payload.into_bytes()
}

fn parse_recovery_record(bytes: &[u8]) -> Result<MigrationRecoveryRecord, MigrationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        MigrationError::CorruptRecoveryMarker("recovery marker is not UTF-8".into())
    })?;
    let integrity_start = text.rfind("integrity=").ok_or_else(|| {
        MigrationError::CorruptRecoveryMarker("integrity record is missing".into())
    })?;
    let (payload, integrity_line) = text.split_at(integrity_start);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| MigrationError::CorruptRecoveryMarker("invalid integrity record".into()))?;
    if expected.len() != 16 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "invalid integrity tag".into(),
        ));
    }
    let expected = u64::from_str_radix(expected, 16)
        .map_err(|_| MigrationError::CorruptRecoveryMarker("invalid integrity tag".into()))?;
    if integrity_tag(payload.as_bytes()) != expected {
        return Err(MigrationError::CorruptRecoveryMarker(
            "integrity tag mismatch".into(),
        ));
    }

    let mut lines = payload.lines();
    if lines.next() != Some(RECOVERY_MAGIC) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "unsupported recovery marker version".into(),
        ));
    }
    let migration_id = recovery_field(lines.next(), "migration")?.to_owned();
    if !valid_identifier(&migration_id, 128) {
        return Err(MigrationError::CorruptRecoveryMarker(
            "invalid migration field".into(),
        ));
    }
    let checkpoint_kind = recovery_field(lines.next(), "checkpoint")?;
    let target_path = recovery_field(lines.next(), "target_path")?;
    let backup_path = recovery_field(lines.next(), "backup_path")?;
    let target_device = recovery_field(lines.next(), "target_device")?;
    let target_inode = recovery_field(lines.next(), "target_inode")?;
    let backup_device = recovery_field(lines.next(), "backup_device")?;
    let backup_inode = recovery_field(lines.next(), "backup_inode")?;
    let size = recovery_field(lines.next(), "size")?;
    let checkpoint_integrity = recovery_field(lines.next(), "checkpoint_integrity")?;
    if lines.next().is_some() {
        return Err(MigrationError::CorruptRecoveryMarker(
            "unexpected recovery marker field".into(),
        ));
    }

    let checkpoint = match checkpoint_kind {
        "none" => {
            if [
                target_path,
                backup_path,
                target_device,
                target_inode,
                backup_device,
                backup_inode,
                size,
                checkpoint_integrity,
            ]
            .iter()
            .any(|value| *value != "-")
            {
                return Err(MigrationError::CorruptRecoveryMarker(
                    "checkpoint=none retained checkpoint fields".into(),
                ));
            }
            None
        }
        "file" => {
            if checkpoint_integrity.len() != 16
                || !checkpoint_integrity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(MigrationError::CorruptRecoveryMarker(
                    "invalid checkpoint integrity tag".into(),
                ));
            }
            let checkpoint = MigrationRecoveryCheckpoint {
                target_path: parse_recovery_path(target_path, "target path")?,
                backup_path: parse_recovery_path(backup_path, "backup path")?,
                target_device: parse_recovery_u64(target_device, "target device")?,
                target_inode: parse_recovery_u64(target_inode, "target inode")?,
                backup_device: parse_recovery_u64(backup_device, "backup device")?,
                backup_inode: parse_recovery_u64(backup_inode, "backup inode")?,
                size: parse_recovery_u64(size, "checkpoint size")?,
                integrity_tag: u64::from_str_radix(checkpoint_integrity, 16).map_err(|_| {
                    MigrationError::CorruptRecoveryMarker(
                        "invalid checkpoint integrity tag".into(),
                    )
                })?,
            };
            checkpoint.validate_descriptor()?;
            Some(checkpoint)
        }
        _ => {
            return Err(MigrationError::CorruptRecoveryMarker(
                "unknown recovery checkpoint kind".into(),
            ));
        }
    };

    MigrationRecoveryRecord::new(migration_id, checkpoint)
}
'''
    text = replace_once(
        text,
        recovery_serializers_old,
        recovery_serializers_new,
        "versioned durable recovery record serialization",
    )

    # Adjust the stale-marker test to persist a typed v2 record.
    text = replace_once(
        text,
        '''        store
            .persist_recovery_marker("0001-committed")
            .unwrap_or_else(|error| unreachable!("{error}"));
''',
        '''        let record = MigrationRecoveryRecord::new("0001-committed", None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        store
            .persist_recovery_record(&record)
            .unwrap_or_else(|error| unreachable!("{error}"));
''',
        "test typed recovery record",
    )
    text = replace_once(
        text,
        "        assert_eq!(store.load_recovery_marker(), Ok(None));\n",
        "        assert_eq!(store.load_recovery_record(), Ok(None));\n",
        "test recovery record cleanup",
    )

    # Add an injected apply failure so a risky migration can exercise durable
    # recovery evidence across a simulated crash boundary.
    text = replace_once(
        text,
        "        precondition: bool,\n        verify_ok: bool,\n",
        "        precondition: bool,\n        apply_ok: bool,\n        verify_ok: bool,\n",
        "test migration apply flag",
    )
    text = replace_once(
        text,
        "                precondition: true,\n                verify_ok: true,\n",
        "                precondition: true,\n                apply_ok: true,\n                verify_ok: true,\n",
        "test migration default apply flag",
    )
    text = replace_once(
        text,
        '''        fn apply(&self) -> Result<(), MigrationError> {
            self.applications.set(self.applications.get() + 1);
            Ok(())
        }
''',
        '''        fn apply(&self) -> Result<(), MigrationError> {
            self.applications.set(self.applications.get() + 1);
            if self.apply_ok {
                Ok(())
            } else {
                Err(MigrationError::Operation("injected apply failure".into()))
            }
        }
''',
        "test migration injected apply failure",
    )

    new_test = r'''
    #[test]
    fn risky_recovery_record_survives_crash_with_exact_backup_identity() {
        let dir = TestDir::new("durable-recovery-record");
        let source = dir.path().join("state.db");
        let backup = dir.path().join("state.db.backup");
        fs::write(&source, b"pre-migration-state")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = ValidatedBackup::verify(&source, &backup)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let mut migration =
            TestMigration::new("0003-durable-checkpoint", true).with_recovery_target(source.clone());
        migration.apply_ok = false;
        let mut runner =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            runner.run_with_backup(&migration, Some(&evidence)),
            Err(MigrationError::ManualRecoveryRequired(
                "0003-durable-checkpoint".into()
            ))
        );
        let record = store
            .load_recovery_record()
            .unwrap_or_else(|error| unreachable!("{error}"))
            .unwrap_or_else(|| unreachable!("missing recovery record"));
        let checkpoint = record
            .checkpoint()
            .unwrap_or_else(|| unreachable!("missing recovery checkpoint"));
        assert_eq!(checkpoint.target_path(), evidence.source_path());
        assert_eq!(checkpoint.backup_path(), evidence.backup_path());
        assert_eq!(checkpoint.size(), evidence.size());
        assert_eq!(checkpoint.integrity_tag(), evidence.integrity_tag());
        assert_eq!(record.revalidate_recovery_backup(), Ok(()));

        // The target may already have changed when recovery starts; the backup
        // must remain independently identifiable and verifiable.
        fs::write(&source, b"post-failure-target-state")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(record.revalidate_recovery_backup(), Ok(()));

        fs::write(&backup, b"tampered-backup")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            record.revalidate_recovery_backup(),
            Err(MigrationError::UntrustedBackupArtifact | MigrationError::BackupMismatch)
        ));

        drop(runner);
        let reopened =
            MigrationRunner::open(store).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(reopened.requires_recovery());
        assert!(reopened.recovery_record().is_some());
    }
'''.strip("\n")
    text = replace_once(
        text,
        "    #[test]\n    fn verification_failure_rolls_back_and_never_commits_ledger() {\n",
        new_test + "\n\n    #[test]\n    fn verification_failure_rolls_back_and_never_commits_ledger() {\n",
        "test durable risky recovery record",
    )

    MIGRATIONS.write_text(text, encoding="utf-8")


def patch_threat_model() -> None:
    text = THREAT.read_text(encoding="utf-8")
    anchor = "- package verification evidence carries an issuance timestamp, must not predate the current dispatch generation, must not be implausibly future-dated, and is accepted only within the bounded verification freshness window;\n"
    replacement = anchor + "- snapshot evidence is likewise bound to the exact current Snapshot journal generation and a bounded issuance window, so an old snapshot receipt cannot authorize a later update attempt that reuses caller-visible IDs;\n- a resumed `Prepared` transaction is re-evaluated against the current snapshot policy before it can be reported safe or cross the dispatch boundary;\n"
    text = replace_once(text, anchor, replacement, "document snapshot attempt binding")

    anchor = "- a migration marked as requiring a snapshot/backup cannot start without both an exact target binding and validated recovery evidence.\n"
    replacement = anchor + "- before any risky migration effect, the durable recovery record persists the migration ID plus canonical target/backup paths, target and backup device/inode identities, byte size, and pre-migration integrity tag;\n- after restart, the persisted recovery record can independently revalidate the exact backup artifact even when the target has already changed, without treating that evidence as authority.\n"
    text = replace_once(text, anchor, replacement, "document persisted migration recovery identity")
    THREAT.write_text(text, encoding="utf-8")


def patch_qualification_contract() -> None:
    text = QUAL_TEST.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '            "PACKAGE_VERIFICATION_MAX_AGE_MS",\n',
        '            "PACKAGE_VERIFICATION_MAX_AGE_MS",\n            "SNAPSHOT_EVIDENCE_MAX_AGE_MS",\n            "validate_snapshot_evidence_freshness",\n            "snapshot_policy_satisfied",\n',
        "bind snapshot hardening in source contract",
    )
    text = replace_once(
        text,
        '            "guard.assert_stable()?",\n',
        '            "guard.assert_stable()?",\n            "MigrationRecoveryRecord",\n            "MigrationRecoveryCheckpoint",\n            "revalidate_recovery_backup",\n            "persist_recovery_record",\n',
        "bind durable recovery record in source contract",
    )
    QUAL_TEST.write_text(text, encoding="utf-8")


def main() -> None:
    patch_update()
    patch_migrations()
    patch_threat_model()
    patch_qualification_contract()
    print("PR #128 repair transformations applied")


if __name__ == "__main__":
    main()
