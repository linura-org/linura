#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const LEDGER_MAGIC: &str = "linura-migration-ledger-v1";
const RECOVERY_MAGIC: &str = "linura-migration-recovery-v1";
const MAX_LEDGER_BYTES: u64 = 1024 * 1024;
const MAX_RECOVERY_MARKER_BYTES: u64 = 16 * 1024;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const O_NOFOLLOW: i32 = 0o400000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MigrationScope {
    System,
    User,
    Intent,
    Graph,
    Profile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationDescriptor {
    pub id: String,
    pub introduced_in: String,
    pub scope: MigrationScope,
    pub reversible: bool,
    pub requires_snapshot: bool,
}

impl MigrationDescriptor {
    pub fn validate(&self) -> Result<(), MigrationError> {
        if !valid_identifier(&self.id, 128) {
            return Err(MigrationError::InvalidDescriptor(
                "migration id must be a bounded path-safe identifier",
            ));
        }
        if self.introduced_in.trim().is_empty()
            || self.introduced_in.len() > 64
            || self.introduced_in.chars().any(char::is_control)
        {
            return Err(MigrationError::InvalidDescriptor(
                "introduced_in must be a bounded version identifier",
            ));
        }
        Ok(())
    }
}

pub trait Migration {
    fn descriptor(&self) -> &MigrationDescriptor;
    fn precondition(&self) -> Result<bool, MigrationError>;
    fn apply(&self) -> Result<(), MigrationError>;
    fn verify(&self) -> Result<(), MigrationError>;

    /// Exact regular file whose pre-migration bytes are represented by the
    /// recovery backup. Risky file-backed migrations must provide this target;
    /// an unrelated valid backup is never sufficient recovery evidence.
    fn recovery_target(&self) -> Option<&Path> {
        None
    }

    fn rollback(&self) -> Result<(), MigrationError> {
        Err(MigrationError::ManualRecoveryRequired(
            self.descriptor().id.clone(),
        ))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MigrationLedger {
    applied: BTreeSet<String>,
}

impl MigrationLedger {
    pub fn from_applied(applied: impl IntoIterator<Item = String>) -> Result<Self, MigrationError> {
        let mut ledger = Self::default();
        for id in applied {
            if !valid_identifier(&id, 128) {
                return Err(MigrationError::CorruptLedger(
                    "persisted migration id is invalid".into(),
                ));
            }
            if !ledger.applied.insert(id) {
                return Err(MigrationError::CorruptLedger(
                    "persisted migration ledger contains a duplicate id".into(),
                ));
            }
        }
        Ok(ledger)
    }

    #[must_use]
    pub fn is_applied(&self, id: &str) -> bool {
        self.applied.contains(id)
    }

    pub fn mark_applied(&mut self, id: impl Into<String>) -> Result<(), MigrationError> {
        let id = id.into();
        if !valid_identifier(&id, 128) {
            return Err(MigrationError::InvalidDescriptor(
                "migration id must be a bounded path-safe identifier",
            ));
        }
        self.applied.insert(id);
        Ok(())
    }

    pub fn applied(&self) -> impl Iterator<Item = &str> {
        self.applied.iter().map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBackup {
    source_path: PathBuf,
    backup_path: PathBuf,
    source_device: u64,
    source_inode: u64,
    backup_device: u64,
    backup_inode: u64,
    size: u64,
    integrity_tag: u64,
}

impl ValidatedBackup {
    pub fn verify(
        source_path: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
    ) -> Result<Self, MigrationError> {
        let source_path = verified_regular_file(source_path.as_ref())?;
        let backup_path = verified_regular_file(backup_path.as_ref())?;
        let source_metadata = fs::metadata(&source_path).map_err(io_error)?;
        let backup_metadata = fs::metadata(&backup_path).map_err(io_error)?;
        if source_path == backup_path
            || (source_metadata.dev() == backup_metadata.dev()
                && source_metadata.ino() == backup_metadata.ino())
        {
            return Err(MigrationError::BackupNotIndependent);
        }
        if source_metadata.len() == 0 || source_metadata.len() != backup_metadata.len() {
            return Err(MigrationError::BackupMismatch);
        }
        let (equal, integrity_tag) = compare_files(&source_path, &backup_path)?;
        if !equal {
            return Err(MigrationError::BackupMismatch);
        }
        Ok(Self {
            source_path,
            backup_path,
            source_device: source_metadata.dev(),
            source_inode: source_metadata.ino(),
            backup_device: backup_metadata.dev(),
            backup_inode: backup_metadata.ino(),
            size: source_metadata.len(),
            integrity_tag,
        })
    }

    pub fn revalidate(&self) -> Result<(), MigrationError> {
        let current = Self::verify(&self.source_path, &self.backup_path)?;
        if current.source_device != self.source_device
            || current.source_inode != self.source_inode
            || current.backup_device != self.backup_device
            || current.backup_inode != self.backup_inode
            || current.size != self.size
            || current.integrity_tag != self.integrity_tag
        {
            return Err(MigrationError::BackupMismatch);
        }
        Ok(())
    }

    pub fn revalidate_for_target(&self, target: &Path) -> Result<(), MigrationError> {
        self.revalidate()?;
        let target_path = verified_regular_file(target)?;
        let target_metadata = fs::metadata(&target_path).map_err(io_error)?;
        if target_path != self.source_path
            || target_metadata.dev() != self.source_device
            || target_metadata.ino() != self.source_inode
        {
            return Err(MigrationError::BackupTargetMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    #[must_use]
    pub fn backup_path(&self) -> &Path {
        &self.backup_path
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationLedgerStore {
    path: PathBuf,
}

impl MigrationLedgerStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<MigrationLedger, MigrationError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(MigrationLedger::default());
            }
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedLedgerPath);
        }
        if metadata.len() > MAX_LEDGER_BYTES {
            return Err(MigrationError::CorruptLedger(
                "migration ledger exceeds the supported size bound".into(),
            ));
        }
        parse_ledger(&fs::read(&self.path).map_err(io_error)?)
    }

    pub fn persist(&self, ledger: &MigrationLedger) -> Result<(), MigrationError> {
        atomic_write(&self.path, &serialize_ledger(ledger), "migration ledger")
    }

    fn acquire_exclusive(&self) -> Result<fs::File, MigrationError> {
        let lock_path = sidecar_path(&self.path, "lock")?;
        let parent = lock_path.parent().ok_or_else(|| {
            MigrationError::Io("migration lock path has no parent directory".into())
        })?;
        fs::create_dir_all(parent).map_err(io_error)?;
        reject_untrusted_existing_lock(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&lock_path)
            .map_err(io_error)?;
        validate_control_file_identity(&lock_path, &file, MigrationError::UntrustedLockPath)?;
        file.lock().map_err(io_error)?;
        validate_control_file_identity(&lock_path, &file, MigrationError::UntrustedLockPath)?;
        Ok(file)
    }

    fn load_recovery_marker(&self) -> Result<Option<String>, MigrationError> {
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

    fn persist_recovery_marker(&self, migration_id: &str) -> Result<(), MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        atomic_write(
            &path,
            &serialize_recovery_marker(migration_id),
            "migration recovery marker",
        )
    }

    fn clear_recovery_marker(&self) -> Result<(), MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        fs::remove_file(&path).map_err(io_error)?;
        let parent = path.parent().ok_or_else(|| {
            MigrationError::Io("migration recovery path has no parent directory".into())
        })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                MigrationError::DurabilityUncertain(format!(
                    "migration recovery marker removal completed but parent-directory fsync failed: {error}"
                ))
            })
    }
}

#[derive(Debug)]
pub struct MigrationRunner {
    ledger: MigrationLedger,
    store: Option<MigrationLedgerStore>,
    recovery_required: Option<String>,
}

impl MigrationRunner {
    #[must_use]
    pub fn new(ledger: MigrationLedger) -> Self {
        Self {
            ledger,
            store: None,
            recovery_required: None,
        }
    }

    pub fn open(store: MigrationLedgerStore) -> Result<Self, MigrationError> {
        let _lock = store.acquire_exclusive()?;
        let ledger = store.load()?;
        let recovery_required = store
            .load_recovery_marker()?
            .map(|id| format!("persisted recovery marker for migration {id}"));
        Ok(Self {
            ledger,
            store: Some(store),
            recovery_required,
        })
    }

    pub fn run(&mut self, migration: &dyn Migration) -> Result<MigrationOutcome, MigrationError> {
        self.run_with_backup(migration, None)
    }

    pub fn run_with_backup(
        &mut self,
        migration: &dyn Migration,
        backup: Option<&ValidatedBackup>,
    ) -> Result<MigrationOutcome, MigrationError> {
        if let Some(reason) = &self.recovery_required {
            return Err(MigrationError::RecoveryRequired(reason.clone()));
        }

        let store = self.store.clone();
        let _lock = if let Some(store) = &store {
            let lock = store.acquire_exclusive()?;
            self.ledger = store.load()?;
            if let Some(id) = store.load_recovery_marker()? {
                let reason = format!("persisted recovery marker for migration {id}");
                self.recovery_required = Some(reason.clone());
                return Err(MigrationError::RecoveryRequired(reason));
            }
            Some(lock)
        } else {
            None
        };

        let descriptor = migration.descriptor();
        descriptor.validate()?;
        if self.ledger.is_applied(&descriptor.id) {
            return Ok(MigrationOutcome::AlreadyApplied);
        }
        if !migration.precondition()? {
            return Ok(MigrationOutcome::NotApplicable);
        }
        if descriptor.requires_snapshot {
            let target = migration
                .recovery_target()
                .ok_or_else(|| MigrationError::RecoveryTargetRequired(descriptor.id.clone()))?;
            let backup = backup
                .ok_or_else(|| MigrationError::RecoveryCheckpointRequired(descriptor.id.clone()))?;
            backup.revalidate_for_target(target)?;
        }

        if let Some(store) = &store
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

        if migration.apply().is_err() {
            return Err(self.manual_recovery_error(&descriptor.id));
        }
        if let Err(error) = migration.verify() {
            return self.handle_post_apply_failure(migration, error, store.as_ref());
        }

        let mut next = self.ledger.clone();
        next.mark_applied(descriptor.id.clone())?;
        if let Some(store) = &store
            && let Err(error) = store.persist(&next)
        {
            return self.handle_persist_failure(migration, error, Some(store));
        }
        self.ledger = next;
        if let Some(store) = &store
            && let Err(error) = store.clear_recovery_marker()
        {
            return self.handle_cleanup_failure(error);
        }
        Ok(MigrationOutcome::Applied)
    }

    fn handle_persist_failure<T>(
        &mut self,
        migration: &dyn Migration,
        error: MigrationError,
        store: Option<&MigrationLedgerStore>,
    ) -> Result<T, MigrationError> {
        let descriptor = migration.descriptor();
        if let MigrationError::DurabilityUncertain(reason) = error {
            let reason = format!("{}: {reason}", descriptor.id);
            self.latch_recovery(reason.clone());
            return Err(MigrationError::DurabilityUncertain(reason));
        }

        if !descriptor.reversible {
            return Err(self.manual_recovery_error(&descriptor.id));
        }
        if migration.rollback().is_err() {
            return Err(self.manual_recovery_error(&descriptor.id));
        }
        if let Some(store) = store
            && let Err(cleanup_error) = store.clear_recovery_marker()
        {
            return self.handle_cleanup_failure(cleanup_error);
        }
        Err(MigrationError::LedgerCommitFailed {
            migration_id: descriptor.id.clone(),
            reason: error.to_string(),
        })
    }

    fn handle_post_apply_failure<T>(
        &mut self,
        migration: &dyn Migration,
        error: MigrationError,
        store: Option<&MigrationLedgerStore>,
    ) -> Result<T, MigrationError> {
        let descriptor = migration.descriptor();
        if descriptor.reversible {
            if migration.rollback().is_err() {
                return Err(self.manual_recovery_error(&descriptor.id));
            }
            if let Some(store) = store
                && let Err(cleanup_error) = store.clear_recovery_marker()
            {
                return self.handle_cleanup_failure(cleanup_error);
            }
            Err(MigrationError::VerificationFailed {
                migration_id: descriptor.id.clone(),
                reason: error.to_string(),
            })
        } else {
            Err(self.manual_recovery_error(&descriptor.id))
        }
    }

    fn manual_recovery_error(&mut self, migration_id: &str) -> MigrationError {
        self.latch_recovery(format!("migration {migration_id} requires manual recovery"));
        MigrationError::ManualRecoveryRequired(migration_id.to_owned())
    }

    fn handle_cleanup_failure<T>(&mut self, error: MigrationError) -> Result<T, MigrationError> {
        let reason = format!("migration recovery marker cleanup is uncertain: {error}");
        self.latch_recovery(reason.clone());
        Err(MigrationError::DurabilityUncertain(reason))
    }

    fn latch_recovery(&mut self, reason: String) {
        self.recovery_required = Some(reason);
    }

    #[must_use]
    pub fn ledger(&self) -> &MigrationLedger {
        &self.ledger
    }

    #[must_use]
    pub const fn requires_recovery(&self) -> bool {
        self.recovery_required.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationOutcome {
    Applied,
    AlreadyApplied,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationError {
    InvalidDescriptor(&'static str),
    Operation(String),
    RecoveryCheckpointRequired(String),
    RecoveryTargetRequired(String),
    BackupNotIndependent,
    BackupMismatch,
    BackupTargetMismatch,
    BackupArtifactNotRegular,
    UntrustedLedgerPath,
    UntrustedLockPath,
    UntrustedRecoveryPath,
    UnsupportedLedgerVersion,
    CorruptLedger(String),
    CorruptRecoveryMarker(String),
    LedgerCommitFailed {
        migration_id: String,
        reason: String,
    },
    DurabilityUncertain(String),
    RecoveryRequired(String),
    VerificationFailed {
        migration_id: String,
        reason: String,
    },
    ManualRecoveryRequired(String),
    Io(String),
}

impl Display for MigrationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDescriptor(message) => f.write_str(message),
            Self::Operation(message) => f.write_str(message),
            Self::RecoveryCheckpointRequired(id) => {
                write!(f, "migration {id} requires a validated recovery backup")
            }
            Self::RecoveryTargetRequired(id) => {
                write!(f, "migration {id} requires an exact recovery target binding")
            }
            Self::BackupNotIndependent => {
                f.write_str("migration backup must be a distinct file/inode")
            }
            Self::BackupMismatch => {
                f.write_str("migration backup no longer matches its validated source bytes/identity")
            }
            Self::BackupTargetMismatch => {
                f.write_str("migration backup is not bound to the exact migration target")
            }
            Self::BackupArtifactNotRegular => {
                f.write_str("migration backup evidence must use regular non-symlink files")
            }
            Self::UntrustedLedgerPath => f.write_str(
                "migration ledger must be a regular non-symlink file without group/other write access",
            ),
            Self::UntrustedLockPath => f.write_str(
                "migration lock must be a stable regular non-symlink file without group/other write access",
            ),
            Self::UntrustedRecoveryPath => f.write_str(
                "migration recovery marker must be a regular non-symlink file without group/other write access",
            ),
            Self::UnsupportedLedgerVersion => {
                f.write_str("unsupported migration ledger version")
            }
            Self::CorruptLedger(reason) => write!(f, "corrupt migration ledger: {reason}"),
            Self::CorruptRecoveryMarker(reason) => {
                write!(f, "corrupt migration recovery marker: {reason}")
            }
            Self::LedgerCommitFailed {
                migration_id,
                reason,
            } => write!(
                f,
                "migration {migration_id} ledger commit failed before the commit point and the effect was rolled back: {reason}"
            ),
            Self::DurabilityUncertain(reason) => write!(
                f,
                "migration effect or recovery state has uncertain durability: {reason}"
            ),
            Self::RecoveryRequired(reason) => {
                write!(f, "migration runner requires reopen/recovery before further work: {reason}")
            }
            Self::VerificationFailed {
                migration_id,
                reason,
            } => write!(
                f,
                "migration {migration_id} verification failed after rollback: {reason}"
            ),
            Self::ManualRecoveryRequired(id) => {
                write!(f, "migration {id} requires manual recovery")
            }
            Self::Io(message) => write!(f, "migration persistence I/O failed: {message}"),
        }
    }
}

impl std::error::Error for MigrationError {}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.contains("..")
}

fn io_error(error: std::io::Error) -> MigrationError {
    MigrationError::Io(error.to_string())
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, MigrationError> {
    let parent = path.parent().ok_or_else(|| {
        MigrationError::Io("migration ledger path has no parent directory".into())
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MigrationError::Io("invalid migration ledger file name".into()))?;
    Ok(parent.join(format!(".{file_name}.{suffix}")))
}

fn reject_untrusted_existing_lock(path: &Path) -> Result<(), MigrationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o022 != 0 =>
        {
            Err(MigrationError::UntrustedLockPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn validate_control_file_identity(
    path: &Path,
    file: &fs::File,
    error: MigrationError,
) -> Result<(), MigrationError> {
    let path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
    let opened_metadata = file.metadata().map_err(io_error)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.permissions().mode() & 0o022 != 0
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(error);
    }
    Ok(())
}

fn verified_regular_file(path: &Path) -> Result<PathBuf, MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(MigrationError::BackupArtifactNotRegular);
    }
    path.canonicalize().map_err(io_error)
}

fn compare_files(source: &Path, backup: &Path) -> Result<(bool, u64), MigrationError> {
    let mut source = fs::File::open(source).map_err(io_error)?;
    let mut backup = fs::File::open(backup).map_err(io_error)?;
    let mut source_buffer = [0_u8; 64 * 1024];
    let mut backup_buffer = [0_u8; 64 * 1024];
    let mut integrity = FNV_OFFSET;
    loop {
        let source_read = source.read(&mut source_buffer).map_err(io_error)?;
        let backup_read = backup.read(&mut backup_buffer).map_err(io_error)?;
        if source_read != backup_read {
            return Ok((false, integrity));
        }
        if source_read == 0 {
            return Ok((true, integrity));
        }
        if source_buffer[..source_read] != backup_buffer[..backup_read] {
            return Ok((false, integrity));
        }
        integrity = fnv1a_update(integrity, &source_buffer[..source_read]);
    }
}

fn fnv1a_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn integrity_tag(bytes: &[u8]) -> u64 {
    fnv1a_update(FNV_OFFSET, bytes)
}

fn serialize_ledger(ledger: &MigrationLedger) -> Vec<u8> {
    let mut payload = String::from(LEDGER_MAGIC);
    payload.push('\n');
    for id in ledger.applied() {
        payload.push_str("applied=");
        payload.push_str(id);
        payload.push('\n');
    }
    let tag = integrity_tag(payload.as_bytes());
    payload.push_str(&format!("integrity={tag:016x}\n"));
    payload.into_bytes()
}

fn parse_ledger(bytes: &[u8]) -> Result<MigrationLedger, MigrationError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| MigrationError::CorruptLedger("ledger is not UTF-8".into()))?;
    let integrity_start = text
        .rfind("integrity=")
        .ok_or_else(|| MigrationError::CorruptLedger("integrity record is missing".into()))?;
    let (payload, integrity_line) = text.split_at(integrity_start);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| MigrationError::CorruptLedger("invalid integrity record".into()))?;
    if expected.len() != 16 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MigrationError::CorruptLedger(
            "invalid integrity tag".into(),
        ));
    }
    let expected = u64::from_str_radix(expected, 16)
        .map_err(|_| MigrationError::CorruptLedger("invalid integrity tag".into()))?;
    if integrity_tag(payload.as_bytes()) != expected {
        return Err(MigrationError::CorruptLedger(
            "integrity tag mismatch".into(),
        ));
    }

    let mut lines = payload.lines();
    if lines.next() != Some(LEDGER_MAGIC) {
        return Err(MigrationError::UnsupportedLedgerVersion);
    }
    let mut applied = Vec::new();
    for line in lines {
        let id = line
            .strip_prefix("applied=")
            .ok_or_else(|| MigrationError::CorruptLedger("unknown ledger field".into()))?;
        if !valid_identifier(id, 128) {
            return Err(MigrationError::CorruptLedger(
                "invalid persisted migration id".into(),
            ));
        }
        applied.push(id.to_owned());
    }
    MigrationLedger::from_applied(applied)
}

fn serialize_recovery_marker(migration_id: &str) -> Vec<u8> {
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

fn atomic_write(path: &Path, bytes: &[u8], label: &str) -> Result<(), MigrationError> {
    let parent = path
        .parent()
        .ok_or_else(|| MigrationError::Io(format!("{label} path has no parent directory")))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| MigrationError::Io(error.to_string()))?
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MigrationError::Io(format!("invalid {label} file name")))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut renamed = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temporary, path).map_err(io_error)?;
        renamed = true;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                MigrationError::DurabilityUncertain(format!(
                    "{label} rename completed but parent-directory fsync failed: {error}"
                ))
            })?;
        Ok(())
    })();
    if result.is_err() && !renamed {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    #[derive(Debug)]
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "linura-migrations-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap_or_else(|error| unreachable!("{error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug)]
    struct TestMigration {
        descriptor: MigrationDescriptor,
        applications: Cell<u32>,
        rollbacks: Cell<u32>,
        precondition: bool,
        verify_ok: bool,
        rollback_ok: bool,
        recovery_target: Option<PathBuf>,
    }

    impl TestMigration {
        fn new(id: &str, requires_snapshot: bool) -> Self {
            Self {
                descriptor: MigrationDescriptor {
                    id: id.into(),
                    introduced_in: "0.9.0".into(),
                    scope: MigrationScope::System,
                    reversible: true,
                    requires_snapshot,
                },
                applications: Cell::new(0),
                rollbacks: Cell::new(0),
                precondition: true,
                verify_ok: true,
                rollback_ok: true,
                recovery_target: None,
            }
        }

        fn with_recovery_target(mut self, path: impl Into<PathBuf>) -> Self {
            self.recovery_target = Some(path.into());
            self
        }
    }

    impl Migration for TestMigration {
        fn descriptor(&self) -> &MigrationDescriptor {
            &self.descriptor
        }

        fn precondition(&self) -> Result<bool, MigrationError> {
            Ok(self.precondition)
        }

        fn apply(&self) -> Result<(), MigrationError> {
            self.applications.set(self.applications.get() + 1);
            Ok(())
        }

        fn verify(&self) -> Result<(), MigrationError> {
            if self.verify_ok {
                Ok(())
            } else {
                Err(MigrationError::Operation("injected verify failure".into()))
            }
        }

        fn recovery_target(&self) -> Option<&Path> {
            self.recovery_target.as_deref()
        }

        fn rollback(&self) -> Result<(), MigrationError> {
            self.rollbacks.set(self.rollbacks.get() + 1);
            if self.rollback_ok {
                Ok(())
            } else {
                Err(MigrationError::Operation(
                    "injected rollback failure".into(),
                ))
            }
        }
    }

    #[test]
    fn migrations_are_idempotent_through_durable_ledger() {
        let dir = TestDir::new("idempotent");
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let migration = TestMigration::new("0001-test", false);
        let mut runner =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(runner.run(&migration), Ok(MigrationOutcome::Applied));
        assert_eq!(runner.run(&migration), Ok(MigrationOutcome::AlreadyApplied));
        assert_eq!(migration.applications.get(), 1);

        let mut reopened =
            MigrationRunner::open(store).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.run(&migration),
            Ok(MigrationOutcome::AlreadyApplied)
        );
        assert_eq!(migration.applications.get(), 1);
    }

    #[test]
    fn stale_runners_merge_durable_applied_ids_instead_of_overwriting() {
        let dir = TestDir::new("serialized-writers");
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let mut first =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));
        let mut stale =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));
        let migration_a = TestMigration::new("0001-a", false);
        let migration_b = TestMigration::new("0002-b", false);

        assert_eq!(first.run(&migration_a), Ok(MigrationOutcome::Applied));
        assert_eq!(stale.run(&migration_b), Ok(MigrationOutcome::Applied));

        let reopened = MigrationRunner::open(store).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(reopened.ledger().is_applied("0001-a"));
        assert!(reopened.ledger().is_applied("0002-b"));
    }

    #[test]
    fn stale_runner_cannot_reapply_same_migration_effect() {
        let dir = TestDir::new("same-migration-writers");
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let mut first =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));
        let mut stale =
            MigrationRunner::open(store).unwrap_or_else(|error| unreachable!("{error}"));
        let migration = TestMigration::new("0001-once", false);

        assert_eq!(first.run(&migration), Ok(MigrationOutcome::Applied));
        assert_eq!(stale.run(&migration), Ok(MigrationOutcome::AlreadyApplied));
        assert_eq!(migration.applications.get(), 1);
    }

    #[test]
    fn risky_migration_requires_a_validated_independent_backup() {
        let dir = TestDir::new("backup");
        let source = dir.path().join("state.db");
        let backup = dir.path().join("state.db.backup");
        fs::write(&source, b"durable-state").unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = ValidatedBackup::verify(&source, &backup)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let migration = TestMigration::new("0002-risky", true).with_recovery_target(source.clone());
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert!(matches!(
            runner.run(&migration),
            Err(MigrationError::RecoveryCheckpointRequired(_))
        ));
        assert_eq!(migration.applications.get(), 0);
        assert_eq!(
            runner.run_with_backup(&migration, Some(&evidence)),
            Ok(MigrationOutcome::Applied)
        );
    }

    #[test]
    fn risky_migration_requires_an_exact_recovery_target() {
        let dir = TestDir::new("target-required");
        let source = dir.path().join("state.db");
        let backup = dir.path().join("state.db.backup");
        fs::write(&source, b"state").unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = ValidatedBackup::verify(&source, &backup)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let migration = TestMigration::new("0002-target-required", true);
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert!(matches!(
            runner.run_with_backup(&migration, Some(&evidence)),
            Err(MigrationError::RecoveryTargetRequired(_))
        ));
        assert_eq!(migration.applications.get(), 0);
    }

    #[test]
    fn unrelated_backup_cannot_authorize_a_risky_migration() {
        let dir = TestDir::new("wrong-target");
        let backed_up_source = dir.path().join("unrelated.db");
        let backup = dir.path().join("unrelated.db.backup");
        let actual_target = dir.path().join("state.db");
        fs::write(&backed_up_source, b"same-bytes").unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&backed_up_source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&actual_target, b"same-bytes").unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = ValidatedBackup::verify(&backed_up_source, &backup)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let migration =
            TestMigration::new("0002-wrong-target", true).with_recovery_target(actual_target);
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert_eq!(
            runner.run_with_backup(&migration, Some(&evidence)),
            Err(MigrationError::BackupTargetMismatch)
        );
        assert_eq!(migration.applications.get(), 0);
    }

    #[test]
    fn hard_link_cannot_masquerade_as_backup() {
        let dir = TestDir::new("hard-link");
        let source = dir.path().join("state.db");
        let backup = dir.path().join("state.db.backup");
        fs::write(&source, b"state").unwrap_or_else(|error| unreachable!("{error}"));
        fs::hard_link(&source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            ValidatedBackup::verify(source, backup),
            Err(MigrationError::BackupNotIndependent)
        );
    }

    #[test]
    fn changed_backup_fails_revalidation_before_apply() {
        let dir = TestDir::new("changed-backup");
        let source = dir.path().join("state.db");
        let backup = dir.path().join("state.db.backup");
        fs::write(&source, b"state-v1").unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&source, &backup).unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = ValidatedBackup::verify(&source, &backup)
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&source, b"state-v2").unwrap_or_else(|error| unreachable!("{error}"));
        let migration =
            TestMigration::new("0003-change", true).with_recovery_target(source.clone());
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert_eq!(
            runner.run_with_backup(&migration, Some(&evidence)),
            Err(MigrationError::BackupMismatch)
        );
        assert_eq!(migration.applications.get(), 0);
    }

    #[test]
    fn verification_failure_rolls_back_and_never_commits_ledger() {
        let mut migration = TestMigration::new("0004-verify", false);
        migration.verify_ok = false;
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert!(matches!(
            runner.run(&migration),
            Err(MigrationError::VerificationFailed { .. })
        ));
        assert_eq!(migration.applications.get(), 1);
        assert_eq!(migration.rollbacks.get(), 1);
        assert!(!runner.ledger().is_applied("0004-verify"));
    }

    #[test]
    fn failed_rollback_latches_recovery_and_survives_reopen() {
        let dir = TestDir::new("rollback-recovery-marker");
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let mut migration = TestMigration::new("0004-rollback-fails", false);
        migration.verify_ok = false;
        migration.rollback_ok = false;
        let mut runner =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            runner.run(&migration),
            Err(MigrationError::ManualRecoveryRequired(
                "0004-rollback-fails".into()
            ))
        );
        assert_eq!(migration.rollbacks.get(), 1);
        assert!(runner.requires_recovery());
        assert!(!runner.ledger().is_applied("0004-rollback-fails"));
        drop(runner);

        let mut reopened =
            MigrationRunner::open(store).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(reopened.requires_recovery());
        assert!(matches!(
            reopened.run(&migration),
            Err(MigrationError::RecoveryRequired(_))
        ));
        assert_eq!(migration.applications.get(), 1);
    }

    #[test]
    fn ambiguous_ledger_commit_never_rolls_back_or_replays_in_process() {
        let migration = TestMigration::new("0004-ambiguous-ledger", false);
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        let result: Result<MigrationOutcome, MigrationError> = runner.handle_persist_failure(
            &migration,
            MigrationError::DurabilityUncertain("injected post-rename fsync failure".into()),
            None,
        );
        assert!(matches!(
            result,
            Err(MigrationError::DurabilityUncertain(_))
        ));
        assert_eq!(migration.rollbacks.get(), 0);
        assert!(runner.requires_recovery());
        assert!(matches!(
            runner.run(&migration),
            Err(MigrationError::RecoveryRequired(_))
        ));
        assert_eq!(migration.applications.get(), 0);
    }

    #[test]
    fn definite_precommit_ledger_failure_rolls_back_reversible_effect() {
        let migration = TestMigration::new("0004-precommit-ledger", false);
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        let result: Result<MigrationOutcome, MigrationError> = runner.handle_persist_failure(
            &migration,
            MigrationError::Io("injected pre-rename failure".into()),
            None,
        );
        assert!(matches!(
            result,
            Err(MigrationError::LedgerCommitFailed { .. })
        ));
        assert_eq!(migration.rollbacks.get(), 1);
        assert!(!runner.requires_recovery());
    }

    #[test]
    fn dangling_ledger_symlink_fails_closed() {
        let dir = TestDir::new("dangling-ledger-symlink");
        let ledger = dir.path().join("migration.ledger");
        symlink(dir.path().join("missing-target"), &ledger)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            MigrationLedgerStore::new(ledger).load(),
            Err(MigrationError::UntrustedLedgerPath)
        );
    }

    #[test]
    fn lock_symlink_fails_closed_without_following_target() {
        let dir = TestDir::new("lock-symlink");
        let ledger = dir.path().join("migration.ledger");
        let store = MigrationLedgerStore::new(&ledger);
        let target = dir.path().join("missing-lock-target");
        let lock = sidecar_path(&ledger, "lock").unwrap_or_else(|error| unreachable!("{error}"));
        symlink(&target, lock).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            store.acquire_exclusive(),
            Err(MigrationError::UntrustedLockPath)
        ));
        assert!(!target.exists());
    }

    #[test]
    fn ledger_detects_corruption_and_unknown_versions() {
        let dir = TestDir::new("corruption");
        let path = dir.path().join("migration.ledger");
        let store = MigrationLedgerStore::new(&path);
        let mut ledger = MigrationLedger::default();
        ledger
            .mark_applied("0001-test")
            .unwrap_or_else(|error| unreachable!("{error}"));
        store
            .persist(&ledger)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut bytes = fs::read(&path).unwrap_or_else(|error| unreachable!("{error}"));
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            store.load(),
            Err(MigrationError::CorruptLedger(_))
        ));

        let payload = b"linura-migration-ledger-v2\n";
        let tag = integrity_tag(payload);
        fs::write(
            &path,
            format!("linura-migration-ledger-v2\nintegrity={tag:016x}\n"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.load(), Err(MigrationError::UnsupportedLedgerVersion));
    }

    #[test]
    fn non_applicable_migration_performs_no_effect() {
        let mut migration = TestMigration::new("0005-not-applicable", false);
        migration.precondition = false;
        let mut runner = MigrationRunner::new(MigrationLedger::default());
        assert_eq!(runner.run(&migration), Ok(MigrationOutcome::NotApplicable));
        assert_eq!(migration.applications.get(), 0);
    }
}
