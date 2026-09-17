use crate::{Migration, MigrationDescriptor, MigrationError, MigrationScope, ValidatedBackup};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const V09_LIBRARY_SQLITE_MIGRATION_ID: &str = "v09-library-sqlite-preservation";
pub const V09_AUTHORITY_SQLITE_MIGRATION_ID: &str = "v09-authority-sqlite-preservation";
const AUTHORITY_APPLICATION_ID: i64 = 0x4c4e5254; // LNRT
const V08_LIBRARY_SCHEMA_VERSION: i64 = 1;
const V08_AUTHORITY_SCHEMA_VERSION: i64 = 2;
const MAX_SQLITE_BYTES: u64 = 64 * 1024 * 1024;
const O_NOFOLLOW: i32 = 0o400000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V08SqliteStoreKind {
    Library,
    Authority,
}

impl V08SqliteStoreKind {
    fn migration_id(self) -> &'static str {
        match self {
            Self::Library => V09_LIBRARY_SQLITE_MIGRATION_ID,
            Self::Authority => V09_AUTHORITY_SQLITE_MIGRATION_ID,
        }
    }
}

#[derive(Debug)]
pub struct V09PersistentStateMigration {
    descriptor: MigrationDescriptor,
    target: PathBuf,
    backup: PathBuf,
    kind: V08SqliteStoreKind,
    expected_semantic_sha256: String,
    #[cfg(feature = "qualification-harness")]
    force_verification_failure: bool,
}

impl V09PersistentStateMigration {
    pub fn open_library(
        target: impl Into<PathBuf>,
        backup: impl Into<PathBuf>,
    ) -> Result<Self, MigrationError> {
        Self::open(V08SqliteStoreKind::Library, target, backup)
    }

    pub fn open_authority(
        target: impl Into<PathBuf>,
        backup: impl Into<PathBuf>,
    ) -> Result<Self, MigrationError> {
        Self::open(V08SqliteStoreKind::Authority, target, backup)
    }

    fn open(
        kind: V08SqliteStoreKind,
        target: impl Into<PathBuf>,
        backup: impl Into<PathBuf>,
    ) -> Result<Self, MigrationError> {
        let target = target.into();
        let backup = backup.into();
        validate_distinct_absolute_paths(&target, &backup)?;
        validate_sqlite_file(&target)?;
        let expected_semantic_sha256 = semantic_fingerprint(&target, kind)?;
        Ok(Self {
            descriptor: MigrationDescriptor {
                id: kind.migration_id().into(),
                introduced_in: "0.9.0".into(),
                scope: MigrationScope::System,
                reversible: true,
                requires_snapshot: true,
            },
            target,
            backup,
            kind,
            expected_semantic_sha256,
            #[cfg(feature = "qualification-harness")]
            force_verification_failure: false,
        })
    }

    #[cfg(feature = "qualification-harness")]
    pub fn open_library_with_forced_verification_failure(
        target: impl Into<PathBuf>,
        backup: impl Into<PathBuf>,
    ) -> Result<Self, MigrationError> {
        let mut migration = Self::open_library(target, backup)?;
        migration.force_verification_failure = true;
        Ok(migration)
    }

    #[cfg(feature = "qualification-harness")]
    pub fn open_authority_with_forced_verification_failure(
        target: impl Into<PathBuf>,
        backup: impl Into<PathBuf>,
    ) -> Result<Self, MigrationError> {
        let mut migration = Self::open_authority(target, backup)?;
        migration.force_verification_failure = true;
        Ok(migration)
    }

    #[must_use]
    pub const fn kind(&self) -> V08SqliteStoreKind {
        self.kind
    }

    #[must_use]
    pub fn expected_semantic_sha256(&self) -> &str {
        &self.expected_semantic_sha256
    }

    pub fn semantic_sha256(
        path: impl AsRef<Path>,
        kind: V08SqliteStoreKind,
    ) -> Result<String, MigrationError> {
        semantic_fingerprint(path.as_ref(), kind)
    }
}

/// Create a byte-identical recovery image after folding every committed WAL
/// frame into the SQLite main database. The writer reservation prevents a new
/// committed WAL generation from racing the checkpoint-to-copy interval.
pub fn create_validated_sqlite_backup(
    source: impl AsRef<Path>,
    backup: impl AsRef<Path>,
) -> Result<ValidatedBackup, MigrationError> {
    let source = source.as_ref();
    let backup = backup.as_ref();
    validate_distinct_absolute_paths(source, backup)?;
    validate_sqlite_file(source)?;
    validate_protected_parent(source)?;
    validate_protected_parent(backup)?;

    match fs::symlink_metadata(backup) {
        Ok(_) => {
            return Err(MigrationError::Operation(
                "SQLite recovery backup path already exists".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }

    // Reserve SQLite's single writer slot *before* checkpointing. The separate
    // checkpoint connection can fold all previously committed WAL frames into
    // the main database while BEGIN IMMEDIATE prevents a new writer from
    // committing between checkpoint and byte-identical snapshot creation.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let writer_guard = Connection::open_with_flags(source, flags).map_err(sqlite_error)?;
    writer_guard
        .busy_timeout(Duration::from_secs(5))
        .map_err(sqlite_error)?;
    writer_guard
        .execute_batch("BEGIN IMMEDIATE;")
        .map_err(sqlite_error)?;

    let snapshot_result = (|| {
        let checkpoint = Connection::open_with_flags(source, flags).map_err(sqlite_error)?;
        checkpoint
            .busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_error)?;
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = checkpoint
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(sqlite_error)?;
        if busy != 0 || log_frames < 0 || checkpointed_frames != log_frames {
            return Err(MigrationError::Operation(format!(
                "SQLite WAL could not be fully checkpointed under writer reservation: busy={busy}, log={log_frames}, checkpointed={checkpointed_frames}"
            )));
        }

        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(source)
            .map_err(io_error)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(backup)
            .map_err(io_error)?;
        std::io::copy(&mut input, &mut output).map_err(io_error)?;
        output.sync_all().map_err(io_error)?;
        let parent = backup.parent().ok_or_else(|| {
            MigrationError::Operation("SQLite backup path has no parent directory".into())
        })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        ValidatedBackup::verify(source, backup)
    })();

    let unlock_result = writer_guard
        .execute_batch("ROLLBACK;")
        .map_err(sqlite_error);
    if snapshot_result.is_err() {
        let _ = fs::remove_file(backup);
    }
    let evidence = snapshot_result?;
    unlock_result?;
    Ok(evidence)
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn validate_protected_parent(path: &Path) -> Result<(), MigrationError> {
    let parent = path
        .parent()
        .ok_or_else(|| MigrationError::Operation("SQLite path has no parent directory".into()))?;
    let metadata = fs::symlink_metadata(parent).map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(MigrationError::Operation(
            "SQLite path parent directory is not protected".into(),
        ));
    }
    Ok(())
}

fn remove_sqlite_sidecars(path: &Path) -> Result<(), MigrationError> {
    validate_protected_parent(path)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => {
                if metadata.file_type().is_dir() {
                    return Err(MigrationError::Operation(format!(
                        "SQLite recovery sidecar is unexpectedly a directory: {}",
                        sidecar.display()
                    )));
                }
                fs::remove_file(&sidecar).map_err(io_error)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| MigrationError::Operation("SQLite target has no parent directory".into()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

impl Migration for V09PersistentStateMigration {
    fn descriptor(&self) -> &MigrationDescriptor {
        &self.descriptor
    }

    fn precondition(&self) -> Result<bool, MigrationError> {
        Ok(semantic_fingerprint(&self.target, self.kind)? == self.expected_semantic_sha256)
    }

    fn apply(&self) -> Result<(), MigrationError> {
        // v0.9 intentionally does not rewrite the released v0.8 SQLite schemas.
        // The migration is an explicit compatibility/preservation gate recorded
        // in the independent Linura migration ledger. Opening a write transaction
        // proves the actual store is writable without translating it into a
        // synthetic envelope or changing semantic rows.
        validate_sqlite_file(&self.target)?;
        let connection = Connection::open(&self.target).map_err(sqlite_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; BEGIN IMMEDIATE; COMMIT;")
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn verify(&self) -> Result<(), MigrationError> {
        #[cfg(feature = "qualification-harness")]
        if self.force_verification_failure {
            return Err(MigrationError::Operation(
                "injected v0.9 SQLite preservation verification failure".into(),
            ));
        }
        validate_sqlite_file(&self.target)?;
        let observed = semantic_fingerprint(&self.target, self.kind)?;
        if observed != self.expected_semantic_sha256 {
            return Err(MigrationError::Operation(format!(
                "v0.9 {:?} SQLite semantic fingerprint changed during migration",
                self.kind
            )));
        }
        Ok(())
    }

    fn recovery_target(&self) -> Option<&Path> {
        Some(&self.target)
    }

    fn rollback(&self) -> Result<(), MigrationError> {
        validate_sqlite_file(&self.backup)?;
        let backup_fingerprint = semantic_fingerprint(&self.backup, self.kind)?;
        if backup_fingerprint != self.expected_semantic_sha256 {
            return Err(MigrationError::Operation(
                "validated SQLite recovery backup does not preserve expected semantics".into(),
            ));
        }
        let bytes = fs::read(&self.backup).map_err(io_error)?;
        remove_sqlite_sidecars(&self.target)?;
        durable_replace(&self.target, &bytes)?;
        remove_sqlite_sidecars(&self.target)
    }
}

fn validate_distinct_absolute_paths(target: &Path, backup: &Path) -> Result<(), MigrationError> {
    if target == backup || !target.is_absolute() || !backup.is_absolute() {
        return Err(MigrationError::Operation(
            "v0.9 SQLite migration requires distinct absolute target/backup paths".into(),
        ));
    }
    Ok(())
}

fn validate_sqlite_file(path: &Path) -> Result<(), MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() < 100
        || metadata.len() > MAX_SQLITE_BYTES
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(MigrationError::Operation(
            "v0.9 migration target must be a protected bounded SQLite regular file".into(),
        ));
    }
    let header = fs::read(path).map_err(io_error)?;
    if !header.starts_with(b"SQLite format 3\0") {
        return Err(MigrationError::Operation(
            "v0.9 migration target is not a SQLite database".into(),
        ));
    }
    Ok(())
}

fn semantic_fingerprint(path: &Path, kind: V08SqliteStoreKind) -> Result<String, MigrationError> {
    validate_sqlite_file(path)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags).map_err(sqlite_error)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if integrity != "ok" {
        return Err(MigrationError::Operation(format!(
            "SQLite integrity_check failed: {integrity}"
        )));
    }
    let foreign_key_violation: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    if foreign_key_violation != 0 {
        return Err(MigrationError::Operation(
            "SQLite foreign_key_check reported violations".into(),
        ));
    }

    let mut canonical = Vec::new();
    match kind {
        V08SqliteStoreKind::Library => fingerprint_library(&connection, &mut canonical)?,
        V08SqliteStoreKind::Authority => fingerprint_authority(&connection, &mut canonical)?,
    }
    let mut hasher = Sha256::new();
    hasher.update(kind.migration_id().as_bytes());
    hasher.update([0]);
    hasher.update(&canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn fingerprint_library(
    connection: &Connection,
    canonical: &mut Vec<u8>,
) -> Result<(), MigrationError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if version != V08_LIBRARY_SCHEMA_VERSION {
        return Err(MigrationError::Operation(format!(
            "unsupported v0.8 Library schema version {version}"
        )));
    }

    let relations: [(&str, usize); 21] = [
        (
            "SELECT intent_id, revision, actor_id, actor_kind, actor_interactive, statement, status FROM intent_revisions ORDER BY intent_id, revision",
            7,
        ),
        (
            "SELECT intent_id, intent_revision, requirement_id, kind, statement FROM intent_requirements ORDER BY intent_id, intent_revision, requirement_id",
            5,
        ),
        (
            "SELECT intent_id, intent_revision, superseded_intent_id FROM intent_supersedes ORDER BY intent_id, intent_revision, superseded_intent_id",
            3,
        ),
        (
            "SELECT intent_id, revision, causal_generation, causal_complete FROM intents_current ORDER BY intent_id",
            4,
        ),
        (
            "SELECT sequence, intent_id, from_revision, to_revision, from_status, to_status, operation_id FROM intent_transitions ORDER BY sequence",
            7,
        ),
        (
            "SELECT operation_id, semantic_digest, result_kind, result_id, result_revision FROM library_operations ORDER BY operation_id",
            5,
        ),
        (
            "SELECT intent_id, intent_revision, generation, provider_id, resource_id, capability_id, ownership_complete FROM desired_resources ORDER BY intent_id, intent_revision, generation, provider_id, resource_id, capability_id",
            7,
        ),
        (
            "SELECT intent_id, intent_revision, generation, provider_id, resource_id, capability_id, key, value FROM desired_resource_attributes ORDER BY intent_id, intent_revision, generation, provider_id, resource_id, capability_id, key",
            8,
        ),
        (
            "SELECT intent_id, intent_revision, generation, provider_id, resource_id, capability_id, origin_kind, origin_id FROM desired_resource_origins ORDER BY intent_id, intent_revision, generation, provider_id, resource_id, capability_id, origin_kind, origin_id",
            8,
        ),
        (
            "SELECT setup_id, revision, name, description FROM setup_revisions ORDER BY setup_id, revision",
            4,
        ),
        (
            "SELECT setup_id, setup_revision, intent_id, intent_revision FROM setup_intents ORDER BY setup_id, setup_revision, intent_id, intent_revision",
            4,
        ),
        (
            "SELECT setup_id, setup_revision, included_setup_id, included_revision FROM setup_includes ORDER BY setup_id, setup_revision, included_setup_id, included_revision",
            4,
        ),
        (
            "SELECT setup_id, setup_revision, ordinal, value FROM setup_constraints ORDER BY setup_id, setup_revision, ordinal",
            4,
        ),
        (
            "SELECT setup_id, setup_revision, ordinal, value FROM setup_secret_refs ORDER BY setup_id, setup_revision, ordinal",
            4,
        ),
        (
            "SELECT setup_id, setup_revision, ordinal, value FROM setup_hardware_hints ORDER BY setup_id, setup_revision, ordinal",
            4,
        ),
        (
            "SELECT profile_id, revision, name, machine_class FROM profile_revisions ORDER BY profile_id, revision",
            4,
        ),
        (
            "SELECT profile_id, profile_revision, setup_id, setup_revision FROM profile_setups ORDER BY profile_id, profile_revision, setup_id, setup_revision",
            4,
        ),
        (
            "SELECT profile_id, profile_revision, intent_id, intent_revision FROM profile_intents ORDER BY profile_id, profile_revision, intent_id, intent_revision",
            4,
        ),
        (
            "SELECT profile_id, profile_revision, ordinal, value FROM profile_constraints ORDER BY profile_id, profile_revision, ordinal",
            4,
        ),
        (
            "SELECT profile_id, profile_revision, ordinal, value FROM profile_hardware_hints ORDER BY profile_id, profile_revision, ordinal",
            4,
        ),
        (
            "SELECT sequence, record_kind, entity_id, content_digest, payload FROM lifecycle_records ORDER BY sequence",
            5,
        ),
    ];
    for (sql, columns) in relations {
        append_query_rows(connection, canonical, sql, columns)?;
    }
    Ok(())
}

fn fingerprint_authority(
    connection: &Connection,
    canonical: &mut Vec<u8>,
) -> Result<(), MigrationError> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if application_id != AUTHORITY_APPLICATION_ID || version != V08_AUTHORITY_SCHEMA_VERSION {
        return Err(MigrationError::Operation(format!(
            "unsupported v0.8 authority SQLite identity/schema: application_id={application_id:#x}, user_version={version}"
        )));
    }
    append_query_rows(
        connection,
        canonical,
        "SELECT transaction_id, principal, request_id, current_generation, state_version FROM transactions ORDER BY transaction_id",
        5,
    )?;
    append_query_rows(
        connection,
        canonical,
        "SELECT transaction_id, generation, state, binding_digest, request_digest, precondition_digest, observation_digest, COALESCE(desired_state_digest, ''), COALESCE(graph_digest, ''), COALESCE(provenance_digest, '') FROM generations ORDER BY transaction_id, generation",
        10,
    )?;
    append_query_rows(
        connection,
        canonical,
        "SELECT transaction_id, event_sequence, generation, state_version, event_kind, payload_digest, previous_digest, event_digest FROM audit_events ORDER BY transaction_id, event_sequence",
        8,
    )?;
    append_query_rows(
        connection,
        canonical,
        "SELECT migration_id, checksum FROM schema_migrations ORDER BY migration_id",
        2,
    )?;
    Ok(())
}

fn append_query_rows(
    connection: &Connection,
    canonical: &mut Vec<u8>,
    sql: &str,
    columns: usize,
) -> Result<(), MigrationError> {
    let mut statement = connection.prepare(sql).map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        for index in 0..columns {
            let value = row.get_ref(index).map_err(sqlite_error)?;
            match value {
                rusqlite::types::ValueRef::Null => canonical.extend_from_slice(b"N:"),
                rusqlite::types::ValueRef::Integer(value) => {
                    canonical.extend_from_slice(format!("I:{value}").as_bytes());
                }
                rusqlite::types::ValueRef::Real(value) => {
                    canonical.extend_from_slice(format!("R:{value:.17}").as_bytes());
                }
                rusqlite::types::ValueRef::Text(value) => {
                    canonical.extend_from_slice(b"T:");
                    canonical.extend_from_slice(value);
                }
                rusqlite::types::ValueRef::Blob(value) => {
                    canonical.extend_from_slice(b"B:");
                    canonical.extend_from_slice(format!("{:x}", Sha256::digest(value)).as_bytes());
                }
            }
            canonical.push(0x1f);
        }
        canonical.push(0x1e);
    }
    Ok(())
}

fn durable_replace(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    if bytes.len() < 100 || bytes.len() as u64 > MAX_SQLITE_BYTES {
        return Err(MigrationError::Operation(
            "SQLite recovery output exceeds the supported bound".into(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        MigrationError::Operation("SQLite migration target has no parent directory".into())
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(io_error)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(MigrationError::Operation(
            "SQLite migration parent directory is not protected".into(),
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MigrationError::Operation("invalid SQLite file name".into()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| MigrationError::Io(error.to_string()))?
        .as_nanos();
    let temporary = parent.join(format!(
        ".{file_name}.migration-{}-{nonce}",
        std::process::id()
    ));
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
                    "SQLite recovery rename completed but parent-directory fsync failed: {error}"
                ))
            })?;
        Ok(())
    })();
    if result.is_err() && !renamed {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sqlite_error(error: rusqlite::Error) -> MigrationError {
    MigrationError::Operation(format!("SQLite migration validation failed: {error}"))
}

fn io_error(error: std::io::Error) -> MigrationError {
    MigrationError::Io(error.to_string())
}
