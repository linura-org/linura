use std::fmt::{Debug, Formatter};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use linura_control::{
    TransientEffectAuditDisposition, TransientEffectAuditError, TransientEffectAuditFailureCode,
    TransientEffectAuditRecord, TransientEffectAuditSink,
};
use linura_core::RiskClass;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

const APPLICATION_ID: i64 = 1_280_201_810; // "LNTR"
const SCHEMA_VERSION: i64 = 1;
const MAX_AUDIT_RECORDS: i64 = 100_000;
const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_RISK_RULES: usize = 32;
const MAX_RISK_RULE_BYTES: usize = 256;
const BUSY_TIMEOUT_MS: u64 = 250;

const EXPECTED_AUDIT_COLUMNS: [(&str, bool, bool); 20] = [
    ("audit_attempt_sha256", true, true),
    ("principal", true, false),
    ("operation_id", true, false),
    ("plan_id", true, false),
    ("request_id", true, false),
    ("provider", true, false),
    ("resource", true, false),
    ("observation_capability", true, false),
    ("risk", true, false),
    ("policy_id", true, false),
    ("policy_revision_id", true, false),
    ("policy_subject_risk", true, false),
    ("risk_classification_revision", true, false),
    ("risk_rule_ids", true, false),
    ("canonical_plan_sha256", true, false),
    ("requested_postcondition_sha256", true, false),
    ("pre_effect_evidence_id", true, false),
    ("post_effect_evidence_id", false, false),
    ("disposition", true, false),
    ("failure_code", false, false),
];

const SCHEMA: &str = r#"
CREATE TABLE transient_effect_audit (
    audit_attempt_sha256 TEXT PRIMARY KEY NOT NULL,
    principal TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    resource TEXT NOT NULL,
    observation_capability TEXT NOT NULL,
    risk TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision_id TEXT NOT NULL,
    policy_subject_risk TEXT NOT NULL,
    risk_classification_revision TEXT NOT NULL,
    risk_rule_ids TEXT NOT NULL,
    canonical_plan_sha256 TEXT NOT NULL,
    requested_postcondition_sha256 TEXT NOT NULL,
    pre_effect_evidence_id TEXT NOT NULL,
    post_effect_evidence_id TEXT,
    disposition TEXT NOT NULL,
    failure_code TEXT
) STRICT;
"#;

pub(crate) struct SqliteTransientAudit {
    connection: Connection,
    database_path: PathBuf,
}

impl Debug for SqliteTransientAudit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteTransientAudit")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct StoredAudit {
    binding: Vec<String>,
    post_effect_evidence_id: Option<String>,
    disposition: String,
    failure_code: Option<String>,
}

impl SqliteTransientAudit {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "transient audit path has no parent directory".to_owned())?;
        prepare_private_directory(parent)?;
        prepare_private_database_file(path)?;
        validate_wal_sidecar(path)?;

        let mut connection = Connection::open(path)
            .map_err(|error| format!("cannot open transient audit: {error}"))?;
        connection
            .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(|error| format!("cannot set transient audit busy timeout: {error}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(|error| format!("cannot configure transient audit SQLite: {error}"))?;
        verify_effective_sqlite_configuration(&connection)?;
        configure_storage_bounds(&connection)?;

        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(|error| format!("cannot read transient audit application_id: {error}"))?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|error| format!("cannot read transient audit schema version: {error}"))?;

        match (application_id, user_version) {
            (0, 0) => {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| format!("cannot initialize transient audit: {error}"))?;
                transaction
                    .execute_batch(&format!(
                        "PRAGMA application_id = {APPLICATION_ID};
                         PRAGMA user_version = {SCHEMA_VERSION};
                         {SCHEMA}"
                    ))
                    .map_err(|error| format!("cannot create transient audit schema: {error}"))?;
                transaction
                    .commit()
                    .map_err(|error| format!("cannot commit transient audit schema: {error}"))?;
            }
            (APPLICATION_ID, SCHEMA_VERSION) => {}
            _ => {
                return Err(format!(
                    "transient audit database identity mismatch: application_id={application_id}, user_version={user_version}"
                ));
            }
        }

        validate_exact_schema(&connection)?;

        let quick_check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(|error| format!("cannot integrity-check transient audit: {error}"))?;
        if quick_check != "ok" {
            return Err(format!(
                "transient audit integrity check failed: {quick_check}"
            ));
        }

        checkpoint_and_validate_wal(&connection, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot harden transient audit permissions: {error}"))?;
        Ok(Self {
            connection,
            database_path: path.to_path_buf(),
        })
    }

    fn store_reservation(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError> {
        validate_record(record)?;
        checkpoint_and_validate_wal(&self.connection, &self.database_path).map_err(audit_error)?;
        if record.disposition != TransientEffectAuditDisposition::AttemptReserved {
            return Err(audit_error("reservation record has a terminal disposition"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_audit_error)?;

        if let Some(stored) = load_record(&transaction, &record.audit_attempt_sha256)? {
            require_same_binding(record, &stored)?;
            transaction.commit().map_err(sqlite_audit_error)?;
            checkpoint_and_validate_wal(&self.connection, &self.database_path)
                .map_err(audit_error)?;
            return Ok(());
        }

        require_capacity(&transaction)?;
        insert_record(&transaction, record)?;
        transaction.commit().map_err(sqlite_audit_error)?;
        checkpoint_and_validate_wal(&self.connection, &self.database_path).map_err(audit_error)
    }

    fn store_terminal(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError> {
        validate_record(record)?;
        checkpoint_and_validate_wal(&self.connection, &self.database_path).map_err(audit_error)?;
        if record.disposition == TransientEffectAuditDisposition::AttemptReserved {
            return Err(audit_error(
                "terminal record cannot be an attempt reservation",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_audit_error)?;

        match load_record(&transaction, &record.audit_attempt_sha256)? {
            Some(stored) => {
                require_same_binding(record, &stored)?;
                let terminal_disposition = disposition_name(record.disposition);
                let terminal_failure = record.failure_code.map(failure_name);
                if stored.disposition == "attempt-reserved" {
                    let changed = transaction
                        .execute(
                            "UPDATE transient_effect_audit
                             SET post_effect_evidence_id = ?1,
                                 disposition = ?2,
                                 failure_code = ?3
                             WHERE audit_attempt_sha256 = ?4
                               AND disposition = 'attempt-reserved'",
                            params![
                                record.post_effect_evidence_id.as_deref(),
                                terminal_disposition,
                                terminal_failure,
                                record.audit_attempt_sha256,
                            ],
                        )
                        .map_err(sqlite_audit_error)?;
                    if changed != 1 {
                        return Err(audit_error(
                            "transient audit reservation changed concurrently",
                        ));
                    }
                } else if stored.disposition != terminal_disposition
                    || stored.post_effect_evidence_id != record.post_effect_evidence_id
                    || stored.failure_code.as_deref() != terminal_failure
                {
                    return Err(audit_error(
                        "transient audit attempt already has a different terminal result",
                    ));
                }
            }
            None if record.disposition == TransientEffectAuditDisposition::NoChange => {
                require_capacity(&transaction)?;
                insert_record(&transaction, record)?;
            }
            None => {
                return Err(audit_error(
                    "transient terminal audit has no durable attempt reservation",
                ));
            }
        }

        transaction.commit().map_err(sqlite_audit_error)?;
        checkpoint_and_validate_wal(&self.connection, &self.database_path).map_err(audit_error)
    }
}

impl TransientEffectAuditSink for SqliteTransientAudit {
    fn reserve_attempt(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError> {
        self.store_reservation(record)
    }

    fn record_terminal(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError> {
        self.store_terminal(record)
    }
}

fn prepare_private_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("transient audit state path is not a real directory".into());
        }
    } else {
        fs::create_dir_all(path)
            .map_err(|error| format!("cannot create transient audit state directory: {error}"))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot harden transient audit state directory: {error}"))
}

fn prepare_private_database_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("transient audit database path is not a regular file".into());
            }
            if metadata.nlink() != 1 {
                return Err("transient audit database must not have hard-link aliases".into());
            }
            if metadata.len() > MAX_DATABASE_BYTES {
                return Err(
                    "transient audit database exceeds the bounded file-size ceiling".into(),
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot harden transient audit permissions: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|error| format!("cannot create transient audit database: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync new transient audit database: {error}"))?;
            drop(file);
            let parent = path
                .parent()
                .ok_or_else(|| "transient audit path has no parent directory".to_owned())?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("cannot sync transient audit state directory: {error}"))
        }
        Err(error) => Err(format!(
            "cannot inspect transient audit database path: {error}"
        )),
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn validate_wal_sidecar(path: &Path) -> Result<(), String> {
    let wal_path = sqlite_sidecar_path(path, "-wal");
    match fs::symlink_metadata(&wal_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("transient audit WAL sidecar is not a regular file".into());
            }
            if metadata.nlink() != 1 {
                return Err("transient audit WAL sidecar must not have hard-link aliases".into());
            }
            if metadata.len() > MAX_WAL_BYTES {
                return Err(format!(
                    "transient audit WAL sidecar exceeds the {}-byte ceiling",
                    MAX_WAL_BYTES
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect transient audit WAL sidecar: {error}"
        )),
    }
}

fn checkpoint_and_validate_wal(connection: &Connection, path: &Path) -> Result<(), String> {
    validate_wal_sidecar(path)?;
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| format!("cannot checkpoint transient audit WAL: {error}"))?;
    if busy != 0 || checkpointed_frames != log_frames {
        return Err(format!(
            "transient audit WAL checkpoint could not complete: busy={busy}, log_frames={log_frames}, checkpointed_frames={checkpointed_frames}"
        ));
    }
    validate_wal_sidecar(path)
}

fn verify_effective_sqlite_configuration(connection: &Connection) -> Result<(), String> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| format!("cannot read transient audit journal_mode: {error}"))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(format!(
            "transient audit SQLite journal_mode is {journal_mode:?}; WAL is required"
        ));
    }

    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| format!("cannot read transient audit synchronous mode: {error}"))?;
    const SQLITE_SYNCHRONOUS_FULL: i64 = 2;
    if synchronous != SQLITE_SYNCHRONOUS_FULL {
        return Err(format!(
            "transient audit SQLite synchronous mode is {synchronous}; FULL ({SQLITE_SYNCHRONOUS_FULL}) is required"
        ));
    }

    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| format!("cannot read transient audit foreign_keys mode: {error}"))?;
    if foreign_keys != 1 {
        return Err(format!(
            "transient audit SQLite foreign_keys mode is {foreign_keys}; enabled mode is required"
        ));
    }

    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| format!("cannot read transient audit trusted_schema mode: {error}"))?;
    if trusted_schema != 0 {
        return Err(format!(
            "transient audit SQLite trusted_schema mode is {trusted_schema}; disabled mode is required"
        ));
    }

    Ok(())
}

fn configure_storage_bounds(connection: &Connection) -> Result<(), String> {
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| format!("cannot read transient audit page size: {error}"))?;
    let page_size =
        u64::try_from(page_size).map_err(|_| "transient audit page size is negative".to_owned())?;
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(format!(
            "transient audit page size is unsupported: {page_size}"
        ));
    }
    let max_pages = (MAX_DATABASE_BYTES / page_size).max(1);
    const WAL_HEADER_BYTES: u64 = 32;
    const WAL_FRAME_HEADER_BYTES: u64 = 24;
    let wal_frame_bytes = page_size
        .checked_add(WAL_FRAME_HEADER_BYTES)
        .ok_or_else(|| "transient audit WAL frame-size overflow".to_owned())?;
    let max_wal_frames = MAX_WAL_BYTES
        .saturating_sub(WAL_HEADER_BYTES)
        .checked_div(wal_frame_bytes)
        .unwrap_or(0)
        .max(1);
    connection
        .execute_batch(&format!(
            "PRAGMA max_page_count = {max_pages};
             PRAGMA journal_size_limit = {MAX_WAL_BYTES};
             PRAGMA wal_autocheckpoint = {max_wal_frames};"
        ))
        .map_err(|error| format!("cannot bound transient audit storage: {error}"))?;
    let configured_max_pages: i64 = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .map_err(|error| format!("cannot verify transient audit max_page_count: {error}"))?;
    let configured_max_pages = u64::try_from(configured_max_pages)
        .map_err(|_| "transient audit max_page_count is negative".to_owned())?;
    if configured_max_pages > max_pages {
        return Err("transient audit max_page_count exceeds the configured ceiling".into());
    }
    let configured_wal_autocheckpoint: i64 = connection
        .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
        .map_err(|error| format!("cannot verify transient audit wal_autocheckpoint: {error}"))?;
    let configured_wal_autocheckpoint = u64::try_from(configured_wal_autocheckpoint)
        .map_err(|_| "transient audit wal_autocheckpoint is negative".to_owned())?;
    if configured_wal_autocheckpoint == 0 || configured_wal_autocheckpoint > max_wal_frames {
        return Err("transient audit wal_autocheckpoint exceeds the WAL byte ceiling".into());
    }
    Ok(())
}

fn validate_exact_schema(connection: &Connection) -> Result<(), String> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .map_err(|error| format!("cannot inspect transient audit schema objects: {error}"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| format!("cannot query transient audit schema objects: {error}"))?;
    let mut objects = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("cannot read transient audit schema object: {error}"))?
    {
        objects.push((
            row.get::<_, String>(0)
                .map_err(|error| format!("cannot decode transient audit schema type: {error}"))?,
            row.get::<_, String>(1)
                .map_err(|error| format!("cannot decode transient audit schema name: {error}"))?,
            row.get::<_, String>(2)
                .map_err(|error| format!("cannot decode transient audit schema table: {error}"))?,
        ));
    }
    drop(rows);
    drop(statement);
    if objects
        != vec![(
            "table".to_owned(),
            "transient_effect_audit".to_owned(),
            "transient_effect_audit".to_owned(),
        )]
    {
        return Err("transient audit schema contains unexpected objects".into());
    }

    let table_shape: (String, String, String, i64, i64, i64) = connection
        .query_row("PRAGMA table_list('transient_effect_audit')", [], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|error| format!("cannot inspect transient audit table shape: {error}"))?;
    if table_shape
        != (
            "main".to_owned(),
            "transient_effect_audit".to_owned(),
            "table".to_owned(),
            i64::try_from(EXPECTED_AUDIT_COLUMNS.len())
                .map_err(|_| "transient audit column count overflow".to_owned())?,
            0,
            1,
        )
    {
        return Err("transient audit table shape is not the exact STRICT schema".into());
    }

    let mut statement = connection
        .prepare("PRAGMA table_xinfo('transient_effect_audit')")
        .map_err(|error| format!("cannot inspect transient audit columns: {error}"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| format!("cannot query transient audit columns: {error}"))?;
    let mut index = 0_usize;
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("cannot read transient audit column: {error}"))?
    {
        let Some(&(expected_name, expected_not_null, expected_primary_key)) =
            EXPECTED_AUDIT_COLUMNS.get(index)
        else {
            return Err("transient audit table has extra columns".into());
        };
        let cid: i64 = row
            .get(0)
            .map_err(|error| format!("cannot decode transient audit column id: {error}"))?;
        let name: String = row
            .get(1)
            .map_err(|error| format!("cannot decode transient audit column name: {error}"))?;
        let declared_type: String = row
            .get(2)
            .map_err(|error| format!("cannot decode transient audit column type: {error}"))?;
        let not_null: i64 = row
            .get(3)
            .map_err(|error| format!("cannot decode transient audit nullability: {error}"))?;
        let default_value: Option<String> = row
            .get(4)
            .map_err(|error| format!("cannot decode transient audit default: {error}"))?;
        let primary_key: i64 = row
            .get(5)
            .map_err(|error| format!("cannot decode transient audit key shape: {error}"))?;
        let hidden: i64 = row
            .get(6)
            .map_err(|error| format!("cannot decode transient audit hidden shape: {error}"))?;
        if cid
            != i64::try_from(index)
                .map_err(|_| "transient audit column index overflow".to_owned())?
            || name != expected_name
            || declared_type != "TEXT"
            || (not_null != 0) != expected_not_null
            || default_value.is_some()
            || (primary_key != 0) != expected_primary_key
            || hidden != 0
        {
            return Err(format!(
                "transient audit column {index} does not match the exact schema"
            ));
        }
        index += 1;
    }
    if index != EXPECTED_AUDIT_COLUMNS.len() {
        return Err("transient audit table is missing required columns".into());
    }
    Ok(())
}

fn validate_record(record: &TransientEffectAuditRecord) -> Result<(), TransientEffectAuditError> {
    for value in [
        record.principal.as_str(),
        record.operation_id.as_str(),
        record.plan_id.as_str(),
        record.request_id.as_str(),
        record.provider.as_str(),
        record.resource.as_str(),
        record.observation_capability.as_str(),
        record.policy_id.as_str(),
        record.policy_revision_id.as_str(),
        record.risk_classification_revision.as_str(),
        record.pre_effect_evidence_id.as_str(),
    ] {
        if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control)
        {
            return Err(audit_error(
                "transient audit field is outside bounded canonical form",
            ));
        }
    }
    for digest in [
        record.canonical_plan_sha256.as_str(),
        record.requested_postcondition_sha256.as_str(),
        record.audit_attempt_sha256.as_str(),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(audit_error(
                "transient audit digest is not lowercase SHA-256",
            ));
        }
    }
    if record.risk_rule_ids.len() > MAX_RISK_RULES
        || record.risk_rule_ids.iter().any(|rule| {
            rule.is_empty()
                || rule.len() > MAX_RISK_RULE_BYTES
                || rule.chars().any(char::is_control)
        })
    {
        return Err(audit_error(
            "transient audit risk-rule set is outside bounds",
        ));
    }
    if record
        .post_effect_evidence_id
        .as_ref()
        .is_some_and(|value| {
            value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control)
        })
    {
        return Err(audit_error(
            "transient audit post-effect evidence is invalid",
        ));
    }

    match record.disposition {
        TransientEffectAuditDisposition::AttemptReserved
        | TransientEffectAuditDisposition::NoChange
        | TransientEffectAuditDisposition::Verified
            if record.failure_code.is_some() =>
        {
            Err(audit_error(
                "successful transient audit disposition carries a failure code",
            ))
        }
        TransientEffectAuditDisposition::AttemptReserved
            if record.post_effect_evidence_id.is_some() =>
        {
            Err(audit_error(
                "transient audit reservation carries post-effect evidence",
            ))
        }
        TransientEffectAuditDisposition::Verified if record.post_effect_evidence_id.is_none() => {
            Err(audit_error(
                "verified transient audit is missing post-effect evidence",
            ))
        }
        TransientEffectAuditDisposition::NoChange if record.post_effect_evidence_id.is_some() => {
            Err(audit_error(
                "no-change transient audit unexpectedly carries post-effect evidence",
            ))
        }
        TransientEffectAuditDisposition::ExecutorFailed
        | TransientEffectAuditDisposition::PostEffectObservationFailed
        | TransientEffectAuditDisposition::VerificationFailed
            if record.failure_code.is_none() =>
        {
            Err(audit_error(
                "failed transient audit disposition is missing a failure code",
            ))
        }
        _ => Ok(()),
    }
}

fn require_capacity(transaction: &Transaction<'_>) -> Result<(), TransientEffectAuditError> {
    let count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM transient_effect_audit", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_audit_error)?;
    if count >= MAX_AUDIT_RECORDS {
        return Err(audit_error(
            "transient audit capacity exhausted; refusing unauditable dispatch",
        ));
    }
    Ok(())
}

fn insert_record(
    transaction: &Transaction<'_>,
    record: &TransientEffectAuditRecord,
) -> Result<(), TransientEffectAuditError> {
    transaction
        .execute(
            "INSERT INTO transient_effect_audit (
                audit_attempt_sha256, principal, operation_id, plan_id, request_id,
                provider, resource, observation_capability, risk, policy_id,
                policy_revision_id, policy_subject_risk, risk_classification_revision,
                risk_rule_ids, canonical_plan_sha256, requested_postcondition_sha256,
                pre_effect_evidence_id, post_effect_evidence_id, disposition, failure_code
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
             )",
            params![
                record.audit_attempt_sha256,
                record.principal,
                record.operation_id.as_str(),
                record.plan_id.as_str(),
                record.request_id.as_str(),
                record.provider.as_str(),
                record.resource.as_str(),
                record.observation_capability.as_str(),
                risk_name(record.risk),
                record.policy_id.as_str(),
                record.policy_revision_id.as_str(),
                risk_name(record.policy_subject_risk),
                record.risk_classification_revision,
                record.risk_rule_ids.join("\n"),
                record.canonical_plan_sha256,
                record.requested_postcondition_sha256,
                record.pre_effect_evidence_id,
                record.post_effect_evidence_id.as_deref(),
                disposition_name(record.disposition),
                record.failure_code.map(failure_name),
            ],
        )
        .map_err(sqlite_audit_error)?;
    Ok(())
}

fn load_record(
    transaction: &Transaction<'_>,
    attempt: &str,
) -> Result<Option<StoredAudit>, TransientEffectAuditError> {
    transaction
        .query_row(
            "SELECT principal, operation_id, plan_id, request_id, provider, resource,
                    observation_capability, risk, policy_id, policy_revision_id,
                    policy_subject_risk, risk_classification_revision, risk_rule_ids,
                    canonical_plan_sha256, requested_postcondition_sha256,
                    pre_effect_evidence_id, post_effect_evidence_id, disposition, failure_code
             FROM transient_effect_audit WHERE audit_attempt_sha256 = ?1",
            [attempt],
            |row| {
                let mut binding = Vec::with_capacity(16);
                for index in 0..16 {
                    binding.push(row.get(index)?);
                }
                Ok(StoredAudit {
                    binding,
                    post_effect_evidence_id: row.get(16)?,
                    disposition: row.get(17)?,
                    failure_code: row.get(18)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_audit_error)
}

fn require_same_binding(
    record: &TransientEffectAuditRecord,
    stored: &StoredAudit,
) -> Result<(), TransientEffectAuditError> {
    if stored.binding != record_binding(record) {
        return Err(audit_error(
            "transient audit attempt digest is bound to different authority material",
        ));
    }
    Ok(())
}

fn record_binding(record: &TransientEffectAuditRecord) -> Vec<String> {
    vec![
        record.principal.clone(),
        record.operation_id.as_str().to_owned(),
        record.plan_id.as_str().to_owned(),
        record.request_id.as_str().to_owned(),
        record.provider.as_str().to_owned(),
        record.resource.as_str().to_owned(),
        record.observation_capability.as_str().to_owned(),
        risk_name(record.risk).to_owned(),
        record.policy_id.as_str().to_owned(),
        record.policy_revision_id.as_str().to_owned(),
        risk_name(record.policy_subject_risk).to_owned(),
        record.risk_classification_revision.clone(),
        record.risk_rule_ids.join("\n"),
        record.canonical_plan_sha256.clone(),
        record.requested_postcondition_sha256.clone(),
        record.pre_effect_evidence_id.clone(),
    ]
}

const fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

const fn disposition_name(disposition: TransientEffectAuditDisposition) -> &'static str {
    match disposition {
        TransientEffectAuditDisposition::AttemptReserved => "attempt-reserved",
        TransientEffectAuditDisposition::NoChange => "no-change",
        TransientEffectAuditDisposition::Verified => "verified",
        TransientEffectAuditDisposition::ExecutorFailed => "executor-failed",
        TransientEffectAuditDisposition::PostEffectObservationFailed => {
            "post-effect-observation-failed"
        }
        TransientEffectAuditDisposition::VerificationFailed => "verification-failed",
    }
}

const fn failure_name(failure: TransientEffectAuditFailureCode) -> &'static str {
    match failure {
        TransientEffectAuditFailureCode::ExecutorFailed => "executor-failed",
        TransientEffectAuditFailureCode::PostEffectObservationFailed => {
            "post-effect-observation-failed"
        }
        TransientEffectAuditFailureCode::PostEffectEvidenceNotFresh => {
            "post-effect-evidence-not-fresh"
        }
        TransientEffectAuditFailureCode::PostEffectEvidenceNotAfterDispatch => {
            "post-effect-evidence-not-after-dispatch"
        }
        TransientEffectAuditFailureCode::PostEffectEvidenceReused => "post-effect-evidence-reused",
        TransientEffectAuditFailureCode::PostEffectBindingMismatch => {
            "post-effect-binding-mismatch"
        }
        TransientEffectAuditFailureCode::PostconditionMismatch => "postcondition-mismatch",
    }
}

fn audit_error(detail: impl Into<String>) -> TransientEffectAuditError {
    TransientEffectAuditError::new(detail)
}

fn sqlite_audit_error(error: rusqlite::Error) -> TransientEffectAuditError {
    TransientEffectAuditError::new(format!("transient SQLite audit failure: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        CapabilityId, OperationId, PlanId, PolicyId, PolicyRevisionId, ProviderId, RequestId,
        ResourceId,
    };

    fn test_record(disposition: TransientEffectAuditDisposition) -> TransientEffectAuditRecord {
        TransientEffectAuditRecord {
            principal: "unix:uid:1000".into(),
            operation_id: OperationId::new("operation:audio.output.set-session-volume")
                .unwrap_or_else(|error| unreachable!("{error}")),
            plan_id: PlanId::new("plan:test").unwrap_or_else(|error| unreachable!("{error}")),
            request_id: RequestId::new("request:test")
                .unwrap_or_else(|error| unreachable!("{error}")),
            provider: ProviderId::new("pipewire").unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new("audio:session:output:42")
                .unwrap_or_else(|error| unreachable!("{error}")),
            observation_capability: CapabilityId::new("audio.session.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            risk: RiskClass::UserState,
            policy_id: PolicyId::new("policy:baseline")
                .unwrap_or_else(|error| unreachable!("{error}")),
            policy_revision_id: PolicyRevisionId::new("policy:baseline:v1")
                .unwrap_or_else(|error| unreachable!("{error}")),
            policy_subject_risk: RiskClass::UserState,
            risk_classification_revision: "risk-policy:v0.10:registered-transient-refinement"
                .into(),
            risk_rule_ids: vec!["audio.session.output-state.user-state".into()],
            canonical_plan_sha256:
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            requested_postcondition_sha256:
                "2222222222222222222222222222222222222222222222222222222222222222".into(),
            audit_attempt_sha256:
                "3333333333333333333333333333333333333333333333333333333333333333".into(),
            pre_effect_evidence_id: "observation:pre".into(),
            post_effect_evidence_id: match disposition {
                TransientEffectAuditDisposition::Verified => Some("observation:post".into()),
                _ => None,
            },
            disposition,
            failure_code: None,
        }
    }

    fn temp_database() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linura-session-audit-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap_or_else(|error| unreachable!("{error}"));
        root.join("audit.sqlite3")
    }

    #[test]
    fn ineffective_wal_mode_fails_closed_before_audit_use() {
        let connection =
            Connection::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA trusted_schema = OFF;",
            )
            .unwrap_or_else(|error| unreachable!("{error}"));

        let Err(error) = verify_effective_sqlite_configuration(&connection) else {
            unreachable!("in-memory SQLite cannot satisfy the required WAL audit mode");
        };
        assert!(error.contains("journal_mode"));
        assert!(error.contains("WAL"));
    }

    #[test]
    fn opened_audit_store_uses_effective_wal_full_sync_and_hardened_schema_mode() {
        let path = temp_database();
        let audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));

        let journal_mode: String = audit
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let synchronous: i64 = audit
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let foreign_keys: i64 = audit
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let trusted_schema: i64 = audit
            .connection
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(trusted_schema, 0);

        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        drop(audit);
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn reservation_is_durable_and_terminal_finalization_is_idempotent() {
        let path = temp_database();
        let mut audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        let reservation = test_record(TransientEffectAuditDisposition::AttemptReserved);
        audit
            .reserve_attempt(&reservation)
            .unwrap_or_else(|error| unreachable!("{error}"));
        audit
            .reserve_attempt(&reservation)
            .unwrap_or_else(|error| unreachable!("{error}"));

        let terminal = test_record(TransientEffectAuditDisposition::Verified);
        audit
            .record_terminal(&terminal)
            .unwrap_or_else(|error| unreachable!("{error}"));
        audit
            .record_terminal(&terminal)
            .unwrap_or_else(|error| unreachable!("{error}"));

        drop(audit);
        let reopened =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        let stored = reopened
            .connection
            .query_row(
                "SELECT disposition, post_effect_evidence_id FROM transient_effect_audit",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(stored.0, "verified");
        assert_eq!(stored.1.as_deref(), Some("observation:post"));
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        drop(reopened);
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn schema_substitution_or_trigger_injection_fails_closed_on_reopen() {
        let path = temp_database();
        let audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        drop(audit);
        let connection = Connection::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        connection
            .execute_batch(
                "CREATE TRIGGER transient_effect_audit_drop
                 AFTER INSERT ON transient_effect_audit
                 BEGIN
                     DELETE FROM transient_effect_audit
                     WHERE audit_attempt_sha256 = NEW.audit_attempt_sha256;
                 END;",
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(connection);
        assert!(SqliteTransientAudit::open(&path).is_err());
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn hard_link_alias_is_rejected_before_sqlite_open() {
        let path = temp_database();
        let audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        drop(audit);
        let alias = path.with_file_name("audit-alias.sqlite3");
        fs::hard_link(&path, &alias).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(SqliteTransientAudit::open(&path).is_err());
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn oversized_database_is_rejected_before_sqlite_parsing() {
        let path = temp_database();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap_or_else(|error| unreachable!("{error}"));
        file.set_len(MAX_DATABASE_BYTES + 1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(file);
        assert!(SqliteTransientAudit::open(&path).is_err());
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn oversized_wal_sidecar_is_rejected_before_sqlite_open() {
        let path = temp_database();
        let audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        drop(audit);

        let wal_path = sqlite_sidecar_path(&path, "-wal");
        let wal = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&wal_path)
            .unwrap_or_else(|error| unreachable!("{error}"));
        wal.set_len(MAX_WAL_BYTES + 1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(wal);

        assert!(SqliteTransientAudit::open(&path).is_err());
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn terminal_without_reservation_fails_closed_except_no_change() {
        let path = temp_database();
        let mut audit =
            SqliteTransientAudit::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        let verified = test_record(TransientEffectAuditDisposition::Verified);
        assert!(audit.record_terminal(&verified).is_err());

        let no_change = test_record(TransientEffectAuditDisposition::NoChange);
        audit
            .record_terminal(&no_change)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let root = path
            .parent()
            .unwrap_or_else(|| unreachable!())
            .to_path_buf();
        drop(audit);
        fs::remove_dir_all(root).unwrap_or_else(|error| unreachable!("{error}"));
    }
}
