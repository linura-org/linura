use rusqlite::{Connection, params};

use crate::LibraryError;

pub const LIBRARY_SCHEMA_VERSION: u32 = 1;

const MAX_SCHEMA_OBJECTS: i64 = 128;
const MAX_SCHEMA_TYPE_BYTES: i64 = 32;
const MAX_SCHEMA_NAME_BYTES: i64 = 256;
const MAX_SCHEMA_SQL_BYTES: i64 = 64 * 1024;
const MAX_SCHEMA_AGGREGATE_SQL_BYTES: i64 = 1024 * 1024;

const SCHEMA_V1: &str = r#"
CREATE TABLE intent_revisions (
    intent_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_interactive INTEGER NOT NULL CHECK (actor_interactive IN (0, 1)),
    statement TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (intent_id, revision)
) STRICT;

CREATE TABLE intent_requirements (
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL,
    requirement_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    statement TEXT NOT NULL,
    PRIMARY KEY (intent_id, intent_revision, requirement_id),
    FOREIGN KEY (intent_id, intent_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE intent_supersedes (
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL,
    superseded_intent_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, intent_revision, superseded_intent_id),
    FOREIGN KEY (intent_id, intent_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE intents_current (
    intent_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision > 0),
    causal_generation INTEGER NOT NULL DEFAULT 0 CHECK (causal_generation >= 0),
    causal_complete INTEGER NOT NULL DEFAULT 0 CHECK (causal_complete IN (0, 1)),
    FOREIGN KEY (intent_id, revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE intent_transitions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    intent_id TEXT NOT NULL,
    from_revision INTEGER NOT NULL,
    to_revision INTEGER NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (intent_id, from_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id, to_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE library_operations (
    operation_id TEXT PRIMARY KEY,
    semantic_digest TEXT NOT NULL,
    result_kind TEXT NOT NULL,
    result_id TEXT NOT NULL,
    result_revision INTEGER NOT NULL CHECK (result_revision > 0)
) STRICT;

CREATE TABLE desired_resources (
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    provider_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    ownership_complete INTEGER NOT NULL CHECK (ownership_complete IN (0, 1)),
    PRIMARY KEY (
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id
    ),
    FOREIGN KEY (intent_id, intent_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE desired_resource_attributes (
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    provider_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id, key
    ),
    FOREIGN KEY (
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id
    ) REFERENCES desired_resources(
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE desired_resource_origins (
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    provider_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    origin_kind TEXT NOT NULL,
    origin_id TEXT NOT NULL,
    PRIMARY KEY (
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id, origin_kind, origin_id
    ),
    FOREIGN KEY (
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id
    ) REFERENCES desired_resources(
        intent_id, intent_revision, generation,
        provider_id, resource_id, capability_id
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE setup_revisions (
    setup_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (setup_id, revision)
) STRICT;

CREATE TABLE setup_intents (
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL,
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL CHECK (intent_revision > 0),
    PRIMARY KEY (setup_id, setup_revision, intent_id, intent_revision),
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id, intent_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE setup_includes (
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL,
    included_setup_id TEXT NOT NULL,
    included_revision INTEGER NOT NULL CHECK (included_revision > 0),
    PRIMARY KEY (
        setup_id, setup_revision, included_setup_id, included_revision
    ),
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (included_setup_id, included_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE setup_constraints (
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    value TEXT NOT NULL,
    PRIMARY KEY (setup_id, setup_revision, ordinal),
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE setup_secret_refs (
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    value TEXT NOT NULL,
    PRIMARY KEY (setup_id, setup_revision, ordinal),
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE setup_hardware_hints (
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    value TEXT NOT NULL,
    PRIMARY KEY (setup_id, setup_revision, ordinal),
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE profile_revisions (
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    name TEXT NOT NULL,
    machine_class TEXT NOT NULL,
    PRIMARY KEY (profile_id, revision)
) STRICT;

CREATE TABLE profile_setups (
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    setup_id TEXT NOT NULL,
    setup_revision INTEGER NOT NULL CHECK (setup_revision > 0),
    PRIMARY KEY (profile_id, profile_revision, setup_id, setup_revision),
    FOREIGN KEY (profile_id, profile_revision)
        REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (setup_id, setup_revision)
        REFERENCES setup_revisions(setup_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE profile_intents (
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    intent_id TEXT NOT NULL,
    intent_revision INTEGER NOT NULL CHECK (intent_revision > 0),
    PRIMARY KEY (profile_id, profile_revision, intent_id, intent_revision),
    FOREIGN KEY (profile_id, profile_revision)
        REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id, intent_revision)
        REFERENCES intent_revisions(intent_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE profile_constraints (
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    value TEXT NOT NULL,
    PRIMARY KEY (profile_id, profile_revision, ordinal),
    FOREIGN KEY (profile_id, profile_revision)
        REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE profile_hardware_hints (
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    value TEXT NOT NULL,
    PRIMARY KEY (profile_id, profile_revision, ordinal),
    FOREIGN KEY (profile_id, profile_revision)
        REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TABLE lifecycle_records (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload TEXT NOT NULL
) STRICT;

CREATE INDEX idx_desired_resource_current_lookup
    ON desired_resources(
        provider_id, resource_id, capability_id,
        intent_id, intent_revision, generation
    );
CREATE INDEX idx_setup_intents_intent ON setup_intents(intent_id, intent_revision);
CREATE INDEX idx_profile_intents_intent ON profile_intents(intent_id, intent_revision);
CREATE INDEX idx_lifecycle_entity ON lifecycle_records(entity_id, sequence);
"#;

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), LibraryError> {
    let found = read_schema_version(connection)?;
    if found > LIBRARY_SCHEMA_VERSION {
        return Err(LibraryError::UnsupportedSchema {
            found,
            supported: LIBRARY_SCHEMA_VERSION,
        });
    }
    if found == LIBRARY_SCHEMA_VERSION {
        return Ok(());
    }

    let transaction = connection.transaction()?;
    if found == 0 {
        transaction.execute_batch(SCHEMA_V1)?;
        transaction.pragma_update(None, "user_version", LIBRARY_SCHEMA_VERSION)?;
    }
    transaction.commit()?;
    Ok(())
}

pub(crate) fn read_schema_version(connection: &Connection) -> Result<u32, LibraryError> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == LIBRARY_SCHEMA_VERSION {
        validate_schema_v1(connection)?;
    }
    Ok(version)
}

fn validate_schema_v1(connection: &Connection) -> Result<(), LibraryError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA_V1)?;

    if schema_objects(connection)? != schema_objects(&expected)? {
        return Err(LibraryError::Corrupt(
            "installed Library schema does not match the canonical v1 schema".into(),
        ));
    }

    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        return Err(LibraryError::Corrupt(
            "Library foreign-key integrity check failed".into(),
        ));
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<Vec<(String, String, String, String)>, LibraryError> {
    let (object_count, maximum_sql_bytes, aggregate_sql_bytes): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), \
                    COALESCE(MAX(length(CAST(sql AS BLOB))), 0), \
                    COALESCE(SUM(length(CAST(sql AS BLOB))), 0) \
             FROM sqlite_schema \
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| {
            LibraryError::Corrupt(format!(
                "failed to preflight Library schema metadata: {error}"
            ))
        })?;
    if !(0..=MAX_SCHEMA_OBJECTS).contains(&object_count)
        || !(0..=MAX_SCHEMA_SQL_BYTES).contains(&maximum_sql_bytes)
        || !(0..=MAX_SCHEMA_AGGREGATE_SQL_BYTES).contains(&aggregate_sql_bytes)
    {
        return Err(LibraryError::Corrupt(
            "Library schema metadata exceeds validation bounds".into(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT \
            length(CAST(type AS BLOB)), \
            CASE WHEN length(CAST(type AS BLOB)) <= ?1 THEN type ELSE NULL END, \
            length(CAST(name AS BLOB)), \
            CASE WHEN length(CAST(name AS BLOB)) <= ?2 THEN name ELSE NULL END, \
            length(CAST(tbl_name AS BLOB)), \
            CASE WHEN length(CAST(tbl_name AS BLOB)) <= ?2 THEN tbl_name ELSE NULL END, \
            length(CAST(sql AS BLOB)), \
            CASE WHEN length(CAST(sql AS BLOB)) <= ?3 THEN sql ELSE NULL END \
         FROM sqlite_schema \
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' \
         ORDER BY type, name \
         LIMIT ?4",
    )?;
    let mut rows = statement.query(params![
        MAX_SCHEMA_TYPE_BYTES,
        MAX_SCHEMA_NAME_BYTES,
        MAX_SCHEMA_SQL_BYTES,
        MAX_SCHEMA_OBJECTS + 1
    ])?;
    let expected_count = usize::try_from(object_count)
        .map_err(|_| LibraryError::Corrupt("negative Library schema object count".into()))?;
    let mut objects = Vec::with_capacity(expected_count);
    let mut materialized_sql_bytes = 0_i64;
    while let Some(row) = rows.next()? {
        let type_bytes: i64 = row.get(0)?;
        let object_type: Option<String> = row.get(1)?;
        let name_bytes: i64 = row.get(2)?;
        let name: Option<String> = row.get(3)?;
        let table_name_bytes: i64 = row.get(4)?;
        let table_name: Option<String> = row.get(5)?;
        let sql_bytes: i64 = row.get(6)?;
        let sql: Option<String> = row.get(7)?;
        if !(0..=MAX_SCHEMA_TYPE_BYTES).contains(&type_bytes)
            || !(0..=MAX_SCHEMA_NAME_BYTES).contains(&name_bytes)
            || !(0..=MAX_SCHEMA_NAME_BYTES).contains(&table_name_bytes)
            || !(0..=MAX_SCHEMA_SQL_BYTES).contains(&sql_bytes)
        {
            return Err(LibraryError::Corrupt(
                "Library schema object exceeds validation bounds".into(),
            ));
        }
        materialized_sql_bytes = materialized_sql_bytes
            .checked_add(sql_bytes)
            .ok_or_else(|| LibraryError::Corrupt("Library schema byte count overflow".into()))?;
        if materialized_sql_bytes > MAX_SCHEMA_AGGREGATE_SQL_BYTES {
            return Err(LibraryError::Corrupt(
                "Library schema aggregate SQL exceeds validation bounds".into(),
            ));
        }
        objects.push((
            object_type.ok_or_else(|| {
                LibraryError::Corrupt("Library schema type withheld by length preflight".into())
            })?,
            name.ok_or_else(|| {
                LibraryError::Corrupt("Library schema name withheld by length preflight".into())
            })?,
            table_name.ok_or_else(|| {
                LibraryError::Corrupt(
                    "Library schema table name withheld by length preflight".into(),
                )
            })?,
            sql.ok_or_else(|| {
                LibraryError::Corrupt("Library schema SQL withheld by length preflight".into())
            })?,
        ));
        if objects.len() > usize::try_from(MAX_SCHEMA_OBJECTS).unwrap_or(usize::MAX) {
            return Err(LibraryError::Corrupt(
                "Library schema object count exceeds validation bounds".into(),
            ));
        }
    }
    if objects.len() != expected_count {
        return Err(LibraryError::Corrupt(
            "Library schema changed during validation".into(),
        ));
    }
    Ok(objects)
}
