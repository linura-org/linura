use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use linura_core::{
    Actor, ActorId, ActorKind, CapabilityId, IntentId, ProfileId, ProviderId, RequestId,
    RequirementId, ResourceId, SetupId, ValidationError,
};
use linura_intent::{
    Intent, IntentStatus, MachineClass, MachineProfile, Requirement, RequirementKind, Setup,
};
use linura_planner::DesiredState;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::portable::{PORTABLE_FORMAT_VERSION, PortableProfileBundle, PortableSetupBundle};
use crate::schema::{self, LIBRARY_SCHEMA_VERSION};
use crate::{
    IntentRevisionRef, IntentTransition, LibraryError, LifecycleRecord, LifecycleRecordKind,
    ManagedResourceIdentity, RemovalImpactReport, SetupRevisionRef, StoredIntent, StoredProfile,
    StoredSetup,
};

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_COLLECTION_ITEMS: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibrarySettings {
    pub busy_timeout_ms: u64,
}

impl Default for LibrarySettings {
    fn default() -> Self {
        Self {
            busy_timeout_ms: 5_000,
        }
    }
}

#[derive(Debug)]
pub struct LocalLibrary {
    pub(crate) connection: Connection,
    path: Option<PathBuf>,
}

impl LocalLibrary {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LibraryError> {
        Self::open_with_settings(path, LibrarySettings::default())
    }

    pub fn open_with_settings(
        path: impl AsRef<Path>,
        settings: LibrarySettings,
    ) -> Result<Self, LibraryError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut connection = Connection::open(&path)?;
        configure_writable(&connection, settings)?;
        integrity_check_connection(&connection)?;
        schema::migrate(&mut connection)?;
        integrity_check_connection(&connection)?;
        Ok(Self {
            connection,
            path: Some(path),
        })
    }

    pub fn open_in_memory() -> Result<Self, LibraryError> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        schema::migrate(&mut connection)?;
        integrity_check_connection(&connection)?;
        Ok(Self {
            connection,
            path: None,
        })
    }

    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn schema_version(&self) -> Result<u32, LibraryError> {
        schema::read_schema_version(&self.connection)
    }

    pub fn integrity_check(&self) -> Result<(), LibraryError> {
        integrity_check_connection(&self.connection)
    }

    pub fn create_intent(
        &mut self,
        operation_id: &RequestId,
        intent: &Intent,
    ) -> Result<StoredIntent, LibraryError> {
        validate_new_intent(intent)?;
        let digest = intent_operation_digest("create-intent", intent, &[]);
        let transaction = self.connection.transaction()?;
        if let Some((result_id, result_revision)) =
            replay_operation(&transaction, operation_id, &digest, "intent")?
        {
            let id = IntentId::new(result_id).map_err(validation_error)?;
            return load_intent_revision(&transaction, &id, result_revision);
        }
        if current_intent_state(&transaction, &intent.id)?.is_some() {
            return Err(LibraryError::AlreadyExists {
                kind: "intent",
                id: intent.id.as_str().into(),
            });
        }
        insert_intent_revision(&transaction, intent, 1)?;
        transaction.execute(
            "INSERT INTO intents_current(intent_id, revision, causal_generation, causal_complete) VALUES (?1, 1, 0, 0)",
            params![intent.id.as_str()],
        )?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "intent",
            intent.id.as_str(),
            1,
        )?;
        transaction.commit()?;
        load_intent_revision(&self.connection, &intent.id, 1)
    }

    pub fn intent(&self, id: &IntentId) -> Result<StoredIntent, LibraryError> {
        let (revision, _, _) =
            current_intent_state(&self.connection, id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "intent",
                id: id.as_str().into(),
            })?;
        load_intent_revision(&self.connection, id, revision)
    }

    pub fn intent_revision(
        &self,
        id: &IntentId,
        revision: u64,
    ) -> Result<StoredIntent, LibraryError> {
        load_intent_revision(&self.connection, id, revision)
    }

    pub fn intent_history(&self, id: &IntentId) -> Result<Vec<StoredIntent>, LibraryError> {
        let mut statement = self.connection.prepare(
            "SELECT revision FROM intent_revisions WHERE intent_id = ?1 ORDER BY revision",
        )?;
        let revisions = statement
            .query_map(params![id.as_str()], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if revisions.is_empty() {
            return Err(LibraryError::NotFound {
                kind: "intent",
                id: id.as_str().into(),
            });
        }
        revisions
            .into_iter()
            .map(|revision| {
                load_intent_revision(&self.connection, id, to_u64(revision, "intent revision")?)
            })
            .collect()
    }

    pub fn list_intents(&self) -> Result<Vec<StoredIntent>, LibraryError> {
        let mut statement = self
            .connection
            .prepare("SELECT intent_id, revision FROM intents_current ORDER BY intent_id")?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(id, revision)| {
                let id = IntentId::new(id).map_err(validation_error)?;
                load_intent_revision(&self.connection, &id, to_u64(revision, "intent revision")?)
            })
            .collect()
    }

    pub fn transition_intent(
        &mut self,
        operation_id: &RequestId,
        id: &IntentId,
        expected_revision: u64,
        transition: IntentTransition,
    ) -> Result<StoredIntent, LibraryError> {
        let digest = digest_fields(&[
            "transition-intent",
            operation_id.as_str(),
            id.as_str(),
            &expected_revision.to_string(),
            transition.as_str(),
        ]);
        let transaction = self.connection.transaction()?;
        if let Some((result_id, result_revision)) =
            replay_operation(&transaction, operation_id, &digest, "intent")?
        {
            let result_id = IntentId::new(result_id).map_err(validation_error)?;
            return load_intent_revision(&transaction, &result_id, result_revision);
        }
        let (actual_revision, causal_generation, causal_complete) =
            current_intent_state(&transaction, id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "intent",
                id: id.as_str().into(),
            })?;
        ensure_revision(expected_revision, actual_revision)?;
        let current = load_intent_revision(&transaction, id, actual_revision)?;
        let next_status = transition_status(current.intent.status, transition)?;
        let next_revision = actual_revision
            .checked_add(1)
            .ok_or_else(|| LibraryError::Validation("intent revision overflow".into()))?;
        let mut next = current.intent.clone();
        next.status = next_status;
        insert_intent_revision(&transaction, &next, next_revision)?;
        let (new_generation, new_complete) = copy_current_causal_state(
            &transaction,
            id,
            actual_revision,
            next_revision,
            causal_generation,
            causal_complete,
        )?;
        transaction.execute(
            "UPDATE intents_current SET revision = ?2, causal_generation = ?3, causal_complete = ?4 WHERE intent_id = ?1",
            params![
                id.as_str(),
                to_i64(next_revision, "intent revision")?,
                to_i64(new_generation, "causal generation")?,
                bool_i64(new_complete)
            ],
        )?;
        transaction.execute(
            "INSERT INTO intent_transitions(intent_id, from_revision, to_revision, from_status, to_status, operation_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.as_str(),
                to_i64(actual_revision, "intent revision")?,
                to_i64(next_revision, "intent revision")?,
                intent_status_str(current.intent.status),
                intent_status_str(next_status),
                operation_id.as_str()
            ],
        )?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "intent",
            id.as_str(),
            next_revision,
        )?;
        transaction.commit()?;
        load_intent_revision(&self.connection, id, next_revision)
    }

    pub fn supersede_intent(
        &mut self,
        operation_id: &RequestId,
        old_id: &IntentId,
        expected_revision: u64,
        successor: &Intent,
    ) -> Result<(StoredIntent, StoredIntent), LibraryError> {
        validate_new_intent(successor)?;
        if !successor
            .supersedes
            .iter()
            .any(|candidate| candidate == old_id)
        {
            return Err(LibraryError::Validation(format!(
                "successor {} must explicitly retain supersession lineage to {}",
                successor.id.as_str(),
                old_id.as_str()
            )));
        }
        let digest = intent_operation_digest(
            "supersede-intent",
            successor,
            &[old_id.as_str(), &expected_revision.to_string()],
        );
        let transaction = self.connection.transaction()?;
        if let Some((result_id, result_revision)) =
            replay_operation(&transaction, operation_id, &digest, "intent")?
        {
            let successor_id = IntentId::new(result_id).map_err(validation_error)?;
            let successor_result =
                load_intent_revision(&transaction, &successor_id, result_revision)?;
            let old_revision: i64 = transaction.query_row(
                "SELECT to_revision FROM intent_transitions WHERE operation_id = ?1 AND intent_id = ?2",
                params![operation_id.as_str(), old_id.as_str()],
                |row| row.get(0),
            )?;
            let old_result = load_intent_revision(
                &transaction,
                old_id,
                to_u64(old_revision, "intent revision")?,
            )?;
            return Ok((old_result, successor_result));
        }
        if current_intent_state(&transaction, &successor.id)?.is_some() {
            return Err(LibraryError::AlreadyExists {
                kind: "successor intent",
                id: successor.id.as_str().into(),
            });
        }
        let (actual_revision, causal_generation, causal_complete) =
            current_intent_state(&transaction, old_id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "intent",
                id: old_id.as_str().into(),
            })?;
        ensure_revision(expected_revision, actual_revision)?;
        let old = load_intent_revision(&transaction, old_id, actual_revision)?;
        if matches!(
            old.intent.status,
            IntentStatus::Superseded | IntentStatus::Retired
        ) {
            return Err(LibraryError::InvalidTransition {
                from: intent_status_str(old.intent.status).into(),
                operation: "supersede".into(),
            });
        }
        let old_next_revision = actual_revision
            .checked_add(1)
            .ok_or_else(|| LibraryError::Validation("intent revision overflow".into()))?;
        let mut old_next = old.intent.clone();
        old_next.status = IntentStatus::Superseded;
        insert_intent_revision(&transaction, &old_next, old_next_revision)?;
        let (new_generation, new_complete) = copy_current_causal_state(
            &transaction,
            old_id,
            actual_revision,
            old_next_revision,
            causal_generation,
            causal_complete,
        )?;
        transaction.execute(
            "UPDATE intents_current SET revision = ?2, causal_generation = ?3, causal_complete = ?4 WHERE intent_id = ?1",
            params![
                old_id.as_str(),
                to_i64(old_next_revision, "intent revision")?,
                to_i64(new_generation, "causal generation")?,
                bool_i64(new_complete)
            ],
        )?;
        insert_intent_revision(&transaction, successor, 1)?;
        transaction.execute(
            "INSERT INTO intents_current(intent_id, revision, causal_generation, causal_complete) VALUES (?1, 1, 0, 0)",
            params![successor.id.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO intent_transitions(intent_id, from_revision, to_revision, from_status, to_status, operation_id) VALUES (?1, ?2, ?3, ?4, 'superseded', ?5)",
            params![
                old_id.as_str(),
                to_i64(actual_revision, "intent revision")?,
                to_i64(old_next_revision, "intent revision")?,
                intent_status_str(old.intent.status),
                operation_id.as_str()
            ],
        )?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "intent",
            successor.id.as_str(),
            1,
        )?;
        transaction.commit()?;
        Ok((
            load_intent_revision(&self.connection, old_id, old_next_revision)?,
            load_intent_revision(&self.connection, &successor.id, 1)?,
        ))
    }

    pub fn record_desired_state(
        &mut self,
        intent_id: &IntentId,
        expected_intent_revision: u64,
        desired_state: &DesiredState,
        ownership_complete: bool,
    ) -> Result<u64, LibraryError> {
        desired_state
            .validate()
            .map_err(|error| LibraryError::Validation(error.to_string()))?;
        for desired in &desired_state.resources {
            if !desired.reason.intent_ids.iter().any(|id| id == intent_id) {
                return Err(LibraryError::Validation(format!(
                    "desired resource {} does not retain owning intent {} in semantic provenance",
                    desired.resource.as_str(),
                    intent_id.as_str()
                )));
            }
        }
        let transaction = self.connection.transaction()?;
        let (actual_revision, current_generation, _) =
            current_intent_state(&transaction, intent_id)?.ok_or_else(|| {
                LibraryError::NotFound {
                    kind: "intent",
                    id: intent_id.as_str().into(),
                }
            })?;
        ensure_revision(expected_intent_revision, actual_revision)?;
        let generation = current_generation
            .checked_add(1)
            .ok_or_else(|| LibraryError::Validation("causal generation overflow".into()))?;
        for desired in &desired_state.resources {
            transaction.execute(
                "INSERT INTO desired_resources(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, ownership_complete) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    intent_id.as_str(),
                    to_i64(actual_revision, "intent revision")?,
                    to_i64(generation, "causal generation")?,
                    desired.provider.as_str(),
                    desired.resource.as_str(),
                    desired.observation_capability.as_str(),
                    bool_i64(ownership_complete)
                ],
            )?;
            for (key, value) in &desired.state {
                validate_text("desired-state key", key, 256)?;
                validate_text("desired-state value", value, 4_096)?;
                transaction.execute(
                    "INSERT INTO desired_resource_attributes(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, key, value) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        intent_id.as_str(),
                        to_i64(actual_revision, "intent revision")?,
                        to_i64(generation, "causal generation")?,
                        desired.provider.as_str(),
                        desired.resource.as_str(),
                        desired.observation_capability.as_str(),
                        key,
                        value
                    ],
                )?;
            }
            for origin in &desired.reason.intent_ids {
                insert_desired_origin(
                    &transaction,
                    intent_id,
                    actual_revision,
                    generation,
                    desired.provider.as_str(),
                    desired.resource.as_str(),
                    desired.observation_capability.as_str(),
                    "intent",
                    origin.as_str(),
                )?;
            }
            for origin in &desired.reason.requirement_ids {
                insert_desired_origin(
                    &transaction,
                    intent_id,
                    actual_revision,
                    generation,
                    desired.provider.as_str(),
                    desired.resource.as_str(),
                    desired.observation_capability.as_str(),
                    "requirement",
                    origin.as_str(),
                )?;
            }
            for origin in &desired.reason.capability_ids {
                insert_desired_origin(
                    &transaction,
                    intent_id,
                    actual_revision,
                    generation,
                    desired.provider.as_str(),
                    desired.resource.as_str(),
                    desired.observation_capability.as_str(),
                    "capability",
                    origin.as_str(),
                )?;
            }
        }
        transaction.execute(
            "UPDATE intents_current SET causal_generation = ?2, causal_complete = ?3 WHERE intent_id = ?1",
            params![intent_id.as_str(), to_i64(generation, "causal generation")?, bool_i64(ownership_complete)],
        )?;
        let payload = format!(
            "intent={} revision={} generation={} resources={} ownership_complete={}",
            intent_id.as_str(),
            actual_revision,
            generation,
            desired_state.resources.len(),
            ownership_complete
        );
        append_lifecycle_record_tx(
            &transaction,
            LifecycleRecordKind::DesiredState,
            intent_id.as_str(),
            &payload,
        )?;
        transaction.commit()?;
        Ok(generation)
    }

    pub fn removal_impact(
        &self,
        intent_id: &IntentId,
    ) -> Result<RemovalImpactReport, LibraryError> {
        let (revision, generation, complete) = current_intent_state(&self.connection, intent_id)?
            .ok_or_else(|| LibraryError::NotFound {
            kind: "intent",
            id: intent_id.as_str().into(),
        })?;
        if generation == 0 {
            return Ok(RemovalImpactReport::default());
        }
        let resources =
            desired_resource_identities(&self.connection, intent_id, revision, generation)?;
        let incomplete_active_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM intents_current c JOIN intent_revisions r ON r.intent_id = c.intent_id AND r.revision = c.revision WHERE r.status = 'active' AND c.causal_complete = 0",
            [],
            |row| row.get(0),
        )?;
        let global_complete = incomplete_active_count == 0;
        let mut report = RemovalImpactReport::default();
        for identity in resources {
            if !complete || !global_complete {
                report.indeterminate.insert(identity);
                continue;
            }
            let other_active: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM desired_resources d JOIN intents_current c ON c.intent_id = d.intent_id AND c.revision = d.intent_revision AND c.causal_generation = d.generation JOIN intent_revisions r ON r.intent_id = c.intent_id AND r.revision = c.revision WHERE d.provider_id = ?1 AND d.resource_id = ?2 AND d.capability_id = ?3 AND d.intent_id <> ?4 AND r.status = 'active' AND c.causal_complete = 1",
                params![
                    identity.provider.as_str(),
                    identity.resource.as_str(),
                    identity.capability.as_str(),
                    intent_id.as_str()
                ],
                |row| row.get(0),
            )?;
            if other_active > 0 {
                report.retained_shared.insert(identity);
            } else {
                report.removable.insert(identity);
            }
        }
        Ok(report)
    }

    pub fn save_setup(
        &mut self,
        operation_id: &RequestId,
        setup: &Setup,
        expected_previous_revision: Option<u32>,
    ) -> Result<StoredSetup, LibraryError> {
        setup
            .validate()
            .map_err(|error| LibraryError::Validation(format!("invalid setup: {error:?}")))?;
        validate_collection_size("setup intents", setup.intent_ids.len())?;
        validate_collection_size("included setups", setup.included_setup_ids.len())?;
        let digest = setup_operation_digest(setup, expected_previous_revision);
        let transaction = self.connection.transaction()?;
        if let Some((result_id, result_revision)) =
            replay_operation(&transaction, operation_id, &digest, "setup")?
        {
            let id = SetupId::new(result_id).map_err(validation_error)?;
            return load_setup_revision(
                &transaction,
                &id,
                to_u32(result_revision, "setup revision")?,
            );
        }
        let current = latest_setup_revision(&transaction, &setup.id)?;
        validate_next_revision(
            expected_previous_revision.map(u64::from),
            current.map(u64::from),
            u64::from(setup.revision),
            "setup",
        )?;
        let intent_refs = resolve_current_intents(&transaction, &setup.intent_ids)?;
        let include_refs = resolve_current_setups(&transaction, &setup.included_setup_ids)?;
        for included in &include_refs {
            if setup_revision_reaches(&transaction, &included.id, included.revision, &setup.id)? {
                return Err(LibraryError::Validation(format!(
                    "setup composition cycle reaches {} through {}@{}",
                    setup.id.as_str(),
                    included.id.as_str(),
                    included.revision
                )));
            }
        }
        insert_setup_revision(&transaction, setup, &intent_refs, &include_refs)?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "setup",
            setup.id.as_str(),
            u64::from(setup.revision),
        )?;
        transaction.commit()?;
        load_setup_revision(&self.connection, &setup.id, setup.revision)
    }

    pub fn setup(&self, id: &SetupId) -> Result<StoredSetup, LibraryError> {
        let revision =
            latest_setup_revision(&self.connection, id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "setup",
                id: id.as_str().into(),
            })?;
        load_setup_revision(&self.connection, id, revision)
    }

    pub fn setup_revision(&self, id: &SetupId, revision: u32) -> Result<StoredSetup, LibraryError> {
        load_setup_revision(&self.connection, id, revision)
    }

    pub fn setup_history(&self, id: &SetupId) -> Result<Vec<StoredSetup>, LibraryError> {
        let mut statement = self.connection.prepare(
            "SELECT revision FROM setup_revisions WHERE setup_id = ?1 ORDER BY revision",
        )?;
        let revisions = statement
            .query_map(params![id.as_str()], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if revisions.is_empty() {
            return Err(LibraryError::NotFound {
                kind: "setup",
                id: id.as_str().into(),
            });
        }
        revisions
            .into_iter()
            .map(|revision| {
                load_setup_revision(
                    &self.connection,
                    id,
                    to_u32(to_u64(revision, "setup revision")?, "setup revision")?,
                )
            })
            .collect()
    }

    pub fn list_setups(&self) -> Result<Vec<StoredSetup>, LibraryError> {
        let mut statement = self.connection.prepare(
            "SELECT setup_id, MAX(revision) FROM setup_revisions GROUP BY setup_id ORDER BY setup_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(id, revision)| {
                let id = SetupId::new(id).map_err(validation_error)?;
                load_setup_revision(
                    &self.connection,
                    &id,
                    to_u32(to_u64(revision, "setup revision")?, "setup revision")?,
                )
            })
            .collect()
    }

    pub fn save_profile(
        &mut self,
        operation_id: &RequestId,
        profile: &MachineProfile,
        revision: u32,
        expected_previous_revision: Option<u32>,
    ) -> Result<StoredProfile, LibraryError> {
        validate_profile(profile, revision)?;
        let digest = profile_operation_digest(profile, revision, expected_previous_revision);
        let transaction = self.connection.transaction()?;
        if let Some((result_id, result_revision)) =
            replay_operation(&transaction, operation_id, &digest, "profile")?
        {
            let id = ProfileId::new(result_id).map_err(validation_error)?;
            return load_profile_revision(
                &transaction,
                &id,
                to_u32(result_revision, "profile revision")?,
            );
        }
        let current = latest_profile_revision(&transaction, &profile.id)?;
        validate_next_revision(
            expected_previous_revision.map(u64::from),
            current.map(u64::from),
            u64::from(revision),
            "profile",
        )?;
        let intent_refs = resolve_current_intents(&transaction, &profile.intent_ids)?;
        let setup_refs = resolve_current_setups(&transaction, &profile.setup_ids)?;
        insert_profile_revision(&transaction, profile, revision, &intent_refs, &setup_refs)?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "profile",
            profile.id.as_str(),
            u64::from(revision),
        )?;
        transaction.commit()?;
        load_profile_revision(&self.connection, &profile.id, revision)
    }

    pub fn profile(&self, id: &ProfileId) -> Result<StoredProfile, LibraryError> {
        let revision = latest_profile_revision(&self.connection, id)?.ok_or_else(|| {
            LibraryError::NotFound {
                kind: "profile",
                id: id.as_str().into(),
            }
        })?;
        load_profile_revision(&self.connection, id, revision)
    }

    pub fn profile_revision(
        &self,
        id: &ProfileId,
        revision: u32,
    ) -> Result<StoredProfile, LibraryError> {
        load_profile_revision(&self.connection, id, revision)
    }

    pub fn profile_history(&self, id: &ProfileId) -> Result<Vec<StoredProfile>, LibraryError> {
        let mut statement = self.connection.prepare(
            "SELECT revision FROM profile_revisions WHERE profile_id = ?1 ORDER BY revision",
        )?;
        let revisions = statement
            .query_map(params![id.as_str()], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if revisions.is_empty() {
            return Err(LibraryError::NotFound {
                kind: "profile",
                id: id.as_str().into(),
            });
        }
        revisions
            .into_iter()
            .map(|revision| {
                load_profile_revision(
                    &self.connection,
                    id,
                    to_u32(to_u64(revision, "profile revision")?, "profile revision")?,
                )
            })
            .collect()
    }

    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>, LibraryError> {
        let mut statement = self.connection.prepare(
            "SELECT profile_id, MAX(revision) FROM profile_revisions GROUP BY profile_id ORDER BY profile_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(id, revision)| {
                let id = ProfileId::new(id).map_err(validation_error)?;
                load_profile_revision(
                    &self.connection,
                    &id,
                    to_u32(to_u64(revision, "profile revision")?, "profile revision")?,
                )
            })
            .collect()
    }

    pub fn append_lifecycle_record(
        &mut self,
        kind: LifecycleRecordKind,
        entity_id: &str,
        payload: &str,
    ) -> Result<LifecycleRecord, LibraryError> {
        let transaction = self.connection.transaction()?;
        let record = append_lifecycle_record_tx(&transaction, kind, entity_id, payload)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn lifecycle_records(&self, entity_id: &str) -> Result<Vec<LifecycleRecord>, LibraryError> {
        validate_text("lifecycle entity id", entity_id, 256)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence, record_kind, entity_id, content_digest, payload FROM lifecycle_records WHERE entity_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement
            .query_map(params![entity_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(sequence, kind, entity_id, content_digest, payload)| {
                Ok(LifecycleRecord {
                    sequence: to_u64(sequence, "lifecycle sequence")?,
                    kind: parse_lifecycle_kind(&kind)?,
                    entity_id,
                    content_digest,
                    payload,
                })
            })
            .collect()
    }

    pub fn export_setup(
        &self,
        id: &SetupId,
        revision: Option<u32>,
    ) -> Result<PortableSetupBundle, LibraryError> {
        let root_revision = match revision {
            Some(value) => value,
            None => latest_setup_revision(&self.connection, id)?.ok_or_else(|| {
                LibraryError::NotFound {
                    kind: "setup",
                    id: id.as_str().into(),
                }
            })?,
        };
        let root = SetupRevisionRef {
            id: id.clone(),
            revision: root_revision,
        };
        let (setups, intents) = collect_setup_closure(&self.connection, &root)?;
        Ok(PortableSetupBundle {
            format_version: PORTABLE_FORMAT_VERSION,
            root,
            setups,
            intents,
        })
    }

    pub fn export_profile(
        &self,
        id: &ProfileId,
        revision: Option<u32>,
    ) -> Result<PortableProfileBundle, LibraryError> {
        let revision = match revision {
            Some(value) => value,
            None => latest_profile_revision(&self.connection, id)?.ok_or_else(|| {
                LibraryError::NotFound {
                    kind: "profile",
                    id: id.as_str().into(),
                }
            })?,
        };
        let profile = load_profile_revision(&self.connection, id, revision)?;
        let mut setup_map = BTreeMap::new();
        let mut intent_map = BTreeMap::new();
        for intent_ref in &profile.intent_revisions {
            let stored =
                load_intent_revision(&self.connection, &intent_ref.id, intent_ref.revision)?;
            intent_map.insert(
                (intent_ref.id.as_str().to_owned(), intent_ref.revision),
                stored,
            );
        }
        for setup_ref in &profile.setup_revisions {
            let (setups, intents) = collect_setup_closure(&self.connection, setup_ref)?;
            for setup in setups {
                setup_map.insert(
                    (setup.setup.id.as_str().to_owned(), setup.setup.revision),
                    setup,
                );
            }
            for intent in intents {
                intent_map.insert(
                    (intent.intent.id.as_str().to_owned(), intent.revision),
                    intent,
                );
            }
        }
        Ok(PortableProfileBundle {
            format_version: PORTABLE_FORMAT_VERSION,
            profile,
            setups: setup_map.into_values().collect(),
            intents: intent_map.into_values().collect(),
        })
    }

    pub fn backup_to(&mut self, destination: impl AsRef<Path>) -> Result<(), LibraryError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(LibraryError::AlreadyExists {
                kind: "backup file",
                id: destination.display().to_string(),
            });
        }
        if self.path.is_none() {
            return Err(LibraryError::Validation(
                "in-memory Library cannot produce a filesystem backup".into(),
            ));
        }
        self.integrity_check()?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        let quoted = sql_string_literal(destination)?;
        self.connection
            .execute_batch(&format!("VACUUM INTO {quoted};"))?;
        validate_database_file(destination)?;
        let file = OpenOptions::new().read(true).open(destination)?;
        file.sync_all()?;
        sync_parent(destination)?;
        Ok(())
    }
}

pub(crate) fn validate_database_file(path: &Path) -> Result<(), LibraryError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    integrity_check_connection(&connection)?;
    let version = schema::read_schema_version(&connection)?;
    if version > LIBRARY_SCHEMA_VERSION {
        return Err(LibraryError::UnsupportedSchema {
            found: version,
            supported: LIBRARY_SCHEMA_VERSION,
        });
    }
    if version == 0 {
        return Err(LibraryError::Corrupt(
            "backup does not contain an initialized Linura Library schema".into(),
        ));
    }
    Ok(())
}

pub(crate) fn restore_database_file(backup: &Path, destination: &Path) -> Result<(), LibraryError> {
    validate_database_file(backup)?;
    if backup == destination {
        return Err(LibraryError::Validation(
            "backup and restore destination must be different files".into(),
        ));
    }
    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| LibraryError::Validation("invalid restore destination filename".into()))?;
    let temporary = destination.with_file_name(format!(".{file_name}.restore.tmp"));
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    fs::copy(backup, &temporary)?;
    let copied = OpenOptions::new().read(true).write(true).open(&temporary)?;
    copied.sync_all()?;
    drop(copied);
    validate_database_file(&temporary)?;
    fs::rename(&temporary, destination)?;
    sync_parent(destination)?;
    validate_database_file(destination)
}

fn configure_writable(
    connection: &Connection,
    settings: LibrarySettings,
) -> Result<(), LibraryError> {
    connection.busy_timeout(Duration::from_millis(settings.busy_timeout_ms))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 1_000_u32)?;
    Ok(())
}

fn integrity_check_connection(connection: &Connection) -> Result<(), LibraryError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(LibraryError::Corrupt(result))
    }
}

fn validate_new_intent(intent: &Intent) -> Result<(), LibraryError> {
    validate_text("intent statement", &intent.statement, MAX_TEXT_BYTES)?;
    if !matches!(intent.status, IntentStatus::Proposed | IntentStatus::Active) {
        return Err(LibraryError::Validation(format!(
            "new intent {} must start proposed or active",
            intent.id.as_str()
        )));
    }
    validate_collection_size("intent requirements", intent.requirements.len())?;
    validate_collection_size("intent supersedes", intent.supersedes.len())?;
    let mut requirements = BTreeSet::new();
    for requirement in &intent.requirements {
        if !requirements.insert(requirement.id.clone()) {
            return Err(LibraryError::Validation(format!(
                "duplicate requirement {}",
                requirement.id.as_str()
            )));
        }
        validate_text(
            "requirement statement",
            &requirement.statement,
            MAX_TEXT_BYTES,
        )?;
    }
    let mut supersedes = BTreeSet::new();
    for predecessor in &intent.supersedes {
        if predecessor == &intent.id {
            return Err(LibraryError::Validation(
                "intent cannot supersede itself".into(),
            ));
        }
        if !supersedes.insert(predecessor.clone()) {
            return Err(LibraryError::Validation(format!(
                "duplicate superseded intent {}",
                predecessor.as_str()
            )));
        }
    }
    Ok(())
}

pub(crate) fn insert_intent_revision(
    transaction: &Transaction<'_>,
    intent: &Intent,
    revision: u64,
) -> Result<(), LibraryError> {
    validate_text("intent statement", &intent.statement, MAX_TEXT_BYTES)?;
    transaction.execute(
        "INSERT INTO intent_revisions(intent_id, revision, actor_id, actor_kind, actor_interactive, statement, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            intent.id.as_str(),
            to_i64(revision, "intent revision")?,
            intent.actor.id.as_str(),
            actor_kind_str(intent.actor.kind),
            bool_i64(intent.actor.interactive),
            &intent.statement,
            intent_status_str(intent.status)
        ],
    )?;
    let mut requirement_ids = BTreeSet::new();
    for requirement in &intent.requirements {
        if !requirement_ids.insert(requirement.id.clone()) {
            return Err(LibraryError::Validation(format!(
                "duplicate requirement {}",
                requirement.id.as_str()
            )));
        }
        validate_text(
            "requirement statement",
            &requirement.statement,
            MAX_TEXT_BYTES,
        )?;
        transaction.execute(
            "INSERT INTO intent_requirements(intent_id, intent_revision, requirement_id, kind, statement) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.id.as_str(),
                to_i64(revision, "intent revision")?,
                requirement.id.as_str(),
                requirement_kind_str(requirement.kind),
                &requirement.statement
            ],
        )?;
    }
    let mut predecessors = BTreeSet::new();
    for predecessor in &intent.supersedes {
        if predecessor == &intent.id || !predecessors.insert(predecessor.clone()) {
            return Err(LibraryError::Validation(
                "invalid duplicate/self supersession lineage".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO intent_supersedes(intent_id, intent_revision, superseded_intent_id) VALUES (?1, ?2, ?3)",
            params![
                intent.id.as_str(),
                to_i64(revision, "intent revision")?,
                predecessor.as_str()
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn load_intent_revision(
    connection: &Connection,
    id: &IntentId,
    revision: u64,
) -> Result<StoredIntent, LibraryError> {
    let row = connection
        .query_row(
            "SELECT actor_id, actor_kind, actor_interactive, statement, status FROM intent_revisions WHERE intent_id = ?1 AND revision = ?2",
            params![id.as_str(), to_i64(revision, "intent revision")?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LibraryError::NotFound {
            kind: "intent revision",
            id: format!("{}@{revision}", id.as_str()),
        })?;
    let mut requirements_statement = connection.prepare(
        "SELECT requirement_id, kind, statement FROM intent_requirements WHERE intent_id = ?1 AND intent_revision = ?2 ORDER BY requirement_id",
    )?;
    let requirement_rows = requirements_statement
        .query_map(
            params![id.as_str(), to_i64(revision, "intent revision")?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let requirements = requirement_rows
        .into_iter()
        .map(|(requirement_id, kind, statement)| {
            Ok(Requirement {
                id: RequirementId::new(requirement_id).map_err(validation_error)?,
                kind: parse_requirement_kind(&kind)?,
                statement,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    let mut supersedes_statement = connection.prepare(
        "SELECT superseded_intent_id FROM intent_supersedes WHERE intent_id = ?1 AND intent_revision = ?2 ORDER BY superseded_intent_id",
    )?;
    let superseded_rows = supersedes_statement
        .query_map(
            params![id.as_str(), to_i64(revision, "intent revision")?],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let supersedes = superseded_rows
        .into_iter()
        .map(|value| IntentId::new(value).map_err(validation_error))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StoredIntent {
        intent: Intent {
            id: id.clone(),
            actor: Actor {
                id: ActorId::new(row.0).map_err(validation_error)?,
                kind: parse_actor_kind(&row.1)?,
                interactive: parse_bool_i64(row.2, "actor interactive")?,
            },
            statement: row.3,
            status: parse_intent_status(&row.4)?,
            requirements,
            supersedes,
        },
        revision,
    })
}

pub(crate) fn current_intent_state(
    connection: &Connection,
    id: &IntentId,
) -> Result<Option<(u64, u64, bool)>, LibraryError> {
    let row = connection
        .query_row(
            "SELECT revision, causal_generation, causal_complete FROM intents_current WHERE intent_id = ?1",
            params![id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(revision, generation, complete)| {
        Ok((
            to_u64(revision, "intent revision")?,
            to_u64(generation, "causal generation")?,
            parse_bool_i64(complete, "causal complete")?,
        ))
    })
    .transpose()
}

fn transition_status(
    current: IntentStatus,
    transition: IntentTransition,
) -> Result<IntentStatus, LibraryError> {
    match (current, transition) {
        (IntentStatus::Proposed | IntentStatus::Suspended, IntentTransition::Activate) => {
            Ok(IntentStatus::Active)
        }
        (IntentStatus::Active, IntentTransition::Suspend) => Ok(IntentStatus::Suspended),
        (
            IntentStatus::Proposed | IntentStatus::Active | IntentStatus::Suspended,
            IntentTransition::Retire,
        ) => Ok(IntentStatus::Retired),
        _ => Err(LibraryError::InvalidTransition {
            from: intent_status_str(current).into(),
            operation: transition.as_str().into(),
        }),
    }
}

fn copy_current_causal_state(
    transaction: &Transaction<'_>,
    id: &IntentId,
    old_revision: u64,
    new_revision: u64,
    generation: u64,
    complete: bool,
) -> Result<(u64, bool), LibraryError> {
    if generation == 0 {
        return Ok((0, false));
    }
    transaction.execute(
        "INSERT INTO desired_resources(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, ownership_complete) SELECT intent_id, ?3, 1, provider_id, resource_id, capability_id, ownership_complete FROM desired_resources WHERE intent_id = ?1 AND intent_revision = ?2 AND generation = ?4",
        params![
            id.as_str(),
            to_i64(old_revision, "intent revision")?,
            to_i64(new_revision, "intent revision")?,
            to_i64(generation, "causal generation")?
        ],
    )?;
    transaction.execute(
        "INSERT INTO desired_resource_attributes(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, key, value) SELECT intent_id, ?3, 1, provider_id, resource_id, capability_id, key, value FROM desired_resource_attributes WHERE intent_id = ?1 AND intent_revision = ?2 AND generation = ?4",
        params![
            id.as_str(),
            to_i64(old_revision, "intent revision")?,
            to_i64(new_revision, "intent revision")?,
            to_i64(generation, "causal generation")?
        ],
    )?;
    transaction.execute(
        "INSERT INTO desired_resource_origins(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, origin_kind, origin_id) SELECT intent_id, ?3, 1, provider_id, resource_id, capability_id, origin_kind, origin_id FROM desired_resource_origins WHERE intent_id = ?1 AND intent_revision = ?2 AND generation = ?4",
        params![
            id.as_str(),
            to_i64(old_revision, "intent revision")?,
            to_i64(new_revision, "intent revision")?,
            to_i64(generation, "causal generation")?
        ],
    )?;
    Ok((1, complete))
}

fn insert_desired_origin(
    transaction: &Transaction<'_>,
    intent_id: &IntentId,
    intent_revision: u64,
    generation: u64,
    provider_id: &str,
    resource_id: &str,
    capability_id: &str,
    kind: &str,
    origin_id: &str,
) -> Result<(), LibraryError> {
    transaction.execute(
        "INSERT INTO desired_resource_origins(intent_id, intent_revision, generation, provider_id, resource_id, capability_id, origin_kind, origin_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            intent_id.as_str(),
            to_i64(intent_revision, "intent revision")?,
            to_i64(generation, "causal generation")?,
            provider_id,
            resource_id,
            capability_id,
            kind,
            origin_id
        ],
    )?;
    Ok(())
}

fn desired_resource_identities(
    connection: &Connection,
    intent_id: &IntentId,
    revision: u64,
    generation: u64,
) -> Result<Vec<ManagedResourceIdentity>, LibraryError> {
    let mut statement = connection.prepare(
        "SELECT provider_id, resource_id, capability_id FROM desired_resources WHERE intent_id = ?1 AND intent_revision = ?2 AND generation = ?3 ORDER BY provider_id, resource_id, capability_id",
    )?;
    let rows = statement
        .query_map(
            params![
                intent_id.as_str(),
                to_i64(revision, "intent revision")?,
                to_i64(generation, "causal generation")?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(provider, resource, capability)| {
            Ok(ManagedResourceIdentity {
                provider: ProviderId::new(provider).map_err(validation_error)?,
                resource: ResourceId::new(resource).map_err(validation_error)?,
                capability: CapabilityId::new(capability).map_err(validation_error)?,
            })
        })
        .collect()
}

pub(crate) fn insert_setup_revision(
    transaction: &Transaction<'_>,
    setup: &Setup,
    intents: &[IntentRevisionRef],
    includes: &[SetupRevisionRef],
) -> Result<(), LibraryError> {
    validate_text("setup name", &setup.name, 4_096)?;
    validate_text("setup description", &setup.description, MAX_TEXT_BYTES)?;
    transaction.execute(
        "INSERT INTO setup_revisions(setup_id, revision, name, description) VALUES (?1, ?2, ?3, ?4)",
        params![setup.id.as_str(), i64::from(setup.revision), &setup.name, &setup.description],
    )?;
    for intent in intents {
        transaction.execute(
            "INSERT INTO setup_intents(setup_id, setup_revision, intent_id, intent_revision) VALUES (?1, ?2, ?3, ?4)",
            params![
                setup.id.as_str(),
                i64::from(setup.revision),
                intent.id.as_str(),
                to_i64(intent.revision, "intent revision")?
            ],
        )?;
    }
    for included in includes {
        transaction.execute(
            "INSERT INTO setup_includes(setup_id, setup_revision, included_setup_id, included_revision) VALUES (?1, ?2, ?3, ?4)",
            params![
                setup.id.as_str(),
                i64::from(setup.revision),
                included.id.as_str(),
                i64::from(included.revision)
            ],
        )?;
    }
    insert_ordinal_texts(
        transaction,
        "setup_constraints",
        "setup_id",
        setup.id.as_str(),
        "setup_revision",
        u64::from(setup.revision),
        &setup.portable_constraints,
    )?;
    insert_ordinal_texts(
        transaction,
        "setup_secret_refs",
        "setup_id",
        setup.id.as_str(),
        "setup_revision",
        u64::from(setup.revision),
        &setup.required_secret_refs,
    )?;
    insert_ordinal_texts(
        transaction,
        "setup_hardware_hints",
        "setup_id",
        setup.id.as_str(),
        "setup_revision",
        u64::from(setup.revision),
        &setup.hardware_hints,
    )?;
    Ok(())
}

pub(crate) fn load_setup_revision(
    connection: &Connection,
    id: &SetupId,
    revision: u32,
) -> Result<StoredSetup, LibraryError> {
    let row = connection
        .query_row(
            "SELECT name, description FROM setup_revisions WHERE setup_id = ?1 AND revision = ?2",
            params![id.as_str(), i64::from(revision)],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LibraryError::NotFound {
            kind: "setup revision",
            id: format!("{}@{revision}", id.as_str()),
        })?;
    let mut intent_statement = connection.prepare(
        "SELECT intent_id, intent_revision FROM setup_intents WHERE setup_id = ?1 AND setup_revision = ?2 ORDER BY intent_id, intent_revision",
    )?;
    let intent_rows = intent_statement
        .query_map(params![id.as_str(), i64::from(revision)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let intent_revisions = intent_rows
        .into_iter()
        .map(|(intent_id, intent_revision)| {
            Ok(IntentRevisionRef {
                id: IntentId::new(intent_id).map_err(validation_error)?,
                revision: to_u64(intent_revision, "intent revision")?,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    let mut include_statement = connection.prepare(
        "SELECT included_setup_id, included_revision FROM setup_includes WHERE setup_id = ?1 AND setup_revision = ?2 ORDER BY included_setup_id, included_revision",
    )?;
    let include_rows = include_statement
        .query_map(params![id.as_str(), i64::from(revision)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let included_revisions = include_rows
        .into_iter()
        .map(|(setup_id, included_revision)| {
            Ok(SetupRevisionRef {
                id: SetupId::new(setup_id).map_err(validation_error)?,
                revision: to_u32(
                    to_u64(included_revision, "setup revision")?,
                    "setup revision",
                )?,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    Ok(StoredSetup {
        setup: Setup {
            id: id.clone(),
            name: row.0,
            description: row.1,
            revision,
            intent_ids: intent_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            included_setup_ids: included_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            portable_constraints: load_ordinal_texts(
                connection,
                "setup_constraints",
                "setup_id",
                id.as_str(),
                "setup_revision",
                u64::from(revision),
            )?,
            required_secret_refs: load_ordinal_texts(
                connection,
                "setup_secret_refs",
                "setup_id",
                id.as_str(),
                "setup_revision",
                u64::from(revision),
            )?,
            hardware_hints: load_ordinal_texts(
                connection,
                "setup_hardware_hints",
                "setup_id",
                id.as_str(),
                "setup_revision",
                u64::from(revision),
            )?,
        },
        intent_revisions,
        included_revisions,
    })
}

pub(crate) fn insert_profile_revision(
    transaction: &Transaction<'_>,
    profile: &MachineProfile,
    revision: u32,
    intents: &[IntentRevisionRef],
    setups: &[SetupRevisionRef],
) -> Result<(), LibraryError> {
    transaction.execute(
        "INSERT INTO profile_revisions(profile_id, revision, name, machine_class) VALUES (?1, ?2, ?3, ?4)",
        params![
            profile.id.as_str(),
            i64::from(revision),
            &profile.name,
            profile.machine_class.as_str()
        ],
    )?;
    for intent in intents {
        transaction.execute(
            "INSERT INTO profile_intents(profile_id, profile_revision, intent_id, intent_revision) VALUES (?1, ?2, ?3, ?4)",
            params![
                profile.id.as_str(),
                i64::from(revision),
                intent.id.as_str(),
                to_i64(intent.revision, "intent revision")?
            ],
        )?;
    }
    for setup in setups {
        transaction.execute(
            "INSERT INTO profile_setups(profile_id, profile_revision, setup_id, setup_revision) VALUES (?1, ?2, ?3, ?4)",
            params![
                profile.id.as_str(),
                i64::from(revision),
                setup.id.as_str(),
                i64::from(setup.revision)
            ],
        )?;
    }
    insert_ordinal_texts(
        transaction,
        "profile_constraints",
        "profile_id",
        profile.id.as_str(),
        "profile_revision",
        u64::from(revision),
        &profile.portable_constraints,
    )?;
    insert_ordinal_texts(
        transaction,
        "profile_hardware_hints",
        "profile_id",
        profile.id.as_str(),
        "profile_revision",
        u64::from(revision),
        &profile.hardware_hints,
    )?;
    Ok(())
}

pub(crate) fn load_profile_revision(
    connection: &Connection,
    id: &ProfileId,
    revision: u32,
) -> Result<StoredProfile, LibraryError> {
    let row = connection
        .query_row(
            "SELECT name, machine_class FROM profile_revisions WHERE profile_id = ?1 AND revision = ?2",
            params![id.as_str(), i64::from(revision)],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LibraryError::NotFound {
            kind: "profile revision",
            id: format!("{}@{revision}", id.as_str()),
        })?;
    let mut intent_statement = connection.prepare(
        "SELECT intent_id, intent_revision FROM profile_intents WHERE profile_id = ?1 AND profile_revision = ?2 ORDER BY intent_id, intent_revision",
    )?;
    let intent_rows = intent_statement
        .query_map(params![id.as_str(), i64::from(revision)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let intent_revisions = intent_rows
        .into_iter()
        .map(|(intent_id, intent_revision)| {
            Ok(IntentRevisionRef {
                id: IntentId::new(intent_id).map_err(validation_error)?,
                revision: to_u64(intent_revision, "intent revision")?,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    let mut setup_statement = connection.prepare(
        "SELECT setup_id, setup_revision FROM profile_setups WHERE profile_id = ?1 AND profile_revision = ?2 ORDER BY setup_id, setup_revision",
    )?;
    let setup_rows = setup_statement
        .query_map(params![id.as_str(), i64::from(revision)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let setup_revisions = setup_rows
        .into_iter()
        .map(|(setup_id, setup_revision)| {
            Ok(SetupRevisionRef {
                id: SetupId::new(setup_id).map_err(validation_error)?,
                revision: to_u32(to_u64(setup_revision, "setup revision")?, "setup revision")?,
            })
        })
        .collect::<Result<Vec<_>, LibraryError>>()?;
    Ok(StoredProfile {
        profile: MachineProfile {
            id: id.clone(),
            name: row.0,
            machine_class: parse_machine_class(&row.1)?,
            setup_ids: setup_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            intent_ids: intent_revisions
                .iter()
                .map(|value| value.id.clone())
                .collect(),
            portable_constraints: load_ordinal_texts(
                connection,
                "profile_constraints",
                "profile_id",
                id.as_str(),
                "profile_revision",
                u64::from(revision),
            )?,
            hardware_hints: load_ordinal_texts(
                connection,
                "profile_hardware_hints",
                "profile_id",
                id.as_str(),
                "profile_revision",
                u64::from(revision),
            )?,
        },
        revision,
        intent_revisions,
        setup_revisions,
    })
}

pub(crate) fn latest_setup_revision(
    connection: &Connection,
    id: &SetupId,
) -> Result<Option<u32>, LibraryError> {
    let revision = connection.query_row(
        "SELECT MAX(revision) FROM setup_revisions WHERE setup_id = ?1",
        params![id.as_str()],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    revision
        .map(|value| to_u32(to_u64(value, "setup revision")?, "setup revision"))
        .transpose()
}

pub(crate) fn latest_profile_revision(
    connection: &Connection,
    id: &ProfileId,
) -> Result<Option<u32>, LibraryError> {
    let revision = connection.query_row(
        "SELECT MAX(revision) FROM profile_revisions WHERE profile_id = ?1",
        params![id.as_str()],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    revision
        .map(|value| to_u32(to_u64(value, "profile revision")?, "profile revision"))
        .transpose()
}

fn resolve_current_intents(
    connection: &Connection,
    ids: &[IntentId],
) -> Result<Vec<IntentRevisionRef>, LibraryError> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(LibraryError::Validation(format!(
                "duplicate intent reference {}",
                id.as_str()
            )));
        }
        let (revision, _, _) =
            current_intent_state(connection, id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "intent",
                id: id.as_str().into(),
            })?;
        output.push(IntentRevisionRef {
            id: id.clone(),
            revision,
        });
    }
    output.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(output)
}

fn resolve_current_setups(
    connection: &Connection,
    ids: &[SetupId],
) -> Result<Vec<SetupRevisionRef>, LibraryError> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(LibraryError::Validation(format!(
                "duplicate setup reference {}",
                id.as_str()
            )));
        }
        let revision =
            latest_setup_revision(connection, id)?.ok_or_else(|| LibraryError::NotFound {
                kind: "included setup",
                id: id.as_str().into(),
            })?;
        output.push(SetupRevisionRef {
            id: id.clone(),
            revision,
        });
    }
    output.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(output)
}

fn setup_revision_reaches(
    connection: &Connection,
    start_id: &SetupId,
    start_revision: u32,
    target_id: &SetupId,
) -> Result<bool, LibraryError> {
    let mut queue = VecDeque::from([(start_id.clone(), start_revision)]);
    let mut visited = BTreeSet::new();
    while let Some((id, revision)) = queue.pop_front() {
        if !visited.insert((id.clone(), revision)) {
            continue;
        }
        if &id == target_id {
            return Ok(true);
        }
        let stored = load_setup_revision(connection, &id, revision)?;
        for included in stored.included_revisions {
            queue.push_back((included.id, included.revision));
        }
        if visited.len() > MAX_COLLECTION_ITEMS {
            return Err(LibraryError::Validation(
                "setup composition exceeds traversal bound".into(),
            ));
        }
    }
    Ok(false)
}

fn collect_setup_closure(
    connection: &Connection,
    root: &SetupRevisionRef,
) -> Result<(Vec<StoredSetup>, Vec<StoredIntent>), LibraryError> {
    let mut queue = VecDeque::from([root.clone()]);
    let mut setups = BTreeMap::new();
    let mut intents = BTreeMap::new();
    while let Some(reference) = queue.pop_front() {
        let key = (reference.id.as_str().to_owned(), reference.revision);
        if setups.contains_key(&key) {
            continue;
        }
        let stored = load_setup_revision(connection, &reference.id, reference.revision)?;
        for intent_ref in &stored.intent_revisions {
            let intent_key = (intent_ref.id.as_str().to_owned(), intent_ref.revision);
            if !intents.contains_key(&intent_key) {
                let intent = load_intent_revision(connection, &intent_ref.id, intent_ref.revision)?;
                intents.insert(intent_key, intent);
            }
        }
        for included in &stored.included_revisions {
            queue.push_back(included.clone());
        }
        setups.insert(key, stored);
        if setups.len() + intents.len() > MAX_COLLECTION_ITEMS {
            return Err(LibraryError::Validation(
                "portable setup closure exceeds item bound".into(),
            ));
        }
    }
    Ok((
        setups.into_values().collect(),
        intents.into_values().collect(),
    ))
}

fn insert_ordinal_texts(
    transaction: &Transaction<'_>,
    table: &str,
    id_column: &str,
    id: &str,
    revision_column: &str,
    revision: u64,
    values: &[String],
) -> Result<(), LibraryError> {
    validate_collection_size(table, values.len())?;
    let sql = format!(
        "INSERT INTO {table}({id_column}, {revision_column}, ordinal, value) VALUES (?1, ?2, ?3, ?4)"
    );
    for (ordinal, value) in values.iter().enumerate() {
        validate_text(table, value, MAX_TEXT_BYTES)?;
        transaction.execute(
            &sql,
            params![
                id,
                to_i64(revision, "revision")?,
                to_i64(
                    u64::try_from(ordinal).map_err(|_| LibraryError::Validation(
                        "ordinal cannot be represented durably".into()
                    ))?,
                    "ordinal"
                )?,
                value
            ],
        )?;
    }
    Ok(())
}

fn load_ordinal_texts(
    connection: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    revision_column: &str,
    revision: u64,
) -> Result<Vec<String>, LibraryError> {
    let sql = format!(
        "SELECT value FROM {table} WHERE {id_column} = ?1 AND {revision_column} = ?2 ORDER BY ordinal"
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(params![id, to_i64(revision, "revision")?], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub(crate) fn append_lifecycle_record_tx(
    transaction: &Transaction<'_>,
    kind: LifecycleRecordKind,
    entity_id: &str,
    payload: &str,
) -> Result<LifecycleRecord, LibraryError> {
    validate_text("lifecycle entity id", entity_id, 256)?;
    validate_text("lifecycle payload", payload, MAX_TEXT_BYTES)?;
    let digest = digest_fields(&[kind.as_str(), entity_id, payload]);
    transaction.execute(
        "INSERT INTO lifecycle_records(record_kind, entity_id, content_digest, payload) VALUES (?1, ?2, ?3, ?4)",
        params![kind.as_str(), entity_id, &digest, payload],
    )?;
    let sequence = to_u64(transaction.last_insert_rowid(), "lifecycle sequence")?;
    Ok(LifecycleRecord {
        sequence,
        kind,
        entity_id: entity_id.into(),
        content_digest: digest,
        payload: payload.into(),
    })
}

pub(crate) fn record_operation(
    transaction: &Transaction<'_>,
    operation_id: &RequestId,
    digest: &str,
    result_kind: &str,
    result_id: &str,
    result_revision: u64,
) -> Result<(), LibraryError> {
    transaction.execute(
        "INSERT INTO library_operations(operation_id, semantic_digest, result_kind, result_id, result_revision) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            operation_id.as_str(),
            digest,
            result_kind,
            result_id,
            to_i64(result_revision, "result revision")?
        ],
    )?;
    Ok(())
}

pub(crate) fn replay_operation(
    connection: &Connection,
    operation_id: &RequestId,
    digest: &str,
    result_kind: &str,
) -> Result<Option<(String, u64)>, LibraryError> {
    let existing = connection
        .query_row(
            "SELECT semantic_digest, result_kind, result_id, result_revision FROM library_operations WHERE operation_id = ?1",
            params![operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    match existing {
        None => Ok(None),
        Some((existing_digest, existing_kind, id, revision))
            if existing_digest == digest && existing_kind == result_kind =>
        {
            Ok(Some((id, to_u64(revision, "result revision")?)))
        }
        Some(_) => Err(LibraryError::IdempotencyConflict(operation_id.clone())),
    }
}

fn validate_next_revision(
    expected_previous: Option<u64>,
    current: Option<u64>,
    proposed: u64,
    kind: &'static str,
) -> Result<(), LibraryError> {
    match (current, expected_previous) {
        (None, None) if proposed > 0 => Ok(()),
        (None, Some(expected)) => Err(LibraryError::RevisionConflict {
            expected,
            actual: 0,
        }),
        (Some(actual), Some(expected)) => {
            ensure_revision(expected, actual)?;
            if proposed <= actual {
                return Err(LibraryError::Validation(format!(
                    "{kind} revision must increase beyond {actual}"
                )));
            }
            Ok(())
        }
        (Some(actual), None) => Err(LibraryError::RevisionConflict {
            expected: 0,
            actual,
        }),
    }
}

fn validate_profile(profile: &MachineProfile, revision: u32) -> Result<(), LibraryError> {
    if revision == 0 {
        return Err(LibraryError::Validation(
            "profile revision must be positive".into(),
        ));
    }
    validate_text("profile name", &profile.name, 4_096)?;
    validate_collection_size("profile setups", profile.setup_ids.len())?;
    validate_collection_size("profile intents", profile.intent_ids.len())?;
    Ok(())
}

fn ensure_revision(expected: u64, actual: u64) -> Result<(), LibraryError> {
    if expected == actual {
        Ok(())
    } else {
        Err(LibraryError::RevisionConflict { expected, actual })
    }
}

fn validate_text(label: &str, value: &str, max_bytes: usize) -> Result<(), LibraryError> {
    if value.trim().is_empty() {
        return Err(LibraryError::Validation(format!("{label} cannot be empty")));
    }
    if value.len() > max_bytes {
        return Err(LibraryError::Validation(format!(
            "{label} exceeds {max_bytes} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(LibraryError::Validation(format!(
            "{label} contains control characters"
        )));
    }
    Ok(())
}

fn validate_collection_size(label: &str, size: usize) -> Result<(), LibraryError> {
    if size > MAX_COLLECTION_ITEMS {
        Err(LibraryError::Validation(format!(
            "{label} exceeds {MAX_COLLECTION_ITEMS} items"
        )))
    } else {
        Ok(())
    }
}

fn intent_operation_digest(operation: &str, intent: &Intent, extra: &[&str]) -> String {
    let mut fields = vec![
        operation.to_owned(),
        intent.id.as_str().to_owned(),
        intent.actor.id.as_str().to_owned(),
        actor_kind_str(intent.actor.kind).to_owned(),
        intent.actor.interactive.to_string(),
        intent.statement.clone(),
        intent_status_str(intent.status).to_owned(),
    ];
    let mut requirements = intent.requirements.clone();
    requirements.sort_by(|left, right| left.id.cmp(&right.id));
    for requirement in requirements {
        fields.push(requirement.id.as_str().to_owned());
        fields.push(requirement_kind_str(requirement.kind).to_owned());
        fields.push(requirement.statement);
    }
    let mut supersedes = intent.supersedes.clone();
    supersedes.sort();
    fields.extend(
        supersedes
            .into_iter()
            .map(|value| value.as_str().to_owned()),
    );
    fields.extend(extra.iter().map(|value| (*value).to_owned()));
    digest_owned_fields(&fields)
}

fn setup_operation_digest(setup: &Setup, expected: Option<u32>) -> String {
    let mut fields = vec![
        "save-setup".to_owned(),
        setup.id.as_str().to_owned(),
        setup.revision.to_string(),
        setup.name.clone(),
        setup.description.clone(),
        expected.map_or_else(|| "none".into(), |value| value.to_string()),
    ];
    let mut intent_ids = setup.intent_ids.clone();
    intent_ids.sort();
    fields.extend(intent_ids.into_iter().map(|id| id.as_str().to_owned()));
    let mut setup_ids = setup.included_setup_ids.clone();
    setup_ids.sort();
    fields.extend(setup_ids.into_iter().map(|id| id.as_str().to_owned()));
    fields.extend(setup.portable_constraints.iter().cloned());
    fields.extend(setup.required_secret_refs.iter().cloned());
    fields.extend(setup.hardware_hints.iter().cloned());
    digest_owned_fields(&fields)
}

fn profile_operation_digest(
    profile: &MachineProfile,
    revision: u32,
    expected: Option<u32>,
) -> String {
    let mut fields = vec![
        "save-profile".to_owned(),
        profile.id.as_str().to_owned(),
        revision.to_string(),
        profile.name.clone(),
        profile.machine_class.as_str().to_owned(),
        expected.map_or_else(|| "none".into(), |value| value.to_string()),
    ];
    let mut intent_ids = profile.intent_ids.clone();
    intent_ids.sort();
    fields.extend(intent_ids.into_iter().map(|id| id.as_str().to_owned()));
    let mut setup_ids = profile.setup_ids.clone();
    setup_ids.sort();
    fields.extend(setup_ids.into_iter().map(|id| id.as_str().to_owned()));
    fields.extend(profile.portable_constraints.iter().cloned());
    fields.extend(profile.hardware_hints.iter().cloned());
    digest_owned_fields(&fields)
}

fn digest_fields(fields: &[&str]) -> String {
    let owned = fields
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    digest_owned_fields(&owned)
}

fn digest_owned_fields(fields: &[String]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn actor_kind_str(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn parse_actor_kind(value: &str) -> Result<ActorKind, LibraryError> {
    match value {
        "human" => Ok(ActorKind::Human),
        "service" => Ok(ActorKind::Service),
        "agent" => Ok(ActorKind::Agent),
        "remote" => Ok(ActorKind::Remote),
        _ => Err(LibraryError::Corrupt(format!(
            "unknown persisted actor kind {value:?}"
        ))),
    }
}

fn intent_status_str(status: IntentStatus) -> &'static str {
    match status {
        IntentStatus::Proposed => "proposed",
        IntentStatus::Active => "active",
        IntentStatus::Suspended => "suspended",
        IntentStatus::Superseded => "superseded",
        IntentStatus::Retired => "retired",
    }
}

fn parse_intent_status(value: &str) -> Result<IntentStatus, LibraryError> {
    match value {
        "proposed" => Ok(IntentStatus::Proposed),
        "active" => Ok(IntentStatus::Active),
        "suspended" => Ok(IntentStatus::Suspended),
        "superseded" => Ok(IntentStatus::Superseded),
        "retired" => Ok(IntentStatus::Retired),
        _ => Err(LibraryError::Corrupt(format!(
            "unknown persisted intent status {value:?}"
        ))),
    }
}

fn requirement_kind_str(kind: RequirementKind) -> &'static str {
    match kind {
        RequirementKind::Goal => "goal",
        RequirementKind::Constraint => "constraint",
        RequirementKind::Preference => "preference",
        RequirementKind::Prohibition => "prohibition",
    }
}

fn parse_requirement_kind(value: &str) -> Result<RequirementKind, LibraryError> {
    match value {
        "goal" => Ok(RequirementKind::Goal),
        "constraint" => Ok(RequirementKind::Constraint),
        "preference" => Ok(RequirementKind::Preference),
        "prohibition" => Ok(RequirementKind::Prohibition),
        _ => Err(LibraryError::Corrupt(format!(
            "unknown persisted requirement kind {value:?}"
        ))),
    }
}

fn parse_machine_class(value: &str) -> Result<MachineClass, LibraryError> {
    match value {
        "workstation" => Ok(MachineClass::Workstation),
        "server" => Ok(MachineClass::Server),
        "edge" => Ok(MachineClass::Edge),
        _ => Err(LibraryError::Corrupt(format!(
            "unknown persisted machine class {value:?}"
        ))),
    }
}

fn parse_lifecycle_kind(value: &str) -> Result<LifecycleRecordKind, LibraryError> {
    match value {
        "desired-state" => Ok(LifecycleRecordKind::DesiredState),
        "provenance" => Ok(LifecycleRecordKind::Provenance),
        "approval-reference" => Ok(LifecycleRecordKind::ApprovalReference),
        "audit-reference" => Ok(LifecycleRecordKind::AuditReference),
        "reconciliation" => Ok(LifecycleRecordKind::Reconciliation),
        _ => Err(LibraryError::Corrupt(format!(
            "unknown persisted lifecycle record kind {value:?}"
        ))),
    }
}

fn parse_bool_i64(value: i64, label: &str) -> Result<bool, LibraryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LibraryError::Corrupt(format!(
            "{label} contains invalid boolean value {value}"
        ))),
    }
}

const fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn to_u64(value: i64, label: &str) -> Result<u64, LibraryError> {
    u64::try_from(value).map_err(|_| LibraryError::Corrupt(format!("{label} is negative")))
}

fn to_u32(value: u64, label: &str) -> Result<u32, LibraryError> {
    u32::try_from(value).map_err(|_| LibraryError::Corrupt(format!("{label} exceeds u32")))
}

fn to_i64(value: u64, label: &str) -> Result<i64, LibraryError> {
    i64::try_from(value)
        .map_err(|_| LibraryError::Validation(format!("{label} exceeds SQLite INTEGER range")))
}

fn validation_error(error: ValidationError) -> LibraryError {
    LibraryError::Corrupt(error.to_string())
}

fn sql_string_literal(path: &Path) -> Result<String, LibraryError> {
    let value = path
        .to_str()
        .ok_or_else(|| LibraryError::Validation("backup path is not valid UTF-8".into()))?;
    if value.contains('\0') {
        return Err(LibraryError::Validation("backup path contains NUL".into()));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn sync_parent(path: &Path) -> Result<(), LibraryError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}
