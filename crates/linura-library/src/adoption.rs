use std::collections::{BTreeMap, BTreeSet};

use linura_core::{CapabilityId, IntentId, ProfileId, RequestId, SetupId};
use linura_intent::{IntentStatus, MachineClass};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::portable::{
    PortableProfileBundle, PortableSetupBundle, decode_profile_bundle, decode_setup_bundle,
    encode_profile_bundle, encode_setup_bundle,
};
use crate::store::{
    append_lifecycle_record_tx, current_intent_state, insert_intent_revision,
    insert_profile_revision, insert_setup_revision, latest_profile_revision, latest_setup_revision,
    load_intent_revision, load_profile_revision, load_setup_revision, record_operation,
    replay_operation,
};
use crate::{
    AdoptionReport, LibraryError, LifecycleRecordKind, LocalLibrary, StoredIntent, StoredSetup,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdoptionContext {
    pub available_secret_refs: BTreeSet<String>,
    pub target_machine_class: Option<MachineClass>,
    pub unsupported_capabilities: BTreeSet<CapabilityId>,
}

impl LocalLibrary {
    pub fn preflight_setup_adoption(
        &self,
        bundle: &PortableSetupBundle,
        context: &AdoptionContext,
    ) -> Result<AdoptionReport, LibraryError> {
        let _ = encode_setup_bundle(bundle)?;
        preflight_setup(&self.connection, bundle, context)
    }

    pub fn preflight_profile_adoption(
        &self,
        bundle: &PortableProfileBundle,
        context: &AdoptionContext,
    ) -> Result<AdoptionReport, LibraryError> {
        let _ = encode_profile_bundle(bundle)?;
        preflight_profile(&self.connection, bundle, context)
    }

    pub fn import_setup_bytes(
        &mut self,
        operation_id: &RequestId,
        bytes: &[u8],
    ) -> Result<AdoptionReport, LibraryError> {
        let bundle = decode_setup_bundle(bytes)?;
        self.import_setup_bundle(operation_id, &bundle)
    }

    pub fn import_profile_bytes(
        &mut self,
        operation_id: &RequestId,
        bytes: &[u8],
    ) -> Result<AdoptionReport, LibraryError> {
        let bundle = decode_profile_bundle(bytes)?;
        self.import_profile_bundle(operation_id, &bundle)
    }

    pub fn import_setup_bundle(
        &mut self,
        operation_id: &RequestId,
        bundle: &PortableSetupBundle,
    ) -> Result<AdoptionReport, LibraryError> {
        self.adopt_setup_bundle(operation_id, bundle, &AdoptionContext::default(), false)
    }

    pub fn import_profile_bundle(
        &mut self,
        operation_id: &RequestId,
        bundle: &PortableProfileBundle,
    ) -> Result<AdoptionReport, LibraryError> {
        self.adopt_profile_bundle(operation_id, bundle, &AdoptionContext::default(), false)
    }

    pub fn adopt_setup_bundle(
        &mut self,
        operation_id: &RequestId,
        bundle: &PortableSetupBundle,
        context: &AdoptionContext,
        dry_run: bool,
    ) -> Result<AdoptionReport, LibraryError> {
        let canonical = encode_setup_bundle(bundle)?;
        let digest = adoption_digest("setup-adoption", &canonical);
        if dry_run {
            return preflight_setup(&self.connection, bundle, context);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if replay_operation(&transaction, operation_id, &digest, "setup-adoption")?.is_some() {
            let mut report = preflight_setup(&transaction, bundle, context)?;
            report
                .warnings
                .push("exact adoption operation replayed without duplicate mutation".into());
            return Ok(report);
        }

        let report = preflight_setup(&transaction, bundle, context)?;
        if report.is_blocked() {
            return Ok(report);
        }
        import_intents(&transaction, &bundle.intents)?;
        import_setups(&transaction, &bundle.setups)?;
        append_lifecycle_record_tx(
            &transaction,
            LifecycleRecordKind::Provenance,
            bundle.root.id.as_str(),
            &format!(
                "portable setup adoption format={} digest={} authority_restored=false",
                bundle.format_version, digest
            ),
        )?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "setup-adoption",
            bundle.root.id.as_str(),
            u64::from(bundle.root.revision),
        )?;
        transaction.commit()?;
        Ok(report)
    }

    pub fn adopt_profile_bundle(
        &mut self,
        operation_id: &RequestId,
        bundle: &PortableProfileBundle,
        context: &AdoptionContext,
        dry_run: bool,
    ) -> Result<AdoptionReport, LibraryError> {
        let canonical = encode_profile_bundle(bundle)?;
        let digest = adoption_digest("profile-adoption", &canonical);
        if dry_run {
            return preflight_profile(&self.connection, bundle, context);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if replay_operation(&transaction, operation_id, &digest, "profile-adoption")?.is_some() {
            let mut report = preflight_profile(&transaction, bundle, context)?;
            report
                .warnings
                .push("exact adoption operation replayed without duplicate mutation".into());
            return Ok(report);
        }

        let report = preflight_profile(&transaction, bundle, context)?;
        if report.is_blocked() {
            return Ok(report);
        }
        import_intents(&transaction, &bundle.intents)?;
        import_setups(&transaction, &bundle.setups)?;
        if !profile_revision_exists(
            &transaction,
            &bundle.profile.profile.id,
            bundle.profile.revision,
        )? {
            insert_profile_revision(
                &transaction,
                &bundle.profile.profile,
                bundle.profile.revision,
                &bundle.profile.intent_revisions,
                &bundle.profile.setup_revisions,
            )?;
        }
        append_lifecycle_record_tx(
            &transaction,
            LifecycleRecordKind::Provenance,
            bundle.profile.profile.id.as_str(),
            &format!(
                "portable profile adoption format={} digest={} authority_restored=false",
                bundle.format_version, digest
            ),
        )?;
        record_operation(
            &transaction,
            operation_id,
            &digest,
            "profile-adoption",
            bundle.profile.profile.id.as_str(),
            u64::from(bundle.profile.revision),
        )?;
        transaction.commit()?;
        Ok(report)
    }
}

fn preflight_setup(
    connection: &Connection,
    bundle: &PortableSetupBundle,
    context: &AdoptionContext,
) -> Result<AdoptionReport, LibraryError> {
    let mut report = base_report(&bundle.intents, context)?;
    classify_intents(connection, &bundle.intents, &mut report)?;
    classify_setups(connection, &bundle.setups, &mut report)?;
    collect_secret_refs(&bundle.setups, context, &mut report)?;
    report.requires_plan = !bundle.intents.is_empty();
    Ok(report)
}

fn preflight_profile(
    connection: &Connection,
    bundle: &PortableProfileBundle,
    context: &AdoptionContext,
) -> Result<AdoptionReport, LibraryError> {
    let mut report = base_report(&bundle.intents, context)?;
    classify_intents(connection, &bundle.intents, &mut report)?;
    classify_setups(connection, &bundle.setups, &mut report)?;
    collect_secret_refs(&bundle.setups, context, &mut report)?;

    match load_profile_revision(
        connection,
        &bundle.profile.profile.id,
        bundle.profile.revision,
    ) {
        Ok(existing) if existing == bundle.profile => {
            report
                .reuse_profiles
                .insert(bundle.profile.profile.id.clone());
        }
        Ok(_) => report.collisions.push(format!(
            "profile {}@{} already exists with different content",
            bundle.profile.profile.id.as_str(),
            bundle.profile.revision
        )),
        Err(LibraryError::NotFound { .. }) => {
            if latest_profile_revision(connection, &bundle.profile.profile.id)?.is_some() {
                report.collisions.push(format!(
                    "profile {} already exists locally at a different revision",
                    bundle.profile.profile.id.as_str()
                ));
            } else {
                report
                    .create_profiles
                    .insert(bundle.profile.profile.id.clone());
            }
        }
        Err(error) => return Err(error),
    }

    report.machine_class_mismatch = context
        .target_machine_class
        .is_some_and(|class| class != bundle.profile.profile.machine_class);
    if report.machine_class_mismatch {
        report.warnings.push(format!(
            "profile machine class {} does not match target machine class {}",
            bundle.profile.profile.machine_class.as_str(),
            context
                .target_machine_class
                .map(MachineClass::as_str)
                .unwrap_or("unknown")
        ));
    }
    report.requires_plan = !bundle.intents.is_empty();
    Ok(report)
}

fn base_report(
    intents: &[StoredIntent],
    context: &AdoptionContext,
) -> Result<AdoptionReport, LibraryError> {
    let mut report = AdoptionReport::default();
    report.unsupported_capabilities = context.unsupported_capabilities.clone();
    for secret_ref in &context.available_secret_refs {
        validate_secret_ref(secret_ref)?;
    }
    for stored in intents {
        match stored.intent.status {
            IntentStatus::Proposed => {
                report.proposed_intents.insert(stored.intent.id.clone());
            }
            IntentStatus::Active => {
                report.active_intents.insert(stored.intent.id.clone());
            }
            IntentStatus::Suspended | IntentStatus::Superseded | IntentStatus::Retired => {}
        }
    }
    if !report.active_intents.is_empty() {
        report.warnings.push(
            "imported active intent has no imported execution authority and requires fresh local planning and authorization"
                .into(),
        );
    }
    if !report.unsupported_capabilities.is_empty() {
        report.warnings.push(
            "one or more desired capabilities are unsupported on the target and cannot currently execute"
                .into(),
        );
    }
    Ok(report)
}

fn classify_intents(
    connection: &Connection,
    intents: &[StoredIntent],
    report: &mut AdoptionReport,
) -> Result<(), LibraryError> {
    let mut logical_state: BTreeMap<String, bool> = BTreeMap::new();
    for stored in intents {
        let id = &stored.intent.id;
        let exact = intent_revision_exists(connection, id, stored.revision)?;
        if exact {
            let existing = load_intent_revision(connection, id, stored.revision)?;
            if existing == *stored {
                report.reuse_intents.insert(id.clone());
            } else {
                report.collisions.push(format!(
                    "intent {}@{} already exists with different content",
                    id.as_str(),
                    stored.revision
                ));
            }
            logical_state.insert(id.as_str().to_owned(), true);
            continue;
        }

        let any_local = match logical_state.get(id.as_str()) {
            Some(value) => *value,
            None => {
                let value = current_intent_state(connection, id)?.is_some()
                    || connection
                        .query_row(
                            "SELECT 1 FROM intent_revisions WHERE intent_id = ?1 LIMIT 1",
                            params![id.as_str()],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                logical_state.insert(id.as_str().to_owned(), value);
                value
            }
        };
        if any_local {
            report.collisions.push(format!(
                "intent {} already exists locally without exact revision {}",
                id.as_str(),
                stored.revision
            ));
        } else {
            report.create_intents.insert(id.clone());
        }
    }
    Ok(())
}

fn classify_setups(
    connection: &Connection,
    setups: &[StoredSetup],
    report: &mut AdoptionReport,
) -> Result<(), LibraryError> {
    let mut logical_state: BTreeMap<String, bool> = BTreeMap::new();
    for stored in setups {
        let id = &stored.setup.id;
        let revision = stored.setup.revision;
        match load_setup_revision(connection, id, revision) {
            Ok(existing) if existing == *stored => {
                report.reuse_setups.insert(id.clone());
                logical_state.insert(id.as_str().to_owned(), true);
            }
            Ok(_) => {
                report.collisions.push(format!(
                    "setup {}@{} already exists with different content",
                    id.as_str(),
                    revision
                ));
                logical_state.insert(id.as_str().to_owned(), true);
            }
            Err(LibraryError::NotFound { .. }) => {
                let any_local = match logical_state.get(id.as_str()) {
                    Some(value) => *value,
                    None => {
                        let value = latest_setup_revision(connection, id)?.is_some();
                        logical_state.insert(id.as_str().to_owned(), value);
                        value
                    }
                };
                if any_local {
                    report.collisions.push(format!(
                        "setup {} already exists locally without exact revision {}",
                        id.as_str(),
                        revision
                    ));
                } else {
                    report.create_setups.insert(id.clone());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn collect_secret_refs(
    setups: &[StoredSetup],
    context: &AdoptionContext,
    report: &mut AdoptionReport,
) -> Result<(), LibraryError> {
    for setup in setups {
        for secret_ref in &setup.setup.required_secret_refs {
            validate_secret_ref(secret_ref)?;
            if !context.available_secret_refs.contains(secret_ref) {
                report.missing_secret_refs.insert(secret_ref.clone());
            }
        }
    }
    Ok(())
}

fn validate_secret_ref(value: &str) -> Result<(), LibraryError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(LibraryError::Validation(
            "secret reference must be a bounded printable token".into(),
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(LibraryError::Validation(
            "secret reference must not contain whitespace".into(),
        ));
    }
    let Some((namespace, name)) = value.split_once(':') else {
        return Err(LibraryError::Validation(
            "secret reference must use a namespace:name form".into(),
        ));
    };
    if namespace.is_empty() || name.is_empty() || name.contains(':') {
        return Err(LibraryError::Validation(
            "secret reference must contain exactly one non-empty namespace and name".into(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(LibraryError::Validation(
            "secret reference contains unsupported characters".into(),
        ));
    }
    Ok(())
}

fn import_intents(
    transaction: &Transaction<'_>,
    intents: &[StoredIntent],
) -> Result<(), LibraryError> {
    let mut by_id: BTreeMap<IntentId, Vec<&StoredIntent>> = BTreeMap::new();
    for stored in intents {
        if !intent_revision_exists(transaction, &stored.intent.id, stored.revision)? {
            insert_intent_revision(transaction, &stored.intent, stored.revision)?;
        }
        by_id
            .entry(stored.intent.id.clone())
            .or_default()
            .push(stored);
    }

    for (id, mut revisions) in by_id {
        if current_intent_state(transaction, &id)?.is_some() {
            continue;
        }
        revisions.sort_by_key(|stored| stored.revision);
        let current = revisions
            .last()
            .ok_or_else(|| LibraryError::Validation("imported intent set is empty".into()))?;
        transaction.execute(
            "INSERT INTO intents_current(intent_id, revision, causal_generation, causal_complete) VALUES (?1, ?2, 0, 0)",
            params![id.as_str(), i64::try_from(current.revision).map_err(|_| {
                LibraryError::Validation("imported intent revision exceeds SQLite range".into())
            })?],
        )?;
    }
    Ok(())
}

fn import_setups(
    transaction: &Transaction<'_>,
    setups: &[StoredSetup],
) -> Result<(), LibraryError> {
    let map = setups
        .iter()
        .map(|setup| ((setup.setup.id.clone(), setup.setup.revision), setup))
        .collect::<BTreeMap<_, _>>();
    let mut permanent = BTreeSet::new();
    let mut temporary = BTreeSet::new();
    for key in map.keys() {
        import_setup_visit(transaction, key, &map, &mut temporary, &mut permanent)?;
    }
    Ok(())
}

fn import_setup_visit(
    transaction: &Transaction<'_>,
    key: &(SetupId, u32),
    map: &BTreeMap<(SetupId, u32), &StoredSetup>,
    temporary: &mut BTreeSet<(SetupId, u32)>,
    permanent: &mut BTreeSet<(SetupId, u32)>,
) -> Result<(), LibraryError> {
    if permanent.contains(key) {
        return Ok(());
    }
    if !temporary.insert(key.clone()) {
        return Err(LibraryError::Validation(format!(
            "setup import cycle detected at {}@{}",
            key.0.as_str(),
            key.1
        )));
    }
    let setup = map.get(key).ok_or_else(|| {
        LibraryError::Validation("setup import traversal encountered a missing revision".into())
    })?;
    for included in &setup.included_revisions {
        import_setup_visit(
            transaction,
            &(included.id.clone(), included.revision),
            map,
            temporary,
            permanent,
        )?;
    }
    if !setup_revision_exists(transaction, &setup.setup.id, setup.setup.revision)? {
        insert_setup_revision(
            transaction,
            &setup.setup,
            &setup.intent_revisions,
            &setup.included_revisions,
        )?;
    }
    temporary.remove(key);
    permanent.insert(key.clone());
    Ok(())
}

fn intent_revision_exists(
    connection: &Connection,
    id: &IntentId,
    revision: u64,
) -> Result<bool, LibraryError> {
    let revision = i64::try_from(revision)
        .map_err(|_| LibraryError::Validation("intent revision exceeds SQLite range".into()))?;
    Ok(connection
        .query_row(
            "SELECT 1 FROM intent_revisions WHERE intent_id = ?1 AND revision = ?2",
            params![id.as_str(), revision],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn setup_revision_exists(
    connection: &Connection,
    id: &SetupId,
    revision: u32,
) -> Result<bool, LibraryError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM setup_revisions WHERE setup_id = ?1 AND revision = ?2",
            params![id.as_str(), i64::from(revision)],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn profile_revision_exists(
    connection: &Connection,
    id: &ProfileId,
    revision: u32,
) -> Result<bool, LibraryError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM profile_revisions WHERE profile_id = ?1 AND revision = ?2",
            params![id.as_str(), i64::from(revision)],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn adoption_digest(kind: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((kind.len() as u64).to_be_bytes());
    hasher.update(kind.as_bytes());
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IntentRevisionRef, SetupRevisionRef};
    use linura_core::{Actor, ActorId, ActorKind, ValidationError};
    use linura_intent::{Intent, Setup};

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn request(value: &str) -> RequestId {
        id(RequestId::new(value))
    }

    fn intent(value: &str) -> StoredIntent {
        StoredIntent {
            intent: Intent {
                id: id(IntentId::new(value)),
                actor: Actor {
                    id: id(ActorId::new("uid:1000")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                statement: format!("manage {value}"),
                status: IntentStatus::Active,
                requirements: vec![],
                supersedes: vec![],
            },
            revision: 1,
        }
    }

    fn setup_bundle() -> PortableSetupBundle {
        let stored_intent = intent("intent:portable");
        let setup_id = id(SetupId::new("setup:portable"));
        PortableSetupBundle {
            format_version: crate::PORTABLE_FORMAT_VERSION,
            root: SetupRevisionRef {
                id: setup_id.clone(),
                revision: 1,
            },
            setups: vec![StoredSetup {
                setup: Setup {
                    id: setup_id,
                    name: "Portable".into(),
                    description: "portable fixture".into(),
                    revision: 1,
                    intent_ids: vec![stored_intent.intent.id.clone()],
                    included_setup_ids: vec![],
                    portable_constraints: vec![],
                    required_secret_refs: vec!["credential:github".into()],
                    hardware_hints: vec![],
                },
                intent_revisions: vec![IntentRevisionRef {
                    id: stored_intent.intent.id.clone(),
                    revision: 1,
                }],
                included_revisions: vec![],
            }],
            intents: vec![stored_intent],
        }
    }

    #[test]
    fn dry_run_never_mutates_and_reports_missing_secrets() {
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        let bundle = setup_bundle();
        let report = library
            .adopt_setup_bundle(
                &request("request:dry-run"),
                &bundle,
                &AdoptionContext::default(),
                true,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            report
                .create_intents
                .contains(&id(IntentId::new("intent:portable")))
        );
        assert!(report.missing_secret_refs.contains("credential:github"));
        assert!(library.list_intents().unwrap_or_default().is_empty());
        assert!(library.list_setups().unwrap_or_default().is_empty());
    }

    #[test]
    fn import_is_atomic_when_setup_insert_fails() {
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        library
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_setup BEFORE INSERT ON setup_revisions BEGIN SELECT RAISE(ABORT, 'injected setup failure'); END;",
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let result = library.import_setup_bundle(&request("request:atomic"), &setup_bundle());
        assert!(result.is_err());
        assert!(library.list_intents().unwrap_or_default().is_empty());
        assert!(library.list_setups().unwrap_or_default().is_empty());
    }

    #[test]
    fn exact_import_retry_is_idempotent() {
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        let operation = request("request:retry");
        let bundle = setup_bundle();
        let first = library
            .import_setup_bundle(&operation, &bundle)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!first.is_blocked());
        let second = library
            .import_setup_bundle(&operation, &bundle)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            second
                .reuse_intents
                .contains(&id(IntentId::new("intent:portable")))
        );
        assert_eq!(
            library
                .intent_history(&id(IntentId::new("intent:portable")))
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            1
        );
    }

    #[test]
    fn operation_id_semantic_substitution_is_rejected() {
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        let operation = request("request:substitution");
        let bundle = setup_bundle();
        library
            .import_setup_bundle(&operation, &bundle)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut changed = bundle;
        changed.setups[0].setup.description = "changed semantics".into();
        assert!(matches!(
            library.import_setup_bundle(&operation, &changed),
            Err(LibraryError::IdempotencyConflict(_))
        ));
    }
}
