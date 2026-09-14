#![forbid(unsafe_code)]

use linura_core::{
    Actor, ActorId, ActorKind, CapabilityId, IntentId, PlanId, PolicyId, PolicyRevisionId,
    PrincipalId, ProviderId, RequestId, ResourceId, RiskClass, SemanticReason, ValidationError,
};
use linura_intent::{Intent, IntentStatus};
use linura_library::LocalLibrary;
use linura_migrations::{
    MigrationError, MigrationLedgerStore, MigrationOutcome, MigrationRunner, V08SqliteStoreKind,
    V09PersistentStateMigration, ValidatedBackup,
};
use linura_persistence_sqlite::{SqliteIntegrityKey, SqliteTransactionStore};
use linura_planner::{DesiredResource, DesiredState};
use linura_transaction::{
    AuthorityBinding, AuthorizationBasis, ContentDigest, PrepareOutcome, TransactionAuthorityKey,
    TransactionAuthorityVerifier, TransactionStore, digest_bytes,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("migration qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let root = single_absolute_root()?;
    fs::create_dir_all(&root).map_err(io_string)?;

    let library = root.join("library.db");
    let library_backup = root.join("library.db.backup");
    let authority = root.join("authority.db");
    let authority_backup = root.join("authority.db.backup");
    create_released_library_store(&library)?;
    create_released_authority_store(&authority)?;
    fs::copy(&library, &library_backup).map_err(io_string)?;
    fs::copy(&authority, &authority_backup).map_err(io_string)?;

    let original_library_semantics =
        V09PersistentStateMigration::semantic_sha256(&library, V08SqliteStoreKind::Library)
            .map_err(display_string)?;
    let original_authority_semantics =
        V09PersistentStateMigration::semantic_sha256(&authority, V08SqliteStoreKind::Authority)
            .map_err(display_string)?;

    let library_evidence =
        ValidatedBackup::verify(&library, &library_backup).map_err(display_string)?;
    let store = MigrationLedgerStore::new(root.join("migration.ledger"));
    let mut runner = MigrationRunner::open(store.clone()).map_err(display_string)?;

    let failing = V09PersistentStateMigration::open_library_with_forced_verification_failure(
        library.clone(),
        library_backup.clone(),
    )
    .map_err(display_string)?;
    if !matches!(
        runner.run_with_backup(&failing, Some(&library_evidence)),
        Err(MigrationError::VerificationFailed { .. })
    ) {
        return Err("injected real-Library verification failure did not fail closed".into());
    }
    let restored_library_semantics =
        V09PersistentStateMigration::semantic_sha256(&library, V08SqliteStoreKind::Library)
            .map_err(display_string)?;
    if restored_library_semantics != original_library_semantics {
        return Err("validated real Library backup did not restore exact semantics".into());
    }

    // Rollback uses an atomic replace, so establish a fresh target/backup inode
    // binding before retrying the same production migration.
    let library_retry_evidence =
        ValidatedBackup::verify(&library, &library_backup).map_err(display_string)?;
    let library_migration =
        V09PersistentStateMigration::open_library(library.clone(), library_backup.clone())
            .map_err(display_string)?;
    if runner
        .run_with_backup(&library_migration, Some(&library_retry_evidence))
        .map_err(display_string)?
        != MigrationOutcome::Applied
    {
        return Err("real Library v0.9 preservation migration did not report Applied".into());
    }

    let authority_evidence =
        ValidatedBackup::verify(&authority, &authority_backup).map_err(display_string)?;
    let authority_migration =
        V09PersistentStateMigration::open_authority(authority.clone(), authority_backup.clone())
            .map_err(display_string)?;
    if runner
        .run_with_backup(&authority_migration, Some(&authority_evidence))
        .map_err(display_string)?
        != MigrationOutcome::Applied
    {
        return Err("real authority v0.9 preservation migration did not report Applied".into());
    }
    drop(runner);

    let mut reopened = MigrationRunner::open(store).map_err(display_string)?;
    if reopened.run(&library_migration).map_err(display_string)? != MigrationOutcome::AlreadyApplied
        || reopened.run(&authority_migration).map_err(display_string)?
            != MigrationOutcome::AlreadyApplied
    {
        return Err("verified real SQLite migration replayed after restart".into());
    }

    let final_library_semantics =
        V09PersistentStateMigration::semantic_sha256(&library, V08SqliteStoreKind::Library)
            .map_err(display_string)?;
    let final_authority_semantics =
        V09PersistentStateMigration::semantic_sha256(&authority, V08SqliteStoreKind::Authority)
            .map_err(display_string)?;
    if final_library_semantics != original_library_semantics
        || final_authority_semantics != original_authority_semantics
    {
        return Err("v0.9 migration changed released SQLite semantic state".into());
    }

    // Reopen through the released production stores, not direct SQL, so their
    // schema/integrity validators also accept the migrated artifacts.
    let library_reopened = LocalLibrary::open(&library).map_err(display_string)?;
    if library_reopened
        .list_intents()
        .map_err(display_string)?
        .len()
        != 1
    {
        return Err("migrated Library lost the representative intent".into());
    }
    let authority_reopened =
        SqliteTransactionStore::open(&authority, authority_verifier()?, integrity_key()?)
            .map_err(display_string)?;
    authority_reopened
        .integrity_check()
        .map_err(display_string)?;

    println!("q11_migration=real-v08-sqlite-stores");
    println!("q11_library=intent-graph-provenance-preserved");
    println!("q11_authority=transaction-history-preserved");
    println!("q11_backup_restore=injected-library-failure-restored");
    println!("q11_migration_restart=no-replay");
    Ok(())
}

fn create_released_library_store(path: &Path) -> Result<(), String> {
    let mut library = LocalLibrary::open(path).map_err(display_string)?;
    let intent_id = id(IntentId::new("intent:v09-migration-qualification"))?;
    let intent = Intent {
        id: intent_id.clone(),
        actor: Actor {
            id: id(ActorId::new("uid:1000"))?,
            kind: ActorKind::Human,
            interactive: true,
        },
        statement: "preserve released v0.8 Library semantics".into(),
        status: IntentStatus::Active,
        requirements: vec![],
        supersedes: vec![],
    };
    library
        .create_intent(
            &id(RequestId::new("request:v09-migration-create"))?,
            &intent,
        )
        .map_err(display_string)?;
    let desired = DesiredState {
        resources: vec![DesiredResource {
            provider: id(ProviderId::new("systemd"))?,
            resource: id(ResourceId::new("systemd:unit:v09-migration.service"))?,
            observation_capability: id(CapabilityId::new("systemd.unit.observe"))?,
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "v0.8 migration qualification provenance".into(),
                intent_ids: vec![intent_id.clone()],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        }],
    };
    library
        .record_desired_state(&intent_id, 1, &desired, true)
        .map_err(display_string)?;
    library.integrity_check().map_err(display_string)?;
    drop(library);
    sync_file_and_parent(path)
}

fn create_released_authority_store(path: &Path) -> Result<(), String> {
    let binding = qualification_authority_binding()?;
    let mut store = SqliteTransactionStore::open(path, authority_verifier()?, integrity_key()?)
        .map_err(display_string)?;
    let prepared = store.prepare(&binding).map_err(display_string)?;
    match prepared {
        PrepareOutcome::Created(snapshot) | PrepareOutcome::Existing(snapshot)
            if snapshot.binding_digest == *binding.digest() => {}
        _ => return Err("authority fixture did not retain exact authority binding".into()),
    }
    store.integrity_check().map_err(display_string)?;
    drop(store);
    sync_file_and_parent(path)
}

fn qualification_authority_binding() -> Result<AuthorityBinding, String> {
    let request = "request:v09-migration-authority";
    AuthorityBinding::try_new(
        id(PrincipalId::new("uid:1000"))?,
        id(RequestId::new(request))?,
        id(PlanId::new("plan:v09-migration-authority"))?,
        digest("request"),
        digest("precondition"),
        digest("observation"),
        id(ProviderId::new("systemd"))?,
        id(ResourceId::new("systemd:unit:v09-migration.service"))?,
        id(CapabilityId::new("systemd.unit.observe"))?,
        id(PolicyId::new("policy:v09-migration"))?,
        id(PolicyRevisionId::new("policy:v09-migration:v1"))?,
        RiskClass::SecuritySensitive,
        "risk-policy:v0.9:migration-qualification",
        vec!["qualification.no-external-effect".into()],
        digest("review"),
        AuthorizationBasis::PolicyAllow,
    )
    .map_err(display_string)
}

fn authority_verifier() -> Result<TransactionAuthorityVerifier, String> {
    TransactionAuthorityKey::new(vec![0x41; 32])
        .map(TransactionAuthorityKey::split)
        .map(|(_, verifier)| verifier)
        .map_err(display_string)
}

fn integrity_key() -> Result<SqliteIntegrityKey, String> {
    SqliteIntegrityKey::new(vec![0x73; 32]).map_err(display_string)
}

fn digest(value: &str) -> ContentDigest {
    digest_bytes("linura.v09-migration-qualification.v1", value.as_bytes())
}

fn id<T>(result: Result<T, ValidationError>) -> Result<T, String> {
    result.map_err(display_string)
}

fn sync_file_and_parent(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_string)?;
    let parent = path
        .parent()
        .ok_or_else(|| "SQLite fixture path has no parent".to_owned())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_string)
}

fn single_absolute_root() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing qualification state root".to_owned())?,
    );
    if args.next().is_some() || !root.is_absolute() {
        return Err("qualification requires exactly one absolute state root".into());
    }
    Ok(root)
}

fn io_string(error: std::io::Error) -> String {
    error.to_string()
}

fn display_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}
