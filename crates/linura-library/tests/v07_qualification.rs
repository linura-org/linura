use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use linura_core::{
    Actor, ActorId, ActorKind, CapabilityId, IntentId, ProfileId, ProviderId, RequestId,
    RequirementId, ResourceId, SemanticReason, SetupId, ValidationError,
};
use linura_intent::{
    Intent, IntentStatus, MachineClass, MachineProfile, Requirement, RequirementKind, Setup,
};
use linura_library::{
    AdoptionContext, IntentRevisionRef, IntentTransition, LIBRARY_SCHEMA_VERSION, LibraryError,
    LifecycleRecordKind, LocalLibrary, PORTABLE_FORMAT_VERSION, PortableProfileBundle,
    PortableSetupBundle, SetupRevisionRef, StoredIntent, StoredProfile, StoredSetup,
    decode_profile_bundle, decode_setup_bundle, encode_profile_bundle, encode_setup_bundle,
    restore_backup,
};
use linura_planner::{DesiredResource, DesiredState};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn id<T>(result: Result<T, ValidationError>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error}"))
}

fn request(value: &str) -> RequestId {
    id(RequestId::new(value))
}

fn actor() -> Actor {
    Actor {
        id: id(ActorId::new("uid:1000")),
        kind: ActorKind::Human,
        interactive: true,
    }
}

fn requirement(value: &str, kind: RequirementKind) -> Requirement {
    Requirement {
        id: id(RequirementId::new(format!("requirement:{value}"))),
        kind,
        statement: format!("require {value}"),
    }
}

fn intent(value: &str, status: IntentStatus) -> Intent {
    Intent {
        id: id(IntentId::new(format!("intent:{value}"))),
        actor: actor(),
        statement: format!("manage {value}"),
        status,
        requirements: vec![],
        supersedes: vec![],
    }
}

fn setup(value: &str, revision: u32, intents: Vec<IntentId>, includes: Vec<SetupId>) -> Setup {
    Setup {
        id: id(SetupId::new(format!("setup:{value}"))),
        name: format!("Setup {value}"),
        description: format!("Reusable {value} setup"),
        revision,
        intent_ids: intents,
        included_setup_ids: includes,
        portable_constraints: vec!["portable".into()],
        required_secret_refs: vec!["credential:github".into()],
        hardware_hints: vec![],
    }
}

fn desired(intent_id: &IntentId, resource: &str) -> DesiredState {
    DesiredState {
        resources: vec![DesiredResource {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new(resource)),
            observation_capability: id(CapabilityId::new("systemd.unit.observe")),
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "managed by qualification intent".into(),
                intent_ids: vec![intent_id.clone()],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        }],
    }
}

fn portable_fixture() -> PortableSetupBundle {
    let stored = StoredIntent {
        intent: intent("portable", IntentStatus::Active),
        revision: 1,
    };
    let setup_id = id(SetupId::new("setup:portable"));
    PortableSetupBundle {
        format_version: PORTABLE_FORMAT_VERSION,
        root: SetupRevisionRef {
            id: setup_id.clone(),
            revision: 1,
        },
        setups: vec![StoredSetup {
            setup: Setup {
                id: setup_id,
                name: "Portable".into(),
                description: "qualification fixture".into(),
                revision: 1,
                intent_ids: vec![stored.intent.id.clone()],
                included_setup_ids: vec![],
                portable_constraints: vec!["offline-capable".into()],
                required_secret_refs: vec!["credential:github".into()],
                hardware_hints: vec![],
            },
            intent_revisions: vec![IntentRevisionRef {
                id: stored.intent.id.clone(),
                revision: 1,
            }],
            included_revisions: vec![],
        }],
        intents: vec![stored],
    }
}

#[test]
fn intent_lifecycle_concurrency_idempotency_and_lineage_are_durable() {
    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let path = directory.path().join("library.db");
    let mut library = LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));

    let mut original = intent("lifecycle", IntentStatus::Proposed);
    original.requirements = vec![
        requirement("goal", RequirementKind::Goal),
        requirement("constraint", RequirementKind::Constraint),
        requirement("preference", RequirementKind::Preference),
        requirement("prohibition", RequirementKind::Prohibition),
    ];
    let create = request("request:create-lifecycle");
    let first = library
        .create_intent(&create, &original)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let retry = library
        .create_intent(&create, &original)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(first, retry);
    assert_eq!(first.revision, 1);
    assert_eq!(first.intent.requirements.len(), 4);

    let mut substituted = original.clone();
    substituted.statement = "different semantics".into();
    assert!(matches!(
        library.create_intent(&create, &substituted),
        Err(LibraryError::IdempotencyConflict(_))
    ));

    let active = library
        .transition_intent(
            &request("request:activate"),
            &original.id,
            1,
            IntentTransition::Activate,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(active.intent.status, IntentStatus::Active);
    assert!(matches!(
        library.transition_intent(
            &request("request:stale"),
            &original.id,
            1,
            IntentTransition::Suspend,
        ),
        Err(LibraryError::RevisionConflict { .. })
    ));
    let suspended = library
        .transition_intent(
            &request("request:suspend"),
            &original.id,
            2,
            IntentTransition::Suspend,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let reactivated = library
        .transition_intent(
            &request("request:reactivate"),
            &original.id,
            suspended.revision,
            IntentTransition::Activate,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let retired = library
        .transition_intent(
            &request("request:retire"),
            &original.id,
            reactivated.revision,
            IntentTransition::Retire,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(retired.intent.status, IntentStatus::Retired);
    assert!(matches!(
        library.transition_intent(
            &request("request:illegal-terminal"),
            &original.id,
            retired.revision,
            IntentTransition::Activate,
        ),
        Err(LibraryError::InvalidTransition { .. })
    ));
    assert_eq!(
        library
            .intent_history(&original.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        5
    );

    let predecessor = intent("predecessor", IntentStatus::Active);
    library
        .create_intent(&request("request:create-predecessor"), &predecessor)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut successor = intent("successor", IntentStatus::Active);
    successor.supersedes.push(predecessor.id.clone());
    let (old, new) = library
        .supersede_intent(
            &request("request:supersede"),
            &predecessor.id,
            1,
            &successor,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(old.intent.status, IntentStatus::Superseded);
    assert_eq!(new.intent.supersedes, vec![predecessor.id.clone()]);

    drop(library);
    let reopened = LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        reopened
            .intent(&original.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .intent
            .status,
        IntentStatus::Retired
    );
    assert_eq!(
        reopened
            .schema_version()
            .unwrap_or_else(|error| unreachable!("{error}")),
        LIBRARY_SCHEMA_VERSION
    );
    reopened
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
fn causal_ownership_is_shared_or_removable_only_when_proven_complete() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let left = intent("left", IntentStatus::Active);
    let right = intent("right", IntentStatus::Active);
    library
        .create_intent(&request("request:left"), &left)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .create_intent(&request("request:right"), &right)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let shared = "systemd:unit:linura-managed-shared.service";
    library
        .record_desired_state(&left.id, 1, &desired(&left.id, shared), true)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .record_desired_state(&right.id, 1, &desired(&right.id, shared), true)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let impact = library
        .removal_impact(&left.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(impact.retained_shared.len(), 1);
    assert!(impact.removable.is_empty());
    assert!(impact.indeterminate.is_empty());

    let mut orphan_library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let orphan = intent("orphan", IntentStatus::Active);
    orphan_library
        .create_intent(&request("request:orphan"), &orphan)
        .unwrap_or_else(|error| unreachable!("{error}"));
    orphan_library
        .record_desired_state(
            &orphan.id,
            1,
            &desired(&orphan.id, "systemd:unit:linura-managed-orphan.service"),
            true,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let impact = orphan_library
        .removal_impact(&orphan.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(impact.removable.len(), 1);

    let mut incomplete_library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let incomplete = intent("incomplete", IntentStatus::Active);
    incomplete_library
        .create_intent(&request("request:incomplete"), &incomplete)
        .unwrap_or_else(|error| unreachable!("{error}"));
    incomplete_library
        .record_desired_state(
            &incomplete.id,
            1,
            &desired(
                &incomplete.id,
                "systemd:unit:linura-managed-incomplete.service",
            ),
            false,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let impact = incomplete_library
        .removal_impact(&incomplete.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(impact.indeterminate.len(), 1);
    assert!(impact.removable.is_empty());
}

#[test]
fn setup_and_profile_revisions_are_append_only_and_profile_export_supports_multiple_roots() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let one = intent("one", IntentStatus::Active);
    let two = intent("two", IntentStatus::Active);
    library
        .create_intent(&request("request:intent-one"), &one)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .create_intent(&request("request:intent-two"), &two)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let first = setup("first", 1, vec![one.id.clone()], vec![]);
    library
        .save_setup(&request("request:first-v1"), &first, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut first_v2 = first.clone();
    first_v2.revision = 2;
    first_v2.description = "second immutable revision".into();
    library
        .save_setup(&request("request:first-v2"), &first_v2, Some(1))
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        library
            .setup_revision(&first.id, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .setup
            .description,
        first.description
    );
    assert_eq!(
        library
            .setup_history(&first.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        2
    );

    let second = setup("second", 1, vec![two.id.clone()], vec![]);
    library
        .save_setup(&request("request:second-v1"), &second, None)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let profile = MachineProfile {
        id: id(ProfileId::new("profile:multi-root")),
        name: "Multi-root workstation".into(),
        machine_class: MachineClass::Workstation,
        setup_ids: vec![first.id.clone(), second.id.clone()],
        intent_ids: vec![],
        portable_constraints: vec!["local-first".into()],
        hardware_hints: vec![],
    };
    library
        .save_profile(&request("request:profile-v1"), &profile, 1, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let bundle = library
        .export_profile(&profile.id, Some(1))
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(bundle.setups.len(), 2);
    let encoded = encode_profile_bundle(&bundle).unwrap_or_else(|error| unreachable!("{error}"));
    let decoded = decode_profile_bundle(&encoded).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(decoded, bundle);

    let context = AdoptionContext {
        target_machine_class: Some(MachineClass::Server),
        ..AdoptionContext::default()
    };
    let target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let report = target
        .preflight_profile_adoption(&decoded, &context)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(report.machine_class_mismatch);
    assert!(report.is_blocked());
}

#[test]
fn nested_setup_cycles_are_rejected() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let base_intent = intent("cycle", IntentStatus::Active);
    library
        .create_intent(&request("request:cycle-intent"), &base_intent)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let b = setup("b", 1, vec![base_intent.id.clone()], vec![]);
    library
        .save_setup(&request("request:b-v1"), &b, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let a = setup("a", 1, vec![], vec![b.id.clone()]);
    library
        .save_setup(&request("request:a-v1"), &a, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let b2 = setup("b", 2, vec![], vec![a.id.clone()]);
    assert!(matches!(
        library.save_setup(&request("request:b-v2-cycle"), &b2, Some(1)),
        Err(LibraryError::Validation(_))
    ));
}

#[test]
fn portable_setup_is_deterministic_integrity_bound_and_imports_atomically() {
    let bundle = portable_fixture();
    let first = encode_setup_bundle(&bundle).unwrap_or_else(|error| unreachable!("{error}"));
    let second = encode_setup_bundle(&bundle).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains("super-secret-value"));
    let decoded = decode_setup_bundle(&first).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(decoded, bundle);

    let mut tampered = first.clone();
    if let Some(byte) = tampered.iter_mut().find(|byte| **byte == b'p') {
        *byte = b'q';
    } else {
        unreachable!("portable fixture must contain a mutable payload byte");
    }
    assert!(matches!(
        decode_setup_bundle(&tampered),
        Err(LibraryError::PortableDigestMismatch)
    ));
    assert!(decode_setup_bundle(b"not-a-linura-artifact\n").is_err());

    let mut newer = bundle.clone();
    newer.format_version = PORTABLE_FORMAT_VERSION + 1;
    assert!(matches!(
        encode_setup_bundle(&newer),
        Err(LibraryError::UnsupportedPortableFormat { .. })
    ));

    let mut malformed_secret = bundle.clone();
    malformed_secret.setups[0].setup.required_secret_refs = vec!["hunter2".into()];
    assert!(matches!(
        encode_setup_bundle(&malformed_secret),
        Err(LibraryError::PortableFormat(_))
    ));
    let mut direct_target =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        direct_target.adopt_setup_bundle(
            &request("request:malformed-secret-direct"),
            &malformed_secret,
            &AdoptionContext::default(),
            false,
        ),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut conflicting_revisions = bundle.clone();
    let intent_id = conflicting_revisions.intents[0].intent.id.clone();
    let mut second_revision = conflicting_revisions.intents[0].clone();
    second_revision.revision = 2;
    conflicting_revisions.intents.push(second_revision);
    conflicting_revisions.setups[0]
        .intent_revisions
        .push(IntentRevisionRef {
            id: intent_id.clone(),
            revision: 2,
        });
    conflicting_revisions.setups[0]
        .setup
        .intent_ids
        .push(intent_id);
    assert!(matches!(
        encode_setup_bundle(&conflicting_revisions),
        Err(LibraryError::PortableFormat(_))
    ));
    assert!(matches!(
        direct_target.adopt_setup_bundle(
            &request("request:conflicting-revisions-direct"),
            &conflicting_revisions,
            &AdoptionContext::default(),
            false,
        ),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut cyclic = bundle.clone();
    cyclic.setups[0]
        .included_revisions
        .push(cyclic.root.clone());
    cyclic.setups[0]
        .setup
        .included_setup_ids
        .push(cyclic.root.id.clone());
    assert!(matches!(
        encode_setup_bundle(&cyclic),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let report = target
        .import_setup_bytes(&request("request:roundtrip"), &first)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(!report.is_blocked());
    assert_eq!(target.list_intents().unwrap_or_default().len(), 1);
    assert_eq!(target.list_setups().unwrap_or_default().len(), 1);
    let records = target
        .lifecycle_records(bundle.root.id.as_str())
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        records
            .iter()
            .any(|record| record.payload.contains("authority_restored=false"))
    );

    if let Ok(directory) = std::env::var("LINURA_V07_EVIDENCE_DIR") {
        let digest = Sha256::digest(&first);
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::create_dir_all(&directory).unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(
            format!("{directory}/portable-roundtrip.sha256"),
            format!("{digest}\n"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    }
}

#[test]
fn paired_reference_identity_is_order_insensitive() {
    let mut bundle = portable_fixture();
    let second = StoredIntent {
        intent: intent("portable-order-second", IntentStatus::Proposed),
        revision: 1,
    };
    let first_id = bundle.intents[0].intent.id.clone();
    let second_id = second.intent.id.clone();
    bundle.intents.push(second);
    bundle.setups[0].intent_revisions.push(IntentRevisionRef {
        id: second_id.clone(),
        revision: 1,
    });
    bundle.setups[0].setup.intent_ids = vec![second_id, first_id];

    let encoded = encode_setup_bundle(&bundle)
        .unwrap_or_else(|error| unreachable!("reordered equivalent IDs must encode: {error}"));
    let decoded = decode_setup_bundle(&encoded)
        .unwrap_or_else(|error| unreachable!("reordered equivalent IDs must decode: {error}"));
    assert_eq!(decoded.intents.len(), 2);

    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let report = target
        .adopt_setup_bundle(
            &request("request:order-insensitive-pairing"),
            &bundle,
            &AdoptionContext::default(),
            false,
        )
        .unwrap_or_else(|error| unreachable!("reordered equivalent IDs must adopt: {error}"));
    assert!(!report.is_blocked());
}

#[test]
fn adoption_dry_run_reports_context_without_mutation_and_collisions_fail_closed() {
    let bundle = portable_fixture();
    let unsupported = id(CapabilityId::new("package.install"));
    let context = AdoptionContext {
        available_secret_refs: BTreeSet::new(),
        target_machine_class: None,
        unsupported_capabilities: BTreeSet::from([unsupported.clone()]),
    };
    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let report = target
        .adopt_setup_bundle(
            &request("request:dry-run-qualification"),
            &bundle,
            &context,
            true,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(report.create_intents.contains(&bundle.intents[0].intent.id));
    assert!(report.active_intents.contains(&bundle.intents[0].intent.id));
    assert!(report.missing_secret_refs.contains("credential:github"));
    assert!(report.unsupported_capabilities.contains(&unsupported));
    assert!(report.requires_plan);
    assert!(target.list_intents().unwrap_or_default().is_empty());

    target
        .import_setup_bundle(&request("request:first-import"), &bundle)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut conflicting = bundle.clone();
    conflicting.intents[0].intent.statement = "different local meaning".into();
    let collision = target
        .adopt_setup_bundle(
            &request("request:collision"),
            &conflicting,
            &AdoptionContext::default(),
            false,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(collision.is_blocked());
    assert!(!collision.collisions.is_empty());
    assert_eq!(
        target
            .intent_history(&bundle.intents[0].intent.id)
            .map(|v| v.len())
            .unwrap_or_default(),
        1
    );
}

#[test]
fn backup_restore_and_schema_corruption_fail_closed() {
    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let source_path = directory.path().join("source.db");
    let backup_path = directory.path().join("backup.db");
    let destination_path = directory.path().join("destination.db");

    let durable_intent = intent("backup", IntentStatus::Active);
    let peer_intent = intent("backup-peer", IntentStatus::Active);
    let create_operation = request("request:backup-intent");
    let suspend_operation = request("request:backup-suspend");
    let reactivate_operation = request("request:backup-reactivate");
    let shared_resource = "systemd:unit:linura-managed-backup-shared.service";

    let mut source =
        LocalLibrary::open(&source_path).unwrap_or_else(|error| unreachable!("{error}"));
    source
        .create_intent(&create_operation, &durable_intent)
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .create_intent(&request("request:backup-peer"), &peer_intent)
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .transition_intent(
            &suspend_operation,
            &durable_intent.id,
            1,
            IntentTransition::Suspend,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let reactivated = source
        .transition_intent(
            &reactivate_operation,
            &durable_intent.id,
            2,
            IntentTransition::Activate,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(reactivated.revision, 3);
    source
        .record_desired_state(
            &durable_intent.id,
            3,
            &desired(&durable_intent.id, shared_resource),
            true,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .record_desired_state(
            &peer_intent.id,
            1,
            &desired(&peer_intent.id, shared_resource),
            true,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .append_lifecycle_record(
            LifecycleRecordKind::Reconciliation,
            durable_intent.id.as_str(),
            "backup-lineage-v1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));

    let setup_v1 = setup("backup", 1, vec![durable_intent.id.clone()], vec![]);
    source
        .save_setup(&request("request:backup-setup-v1"), &setup_v1, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut setup_v2 = setup_v1.clone();
    setup_v2.revision = 2;
    setup_v2.description = "backup setup second immutable revision".into();
    source
        .save_setup(&request("request:backup-setup-v2"), &setup_v2, Some(1))
        .unwrap_or_else(|error| unreachable!("{error}"));

    let profile_v1 = MachineProfile {
        id: id(ProfileId::new("profile:backup")),
        name: "Backup profile v1".into(),
        machine_class: MachineClass::Workstation,
        setup_ids: vec![setup_v2.id.clone()],
        intent_ids: vec![],
        portable_constraints: vec!["local-first".into()],
        hardware_hints: vec![],
    };
    source
        .save_profile(&request("request:backup-profile-v1"), &profile_v1, 1, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut profile_v2 = profile_v1.clone();
    profile_v2.name = "Backup profile v2".into();
    source
        .save_profile(
            &request("request:backup-profile-v2"),
            &profile_v2,
            2,
            Some(1),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));

    source
        .backup_to(&backup_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(source);

    restore_backup(&backup_path, &destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    let mut restored =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    let restored_current = restored
        .intent(&durable_intent.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(restored_current.revision, 3);
    assert_eq!(restored_current.intent, durable_intent);
    let intent_history = restored
        .intent_history(&durable_intent.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(intent_history.len(), 3);
    assert_eq!(
        intent_history
            .into_iter()
            .map(|entry| entry.intent.status)
            .collect::<Vec<_>>(),
        vec![
            IntentStatus::Active,
            IntentStatus::Suspended,
            IntentStatus::Active,
        ]
    );
    let setup_history = restored
        .setup_history(&setup_v1.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(setup_history.len(), 2);
    assert_eq!(setup_history[0].setup.description, setup_v1.description);
    assert_eq!(setup_history[1].setup.description, setup_v2.description);
    let profile_history = restored
        .profile_history(&profile_v1.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(profile_history.len(), 2);
    assert_eq!(profile_history[0].profile.name, profile_v1.name);
    assert_eq!(profile_history[1].profile.name, profile_v2.name);
    let lifecycle = restored
        .lifecycle_records(durable_intent.id.as_str())
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        lifecycle
            .iter()
            .any(|record| record.payload == "backup-lineage-v1")
    );
    let impact = restored
        .removal_impact(&durable_intent.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(impact.retained_shared.len(), 1);
    assert!(impact.removable.is_empty());
    assert!(impact.indeterminate.is_empty());

    let replay = restored
        .transition_intent(
            &reactivate_operation,
            &durable_intent.id,
            2,
            IntentTransition::Activate,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(replay, restored_current);
    assert_eq!(
        restored
            .intent_history(&durable_intent.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        3
    );
    restored
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(restored);

    let newer_path = directory.path().join("newer.db");
    fs::copy(&backup_path, &newer_path).unwrap_or_else(|error| unreachable!("{error}"));
    let newer = Connection::open(&newer_path).unwrap_or_else(|error| unreachable!("{error}"));
    newer
        .pragma_update(None, "user_version", LIBRARY_SCHEMA_VERSION + 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(newer);
    assert!(matches!(
        restore_backup(&newer_path, &destination_path),
        Err(LibraryError::UnsupportedSchema { .. })
    ));
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        preserved
            .intent(&durable_intent.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .revision,
        3
    );
    assert_eq!(
        preserved
            .setup_history(&setup_v1.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        2
    );
    drop(preserved);

    let alien_path = directory.path().join("alien-v1.db");
    let alien = Connection::open(&alien_path).unwrap_or_else(|error| unreachable!("{error}"));
    alien
        .execute_batch("CREATE TABLE unrelated (id INTEGER PRIMARY KEY) STRICT;")
        .unwrap_or_else(|error| unreachable!("{error}"));
    alien
        .pragma_update(None, "user_version", LIBRARY_SCHEMA_VERSION)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(alien);
    assert!(matches!(
        restore_backup(&alien_path, &destination_path),
        Err(LibraryError::Corrupt(_))
    ));
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        preserved
            .intent_history(&durable_intent.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        3
    );
    assert_eq!(
        preserved
            .profile_history(&profile_v1.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        2
    );
    drop(preserved);

    let corrupt_path = directory.path().join("corrupt.db");
    fs::write(&corrupt_path, b"not sqlite").unwrap_or_else(|error| unreachable!("{error}"));
    assert!(restore_backup(&corrupt_path, &destination_path).is_err());
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    preserved
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        preserved
            .removal_impact(&durable_intent.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .retained_shared
            .len(),
        1
    );
}

#[test]
fn malformed_secret_reference_is_rejected_before_persistence_or_export() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let stored_intent = intent("secret-ref", IntentStatus::Proposed);
    library
        .create_intent(&request("request:secret-ref-intent"), &stored_intent)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut stored_setup = setup("secret-ref", 1, vec![stored_intent.id.clone()], vec![]);
    stored_setup.required_secret_refs = vec!["hunter2".into()];
    assert!(matches!(
        library.save_setup(&request("request:bad-secret-ref"), &stored_setup, None),
        Err(LibraryError::Validation(_))
    ));
    assert!(library.setup(&stored_setup.id).is_err());

    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let path = directory.path().join("legacy-secret-ref.db");
    let persisted_intent = intent("persisted-secret-ref", IntentStatus::Proposed);
    let persisted_setup = setup(
        "persisted-secret-ref",
        1,
        vec![persisted_intent.id.clone()],
        vec![],
    );
    {
        let mut persistent =
            LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        persistent
            .create_intent(
                &request("request:persisted-secret-intent"),
                &persisted_intent,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        persistent
            .save_setup(
                &request("request:persisted-secret-setup"),
                &persisted_setup,
                None,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
    }
    let connection = Connection::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .execute("UPDATE setup_secret_refs SET value = 'hunter2'", [])
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(connection);
    let persistent = LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        persistent.export_setup(&persisted_setup.id, Some(1)),
        Err(LibraryError::PortableFormat(_))
    ));
}

#[test]
fn direct_setup_bundle_rejects_mismatched_logical_and_revision_representations() {
    let bundle = portable_fixture();

    let mut missing_intent_revision = bundle.clone();
    missing_intent_revision.setups[0].intent_revisions.clear();
    assert!(matches!(
        encode_setup_bundle(&missing_intent_revision),
        Err(LibraryError::PortableFormat(_))
    ));
    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        target.adopt_setup_bundle(
            &request("request:mismatched-setup-intents"),
            &missing_intent_revision,
            &AdoptionContext::default(),
            false,
        ),
        Err(LibraryError::PortableFormat(_))
    ));
    assert!(target.list_setups().unwrap_or_default().is_empty());

    let mut phantom_include = bundle;
    phantom_include.setups[0]
        .setup
        .included_setup_ids
        .push(id(SetupId::new("setup:phantom")));
    assert!(matches!(
        encode_setup_bundle(&phantom_include),
        Err(LibraryError::PortableFormat(_))
    ));
}

#[test]
fn setup_closure_rejects_conflicting_logical_intent_revisions_across_nested_setups() {
    let mut bundle = portable_fixture();
    let logical_id = bundle.intents[0].intent.id.clone();
    let mut later = bundle.intents[0].clone();
    later.revision = 2;
    bundle.intents.push(later);

    let child_id = id(SetupId::new("setup:portable-child"));
    bundle.setups[0]
        .setup
        .included_setup_ids
        .push(child_id.clone());
    bundle.setups[0].included_revisions.push(SetupRevisionRef {
        id: child_id.clone(),
        revision: 1,
    });
    bundle.setups.push(StoredSetup {
        setup: Setup {
            id: child_id,
            name: "Portable child".into(),
            description: "nested conflicting revision".into(),
            revision: 1,
            intent_ids: vec![logical_id.clone()],
            included_setup_ids: vec![],
            portable_constraints: vec![],
            required_secret_refs: vec![],
            hardware_hints: vec![],
        },
        intent_revisions: vec![IntentRevisionRef {
            id: logical_id,
            revision: 2,
        }],
        included_revisions: vec![],
    });

    assert!(matches!(
        encode_setup_bundle(&bundle),
        Err(LibraryError::PortableFormat(_))
    ));
    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        target.adopt_setup_bundle(
            &request("request:cross-closure-conflict"),
            &bundle,
            &AdoptionContext::default(),
            false,
        ),
        Err(LibraryError::PortableFormat(_))
    ));
}

#[test]
fn profile_bundle_with_direct_and_nested_revisions_round_trips_to_empty_store() {
    let direct = StoredIntent {
        intent: intent("direct", IntentStatus::Proposed),
        revision: 4,
    };
    let nested = StoredIntent {
        intent: intent("nested", IntentStatus::Active),
        revision: 2,
    };
    let setup_id = id(SetupId::new("setup:nested"));
    let stored_setup = StoredSetup {
        setup: Setup {
            id: setup_id.clone(),
            name: "Nested".into(),
            description: "nested setup".into(),
            revision: 3,
            intent_ids: vec![nested.intent.id.clone()],
            included_setup_ids: vec![],
            portable_constraints: vec![],
            required_secret_refs: vec![],
            hardware_hints: vec![],
        },
        intent_revisions: vec![IntentRevisionRef {
            id: nested.intent.id.clone(),
            revision: nested.revision,
        }],
        included_revisions: vec![],
    };
    let profile_id = id(ProfileId::new("profile:portable"));
    let bundle = PortableProfileBundle {
        format_version: PORTABLE_FORMAT_VERSION,
        profile: StoredProfile {
            profile: MachineProfile {
                id: profile_id.clone(),
                name: "Portable workstation".into(),
                machine_class: MachineClass::Workstation,
                setup_ids: vec![setup_id.clone()],
                intent_ids: vec![direct.intent.id.clone()],
                portable_constraints: vec![],
                hardware_hints: vec![],
            },
            revision: 2,
            intent_revisions: vec![IntentRevisionRef {
                id: direct.intent.id.clone(),
                revision: direct.revision,
            }],
            setup_revisions: vec![SetupRevisionRef {
                id: setup_id,
                revision: 3,
            }],
        },
        setups: vec![stored_setup],
        intents: vec![direct, nested],
    };
    let mut mismatched_profile_intents = bundle.clone();
    mismatched_profile_intents
        .profile
        .profile
        .intent_ids
        .clear();
    assert!(matches!(
        encode_profile_bundle(&mismatched_profile_intents),
        Err(LibraryError::PortableFormat(_))
    ));
    let mut mismatch_target =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        mismatch_target.adopt_profile_bundle(
            &request("request:mismatched-profile-intents"),
            &mismatched_profile_intents,
            &AdoptionContext::default(),
            false,
        ),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut mismatched_profile_setups = bundle.clone();
    mismatched_profile_setups.profile.profile.setup_ids.clear();
    assert!(matches!(
        encode_profile_bundle(&mismatched_profile_setups),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut conflicting_profile = bundle.clone();
    let direct_id = conflicting_profile.intents[0].intent.id.clone();
    let mut later_direct = conflicting_profile.intents[0].clone();
    later_direct.revision += 1;
    conflicting_profile.intents.push(later_direct);
    conflicting_profile
        .profile
        .intent_revisions
        .push(IntentRevisionRef {
            id: direct_id.clone(),
            revision: conflicting_profile
                .intents
                .last()
                .map_or(0, |intent| intent.revision),
        });
    conflicting_profile
        .profile
        .profile
        .intent_ids
        .push(direct_id);
    assert!(matches!(
        encode_profile_bundle(&conflicting_profile),
        Err(LibraryError::PortableFormat(_))
    ));

    let mut conflicting_setup_closure = bundle.clone();
    let shared_v3 = conflicting_setup_closure.setups[0].clone();
    let shared_id = shared_v3.setup.id.clone();
    let mut shared_v4 = shared_v3.clone();
    shared_v4.setup.revision = 4;

    let branch_one_id = id(SetupId::new("setup:branch-one"));
    let branch_two_id = id(SetupId::new("setup:branch-two"));
    let branch_one = StoredSetup {
        setup: setup("branch-one", 1, vec![], vec![shared_id.clone()]),
        intent_revisions: vec![],
        included_revisions: vec![SetupRevisionRef {
            id: shared_id.clone(),
            revision: 3,
        }],
    };
    let branch_two = StoredSetup {
        setup: setup("branch-two", 1, vec![], vec![shared_id.clone()]),
        intent_revisions: vec![],
        included_revisions: vec![SetupRevisionRef {
            id: shared_id.clone(),
            revision: 4,
        }],
    };
    assert_eq!(branch_one.setup.id, branch_one_id);
    assert_eq!(branch_two.setup.id, branch_two_id);
    conflicting_setup_closure.setups = vec![shared_v3, shared_v4, branch_one, branch_two];
    conflicting_setup_closure.profile.profile.setup_ids =
        vec![branch_one_id.clone(), branch_two_id.clone()];
    conflicting_setup_closure.profile.setup_revisions = vec![
        SetupRevisionRef {
            id: branch_one_id,
            revision: 1,
        },
        SetupRevisionRef {
            id: branch_two_id,
            revision: 1,
        },
    ];
    assert!(matches!(
        encode_profile_bundle(&conflicting_setup_closure),
        Err(LibraryError::PortableFormat(_))
    ));

    let bytes = encode_profile_bundle(&bundle).unwrap_or_else(|error| unreachable!("{error}"));
    let mut target = LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let report = target
        .import_profile_bytes(&request("request:profile-roundtrip"), &bytes)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(!report.is_blocked());
    assert!(report.create_profiles.contains(&profile_id));
    assert_eq!(
        target
            .profile(&profile_id)
            .unwrap_or_else(|error| unreachable!("{error}")),
        bundle.profile
    );
}

#[test]
fn backup_schema_metadata_bounds_fail_closed_before_restore() {
    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let destination_path = directory.path().join("bounded-destination.db");
    let destination =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    destination
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(destination);

    let oversized_path = directory.path().join("oversized-schema.db");
    let oversized =
        Connection::open(&oversized_path).unwrap_or_else(|error| unreachable!("{error}"));
    let oversized_identifier = "x".repeat(70 * 1024);
    oversized
        .execute_batch(&format!(
            "CREATE TABLE oversized_schema(\"{oversized_identifier}\" TEXT) STRICT;"
        ))
        .unwrap_or_else(|error| unreachable!("{error}"));
    oversized
        .pragma_update(None, "user_version", LIBRARY_SCHEMA_VERSION)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(oversized);

    assert!(matches!(
        restore_backup(&oversized_path, &destination_path),
        Err(LibraryError::Corrupt(_))
    ));
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    preserved
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(preserved);

    let many_path = directory.path().join("many-schema-objects.db");
    let many = Connection::open(&many_path).unwrap_or_else(|error| unreachable!("{error}"));
    for index in 0..129 {
        many.execute_batch(&format!("CREATE TABLE object_{index}(value TEXT) STRICT;"))
            .unwrap_or_else(|error| unreachable!("{error}"));
    }
    many.pragma_update(None, "user_version", LIBRARY_SCHEMA_VERSION)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(many);
    assert!(matches!(
        restore_backup(&many_path, &destination_path),
        Err(LibraryError::Corrupt(_))
    ));
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    preserved
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}
