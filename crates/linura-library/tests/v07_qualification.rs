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
    LocalLibrary, PORTABLE_FORMAT_VERSION, PortableProfileBundle, PortableSetupBundle,
    SetupRevisionRef, StoredIntent, StoredProfile, StoredSetup, decode_profile_bundle,
    decode_setup_bundle, encode_profile_bundle, encode_setup_bundle, restore_backup,
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
    assert_eq!(reopened.schema_version(), Ok(LIBRARY_SCHEMA_VERSION));
    assert_eq!(reopened.integrity_check(), Ok(()));
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
    let mut source =
        LocalLibrary::open(&source_path).unwrap_or_else(|error| unreachable!("{error}"));
    source
        .create_intent(&request("request:backup-intent"), &durable_intent)
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .record_desired_state(
            &durable_intent.id,
            1,
            &desired(
                &durable_intent.id,
                "systemd:unit:linura-managed-backup.service",
            ),
            true,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    source
        .backup_to(&backup_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(source);

    restore_backup(&backup_path, &destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    let restored =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        restored
            .intent(&durable_intent.id)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .intent,
        durable_intent
    );
    assert_eq!(restored.integrity_check(), Ok(()));
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
            .intent,
        durable_intent
    );
    drop(preserved);

    let corrupt_path = directory.path().join("corrupt.db");
    fs::write(&corrupt_path, b"not sqlite").unwrap_or_else(|error| unreachable!("{error}"));
    assert!(restore_backup(&corrupt_path, &destination_path).is_err());
    let preserved =
        LocalLibrary::open(&destination_path).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(preserved.integrity_check(), Ok(()));
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
