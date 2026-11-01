use std::collections::BTreeSet;
use std::fs;

use linura_core::{
    Actor, ActorId, ActorKind, IntentId, ProfileId, RequestId, SetupId, ValidationError,
};
use linura_intent::{Intent, IntentStatus, MachineClass, MachineProfile, Setup};
use linura_library::{
    AdoptionContext, AdoptionReport, LibraryError, LocalLibrary, MachineAdoptionDecision,
    MachineAdoptionReadiness, decode_setup_bundle, inspect_backup_read_only,
};
use tempfile::tempdir;

fn id<T>(value: Result<T, ValidationError>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error}"))
}

fn req(name: &str) -> RequestId {
    id(RequestId::new(format!("request:s26-workflow-{name}")))
}

fn intent(name: &str) -> Intent {
    Intent {
        id: id(IntentId::new(format!("intent:{name}"))),
        actor: Actor {
            id: id(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        },
        statement: format!("manage {name}"),
        status: IntentStatus::Active,
        requirements: vec![],
        supersedes: vec![],
    }
}

fn setup(name: &str, source: &Intent) -> Setup {
    Setup {
        id: id(SetupId::new(format!("setup:{name}"))),
        name: "Same display name".into(),
        description: format!("{name} detail"),
        revision: 1,
        intent_ids: vec![source.id.clone()],
        included_setup_ids: vec![],
        portable_constraints: vec![],
        required_secret_refs: vec!["credential:fixture".into()],
        hardware_hints: vec![],
    }
}

fn profile(base: &Setup) -> MachineProfile {
    MachineProfile {
        id: id(ProfileId::new("profile:s26")),
        name: "Lab workstation".into(),
        machine_class: MachineClass::Workstation,
        setup_ids: vec![base.id.clone()],
        intent_ids: vec![],
        portable_constraints: vec![],
        hardware_hints: vec![],
    }
}

fn populated() -> (LocalLibrary, Intent, Setup, MachineProfile) {
    let mut library = LocalLibrary::open_in_memory()
        .unwrap_or_else(|error| unreachable!("{error}"));
    let source = intent("foundation");
    library
        .create_intent(&req("new-intent"), &source)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let base = setup("foundation", &source);
    library
        .save_setup(&req("new-setup"), &base, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let machine = profile(&base);
    library
        .save_profile(&req("new-profile"), &machine, 1, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    (library, source, base, machine)
}

#[test]
fn immutable_revision_diff_and_exact_closure_digests() {
    let (mut library, _, base, machine) = populated();
    let before = library
        .inspect_setup_revision(&base.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(before.setup_count, 1);
    assert_eq!(before.intent_count, 1);
    assert_eq!(before.closure_sha256.len(), 64);

    let mut draft = base.clone();
    draft.description = "updated detail".into();
    let prepared = library
        .prepare_setup_edit(&base.id, 1, draft)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(prepared.candidate.revision, 2);
    assert_eq!(prepared.base_revision, 1);
    assert_eq!(library.setup_history(&base.id)
        .unwrap_or_else(|error| unreachable!("{error}").len(), 1);

    library
        .save_setup(
            &req("edited-setup"),
            &prepared.candidate,
            Some(prepared.base_revision),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let delta = library
        .compare_setup_revisions(&base.id, 1, 2)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(delta.changed_fields, BTreeSet::from(["description"]));
    let after = library
        .inspect_setup_revision(&base.id, 2)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_ne!(before.closure_sha256, after.closure_sha256);
    assert_eq!(library
        .inspect_setup_revision(&base.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"), before);

    let profile_before = library
        .inspect_profile_revision(&machine.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(profile_before.setup_count, 1);
    let mut updated = machine.clone();
    updated.name = "New title".into();
    let profile_draft = library
        .prepare_profile_edit(&machine.id, 1, updated)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .save_profile(
            &req("edited-profile"),
            &profile_draft.candidate,
            profile_draft.next_revision,
            Some(profile_draft.base_revision),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let profile_delta = library
        .compare_profile_revisions(&machine.id, 1, 2)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(profile_delta.changed_fields, BTreeSet::from(["name", "setup_revisions"]));
    assert_eq!(library
        .inspect_profile_revision(&machine.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"), profile_before);
}

#[test]
fn editor_drafts_reject_wrong_identity_stale_revision_and_overflow() {
    let (mut library, _, base, machine) = populated();
    let mut wrong = base.clone();
    wrong.id = id(SetupId::new("setup:other"));
    assert!(matches!(
        library.prepare_setup_edit(&base.id, 1, wrong),
        Err(LibraryError::Validation(_))
    ));
    let mut candidate = base.clone();
    candidate.description = "changed".into();
    let first = library
        .prepare_setup_edit(&base.id, 1, candidate.clone())
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .save_setup(&req("save-v2"), &first.candidate, Some(1))
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        library.prepare_setup_edit(&base.id, 1, candidate.clone()),
        Err(LibraryError::RevisionConflict { .. })
    ));
    assert!(matches!(
        library.save_setup(&req("save-stale"), &first.candidate, Some(1)),
        Err(LibraryError::RevisionConflict { .. })
    ));
    let mut wrong_profile = machine.clone();
    wrong_profile.id = id(ProfileId::new("profile:other"));
    assert!(matches!(
        library.prepare_profile_edit(&machine.id, 1, wrong_profile),
        Err(LibraryError::Validation(_))
    ));
    assert!(matches!(
        library.prepare_profile_edit(&machine.id, 0, machine.clone()),
        Err(LibraryError::RevisionConflict { .. })
    ));
    let history = library
        .setup_history(&base.id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].setup.description, base.description);
}

#[test]
fn staged_portable_import_has_no_local_write_or_machine_authority() {
    let (source, _, base, machine) = populated();
    let setup_export = source
        .preview_setup_export(&base.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let profile_export = source
        .preview_profile_export(&machine.id, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(setup_export.sha256.len(), 64);
    assert_eq!(profile_export.sha256.len(), 64);
    let roundtrip = decode_setup_bundle(&setup_export.bytes)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(roundtrip.root.id, base.id);
    let target = LocalLibrary::open_in_memory()
        .unwrap_or_else(|error| unreachable!("{error}"));
    let review = target
        .review_setup_import(&setup_export.bytes, &AdoptionContext::default())
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(review.canonical_sha256, setup_export.sha256);
    assert_eq!(review.root_revision, 1);
    assert!(target.list_setups()
        .unwrap_or_else(|error| unreachable!("{error}").is_empty());
    assert!(target.list_intents()
        .unwrap_or_else(|error| unreachable!("{error}").is_empty());
    let readiness = MachineAdoptionReadiness::from_report(&review.report);
    assert_eq!(readiness.decision, MachineAdoptionDecision::Blocked);
    assert!(readiness.blockers.contains("missing-secret-reference"));
    assert!(!readiness.machine_verified);
    let mismatch = target
        .review_profile_import(
            &profile_export.bytes,
            &AdoptionContext {
                target_machine_class: Some(MachineClass::Server),
                ..AdoptionContext::default()
            },
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(mismatch.canonical_sha256, profile_export.sha256);
    assert!(mismatch.report.machine_class_mismatch);
    let mutated = {
        let mut bytes = setup_export.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bytes
    };
    assert!(target
        .review_setup_import(&mutated, &AdoptionContext::default())
        .is_err());
    assert!(target.list_profiles()
        .unwrap_or_else(|error| unreachable!("{error}").is_empty());
}

#[test]
fn readiness_never_approves_machine_effects() {
    let empty = MachineAdoptionReadiness::from_report(&AdoptionReport::default());
    assert_eq!(empty.decision, MachineAdoptionDecision::RequiresFreshControlPlan);
    assert!(!empty.machine_verified);
    let mut blocked = AdoptionReport::default();
    blocked.collisions.push("conflict".into());
    blocked.machine_class_mismatch = true;
    blocked.missing_secret_refs.insert("credential:missing".into());
    let decision = MachineAdoptionReadiness::from_report(&blocked);
    assert_eq!(decision.decision, MachineAdoptionDecision::Blocked);
    assert_eq!(decision.blockers.len(), 3);
    assert!(!decision.machine_verified);
}

#[test]
fn backup_inspection_validates_real_sqlite_without_restoring() {
    let dir = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let active_path = dir.path().join("active.db");
    let backup_path = dir.path().join("source-backup.db");
    let mut local = LocalLibrary::open(&active_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    local
        .create_intent(&req("backup-intent"), &intent("backup"))
        .unwrap_or_else(|error| unreachable!("{error}"));
    local.backup_to(&backup_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let before = fs::read(&active_path).unwrap_or_else(|error| unreachable!("{error}"));
    let inspection = inspect_backup_read_only(&backup_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(inspection.file_size > 0);
    assert_eq!(inspection.sha256.len(), 64);
    assert_eq!(before, fs::read(&active_path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let bad_path = dir.path().join("bad.db");
    fs::write(&bad_path, b"not a SQLite backup")
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(inspect_backup_read_only(&bad_path).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&backup_path, dir.path().join("link.db"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(inspect_backup_read_only(dir.path().join("link.db")).is_err());
    }
}
