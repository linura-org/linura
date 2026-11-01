use linura_core::{
    Actor, ActorId, ActorKind, IntentId, ProfileId, RequestId, SetupId, ValidationError,
};
use linura_intent::{Intent, IntentStatus, MachineClass, MachineProfile, Setup};
use linura_library::{LibraryError, LocalLibrary, MAX_CATALOG_PAGE_SIZE};
use tempfile::tempdir;

fn valid<T>(value: Result<T, ValidationError>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error}"))
}

fn request(value: &str) -> RequestId {
    valid(RequestId::new(format!("request:s26-{value}")))
}

fn intent(value: &str) -> Intent {
    Intent {
        id: valid(IntentId::new(format!("intent:{value}"))),
        actor: Actor {
            id: valid(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        },
        statement: format!("Manage {value}"),
        status: IntentStatus::Active,
        requirements: vec![],
        supersedes: vec![],
    }
}

fn setup(value: &str, intent: &Intent, revision: u32) -> Setup {
    Setup {
        id: valid(SetupId::new(format!("setup:{value}"))),
        name: "Same visible title".into(),
        description: format!("{value} revision {revision}"),
        revision,
        intent_ids: vec![intent.id.clone()],
        included_setup_ids: vec![],
        portable_constraints: vec![],
        required_secret_refs: vec![],
        hardware_hints: vec![],
    }
}

#[test]
fn bounded_catalog_preserves_exact_revisions_order_and_reopen() {
    let dir = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let path = dir.path().join("library.db");
    let mut library = LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
    let first = intent("alpha");
    let second = intent("beta");
    library
        .create_intent(&request("first"), &first)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .create_intent(&request("second"), &second)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let a = setup("alpha", &first, 1);
    let b = setup("beta", &second, 1);
    library
        .save_setup(&request("setup-first"), &a, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    library
        .save_setup(&request("setup-second"), &b, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut next = a.clone();
    next.revision = 2;
    next.description = "new immutable revision".into();
    library
        .save_setup(&request("setup-first-v2"), &next, Some(1))
        .unwrap_or_else(|error| unreachable!("{error}"));

    let first_page = library
        .catalog_setups_page(None, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(first_page.items.len(), 1);
    assert_eq!(first_page.items[0].setup.id, a.id);
    assert_eq!(first_page.items[0].setup.revision, 2);
    assert_eq!(first_page.items[0].setup.name, b.name);
    let second_page = library
        .catalog_setups_page(first_page.next_after.as_ref(), 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(second_page.items[0].setup.id, b.id);
    assert!(second_page.next_after.is_none());
    assert_eq!(
        library
            .setup_revision(&a.id, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .setup
            .description,
        a.description
    );
    let intents = library
        .catalog_intents_page(None, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(intents.items[0].intent.id, first.id);
    let second_intents = library
        .catalog_intents_page(intents.next_after.as_ref(), 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(second_intents.items[0].intent.id, second.id);
    assert!(second_intents.next_after.is_none());
    drop(library);

    let mut reopened = LocalLibrary::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
    let page = reopened
        .catalog_setups_page(None, 2)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].setup.revision, 2);
}

#[test]
fn profiles_retain_exact_setup_references() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let source = intent("profile");
    library
        .create_intent(&request("profile-intent"), &source)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let base = setup("profile", &source, 1);
    library
        .save_setup(&request("profile-setup"), &base, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let profile = MachineProfile {
        id: valid(ProfileId::new("profile:workstation")),
        name: "Workstation".into(),
        machine_class: MachineClass::Workstation,
        setup_ids: vec![base.id.clone()],
        intent_ids: vec![],
        portable_constraints: vec![],
        hardware_hints: vec![],
    };
    library
        .save_profile(&request("profile"), &profile, 1, None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let page = library
        .catalog_profiles_page(None, 1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].revision, 1);
    assert_eq!(page.items[0].setup_revisions[0].id, base.id);
    assert!(page.next_after.is_none());
}

#[test]
fn invalid_page_sizes_fail_closed_and_reads_do_not_create_records() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    for size in [0, MAX_CATALOG_PAGE_SIZE + 1, usize::MAX] {
        assert!(matches!(
            library.catalog_intents_page(None, size),
            Err(LibraryError::Validation(_))
        ));
        assert!(matches!(
            library.catalog_setups_page(None, size),
            Err(LibraryError::Validation(_))
        ));
        assert!(matches!(
            library.catalog_profiles_page(None, size),
            Err(LibraryError::Validation(_))
        ));
    }
    assert!(
        library
            .catalog_intents_page(None, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .items
            .is_empty()
    );
    assert!(
        library
            .catalog_setups_page(None, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .items
            .is_empty()
    );
    assert!(
        library
            .catalog_profiles_page(None, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .items
            .is_empty()
    );
}
