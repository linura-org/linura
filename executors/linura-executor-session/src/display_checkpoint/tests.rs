use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

// Explicit synthetic private envelope. Storage tests exercise framing and
// immutable dispatch correlation; these fields are not native recovery proof.
fn payload(dispatch: &ComponentDigest, preimage: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let digest = dispatch.to_hex();
    for index in 0..19 {
        let field = match index {
            0 => b"linura.native-display.recovery-preimage.v1".as_slice(),
            7 => digest.as_bytes(),
            18 => preimage,
            _ => b"synthetic-comparison-only".as_slice(),
        };
        result.extend_from_slice(&(field.len() as u64).to_be_bytes());
        result.extend_from_slice(field);
    }
    result
}
struct Fixture {
    path: PathBuf,
    fd: OwnedFd,
    uid: u32,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "linura-display-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let fd = fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        Self {
            path,
            fd,
            uid: rustix::process::geteuid().as_raw(),
        }
    }
    fn name(&self, byte: u8) -> PathBuf {
        self.path.join(format!(
            "attempt-{}.checkpoint",
            ComponentDigest::from_bytes([byte; 32]).to_hex()
        ))
    }
    fn reserve(&self, byte: u8, bytes: &[u8]) -> Result<(), String> {
        let dispatch = ComponentDigest::from_bytes([byte; 32]);
        reserve_at(&self.fd, self.uid, &dispatch, &payload(&dispatch, bytes))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.path);
    }
}
#[test]
fn original_preimage_is_immutable_across_reopen_and_redelivery() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .reserve(1, b"explicit synthetic original preimage")
            .is_ok()
    );
    let original = std::fs::read(fixture.name(1)).unwrap_or_else(|e| unreachable!("{e}"));
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(
        reserve_at(
            &reopened,
            fixture.uid,
            &ComponentDigest::from_bytes([1; 32]),
            &payload(&ComponentDigest::from_bytes([1; 32]), b"substituted")
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(fixture.name(1)).unwrap_or_else(|e| unreachable!("{e}")),
        original
    );
    assert!(fixture.reserve(2, b"separate original preimage").is_ok());
    for byte in [1, 2] {
        let fd = fs::open(
            fixture.name(byte),
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(check_record(fd, fixture.uid, &ComponentDigest::from_bytes([byte; 32])).is_ok());
    }
}
#[test]
fn torn_corrupt_unknown_or_substituted_history_fences_new_effects() {
    for kind in 0..6 {
        let fixture = Fixture::new();
        assert!(fixture.reserve(1, b"synthetic original preimage").is_ok());
        let old = fixture.name(1);
        match kind {
            0 => std::fs::write(&old, MAGIC).unwrap_or_else(|e| unreachable!("{e}")),
            1 => {
                let mut bytes = std::fs::read(&old).unwrap_or_else(|e| unreachable!("{e}"));
                bytes[HEADER] ^= 1;
                std::fs::write(&old, bytes).unwrap_or_else(|e| unreachable!("{e}"));
            }
            2 => std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o640))
                .unwrap_or_else(|e| unreachable!("{e}")),
            3 => std::fs::hard_link(&old, fixture.name(3)).unwrap_or_else(|e| unreachable!("{e}")),
            4 => std::os::unix::fs::symlink(&old, fixture.name(3))
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::write(fixture.path.join("unknown"), b"not a checkpoint")
                .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(
            fixture.reserve(2, b"must not be dispatched").is_err(),
            "{kind}"
        );
        assert!(!fixture.name(2).exists());
        assert!(old.exists()); // Failed history is never removed or repaired.
    }
}
#[test]
fn exclusive_directory_lock_bounds_concurrency_and_is_released_on_refusal() {
    let fixture = Fixture::new();
    let separate = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    fs::flock(&separate, FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(fixture.reserve(1, b"synthetic preimage").is_err());
    fs::flock(&separate, FlockOperation::Unlock).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(fixture.reserve(1, b"synthetic preimage").is_ok());
    assert!(fixture.reserve(1, b"duplicate").is_err());
    assert!(fixture.reserve(2, b"new synthetic preimage").is_ok());
}
#[test]
fn bounds_and_private_owner_permissions_are_required_before_publication() {
    let fixture = Fixture::new();
    assert!(
        reserve_at(
            &fixture.fd,
            fixture.uid,
            &ComponentDigest::from_bytes([1; 32]),
            &[]
        )
        .is_err()
    );
    assert!(fixture.reserve(1, &vec![0; MAX_PAYLOAD + 1]).is_err());
    assert!(fixture.reserve(0, b"zero correlation").is_err());
    assert!(
        reserve_at(
            &fixture.fd,
            fixture.uid.saturating_add(1),
            &ComponentDigest::from_bytes([1; 32]),
            &payload(&ComponentDigest::from_bytes([1; 32]), b"wrong owner")
        )
        .is_err()
    );
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o750))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(fixture.reserve(1, b"not private").is_err());
    assert!(!fixture.name(1).exists());
}

#[test]
fn retention_exhaustion_refuses_without_overwriting_or_deleting_history() {
    let fixture = Fixture::new();
    for i in 0..MAX_RECORDS {
        let number = u16::try_from(i + 1).unwrap_or_else(|e| unreachable!("{e}"));
        let mut key = [0; 32];
        key[30..].copy_from_slice(&number.to_be_bytes());
        assert!(
            reserve_at(
                &fixture.fd,
                fixture.uid,
                &ComponentDigest::from_bytes(key),
                &payload(
                    &ComponentDigest::from_bytes(key),
                    b"explicit synthetic retention fixture"
                ),
            )
            .is_ok()
        );
    }
    assert!(
        fixture
            .reserve(42, b"must not retire old history to make room")
            .is_err()
    );
    assert!(!fixture.name(42).exists());
    assert_eq!(
        std::fs::read_dir(&fixture.path)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .count(),
        MAX_RECORDS
    );
    let max = Fixture::new();
    let overhead = payload(&ComponentDigest::from_bytes([1; 32]), &[]).len();
    assert!(max.reserve(1, &vec![b'x'; MAX_PAYLOAD - overhead]).is_ok());
    assert_eq!(
        std::fs::metadata(max.name(1))
            .unwrap_or_else(|e| unreachable!("{e}"))
            .len(),
        (MAX_PAYLOAD + HEADER) as u64
    );
}

#[test]
fn a_valid_checkpoint_cannot_be_renamed_or_copied_to_another_dispatch() {
    for copied in [false, true] {
        let fixture = Fixture::new();
        assert!(fixture.reserve(1, b"original private preimage").is_ok());
        if copied {
            std::fs::copy(fixture.name(1), fixture.name(2)).unwrap_or_else(|e| unreachable!("{e}"));
        } else {
            std::fs::rename(fixture.name(1), fixture.name(2))
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        assert!(
            fixture
                .reserve(3, b"must not pass substituted history")
                .is_err()
        );
        assert!(!fixture.name(3).exists());
        assert!(fixture.name(2).exists());
        if !copied {
            // The original dispatch must not be re-reserved after a rename.
            assert!(fixture.reserve(1, b"must not redeliver").is_err());
            assert!(!fixture.name(1).exists());
        }
    }
}

#[test]
fn private_envelope_framing_and_dispatch_are_checked_before_reservation() {
    let fixture = Fixture::new();
    let dispatch = ComponentDigest::from_bytes([1; 32]);
    let original = payload(&dispatch, b"private historical bytes");
    assert_eq!(
        NativeDisplayRecoveryCheckpoint::stored_dispatch(&original),
        Ok(dispatch)
    );
    for end in 0..original.len() {
        assert!(
            NativeDisplayRecoveryCheckpoint::stored_dispatch(&original[..end]).is_err(),
            "truncation {end}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    let mut huge_length = original.clone();
    huge_length[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut wrong_domain = original.clone();
    wrong_domain[8] ^= 1;
    let mut invalid_utf8 = original.clone();
    invalid_utf8[8] = 0xff;
    let digest = ComponentDigest::from_bytes([0xab; 32]);
    let canonical = payload(&digest, b"preimage");
    let mut uppercase_dispatch = canonical.clone();
    let digest_offset = canonical
        .windows(64)
        .position(|v| v == digest.to_hex().as_bytes())
        .unwrap_or_else(|| unreachable!());
    uppercase_dispatch[digest_offset..digest_offset + 64].make_ascii_uppercase();
    for bad in [
        trailing,
        huge_length,
        wrong_domain,
        invalid_utf8,
        uppercase_dispatch,
        payload(&ComponentDigest::from_bytes([0; 32]), b"zero dispatch"),
    ] {
        assert!(NativeDisplayRecoveryCheckpoint::stored_dispatch(&bad).is_err());
        assert!(reserve_at(&fixture.fd, fixture.uid, &dispatch, &bad).is_err());
        assert!(!fixture.name(1).exists());
    }
    assert!(
        reserve_at(
            &fixture.fd,
            fixture.uid,
            &ComponentDigest::from_bytes([2; 32]),
            &original
        )
        .is_err()
    );
    assert!(!fixture.name(2).exists());
}

#[test]
fn a_valid_outer_checksum_does_not_hide_a_malformed_private_envelope() {
    for malformed in [b"not a framed checkpoint".as_slice(), b"\xff"] {
        let fixture = Fixture::new();
        assert!(fixture.reserve(1, b"original preimage").is_ok());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&Sha256::digest(malformed));
        bytes.extend_from_slice(&(malformed.len() as u64).to_be_bytes());
        bytes.extend_from_slice(malformed);
        std::fs::write(fixture.name(1), &bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(fixture.reserve(2, b"must not dispatch").is_err());
        assert!(!fixture.name(2).exists());
        assert_eq!(
            std::fs::read(fixture.name(1)).unwrap_or_else(|e| unreachable!("{e}")),
            bytes
        );
    }
}

#[test]
fn retained_preimage_reads_are_private_exact_locked_and_non_creating() {
    let fixture = Fixture::new();
    let dispatch = ComponentDigest::from_bytes([1; 32]);
    assert!(load_at(&fixture.fd, fixture.uid, &dispatch).is_err());
    assert!(!fixture.name(1).exists());
    assert!(fixture.reserve(1, b"original private preimage").is_ok());
    assert_eq!(
        load_at(&fixture.fd, fixture.uid, &dispatch),
        Ok(payload(&dispatch, b"original private preimage"))
    );
    assert!(load_at(&fixture.fd, fixture.uid + 1, &dispatch).is_err());
    let separate = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    fs::flock(&separate, FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(load_at(&fixture.fd, fixture.uid, &dispatch).is_err());
    fs::flock(&separate, FlockOperation::Unlock).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(load_at(&fixture.fd, fixture.uid, &dispatch).is_ok());
    std::fs::rename(fixture.name(1), fixture.name(2)).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(load_at(&fixture.fd, fixture.uid, &dispatch).is_err());
    assert!(
        load_at(
            &fixture.fd,
            fixture.uid,
            &ComponentDigest::from_bytes([2; 32])
        )
        .is_err()
    );
    assert!(!fixture.name(1).exists());
    assert!(fixture.name(2).exists());
}

#[test]
fn startup_never_ignores_retained_unknown_or_busy_history() {
    let fixture = Fixture::new();
    assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(true));
    assert!(startup_clear_at(&fixture.fd, fixture.uid + 1).is_err());
    let writer = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    fs::flock(&writer, FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(startup_clear_at(&fixture.fd, fixture.uid).is_err());
    fs::flock(&writer, FlockOperation::Unlock).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(fixture.reserve(1, b"historical original").is_ok());
    assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
    std::fs::write(fixture.name(1), b"torn private record").unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
    std::fs::rename(fixture.name(1), fixture.path.join("unknown-history"))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
    assert_eq!(
        std::fs::read(fixture.path.join("unknown-history")).unwrap_or_else(|e| unreachable!("{e}")),
        b"torn private record"
    );
}

pub(crate) fn restoration(original: u8, attempt: u8) -> NativeDisplayRestorationReservation {
    restoration_on_seat(
        original,
        attempt,
        if original == 4 { "seat1" } else { "seat0" },
    )
}
fn restoration_on_seat(
    original: u8,
    attempt: u8,
    seat: &str,
) -> NativeDisplayRestorationReservation {
    let old = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3".replace("seat0",seat);
    let new = old.replace("c2:42", "c3:99").replace(
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    let lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1";
    let original_intent = format!(
        "LNDI:1;{lock};LNDL:1;{old};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{old};1:2:enabled:1920:1080:60000:1000:0:100:0:-;"
    );
    let replacement = original_intent
        .replace(&old, &new)
        .replace("c2:42", "c3:99")
        .replace("0:100:0:-", "0:0:0:-");
    let mut material = "LNRI:1;".to_owned();
    let dispatch = ComponentDigest::from_bytes([original; 32]).to_hex();
    for field in [
        "request:v010:display-layout:original",
        &dispatch,
        &"b".repeat(64),
        &"c".repeat(64),
        &original_intent,
        &replacement,
        "1:2:1:2;",
    ] {
        material.push_str(&format!("{}:{field};", field.len()));
    }
    let effect = linura_provider_sdk::display_restoration_effect(&material)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = linura_provider_sdk::ExecutionBinding::new(
        format!("transaction:restore-{attempt}"),
        0,
        1,
        ComponentDigest::from_bytes([1; 32]),
        ComponentDigest::from_bytes([attempt; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    NativeDisplayRestorationReservation::new(&material, &binding)
        .unwrap_or_else(|e| unreachable!("{e}"))
}
fn reserve_recovery(
    fixture: &Fixture,
    record: &NativeDisplayRestorationReservation,
) -> Result<(), String> {
    reserve_kind_at(
        &fixture.fd,
        fixture.uid,
        &record.binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::Restoration,
    )
}
#[test]
fn restoration_is_exclusive_durable_and_cannot_supersede_an_unresolved_attempt() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .reserve(1, b"synthetic original comparison data")
            .is_ok()
    );
    let before = std::fs::read(fixture.name(1)).unwrap_or_else(|e| unreachable!("{e}"));
    let record = restoration(1, 2);
    let scope = record
        .decoded_material()
        .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(read_restoration_at(&fixture.fd, fixture.uid, &scope).is_err());
    assert!(reserve_recovery(&fixture, &record).is_ok());
    let observed = read_restoration_at(&fixture.fd, fixture.uid, &scope)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(observed.canonical_bytes(), record.canonical_bytes());
    assert!(read_restoration_at(&fixture.fd, fixture.uid + 1, &scope).is_err());
    let other = restoration(4, 5)
        .decoded_material()
        .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(read_restoration_at(&fixture.fd, fixture.uid, &other).is_err());
    let path = fixture
        .path
        .join(Kind::Restoration.name(&record.binding().dispatch_digest));
    let saved = std::fs::read(&path).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(saved.starts_with(RESTORATION_MAGIC));
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    assert!(reserve_recovery(&fixture, &record).is_err());
    assert!(reserve_recovery(&fixture, &restoration(1, 3)).is_err());
    assert!(reserve_recovery(&fixture, &restoration(6, 7)).is_err());
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(
        reserve_kind_at(
            &reopened,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::Restoration
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(path).unwrap_or_else(|e| unreachable!("{e}")),
        saved
    );
    assert_eq!(
        std::fs::read(fixture.name(1)).unwrap_or_else(|e| unreachable!("{e}")),
        before
    );
    assert!(reserve_recovery(&fixture, &restoration(4, 5)).is_ok());
}
#[test]
fn corruption_or_type_substitution_of_restoration_history_fences_all_new_reservations() {
    for kind in 0..4 {
        let fixture = Fixture::new();
        let record = restoration(1, 2);
        assert!(reserve_recovery(&fixture, &record).is_ok());
        let path = fixture
            .path
            .join(Kind::Restoration.name(&record.binding().dispatch_digest));
        match kind {
            0 => std::fs::write(&path, RESTORATION_MAGIC).unwrap_or_else(|e| unreachable!("{e}")),
            1 => {
                let mut bytes = std::fs::read(&path).unwrap_or_else(|e| unreachable!("{e}"));
                bytes[HEADER] ^= 1;
                std::fs::write(&path, bytes).unwrap_or_else(|e| unreachable!("{e}"));
            }
            2 => std::fs::rename(
                &path,
                fixture
                    .path
                    .join(Kind::Original.name(&record.binding().dispatch_digest)),
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::rename(
                &path,
                fixture
                    .path
                    .join(Kind::Restoration.name(&ComponentDigest::from_bytes([8; 32]))),
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(fixture.reserve(9, b"no dispatch").is_err());
        assert!(reserve_recovery(&fixture, &restoration(4, 5)).is_err());
        let scope = record
            .decoded_material()
            .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(read_restoration_at(&fixture.fd, fixture.uid, &scope).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
}

#[test]
fn read_only_restoration_lookup_refuses_unknown_or_duplicate_history_without_repair() {
    use std::os::unix::fs::OpenOptionsExt;
    for duplicate in [false, true] {
        let fixture = Fixture::new();
        let record = restoration(1, 2);
        assert!(reserve_recovery(&fixture, &record).is_ok());
        let saved = std::fs::read(
            fixture
                .path
                .join(Kind::Restoration.name(&record.binding().dispatch_digest)),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let scope = record
            .decoded_material()
            .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        let next = restoration(1, 3);
        let name = if duplicate {
            Kind::Restoration.name(&next.binding().dispatch_digest)
        } else {
            "unknown-history".into()
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.path.join(name))
            .unwrap_or_else(|e| unreachable!("{e}"));
        let payload = next.canonical_bytes();
        for bytes in [
            RESTORATION_MAGIC,
            &Sha256::digest(&payload),
            &(payload.len() as u64).to_be_bytes(),
            &payload,
        ] {
            file.write_all(bytes)
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        file.sync_all().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(read_restoration_at(&fixture.fd, fixture.uid, &scope).is_err());
        assert_eq!(
            std::fs::read(
                fixture
                    .path
                    .join(Kind::Restoration.name(&record.binding().dispatch_digest))
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
            saved
        );
        assert_eq!(
            std::fs::read_dir(&fixture.path)
                .unwrap_or_else(|e| unreachable!("{e}"))
                .count(),
            2
        );
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
}

// Synthetic metadata correlation only; no live Root/PAM/native evidence.
pub(crate) fn terminal(
    original: u8,
    attempt: u8,
    terminal: u8,
    seat: &str,
) -> (
    NativeDisplayRestorationReservation,
    NativeDisplayFinalizationReservation,
) {
    let source = restoration_on_seat(original, attempt, seat);
    let request =
        linura_core::RequestId::new(format!("request:v010:display-restoration:r-{attempt}"))
            .unwrap_or_else(|e| unreachable!("{e}"));
    let mut hash = Sha256::new();
    for field in [
        "linura.transaction.id.v1",
        "unix:uid:1000",
        request.as_str(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let transaction = format!(
        "transaction:v1:{}",
        ComponentDigest::from_bytes(hash.finalize().into()).to_hex()
    );
    let effect = linura_provider_sdk::display_restoration_effect(source.material())
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = linura_provider_sdk::ExecutionBinding::new(
        transaction,
        0,
        1,
        source.binding().authority_binding_digest,
        source.binding().authority_use_digest,
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let retained = NativeDisplayRestorationReservation::new(source.material(), &binding)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let material = retained
        .decoded_material()
        .unwrap_or_else(|e| unreachable!("{e}"));
    let text = linura_core::DisplayFinalizationMaterial::encode(
        &request,
        &retained.binding().dispatch_digest.to_hex(),
        &"e".repeat(64),
        &"f".repeat(64),
        1,
        material.replacement().lock(),
        retained.material(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let effect = linura_provider_sdk::display_finalization_effect(&text)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = linura_provider_sdk::ExecutionBinding::new(
        format!("transaction:terminal-{terminal}"),
        0,
        1,
        ComponentDigest::from_bytes([1; 32]),
        ComponentDigest::from_bytes([terminal; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let finalization = NativeDisplayFinalizationReservation::new(&text, &binding)
        .unwrap_or_else(|e| unreachable!("{e}"));
    (retained, finalization)
}
fn reserve_terminal(
    fixture: &Fixture,
    record: &NativeDisplayFinalizationReservation,
) -> Result<(), String> {
    reserve_kind_at(
        &fixture.fd,
        fixture.uid,
        &record.binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::Finalization,
    )
}
#[test]
fn terminal_reservation_needs_actual_parent_and_is_immutable_exclusive_and_reopenable() {
    let fixture = Fixture::new();
    let (parent, record) = terminal(1, 2, 3, "seat0");
    assert!(record.validate_restoration(&parent).is_ok());
    assert!(reserve_terminal(&fixture, &record).is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(
        read_finalization_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .is_none()
    );
    assert!(reserve_terminal(&fixture, &record).is_ok());
    let observed = read_finalization_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(
        observed.map(|value| value.canonical_bytes()),
        Some(record.canonical_bytes())
    );
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(
        read_finalization_at(&reopened, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .is_some()
    );
    assert!(reserve_terminal(&fixture, &record).is_err());
    let (_, competing) = terminal(1, 2, 4, "seat0");
    assert!(reserve_terminal(&fixture, &competing).is_err());
    assert!(read_finalization_at(&fixture.fd, fixture.uid + 1, &parent).is_err());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    let name = fixture
        .path
        .join(Kind::Finalization.name(&record.binding().dispatch_digest));
    let original = std::fs::read(&name).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(original.starts_with(FINALIZATION_MAGIC));
    assert_eq!(&original[HEADER..], record.canonical_bytes());
}

#[test]
fn quiescence_is_write_once_and_requires_exact_terminal_and_restoration_parents() {
    let fixture = Fixture::new();
    let (parent, record) = terminal(1, 2, 3, "seat0");
    let reserve = || {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::Quiescence,
        )
    };
    assert!(reserve().is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve().is_err());
    assert!(reserve_terminal(&fixture, &record).is_ok());
    assert!(
        !read_finalization_state_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .1
    );
    assert!(reserve().is_ok());
    let (readback, durable) = read_finalization_state_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(durable);
    assert_eq!(
        readback.map(|value| value.canonical_bytes()),
        Some(record.canonical_bytes())
    );
    assert!(reserve().is_err());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    let marker = fixture
        .path
        .join(Kind::Quiescence.name(&record.binding().dispatch_digest));
    let bytes = std::fs::read(&marker).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(bytes.starts_with(QUIESCENCE_MAGIC));
    assert_eq!(&bytes[HEADER..], record.canonical_bytes());
}

#[test]
fn root_retirement_preparation_is_parent_bound_synced_and_write_once() {
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let preparation = NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let write = |record: &NativeDisplayRetirementPreparation| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.terminal().binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::RetirementPreparation,
        )
    };
    assert!(write(&preparation).is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
    assert!(write(&preparation).is_err()); // Not before the durable native LNRQ marker.
    assert!(
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            &terminal.canonical_bytes(),
            Kind::Quiescence,
        )
        .is_ok()
    );
    assert!(write(&preparation).is_ok());
    let observed = read_retirement_preparation_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!("retirement preparation missing after synced publication"));
    assert_eq!(observed.canonical_bytes(), preparation.canonical_bytes());
    assert!(write(&preparation).is_err()); // Never redeliver after a lost ACK.
    let substituted = NativeDisplayRetirementPreparation::new(
        &terminal,
        8,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([5; 32]),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(write(&substituted).is_err());
    let record = fixture
        .path
        .join(Kind::RetirementPreparation.name(&terminal.binding().dispatch_digest));
    let bytes = std::fs::read(&record).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(bytes.starts_with(RETIREMENT_PREPARATION_MAGIC));
    assert_eq!(&bytes[HEADER..], preparation.canonical_bytes());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
}

#[test]
fn corrupt_or_orphan_root_retirement_preparation_quarantines_every_scope() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let (parent, finished) = terminal(1, 2, 3, "seat0");
        let (other, _) = terminal(11, 12, 13, "seat12");
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &finished).is_ok());
        assert!(
            reserve_kind_at(
                &fixture.fd,
                fixture.uid,
                &finished.binding().dispatch_digest,
                &finished.canonical_bytes(),
                Kind::Quiescence,
            )
            .is_ok()
        );
        let preparation = NativeDisplayRetirementPreparation::new(
            &finished,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            reserve_kind_at(
                &fixture.fd,
                fixture.uid,
                &finished.binding().dispatch_digest,
                &preparation.canonical_bytes(),
                Kind::RetirementPreparation,
            )
            .is_ok()
        );
        assert!(reserve_recovery(&fixture, &other).is_ok());
        let checkpoint = fixture
            .path
            .join(Kind::RetirementPreparation.name(&finished.binding().dispatch_digest));
        let parent_path = fixture
            .path
            .join(Kind::Quiescence.name(&finished.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(parent_path).unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(checkpoint, b"torn preparation")
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::set_permissions(checkpoint, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(read_retirement_preparation_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(read_finalization_state_at(&fixture.fd, fixture.uid, &other).is_err());
        let (new_parent, _) = terminal(21, 22, 23, "seat22");
        assert!(reserve_recovery(&fixture, &new_parent).is_err());
    }
}

#[test]
fn missing_or_corrupt_quiescence_parent_cannot_repair_or_admit() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let (parent, record) = terminal(1, 2, 3, "seat0");
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &record).is_ok());
        assert!(
            reserve_kind_at(
                &fixture.fd,
                fixture.uid,
                &record.binding().dispatch_digest,
                &record.canonical_bytes(),
                Kind::Quiescence,
            )
            .is_ok()
        );
        let terminal_path = fixture
            .path
            .join(Kind::Finalization.name(&record.binding().dispatch_digest));
        let marker_path = fixture
            .path
            .join(Kind::Quiescence.name(&record.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(&terminal_path).unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(&marker_path, b"torn quiescence marker")
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(read_finalization_state_at(&fixture.fd, fixture.uid, &parent).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
        assert!(reserve_terminal(&fixture, &record).is_err());
    }
}

#[test]
fn unrelated_orphan_quiescence_fences_all_scope_reads_and_writes() {
    let fixture = Fixture::new();
    let (first_parent, first_terminal) = terminal(1, 2, 3, "seat0");
    let (other_parent, other_terminal) = terminal(11, 12, 13, "seat12");
    assert!(reserve_recovery(&fixture, &first_parent).is_ok());
    assert!(reserve_terminal(&fixture, &first_terminal).is_ok());
    assert!(
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &first_terminal.binding().dispatch_digest,
            &first_terminal.canonical_bytes(),
            Kind::Quiescence,
        )
        .is_ok()
    );
    assert!(reserve_recovery(&fixture, &other_parent).is_ok());
    assert!(reserve_terminal(&fixture, &other_terminal).is_ok());
    // Deleting an unrelated synced terminal is adversarial corruption, not a
    // qualifying retire. Its surviving marker must poison all other scopes.
    std::fs::remove_file(
        fixture
            .path
            .join(Kind::Finalization.name(&first_terminal.binding().dispatch_digest)),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(read_finalization_state_at(&fixture.fd, fixture.uid, &other_parent).is_err());
    assert!(read_finalization_at(&fixture.fd, fixture.uid, &other_parent).is_err());
    let (new_parent, _) = terminal(21, 22, 23, "seat22");
    assert!(reserve_recovery(&fixture, &new_parent).is_err());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
}

#[test]
fn unrelated_missing_restoration_parent_fences_quiescence_and_other_reads() {
    let fixture = Fixture::new();
    let (parent, terminal_record) = terminal(1, 2, 3, "seat0");
    let (other_parent, _) = terminal(11, 12, 13, "seat12");
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal_record).is_ok());
    assert!(reserve_recovery(&fixture, &other_parent).is_ok());
    // A complete terminal by itself cannot retain authority if the unrelated
    // restoration parent disappeared or its bytes were substituted.
    std::fs::remove_file(
        fixture
            .path
            .join(Kind::Restoration.name(&parent.binding().dispatch_digest)),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let other_scope = other_parent
        .decoded_material()
        .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(read_restoration_at(&fixture.fd, fixture.uid, &other_scope).is_err());
    assert!(read_finalization_state_at(&fixture.fd, fixture.uid, &other_parent).is_err());
    let (new_parent, _) = terminal(21, 22, 23, "seat22");
    assert!(reserve_recovery(&fixture, &new_parent).is_err());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
}

#[test]
fn corrupted_or_substituted_terminal_history_blocks_all_reads_and_reservations_without_repair() {
    for fault in 0..7 {
        let fixture = Fixture::new();
        let (parent, record) = terminal(1, 2, 3, "seat0");
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &record).is_ok());
        let name = fixture
            .path
            .join(Kind::Finalization.name(&record.binding().dispatch_digest));
        let original = std::fs::read(&name).unwrap_or_else(|e| unreachable!("{e}"));
        match fault {
            0 => std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(&name, b"torn terminal reservation")
                .unwrap_or_else(|e| unreachable!("{e}")),
            2 => {
                let mut changed = original.clone();
                changed.push(0);
                std::fs::write(&name, &changed).unwrap_or_else(|e| unreachable!("{e}"));
            }
            3 => {
                let mut changed = original.clone();
                changed[HEADER] ^= 1;
                std::fs::write(&name, &changed).unwrap_or_else(|e| unreachable!("{e}"));
            }
            4 => std::fs::hard_link(&name, fixture.path.join("linked-terminal"))
                .unwrap_or_else(|e| unreachable!("{e}")),
            5 => {
                std::fs::remove_file(&name).unwrap_or_else(|e| unreachable!("{e}"));
                std::os::unix::fs::symlink(
                    fixture
                        .path
                        .join(Kind::Restoration.name(&parent.binding().dispatch_digest)),
                    &name,
                )
                .unwrap_or_else(|e| unreachable!("{e}"));
            }
            _ => {
                std::fs::rename(
                    &name,
                    fixture
                        .path
                        .join(Kind::Original.name(&record.binding().dispatch_digest)),
                )
                .unwrap_or_else(|e| unreachable!("{e}"));
            }
        }
        assert!(read_finalization_at(&fixture.fd, fixture.uid, &parent).is_err());
        let scope = parent
            .decoded_material()
            .and_then(|value| value.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(read_restoration_at(&fixture.fd, fixture.uid, &scope).is_err());
        assert!(reserve_terminal(&fixture, &record).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
}
#[test]
fn terminal_readback_requires_the_same_actual_parent_during_its_locked_scan() {
    for substitute in [false, true] {
        let fixture = Fixture::new();
        let (parent, record) = terminal(1, 2, 3, "seat0");
        assert!(read_finalization_at(&fixture.fd, fixture.uid, &parent).is_err());
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &record).is_ok());
        std::fs::remove_file(
            fixture
                .path
                .join(Kind::Restoration.name(&parent.binding().dispatch_digest)),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        if substitute {
            let (other, _) = terminal(1, 4, 5, "seat0");
            assert_ne!(other.canonical_bytes(), parent.canonical_bytes());
            // A missing parent now globally quarantines every new admission.
            // Exercise an actual on-disk substitution from a separately valid
            // fixture instead of asking the protected writer to repair history.
            assert!(reserve_recovery(&fixture, &other).is_err());
            let foreign = Fixture::new();
            assert!(reserve_recovery(&foreign, &other).is_ok());
            std::fs::copy(
                foreign
                    .path
                    .join(Kind::Restoration.name(&other.binding().dispatch_digest)),
                fixture
                    .path
                    .join(Kind::Restoration.name(&other.binding().dispatch_digest)),
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
        }
        assert!(read_finalization_at(&fixture.fd, fixture.uid, &parent).is_err());
        assert!(reserve_terminal(&fixture, &record).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
}
#[test]
fn terminal_reservation_does_not_increase_or_evict_full_checkpoint_quota() {
    let fixture = Fixture::new();
    let (parent, record) = terminal(1, 2, 3, "seat0");
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    for byte in 1..=255u8 {
        assert!(
            fixture
                .reserve(byte, b"bounded retained quota fixture")
                .is_ok()
        );
    }
    assert!(reserve_terminal(&fixture, &record).is_err());
    assert_eq!(
        std::fs::read_dir(&fixture.path)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .count(),
        MAX_RECORDS
    );
}
