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
fn durable_root_retired_held_requires_exact_prepared_lineage_and_is_one_use() {
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let preparation = NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let publish = |kind| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            &preparation.canonical_bytes(),
            kind,
        )
    };
    assert!(publish(Kind::RootRetiredHeld).is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
    assert!(publish(Kind::RootRetiredHeld).is_err());
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
    assert!(publish(Kind::RootRetiredHeld).is_err());
    assert!(publish(Kind::RetirementPreparation).is_ok());
    assert!(
        read_root_retired_held_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .is_none()
    );
    assert!(publish(Kind::RootRetiredHeld).is_ok());
    let observed = read_root_retired_held_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!("synced RootRetiredHeld marker unavailable"));
    assert_eq!(observed.canonical_bytes(), preparation.canonical_bytes());
    assert!(publish(Kind::RootRetiredHeld).is_err());
    assert!(
        read_finalization_state_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .1
    );
    let native_record = fixture
        .path
        .join(Kind::RootRetiredHeld.name(&terminal.binding().dispatch_digest));
    let bytes = std::fs::read(&native_record).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(bytes.starts_with(ROOT_RETIRED_HELD_MAGIC));
    assert_eq!(&bytes[HEADER..], preparation.canonical_bytes());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
}

#[test]
fn native_release_reservation_is_write_once_after_exact_root_held_parent() {
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let preparation = NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let publish = |kind| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            &preparation.canonical_bytes(),
            kind,
        )
    };
    assert!(publish(Kind::NativeReleaseReserved).is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
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
    assert!(publish(Kind::NativeReleaseReserved).is_err());
    assert!(publish(Kind::RetirementPreparation).is_ok());
    assert!(publish(Kind::NativeReleaseReserved).is_err());
    assert!(publish(Kind::RootRetiredHeld).is_ok());
    assert!(
        read_native_release_reserved_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .is_none()
    );
    assert!(publish(Kind::NativeReleaseReserved).is_ok());
    let observed = read_native_release_reserved_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|error| unreachable!("{error}"))
        .unwrap_or_else(|| unreachable!("native release reservation not durably visible"));
    assert_eq!(observed.canonical_bytes(), preparation.canonical_bytes());
    assert!(publish(Kind::NativeReleaseReserved).is_err()); // Lost reply does not retry.
    let conflicting = NativeDisplayRetirementPreparation::new(
        &terminal,
        8,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            &conflicting.canonical_bytes(),
            Kind::NativeReleaseReserved,
        )
        .is_err()
    );
    let path = fixture
        .path
        .join(Kind::NativeReleaseReserved.name(&terminal.binding().dispatch_digest));
    let bytes = std::fs::read(&path).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(bytes.starts_with(NATIVE_RELEASE_RESERVED_MAGIC));
    assert_eq!(&bytes[HEADER..], preparation.canonical_bytes());
    assert!(
        !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|error| unreachable!("{error}"))
    );
}

#[test]
fn native_release_spent_requires_exact_parent_is_synced_and_cannot_replay() {
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let preparation = NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let publish = |kind| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            &preparation.canonical_bytes(),
            kind,
        )
    };
    assert!(publish(Kind::NativeReleaseSpent).is_err());
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
    assert!(publish(Kind::NativeReleaseSpent).is_err());
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
    assert!(publish(Kind::RetirementPreparation).is_ok());
    assert!(publish(Kind::RootRetiredHeld).is_ok());
    assert!(publish(Kind::NativeReleaseSpent).is_err());
    assert!(publish(Kind::NativeReleaseReserved).is_ok());
    assert!(
        read_native_release_spent_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .is_none()
    );
    assert!(publish(Kind::NativeReleaseSpent).is_ok());
    let observed = read_native_release_spent_at(&fixture.fd, fixture.uid, &parent)
        .unwrap_or_else(|error| unreachable!("{error}"))
        .unwrap_or_else(|| unreachable!("synced native-release-spent missing"));
    assert_eq!(observed.canonical_bytes(), preparation.canonical_bytes());
    assert!(publish(Kind::NativeReleaseSpent).is_err());
    let path = fixture
        .path
        .join(Kind::NativeReleaseSpent.name(&terminal.binding().dispatch_digest));
    let bytes = std::fs::read(path).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(bytes.starts_with(NATIVE_RELEASE_SPENT_MAGIC));
    assert_eq!(&bytes[HEADER..], preparation.canonical_bytes());
    assert!(
        !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|error| unreachable!("{error}"))
    );
}

pub(crate) fn completion(
    parent: &NativeDisplayRestorationReservation,
    retirement: &NativeDisplayRetirementPreparation,
) -> NativeDisplayCompletionPreparation {
    use linura_observation::{
        DisplayNativeHandoffFacts, DisplayNativeHandoffLineage, DisplayNativeHandoffOutput,
        DisplayNativeHandoffWindow,
    };
    let material = retirement
        .terminal()
        .decoded_material()
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = retirement.terminal().binding();
    let scope = material
        .recovery_scope()
        .unwrap_or_else(|e| unreachable!("{e}"));
    let outputs = material
        .restoration()
        .mapping()
        .replacement()
        .outputs()
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let n = u32::try_from(index).unwrap_or_else(|_| unreachable!());
            (
                output.clone(),
                DisplayNativeHandoffOutput {
                    enabled: true,
                    connector: n + 1,
                    crtc: n + 11,
                    plane: n + 21,
                    framebuffer: n + 31,
                    spend_high_water: 5,
                    completed_commit: 6,
                },
            )
        })
        .collect();
    let frames = DisplayNativeHandoffFacts::new(
        scope,
        DisplayNativeHandoffLineage {
            checkpoint: material.restoration().original_checkpoint().into(),
            restoration_transaction: parent.binding().transaction_id.clone(),
            restoration_effect: parent.binding().effect_digest.to_hex(),
            restoration_dispatch: parent.binding().dispatch_digest.to_hex(),
            terminal_transaction: binding.transaction_id.clone(),
            terminal_effect: binding.effect_digest.to_hex(),
            terminal_dispatch: binding.dispatch_digest.to_hex(),
            terminal_link: material.terminal_link().into(),
            source_guard: material.restored_source_guard().into(),
            post_write_epoch: material.post_write_epoch(),
            security_epoch: 7,
        },
        DisplayNativeHandoffWindow {
            observed_unix_ms: 1001,
            observed_boot_ms: 101,
            deadline_unix_ms: 1200,
            deadline_boot_ms: 300,
        },
        outputs,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    NativeDisplayCompletionPreparation::new(
        retirement,
        ComponentDigest::from_bytes([5; 32]),
        ComponentDigest::from_bytes([6; 32]),
        &frames,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"))
}

#[test]
fn completion_preparation_and_spend_need_exact_ancestry_and_never_allow_replay() {
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let retirement = NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let record = completion(&parent, &retirement);
    let publish = |kind, bytes: &[u8]| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            bytes,
            kind,
        )
    };
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
    assert!(publish(Kind::Quiescence, &terminal.canonical_bytes()).is_ok());
    for kind in [
        Kind::RetirementPreparation,
        Kind::RootRetiredHeld,
        Kind::NativeReleaseReserved,
        Kind::NativeReleaseSpent,
    ] {
        // Every earlier phase is insufficient for either completion record.
        assert!(publish(Kind::CompletionPrepared, &record.canonical_bytes()).is_err());
        assert!(publish(Kind::CompletionSpent, &record.canonical_bytes()).is_err());
        assert!(publish(kind, &retirement.canonical_bytes()).is_ok());
    }
    assert!(publish(Kind::CompletionSpent, &record.canonical_bytes()).is_err());
    assert!(publish(Kind::CompletionPrepared, &record.canonical_bytes()).is_ok());
    assert!(publish(Kind::CompletionPrepared, &record.canonical_bytes()).is_err());
    let observed = read_completion_at(&fixture.fd, fixture.uid, &parent, false)
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!("synced preparation missing"));
    assert_eq!(observed.canonical_bytes(), record.canonical_bytes());
    assert!(
        read_completion_at(&fixture.fd, fixture.uid, &parent, true)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .is_none()
    );
    let different = NativeDisplayCompletionPreparation::new(
        &retirement,
        ComponentDigest::from_bytes([7; 32]),
        *record.verification_digest(),
        record.frames(),
        record.expires_at_unix_ms(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(Kind::CompletionSpent, &different.canonical_bytes()).is_err());
    assert!(publish(Kind::CompletionSpent, &record.canonical_bytes()).is_ok());
    assert!(publish(Kind::CompletionSpent, &record.canonical_bytes()).is_err());
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(
        read_completion_at(&reopened, fixture.uid, &parent, true)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!("synced spend missing"))
            .canonical_bytes(),
        record.canonical_bytes()
    );
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    assert!(read_completion_at(&fixture.fd, fixture.uid + 1, &parent, true).is_err());
}

#[test]
fn missing_torn_or_repermissioned_completion_ancestry_quarantines_other_scopes() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        let (parent, terminal) = terminal(1, 2, 3, "seat0");
        let (other, _) = self::terminal(11, 12, 13, "seat12");
        let retirement = NativeDisplayRetirementPreparation::new(
            &terminal,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let record = completion(&parent, &retirement);
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_recovery(&fixture, &other).is_ok());
        assert!(reserve_terminal(&fixture, &terminal).is_ok());
        for (kind, bytes) in [
            (Kind::Quiescence, terminal.canonical_bytes()),
            (Kind::RetirementPreparation, retirement.canonical_bytes()),
            (Kind::RootRetiredHeld, retirement.canonical_bytes()),
            (Kind::NativeReleaseReserved, retirement.canonical_bytes()),
            (Kind::NativeReleaseSpent, retirement.canonical_bytes()),
            (Kind::CompletionPrepared, record.canonical_bytes()),
            (Kind::CompletionSpent, record.canonical_bytes()),
        ] {
            assert!(
                reserve_kind_at(
                    &fixture.fd,
                    fixture.uid,
                    &terminal.binding().dispatch_digest,
                    &bytes,
                    kind
                )
                .is_ok()
            );
        }
        let path = fixture.path.join(if fault == 0 {
            Kind::NativeReleaseSpent.name(&terminal.binding().dispatch_digest)
        } else {
            Kind::CompletionPrepared.name(&terminal.binding().dispatch_digest)
        });
        match fault {
            0 | 1 => std::fs::remove_file(&path),
            2 => std::fs::write(&path, b"torn completion preparation"),
            _ => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)),
        }
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(read_completion_at(&fixture.fd, fixture.uid, &parent, true).is_err());
        assert!(read_finalization_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(read_native_release_spent_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
}

#[test]
fn missing_parent_torn_or_repermissioned_spent_marker_quarantines_every_scope() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let (parent, terminal) = terminal(1, 2, 3, "seat0");
        let (other, _) = self::terminal(11, 12, 13, "seat12");
        let preparation = NativeDisplayRetirementPreparation::new(
            &terminal,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &terminal).is_ok());
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
        for kind in [
            Kind::RetirementPreparation,
            Kind::RootRetiredHeld,
            Kind::NativeReleaseReserved,
            Kind::NativeReleaseSpent,
        ] {
            assert!(
                reserve_kind_at(
                    &fixture.fd,
                    fixture.uid,
                    &terminal.binding().dispatch_digest,
                    &preparation.canonical_bytes(),
                    kind,
                )
                .is_ok()
            );
        }
        assert!(reserve_recovery(&fixture, &other).is_ok());
        let spent = fixture
            .path
            .join(Kind::NativeReleaseSpent.name(&terminal.binding().dispatch_digest));
        let reserved = fixture
            .path
            .join(Kind::NativeReleaseReserved.name(&terminal.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(reserved).unwrap_or_else(|error| unreachable!("{error}")),
            1 => std::fs::write(spent, b"torn release spend")
                .unwrap_or_else(|error| unreachable!("{error}")),
            _ => std::fs::set_permissions(spent, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|error| unreachable!("{error}")),
        }
        assert!(read_native_release_spent_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(read_native_release_reserved_at(&fixture.fd, fixture.uid, &other).is_err());
        let (fresh, _) = self::terminal(21, 22, 23, "seat22");
        assert!(reserve_recovery(&fixture, &fresh).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid)
                .unwrap_or_else(|error| unreachable!("{error}"))
        );
    }
}

#[test]
fn corrupted_or_orphan_native_release_reservation_fences_other_scopes() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let (parent, terminal) = terminal(1, 2, 3, "seat0");
        let (other, _) = self::terminal(11, 12, 13, "seat12");
        let preparation = NativeDisplayRetirementPreparation::new(
            &terminal,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &terminal).is_ok());
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
        for kind in [
            Kind::RetirementPreparation,
            Kind::RootRetiredHeld,
            Kind::NativeReleaseReserved,
        ] {
            assert!(
                reserve_kind_at(
                    &fixture.fd,
                    fixture.uid,
                    &terminal.binding().dispatch_digest,
                    &preparation.canonical_bytes(),
                    kind,
                )
                .is_ok()
            );
        }
        assert!(reserve_recovery(&fixture, &other).is_ok());
        let reserved = fixture
            .path
            .join(Kind::NativeReleaseReserved.name(&terminal.binding().dispatch_digest));
        let held = fixture
            .path
            .join(Kind::RootRetiredHeld.name(&terminal.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(&held).unwrap_or_else(|error| unreachable!("{error}")),
            1 => std::fs::write(&reserved, b"torn one-shot release reservation")
                .unwrap_or_else(|error| unreachable!("{error}")),
            _ => std::fs::set_permissions(&reserved, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|error| unreachable!("{error}")),
        }
        assert!(read_native_release_reserved_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(read_root_retired_held_at(&fixture.fd, fixture.uid, &other).is_err());
        let (fresh, _) = self::terminal(21, 22, 23, "seat22");
        assert!(reserve_recovery(&fixture, &fresh).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid)
                .unwrap_or_else(|error| unreachable!("{error}"))
        );
    }
}

#[test]
fn orphan_or_corrupt_root_retired_held_fences_unrelated_scope_and_admission() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let (parent, native) = terminal(1, 2, 3, "seat0");
        let (other, _) = terminal(11, 12, 13, "seat12");
        let preparation = NativeDisplayRetirementPreparation::new(
            &native,
            7,
            ComponentDigest::from_bytes([3; 32]),
            ComponentDigest::from_bytes([4; 32]),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(reserve_recovery(&fixture, &parent).is_ok());
        assert!(reserve_terminal(&fixture, &native).is_ok());
        assert!(
            reserve_kind_at(
                &fixture.fd,
                fixture.uid,
                &native.binding().dispatch_digest,
                &native.canonical_bytes(),
                Kind::Quiescence,
            )
            .is_ok()
        );
        for kind in [Kind::RetirementPreparation, Kind::RootRetiredHeld] {
            assert!(
                reserve_kind_at(
                    &fixture.fd,
                    fixture.uid,
                    &native.binding().dispatch_digest,
                    &preparation.canonical_bytes(),
                    kind,
                )
                .is_ok()
            );
        }
        assert!(reserve_recovery(&fixture, &other).is_ok());
        let held = fixture
            .path
            .join(Kind::RootRetiredHeld.name(&native.binding().dispatch_digest));
        let prepared = fixture
            .path
            .join(Kind::RetirementPreparation.name(&native.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(&prepared).unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(&held, b"torn Root retirement marker")
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(read_root_retired_held_at(&fixture.fd, fixture.uid, &other).is_err());
        assert!(
            read_restoration_at(
                &fixture.fd,
                fixture.uid,
                &other
                    .decoded_material()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .recovery_scope()
                    .unwrap_or_else(|e| unreachable!("{e}")),
            )
            .is_err()
        );
        let (fresh, _) = terminal(21, 22, 23, "seat22");
        assert!(reserve_recovery(&fixture, &fresh).is_err());
        assert!(
            !startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
        );
    }
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

#[test]
fn native_power_records_require_every_parent_and_preserve_exclusive_spend_on_reopen() {
    use linura_observation::{DisplayNativeCurrentFacts, DisplayNativeCurrentOutput};
    let fixture = Fixture::new();
    let (parent, terminal) = terminal(1, 2, 3, "seat0");
    let value = |result: Result<_, String>| result.unwrap_or_else(|e| unreachable!("{e}"));
    let retirement = value(NativeDisplayRetirementPreparation::new(
        &terminal,
        7,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([4; 32]),
    ));
    let completion = completion(&parent, &retirement);
    let frames = DisplayNativeCurrentFacts::new(
        completion.frames().scope().clone(),
        completion.frames().lineage().clone(),
        completion.frames().window(),
        completion
            .frames()
            .outputs()
            .iter()
            .map(|(id, row)| {
                (
                    id.clone(),
                    DisplayNativeCurrentOutput {
                        enabled: row.enabled,
                        connector: row.connector,
                        crtc: row.crtc,
                        plane: row.plane,
                        framebuffer: row.framebuffer,
                        handoff_commit: row.completed_commit,
                        completed_commit: row.completed_commit + 1,
                    },
                )
            })
            .collect(),
        ComponentDigest::from_bytes(Sha256::digest(completion.canonical_bytes()).into()).to_hex(),
        true,
        true,
        None,
        None,
    )
    .unwrap_or_else(|e| unreachable!("{e:?}"));
    let power = NativeDisplayPowerRetirementPreparation::new(
        &completion,
        ComponentDigest::from_bytes([7; 32]),
        ComponentDigest::from_bytes([8; 32]),
        &frames,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let absent = DisplayNativeCurrentFacts::new(
        frames.scope().clone(),
        frames.lineage().clone(),
        frames.window(),
        frames.outputs().clone(),
        frames.completion_digest().into(),
        true,
        false,
        None,
        None,
    )
    .unwrap_or_else(|e| unreachable!("{e:?}"));
    let root = NativeDisplayRootRetirementPreparation::new(
        &power,
        ComponentDigest::from_bytes([10; 32]),
        ComponentDigest::from_bytes([11; 32]),
        &absent,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let publish = |kind, bytes: &[u8]| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &terminal.binding().dispatch_digest,
            bytes,
            kind,
        )
    };
    assert!(reserve_recovery(&fixture, &parent).is_ok());
    assert!(reserve_terminal(&fixture, &terminal).is_ok());
    for (kind, bytes) in [
        (Kind::Quiescence, terminal.canonical_bytes()),
        (Kind::RetirementPreparation, retirement.canonical_bytes()),
        (Kind::RootRetiredHeld, retirement.canonical_bytes()),
        (Kind::NativeReleaseReserved, retirement.canonical_bytes()),
        (Kind::NativeReleaseSpent, retirement.canonical_bytes()),
        (Kind::CompletionPrepared, completion.canonical_bytes()),
        (Kind::CompletionSpent, completion.canonical_bytes()),
    ] {
        assert!(publish(Kind::PowerPrepared, &power.canonical_bytes()).is_err());
        assert!(publish(Kind::RootPowerPrepared, &root.canonical_bytes()).is_err());
        assert!(publish(Kind::PowerSpent, &power.canonical_bytes()).is_err());
        assert!(publish(kind, &bytes).is_ok());
    }
    assert!(publish(Kind::PowerSpent, &power.canonical_bytes()).is_err());
    assert!(publish(Kind::PowerPrepared, &power.canonical_bytes()).is_ok());
    assert!(publish(Kind::PowerPrepared, &power.canonical_bytes()).is_err());
    let other = NativeDisplayPowerRetirementPreparation::new(
        &completion,
        ComponentDigest::from_bytes([9; 32]),
        ComponentDigest::from_bytes([8; 32]),
        &frames,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(Kind::PowerSpent, &other.canonical_bytes()).is_err());
    assert!(publish(Kind::PowerSpent, &power.canonical_bytes()).is_ok());
    assert!(publish(Kind::PowerSpent, &power.canonical_bytes()).is_err());
    assert!(publish(Kind::RootPowerPrepared, &root.canonical_bytes()).is_ok());
    assert!(publish(Kind::RootPowerPrepared, &root.canonical_bytes()).is_err());
    assert_eq!(
        read_root_power_retirement_at(&fixture.fd, fixture.uid, &parent)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!("Root preparation"))
            .canonical_bytes(),
        root.canonical_bytes()
    );
    let committed = NativeDisplayCurrentCommitPreparation::new(
        &root,
        ComponentDigest::from_bytes([12; 32]),
        ComponentDigest::from_bytes([13; 32]),
        terminal.binding().generation,
        9,
        ComponentDigest::from_bytes([3; 32]),
        &absent,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(Kind::CurrentCommitSpent, &committed.canonical_bytes()).is_err());
    assert!(publish(Kind::CurrentCommitPrepared, &committed.canonical_bytes()).is_ok());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    assert!(
        read_final_lineage_at(&fixture.fd, fixture.uid, &parent, |lineage, scope| lineage
            .final_retirement_prepared
            .remove(scope))
        .unwrap_or_else(|e| unreachable!("{e}"))
        .is_none()
    );
    assert!(publish(Kind::CurrentCommitPrepared, &committed.canonical_bytes()).is_err());
    let substituted = NativeDisplayCurrentCommitPreparation::new(
        &root,
        ComponentDigest::from_bytes([14; 32]),
        ComponentDigest::from_bytes([13; 32]),
        terminal.binding().generation,
        9,
        ComponentDigest::from_bytes([3; 32]),
        &absent,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(Kind::CurrentCommitSpent, &substituted.canonical_bytes()).is_err());
    assert!(publish(Kind::CurrentCommitSpent, &committed.canonical_bytes()).is_ok());
    // Early Control Committed and even a Root current-grant spend do not retire
    // startup admission or create final release/cleanup history.
    let early_reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(
        !startup_clear_at(&early_reopened, fixture.uid).unwrap_or_else(|e| unreachable!("{e}"))
    );
    assert!(
        read_final_lineage_at(&early_reopened, fixture.uid, &parent, |lineage, scope| {
            lineage.released_current.remove(scope)
        })
        .unwrap_or_else(|e| unreachable!("{e}"))
        .is_none()
    );
    assert!(
        fixture
            .path
            .join(Kind::Restoration.name(&parent.binding().dispatch_digest))
            .exists()
    );
    assert!(
        fixture
            .path
            .join(Kind::CurrentCommitSpent.name(&terminal.binding().dispatch_digest))
            .exists()
    );

    assert!(publish(Kind::CurrentCommitSpent, &committed.canonical_bytes()).is_err());
    let qualified = DisplayNativeCurrentFacts::new(
        absent.scope().clone(),
        absent.lineage().clone(),
        absent.window(),
        absent.outputs().clone(),
        absent.completion_digest().into(),
        true,
        false,
        Some(committed.record_digest().to_hex()),
        None,
    )
    .unwrap_or_else(|e| unreachable!("{e:?}"));
    let final_preparation = NativeDisplayFinalRetirementPreparation::new(
        &committed,
        ComponentDigest::from_bytes([15; 32]),
        ComponentDigest::from_bytes([16; 32]),
        &qualified,
        1150,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let released = NativeDisplayReleasedCurrentRecord::new(
        &final_preparation,
        ComponentDigest::from_bytes([17; 32]),
        qualified.window(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(Kind::ReleasedCurrent, &released.canonical_bytes()).is_err());
    assert!(
        publish(
            Kind::FinalRetirementSpent,
            &final_preparation.canonical_bytes()
        )
        .is_err()
    );
    assert!(
        publish(
            Kind::FinalRetirementPrepared,
            &final_preparation.canonical_bytes()
        )
        .is_ok()
    );
    assert!(
        publish(
            Kind::FinalRetirementPrepared,
            &final_preparation.canonical_bytes()
        )
        .is_err()
    );
    assert!(publish(Kind::ReleasedCurrent, &released.canonical_bytes()).is_err());
    assert!(
        publish(
            Kind::FinalRetirementSpent,
            &final_preparation.canonical_bytes()
        )
        .is_ok()
    );
    assert!(
        publish(
            Kind::FinalRetirementSpent,
            &final_preparation.canonical_bytes()
        )
        .is_err()
    );
    // A new original checkpoint is necessary but cannot authorize transfer
    // before the actual final ReleasedCurrent parent exists in this store.
    let successor_payload = successor_checkpoint(31);
    let successor = NativeDisplaySuccessorPreparation::from_checkpoint(
        &released,
        &successor_payload,
        1100,
        237,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let next_dispatch = successor.binding().dispatch_digest;
    let next_publish = |kind, record: &NativeDisplaySuccessorPreparation| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            kind,
        )
    };
    assert!(next_publish(Kind::SuccessorPrepared, &successor).is_err());
    reserve_at(&fixture.fd, fixture.uid, &next_dispatch, &successor_payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(next_publish(Kind::SuccessorPrepared, &successor).is_err());
    assert!(publish(Kind::ReleasedCurrent, &released.canonical_bytes()).is_ok());
    assert!(publish(Kind::ReleasedCurrent, &released.canonical_bytes()).is_err());
    assert_eq!(
        read_final_lineage_at(&fixture.fd, fixture.uid, &parent, |lineage, scope| lineage
            .released_current
            .remove(scope))
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!("Root completion"))
        .canonical_bytes(),
        released.canonical_bytes()
    );
    let encoded_successor = successor.canonical_bytes();
    assert_eq!(
        NativeDisplaySuccessorPreparation::decode(&encoded_successor)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .canonical_bytes(),
        encoded_successor
    );
    // Every outer framing boundary, partial length word and truncated payload;
    // nested codecs already have their own truncation suites. Avoid repeatedly
    // decoding the complete nested ancestry for every byte of its last field.
    let mut cuts = std::collections::BTreeSet::from([0, encoded_successor.len() - 1]);
    let mut cursor = 0;
    while cursor < encoded_successor.len() {
        cuts.extend(cursor..cursor + 8);
        let size = u64::from_be_bytes(
            encoded_successor[cursor..cursor + 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!("length")),
        ) as usize;
        cursor += 8 + size;
        cuts.insert(cursor - 1);
        if cursor < encoded_successor.len() {
            cuts.insert(cursor);
        }
    }
    for length in cuts {
        assert!(NativeDisplaySuccessorPreparation::decode(&encoded_successor[..length]).is_err());
    }
    assert!(
        NativeDisplaySuccessorPreparation::decode(&[encoded_successor.clone(), vec![0]].concat())
            .is_err()
    );
    assert_eq!(successor.window().observed_boot_ms, 200);
    assert_eq!(successor.window().deadline_boot_ms, 2200);
    assert_eq!(successor.window().deadline_unix_ms, 3063);
    for (wall, boot) in [(0, 237), (1100, 199), (1100, 2200), (0, u64::MAX)] {
        assert!(
            NativeDisplaySuccessorPreparation::from_checkpoint(
                &released,
                &successor_payload,
                wall,
                boot
            )
            .is_err()
        );
    }
    let other_payload = successor_checkpoint(32);
    assert!(successor.validate_checkpoint(&other_payload).is_err());
    let other =
        NativeDisplaySuccessorPreparation::from_checkpoint(&released, &other_payload, 1100, 237)
            .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(next_publish(Kind::SuccessorSpent, &successor).is_err());
    assert!(next_publish(Kind::SuccessorPrepared, &successor).is_ok());
    assert!(next_publish(Kind::SuccessorPrepared, &successor).is_err());
    assert!(next_publish(Kind::SuccessorPrepared, &other).is_err());
    assert!(next_publish(Kind::SuccessorSpent, &other).is_err());
    assert!(next_publish(Kind::SuccessorSpent, &successor).is_ok());
    assert!(next_publish(Kind::SuccessorSpent, &successor).is_err());
    assert!(!startup_clear_at(&fixture.fd, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(
        read_power_retirement_at(&reopened, fixture.uid, &parent, true)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!("spent record"))
            .canonical_bytes(),
        power.canonical_bytes()
    );
    assert!(!startup_clear_at(&reopened, fixture.uid).unwrap_or_else(|e| unreachable!("{e}")));
    let read_successor =
        read_final_lineage_at(&reopened, fixture.uid, &parent, |lineage, scope| {
            lineage.successor_spent.remove(scope)
        })
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!("successor spend must survive lost acknowledgement"));
    assert_eq!(read_successor.canonical_bytes(), encoded_successor);
    assert!(next_publish(Kind::SuccessorPrepared, &other).is_err());
    // Losing a parent poisons observation and new publication. No cleanup or
    // historical digest can reconstruct the missing original completion.
    std::fs::remove_file(
        fixture
            .path
            .join(Kind::CompletionSpent.name(&terminal.binding().dispatch_digest)),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(read_root_power_retirement_at(&reopened, fixture.uid, &parent).is_err());
    assert!(read_power_retirement_at(&reopened, fixture.uid, &parent, true).is_err());
    assert!(!matches!(
        startup_clear_at(&reopened, fixture.uid),
        Ok(true)
    ));
}

// Full strictly validated original preimage for ordinary Root persistence
// tests. All identities/rules are synthetic; no live witness is claimed.
pub(crate) fn ordinary_release_fixture(
    attempt: u8,
) -> (Vec<u8>, NativeDisplayOrdinaryReleasePreparation) {
    ordinary_release_fixture_with_original(attempt, 2)
}
fn ordinary_release_fixture_with_original(
    attempt: u8,
    original_use: u8,
) -> (Vec<u8>, NativeDisplayOrdinaryReleasePreparation) {
    use linura_core::{
        DisplayOrdinaryReleaseLineage, DisplayOrdinaryReleaseMaterial,
        DisplayOrdinaryReleaseOutcome, RequestId,
    };
    use linura_provider_sdk::ExecutionBinding;
    let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
    let lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1";
    let original = format!(
        "LNDI:1;{lock};LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:100:0:-;"
    );
    let effect = linura_provider_sdk::display_layout_effect(&original)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = ExecutionBinding::new(
        "transaction:ordinary-original",
        0,
        1,
        ComponentDigest::from_bytes([1; 32]),
        ComponentDigest::from_bytes([original_use; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let rule = concat!(
        "0;0000000000000000;0000000000000000;404e000000000000;",
        "0000000000000000;0000000000000000;bff0000000000000;0;0;;",
        "0;0;0;0;0;0;0;0;0;0;0;0;0;0;",
        "0000000000000000000000000000000000000000000000000000000000000000;;"
    );
    let preimage = serde_json::json!({"schema":2,"upstream":"efb50993780079460b0cbed1363e2166a2de1d9f", "integration":"a".repeat(64), "generation":"3", "heads":[{"handle":"1","generation":"2","kernel_drm":[226,0,1],"linura_owned":false,"owned_target":"","output_identity_digest":"b".repeat(64),"base_rule":format!("LNRL:2;0;0;{rule}{rule}0;0;0;;")}]}).to_string();
    let mut payload = Vec::new();
    for field in [
        "linura.native-display.recovery-preimage.v1",
        &binding.transaction_id,
        "0",
        "1",
        &binding.authority_binding_digest.to_hex(),
        &binding.authority_use_digest.to_hex(),
        &binding.effect_digest.to_hex(),
        &binding.dispatch_digest.to_hex(),
        &original,
        "25000",
        "11111111-1111-4111-8111-111111111111",
        ":1.42",
        "1000",
        "42",
        "22222222-2222-4222-8222-222222222222",
        "100",
        &"c".repeat(64),
        &"d".repeat(64),
        &preimage,
    ] {
        payload.extend_from_slice(&(field.len() as u64).to_be_bytes());
        payload.extend_from_slice(field.as_bytes());
    }
    NativeDisplayRecoveryCheckpoint::validate_stored(&payload, &binding.dispatch_digest)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let checkpoint = ComponentDigest::from_bytes(Sha256::digest(&payload).into()).to_hex();
    let layout = linura_core::DisplayLayoutMaterial::decode(&original)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let material = DisplayOrdinaryReleaseMaterial::encode(
        &DisplayOrdinaryReleaseLineage {
            original_request: RequestId::new("request:v010:display-layout:ordinary-original")
                .unwrap_or_else(|e| unreachable!("{e}")),
            original_dispatch: &binding.dispatch_digest.to_hex(),
            terminal_record: &"e".repeat(64),
            original_checkpoint: &checkpoint,
            signed_binding: &"f".repeat(64),
            generation: 0,
            state_version: 9,
            current_source_guard: &"c".repeat(64),
        },
        DisplayOrdinaryReleaseOutcome::Keep,
        layout.lock(),
        &original,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let effect = linura_provider_sdk::display_ordinary_release_effect(&material)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = ExecutionBinding::new(
        format!("transaction:ordinary-release-{attempt}"),
        0,
        1,
        ComponentDigest::from_bytes([3; 32]),
        ComponentDigest::from_bytes([attempt; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let record = NativeDisplayOrdinaryReleasePreparation::new(
        &material,
        &binding,
        linura_observation::DisplayNativeHandoffWindow {
            observed_unix_ms: 1000,
            observed_boot_ms: 100,
            deadline_unix_ms: 2000,
            deadline_boot_ms: 1100,
        },
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    record
        .validate_original(&payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    (payload, record)
}

#[test]
fn ordinary_release_preparation_requires_original_parent_and_cannot_replay_or_supersede() {
    let fixture = Fixture::new();
    let (payload, record) = ordinary_release_fixture(7);
    let reserve = |record: &NativeDisplayOrdinaryReleasePreparation| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::OrdinaryReleasePrepared,
        )
    };
    assert!(reserve(&record).is_err());
    assert!(
        !fixture
            .path
            .join(Kind::OrdinaryReleasePrepared.name(&record.binding().dispatch_digest))
            .exists()
    );
    let original = NativeDisplayRecoveryCheckpoint::stored_dispatch(&payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    reserve_at(&fixture.fd, fixture.uid, &original, &payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    reserve(&record).unwrap_or_else(|e| unreachable!("{e}"));
    let read = read_ordinary_release_at(&fixture.fd, fixture.uid, &record)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(read, record.canonical_bytes());
    assert!(reserve(&record).is_err());
    let (_, successor) = ordinary_release_fixture(8);
    assert!(reserve(&successor).is_err());
    // A different original dispatch on the same seat is still a competitor,
    // including a recovery path using another scope/invocation.
    let (other_payload, other) = ordinary_release_fixture_with_original(9, 4);
    let other_original = NativeDisplayRecoveryCheckpoint::stored_dispatch(&other_payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    reserve_at(&fixture.fd, fixture.uid, &other_original, &other_payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(reserve(&other).is_err());
    assert!(reserve_recovery(&fixture, &restoration(1, 2)).is_err());
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(
        read_ordinary_release_at(&reopened, fixture.uid, &record),
        Ok(read)
    );
    assert!(
        reserve_kind_at(
            &reopened,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::OrdinaryReleasePrepared
        )
        .is_err()
    );
    assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
}

#[test]
fn orphan_or_corrupt_ordinary_release_quarantines_other_reservations_without_cleanup() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        let (payload, record) = ordinary_release_fixture(7);
        let original = NativeDisplayRecoveryCheckpoint::stored_dispatch(&payload)
            .unwrap_or_else(|e| unreachable!("{e}"));
        reserve_at(&fixture.fd, fixture.uid, &original, &payload)
            .unwrap_or_else(|e| unreachable!("{e}"));
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            Kind::OrdinaryReleasePrepared,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let parent = fixture.path.join(Kind::Original.name(&original));
        let child = fixture
            .path
            .join(Kind::OrdinaryReleasePrepared.name(&record.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(&parent).unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(&parent, MAGIC).unwrap_or_else(|e| unreachable!("{e}")),
            2 => std::fs::write(&child, ORDINARY_RELEASE_PREPARED_MAGIC)
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o640))
                .unwrap_or_else(|e| unreachable!("{e}")),
        }
        assert!(read_ordinary_release_at(&fixture.fd, fixture.uid, &record).is_err());
        assert!(fixture.reserve(9, b"unrelated comparison").is_err());
        assert!(child.exists());
        assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
    }
}

#[test]
fn ordinary_native_spend_requires_exact_preparation_and_survives_missing_ack_without_replay() {
    let fixture = Fixture::new();
    let (payload, record) = ordinary_release_fixture(7);
    let original = NativeDisplayRecoveryCheckpoint::stored_dispatch(&payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let scope = record
        .decoded_material()
        .and_then(|m| m.release_scope().map_err(|e| e.to_string()))
        .unwrap_or_else(|e| unreachable!("{e}"));
    let publish = |record: &NativeDisplayOrdinaryReleasePreparation, kind| {
        reserve_kind_at(
            &fixture.fd,
            fixture.uid,
            &record.binding().dispatch_digest,
            &record.canonical_bytes(),
            kind,
        )
    };
    assert!(publish(&record, Kind::OrdinaryReleaseSpent).is_err());
    reserve_at(&fixture.fd, fixture.uid, &original, &payload)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(&record, Kind::OrdinaryReleaseSpent).is_err());
    publish(&record, Kind::OrdinaryReleasePrepared).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(
        !read_ordinary_release_state_at(&fixture.fd, fixture.uid, &scope)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!())
            .1
    );
    let (_, foreign) = ordinary_release_fixture(8);
    assert!(publish(&foreign, Kind::OrdinaryReleaseSpent).is_err());
    publish(&record, Kind::OrdinaryReleaseSpent).unwrap_or_else(|e| unreachable!("{e}"));
    assert!(publish(&record, Kind::OrdinaryReleaseSpent).is_err());
    let reopened = fs::open(
        &fixture.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let (retained, spent) = read_ordinary_release_state_at(&reopened, fixture.uid, &scope)
        .unwrap_or_else(|e| unreachable!("{e}"))
        .unwrap_or_else(|| unreachable!());
    assert!(spent);
    assert_eq!(retained.canonical_bytes(), record.canonical_bytes());
    assert!(publish(&foreign, Kind::OrdinaryReleasePrepared).is_err());
    assert_eq!(startup_clear_at(&reopened, fixture.uid), Ok(false));
}

#[test]
fn ordinary_spent_orphan_substitution_and_damage_quarantine_the_entire_history() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        let (payload, record) = ordinary_release_fixture(7);
        let original = NativeDisplayRecoveryCheckpoint::stored_dispatch(&payload)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let scope = record
            .decoded_material()
            .and_then(|m| m.release_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        reserve_at(&fixture.fd, fixture.uid, &original, &payload)
            .unwrap_or_else(|e| unreachable!("{e}"));
        for kind in [Kind::OrdinaryReleasePrepared, Kind::OrdinaryReleaseSpent] {
            reserve_kind_at(
                &fixture.fd,
                fixture.uid,
                &record.binding().dispatch_digest,
                &record.canonical_bytes(),
                kind,
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
        }
        let prepared = fixture
            .path
            .join(Kind::OrdinaryReleasePrepared.name(&record.binding().dispatch_digest));
        let spent = fixture
            .path
            .join(Kind::OrdinaryReleaseSpent.name(&record.binding().dispatch_digest));
        match fault {
            0 => std::fs::remove_file(&prepared).unwrap_or_else(|e| unreachable!("{e}")),
            1 => std::fs::write(&spent, ORDINARY_RELEASE_SPENT_MAGIC)
                .unwrap_or_else(|e| unreachable!("{e}")),
            2 => std::fs::set_permissions(&spent, std::fs::Permissions::from_mode(0o640))
                .unwrap_or_else(|e| unreachable!("{e}")),
            _ => {
                let mut changed = record.window();
                changed.deadline_unix_ms -= 1;
                changed.deadline_boot_ms -= 1;
                let foreign = NativeDisplayOrdinaryReleasePreparation::new(
                    record.material(),
                    record.binding(),
                    changed,
                )
                .unwrap_or_else(|e| unreachable!("{e}"));
                let payload = foreign.canonical_bytes();
                let mut bytes = ORDINARY_RELEASE_SPENT_MAGIC.to_vec();
                bytes.extend_from_slice(&Sha256::digest(&payload));
                bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
                bytes.extend_from_slice(&payload);
                std::fs::write(&spent, bytes).unwrap_or_else(|e| unreachable!("{e}"));
            }
        }
        assert!(read_ordinary_release_state_at(&fixture.fd, fixture.uid, &scope).is_err());
        assert!(fixture.reserve(9, b"unrelated comparison").is_err());
        assert!(spent.exists());
        assert_eq!(startup_clear_at(&fixture.fd, fixture.uid), Ok(false));
    }
}

// A complete synthetic new checkpoint for the same replacement invocation.
// These fixtures exercise parsing/storage only and cannot open a native fence.
fn successor_checkpoint(use_byte: u8) -> Vec<u8> {
    let (bytes, _) = ordinary_release_fixture(19);
    let mut rest = bytes.as_slice();
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (size, tail) = rest.split_at(8);
        let size =
            u64::from_be_bytes(size.try_into().unwrap_or_else(|_| unreachable!("length"))) as usize;
        let (field, tail) = tail.split_at(size);
        fields.push(
            std::str::from_utf8(field)
                .unwrap_or_else(|_| unreachable!("text"))
                .to_owned(),
        );
        rest = tail;
    }
    fields[8] = fields[8].replace("c2:42", "c3:99").replace(
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    let effect = linura_provider_sdk::display_layout_effect(&fields[8])
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = linura_provider_sdk::ExecutionBinding::new(
        format!("transaction:successor-{use_byte}"),
        0,
        1,
        ComponentDigest::from_bytes([30; 32]),
        ComponentDigest::from_bytes([use_byte; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    fields[1] = binding.transaction_id;
    fields[4] = binding.authority_binding_digest.to_hex();
    fields[5] = binding.authority_use_digest.to_hex();
    fields[6] = binding.effect_digest.to_hex();
    fields[7] = binding.dispatch_digest.to_hex();
    fields[15] = "200".into();
    let mut encoded = Vec::new();
    for field in fields {
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    NativeDisplayRecoveryCheckpoint::validate_stored(&encoded, &binding.dispatch_digest)
        .unwrap_or_else(|e| unreachable!("{e}"));
    encoded
}
