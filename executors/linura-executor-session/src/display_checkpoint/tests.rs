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
