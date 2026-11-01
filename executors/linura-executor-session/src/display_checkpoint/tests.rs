use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
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
        reserve_at(
            &self.fd,
            self.uid,
            &ComponentDigest::from_bytes([byte; 32]),
            bytes,
        )
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
            b"substituted"
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
        assert!(check_record(fd, fixture.uid).is_ok());
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
    assert!(fixture.reserve(1, &[]).is_err());
    assert!(fixture.reserve(1, &vec![0; MAX_PAYLOAD + 1]).is_err());
    assert!(fixture.reserve(0, b"zero correlation").is_err());
    assert!(
        reserve_at(
            &fixture.fd,
            fixture.uid.saturating_add(1),
            &ComponentDigest::from_bytes([1; 32]),
            b"wrong owner"
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
                b"explicit synthetic retention fixture",
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
    assert!(max.reserve(1, &vec![b'x'; MAX_PAYLOAD]).is_ok());
    assert_eq!(
        std::fs::metadata(max.name(1))
            .unwrap_or_else(|e| unreachable!("{e}"))
            .len(),
        (MAX_PAYLOAD + HEADER) as u64
    );
}
