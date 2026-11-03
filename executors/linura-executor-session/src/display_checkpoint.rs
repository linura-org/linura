//! Immutable private mechanism preimages, not Control authority state. Reserve
//! and fsync before a native write; any uncertainty preserves the record and
//! refuses redelivery. Nothing in this module dispatches or authorizes effects.
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Component;

use linura_linux_session::{NativeDisplayRecoveryCheckpoint, NativeDisplayRestorationReservation};
use linura_provider_sdk::ComponentDigest;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = "/var/lib/linura/display-recovery";
const MAGIC: &[u8] = b"LNRJ:1\n";
const RESTORATION_MAGIC: &[u8] = b"LNRR:1\n";
const MAX_PAYLOAD: usize = 384 * 1024;
const MAX_RECORDS: usize = 256;
const HEADER: usize = MAGIC.len() + 32 + 8;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Original,
    Restoration,
}
impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Original => "attempt-",
            Self::Restoration => "restoration-",
        }
    }
    fn magic(self) -> &'static [u8] {
        match self {
            Self::Original => MAGIC,
            Self::Restoration => RESTORATION_MAGIC,
        }
    }
    fn dispatch(self, payload: &[u8]) -> Result<ComponentDigest, String> {
        match self {
            Self::Original => NativeDisplayRecoveryCheckpoint::stored_dispatch(payload),
            Self::Restoration => Ok(NativeDisplayRestorationReservation::decode(payload)?
                .binding()
                .dispatch_digest),
        }
    }
    fn name(self, dispatch: &ComponentDigest) -> String {
        format!("{}{}.checkpoint", self.prefix(), dispatch.to_hex())
    }
}
fn named_kind(name: &[u8]) -> Result<(Kind, ComponentDigest), String> {
    for kind in [Kind::Original, Kind::Restoration] {
        let prefix = kind.prefix().as_bytes();
        if name.len() == prefix.len() + 64 + 11
            && name.starts_with(prefix)
            && name.ends_with(b".checkpoint")
        {
            let hex = std::str::from_utf8(&name[prefix.len()..prefix.len() + 64])
                .map_err(|_| unavailable())?;
            let dispatch = ComponentDigest::parse_hex(hex).map_err(|_| unavailable())?;
            if dispatch.to_hex() == hex {
                return Ok((kind, dispatch));
            }
        }
    }
    Err(unavailable())
}

fn unavailable() -> String {
    "private native display checkpoint unavailable; no dispatch or retry".into()
}
fn directory(fd: &OwnedFd, uid: u32, final_directory: bool) -> Result<(), String> {
    let stat = fs::fstat(fd).map_err(|_| unavailable())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o022 != 0
        || final_directory && stat.st_mode & 0o7777 != 0o700
    {
        return Err(unavailable());
    }
    Ok(())
}
fn open() -> Result<OwnedFd, String> {
    if !rustix::process::geteuid().is_root() {
        return Err(unavailable());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut fd = fs::open("/", flags, Mode::empty()).map_err(|_| unavailable())?;
    directory(&fd, 0, false)?;
    let parts: Vec<_> = std::path::Path::new(DIRECTORY).components().collect();
    for (i, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(part) = part else {
            return Err(unavailable());
        };
        fd = fs::openat(&fd, *part, flags, Mode::empty()).map_err(|_| unavailable())?;
        directory(&fd, 0, i == parts.len() - 1)?;
    }
    Ok(fd)
}
fn valid_name(name: &[u8]) -> bool {
    named_kind(name).is_ok()
}
fn record_metadata(stat: &fs::Stat, uid: u32) -> Result<(), String> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size <= HEADER as i64
        || stat.st_size > (MAX_PAYLOAD + HEADER) as i64
    {
        return Err(unavailable());
    }
    Ok(())
}
fn check_record(fd: OwnedFd, uid: u32, dispatch: &ComponentDigest) -> Result<Vec<u8>, String> {
    check_kind_record(fd, uid, dispatch, Kind::Original)
}
fn check_kind_record(
    fd: OwnedFd,
    uid: u32,
    dispatch: &ComponentDigest,
    kind: Kind,
) -> Result<Vec<u8>, String> {
    let stat = fs::fstat(&fd).map_err(|_| unavailable())?;
    record_metadata(&stat, uid)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take((MAX_PAYLOAD + HEADER + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() != stat.st_size as usize || !bytes.starts_with(kind.magic()) {
        return Err(unavailable());
    }
    let start = MAGIC.len();
    let payload_len = u64::from_be_bytes(
        bytes[start + 32..HEADER]
            .try_into()
            .map_err(|_| unavailable())?,
    );
    if payload_len != (bytes.len() - HEADER) as u64
        || &bytes[start..start + 32] != Sha256::digest(&bytes[HEADER..]).as_slice()
        || kind.dispatch(&bytes[HEADER..])? != *dispatch
    {
        return Err(unavailable());
    }
    Ok(bytes.split_off(HEADER))
}

fn load_at(fd: &OwnedFd, uid: u32, dispatch: &ComponentDigest) -> Result<Vec<u8>, String> {
    directory(fd, uid, true)?;
    fs::flock(fd, FlockOperation::NonBlockingLockShared).map_err(|_| unavailable())?;
    let result = (|| {
        let name = format!("attempt-{}.checkpoint", dispatch.to_hex());
        let before = fs::statat(fd, name.as_str(), fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| unavailable())?;
        record_metadata(&before, uid)?;
        let record = fs::openat(
            fd,
            name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| unavailable())?;
        let after = fs::fstat(&record).map_err(|_| unavailable())?;
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
            return Err(unavailable());
        }
        check_record(record, uid, dispatch)
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    match (result, unlocked) {
        (Ok(payload), Ok(())) => Ok(payload),
        _ => Err(unavailable()),
    }
}

pub(super) fn validate(
    dispatch: &ComponentDigest,
    original_payload_digest: &ComponentDigest,
) -> Result<(), String> {
    read_original(dispatch, original_payload_digest).map(|_| ())
}

pub(super) fn read_original(
    dispatch: &ComponentDigest,
    original_payload_digest: &ComponentDigest,
) -> Result<Vec<u8>, String> {
    let payload = load_at(&open()?, 0, dispatch)?;
    if ComponentDigest::from_bytes(Sha256::digest(&payload).into()) != *original_payload_digest {
        return Err(unavailable());
    }
    NativeDisplayRecoveryCheckpoint::validate_stored(&payload, dispatch)?;
    Ok(payload)
}
fn reserve_at(
    fd: &OwnedFd,
    uid: u32,
    dispatch: &ComponentDigest,
    payload: &[u8],
) -> Result<(), String> {
    reserve_kind_at(fd, uid, dispatch, payload, Kind::Original)
}
fn reserve_kind_at(
    fd: &OwnedFd,
    uid: u32,
    dispatch: &ComponentDigest,
    payload: &[u8],
    kind: Kind,
) -> Result<(), String> {
    directory(fd, uid, true)?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD || kind.dispatch(payload)? != *dispatch {
        return Err(unavailable());
    }
    // One directory lock serializes quota/integrity checks and exclusive
    // publication across threads/processes. It stays held through both fsyncs.
    fs::flock(fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| unavailable())?;
    let result = (|| {
        let mut count = 0;
        for entry in fs::Dir::read_from(fd).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            count += 1;
            if count >= MAX_RECORDS || !valid_name(name.to_bytes()) {
                return Err(unavailable());
            }
            // Corruption, an incomplete publication, substituted path or
            // unexpected ownership fences future writes. Never clean it up.
            // Inspect type before opening, so a malformed device/FIFO entry
            // cannot turn a history scan into a native device operation.
            let before =
                fs::statat(fd, name, fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|_| unavailable())?;
            record_metadata(&before, uid)?;
            let old = fs::openat(
                fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| unavailable())?;
            let after = fs::fstat(&old).map_err(|_| unavailable())?;
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
                return Err(unavailable());
            }
            let (old_kind, dispatch) = named_kind(name.to_bytes())?;
            let previous = check_kind_record(old, uid, &dispatch, old_kind)?;
            if kind == Kind::Restoration && old_kind == Kind::Restoration {
                let new = NativeDisplayRestorationReservation::decode(payload)?;
                let old = NativeDisplayRestorationReservation::decode(&previous)?;
                let new = new.decoded_material()?;
                let old = old.decoded_material()?;
                let new_scope = new.replacement().topology();
                let old_scope = old.replacement().topology();
                if new.original_dispatch() == old.original_dispatch()
                    || (new_scope.session().boot() == old_scope.session().boot()
                        && new_scope.session().uid() == old_scope.session().uid()
                        && new_scope.seat() == old_scope.seat())
                {
                    // No concurrent attempt or retry can supersede an unresolved
                    // original or competing seat ownership. Qualified
                    // supersession requires qualified old-attempt retirement proof.
                    return Err(unavailable());
                }
            }
        }
        let name = kind.name(dispatch);
        let record = fs::openat(
            fd,
            name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| unavailable())?;
        let mut record = File::from(record);
        // Exclusive creation reserves the attempt first. Any partial write or
        // sync failure leaves an invalid reservation, never an absent attempt.
        record.write_all(kind.magic()).map_err(|_| unavailable())?;
        record
            .write_all(&Sha256::digest(payload))
            .map_err(|_| unavailable())?;
        record
            .write_all(&(payload.len() as u64).to_be_bytes())
            .map_err(|_| unavailable())?;
        record.write_all(payload).map_err(|_| unavailable())?;
        record.sync_all().map_err(|_| unavailable())?;
        fs::fsync(fd).map_err(|_| unavailable())?;
        Ok(())
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    result.and(unlocked)
}

pub(super) fn reserve_stored(dispatch: &ComponentDigest, payload: &[u8]) -> Result<(), String> {
    NativeDisplayRecoveryCheckpoint::validate_stored(payload, dispatch)?;
    reserve_at(&open()?, 0, dispatch, payload)
}

pub(super) fn reserve_restoration(
    record: &NativeDisplayRestorationReservation,
) -> Result<(), String> {
    reserve_kind_at(
        &open()?,
        0,
        &record.binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::Restoration,
    )
}

fn startup_clear_at(fd: &OwnedFd, uid: u32) -> Result<bool, String> {
    directory(fd, uid, true)?;
    fs::flock(fd, FlockOperation::NonBlockingLockShared).map_err(|_| unavailable())?;
    let result: Result<bool, String> = (|| {
        for entry in fs::Dir::read_from(fd).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                // Any retained or unknown history fences ordinary startup. No
                // corrupt/legacy file is silently ignored, repaired or removed.
                return Ok(false);
            }
        }
        Ok(true)
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    match (result, unlocked) {
        (Ok(clear), Ok(())) => Ok(clear),
        _ => Err(unavailable()),
    }
}

/// Caller holds the protection admission mutex through lease publication and
/// reservation. The directory lock also rejects an independent busy writer;
/// the empty-history result is never cached or used without that serialization.
pub(super) fn startup_clear() -> Result<bool, String> {
    startup_clear_at(&open()?, 0)
}

#[cfg(test)]
pub(super) mod tests;
