//! Immutable private mechanism preimages, not Control authority state. Reserve
//! and fsync before a native write; any uncertainty preserves the record and
//! refuses redelivery. Nothing in this module dispatches or authorizes effects.
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Component;

use linura_linux_session::NativeDisplayRecoveryCheckpoint;
use linura_provider_sdk::ComponentDigest;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = "/var/lib/linura/display-recovery";
const MAGIC: &[u8] = b"LNRJ:1\n";
const MAX_PAYLOAD: usize = 384 * 1024;
const MAX_RECORDS: usize = 256;
const HEADER: usize = MAGIC.len() + 32 + 8;

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
    name.len() == 8 + 64 + 11
        && name.starts_with(b"attempt-")
        && name.ends_with(b".checkpoint")
        && name[8..72]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
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
fn check_record(fd: OwnedFd, uid: u32) -> Result<(), String> {
    let stat = fs::fstat(&fd).map_err(|_| unavailable())?;
    record_metadata(&stat, uid)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take((MAX_PAYLOAD + HEADER + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() != stat.st_size as usize || !bytes.starts_with(MAGIC) {
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
    {
        return Err(unavailable());
    }
    Ok(())
}
fn reserve_at(
    fd: &OwnedFd,
    uid: u32,
    dispatch: &ComponentDigest,
    payload: &[u8],
) -> Result<(), String> {
    directory(fd, uid, true)?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD || dispatch.to_hex() == "0".repeat(64) {
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
            check_record(old, uid)?;
        }
        let name = format!("attempt-{}.checkpoint", dispatch.to_hex());
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
        record.write_all(MAGIC).map_err(|_| unavailable())?;
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

pub(super) fn reserve(record: &NativeDisplayRecoveryCheckpoint) -> Result<(), String> {
    let fd = open()?;
    reserve_at(&fd, 0, record.dispatch_digest(), record.canonical_bytes())
}

#[cfg(test)]
mod tests;
