//! Immutable private mechanism preimages, not Control authority state. Reserve
//! and fsync before a native write; any uncertainty preserves the record and
//! refuses redelivery. Nothing in this module dispatches or authorizes effects.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Component;

use linura_linux_session::{
    NativeDisplayFinalizationReservation, NativeDisplayRecoveryCheckpoint,
    NativeDisplayRestorationReservation, NativeDisplayRetirementPreparation,
};
use linura_provider_sdk::ComponentDigest;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = "/var/lib/linura/display-recovery";
const MAGIC: &[u8] = b"LNRJ:1\n";
const RESTORATION_MAGIC: &[u8] = b"LNRR:1\n";
const FINALIZATION_MAGIC: &[u8] = b"LNRT:1\n";
const QUIESCENCE_MAGIC: &[u8] = b"LNRQ:1\n";
const RETIREMENT_PREPARATION_MAGIC: &[u8] = b"LNRP:1\n";
const MAX_PAYLOAD: usize = 384 * 1024;
const MAX_RECORDS: usize = 256;
const HEADER: usize = MAGIC.len() + 32 + 8;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Original,
    Restoration,
    Finalization,
    Quiescence,
    RetirementPreparation,
}
impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Original => "attempt-",
            Self::Restoration => "restoration-",
            Self::Finalization => "finalization-",
            Self::Quiescence => "quiescence-",
            Self::RetirementPreparation => "retirement-",
        }
    }
    fn magic(self) -> &'static [u8] {
        match self {
            Self::Original => MAGIC,
            Self::Restoration => RESTORATION_MAGIC,
            Self::Finalization => FINALIZATION_MAGIC,
            Self::Quiescence => QUIESCENCE_MAGIC,
            Self::RetirementPreparation => RETIREMENT_PREPARATION_MAGIC,
        }
    }
    fn dispatch(self, payload: &[u8]) -> Result<ComponentDigest, String> {
        match self {
            Self::Original => NativeDisplayRecoveryCheckpoint::stored_dispatch(payload),
            Self::Restoration => Ok(NativeDisplayRestorationReservation::decode(payload)?
                .binding()
                .dispatch_digest),
            Self::Finalization | Self::Quiescence => {
                Ok(NativeDisplayFinalizationReservation::decode(payload)?
                    .binding()
                    .dispatch_digest)
            }
            Self::RetirementPreparation => Ok(
                NativeDisplayRetirementPreparation::decode(payload)?
                    .terminal()
                    .binding()
                    .dispatch_digest,
            ),
        }
    }
    fn name(self, dispatch: &ComponentDigest) -> String {
        format!("{}{}.checkpoint", self.prefix(), dispatch.to_hex())
    }
}

/// An immutable, bounded, directory-wide lineage check. A marker for one
/// recovery scope cannot be silently ignored while another scope is queried
/// or reserved. All bytes are read under the existing directory flock; this
/// structure grants neither current native authority nor permission to retire.
#[derive(Default)]
struct TerminalLineage {
    restorations: BTreeMap<String, NativeDisplayRestorationReservation>,
    terminals: BTreeMap<String, NativeDisplayFinalizationReservation>,
    quiescences: BTreeMap<String, NativeDisplayFinalizationReservation>,
    preparations: BTreeMap<String, NativeDisplayRetirementPreparation>,
}

impl TerminalLineage {
    fn observe(&mut self, kind: Kind, bytes: &[u8]) -> Result<(), String> {
        match kind {
            Kind::Original => Ok(()),
            Kind::Restoration => {
                let record = NativeDisplayRestorationReservation::decode(bytes)?;
                let scope = record
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|_| unavailable())?
                    .resource_id()
                    .map_err(|_| unavailable())?
                    .as_str()
                    .to_owned();
                if self.restorations.insert(scope, record).is_some() {
                    return Err(unavailable());
                }
                Ok(())
            }
            Kind::RetirementPreparation => {
                let record = NativeDisplayRetirementPreparation::decode(bytes)?;
                let scope = record
                    .terminal()
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|_| unavailable())?
                    .resource_id()
                    .map_err(|_| unavailable())?
                    .as_str()
                    .to_owned();
                if self.preparations.insert(scope, record).is_some() {
                    return Err(unavailable());
                }
                Ok(())
            }
            Kind::Finalization | Kind::Quiescence => {
                let record = NativeDisplayFinalizationReservation::decode(bytes)?;
                let scope = record
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|_| unavailable())?
                    .resource_id()
                    .map_err(|_| unavailable())?
                    .as_str()
                    .to_owned();
                let table = if kind == Kind::Finalization {
                    &mut self.terminals
                } else {
                    &mut self.quiescences
                };
                if table.insert(scope, record).is_some() {
                    return Err(unavailable());
                }
                Ok(())
            }
        }
    }

    fn verify(&self) -> Result<(), String> {
        // Every retained finalization must have the exact actual restoration
        // transaction and bound material, even when it is for another scope.
        for (scope, record) in &self.terminals {
            let parent = self.restorations.get(scope).ok_or_else(unavailable)?;
            record.validate_restoration(parent)?;
        }
        // A durable native marker without its complete immutable terminal is
        // orphan history, never success or a reason to permit another writer.
        for (scope, record) in &self.quiescences {
            let terminal = self.terminals.get(scope).ok_or_else(unavailable)?;
            if record.canonical_bytes() != terminal.canonical_bytes() {
                return Err(unavailable());
            }
        }
        for (scope, record) in &self.preparations {
            let terminal = self.terminals.get(scope).ok_or_else(unavailable)?;
            let quiesced = self.quiescences.get(scope).ok_or_else(unavailable)?;
            if record.terminal().canonical_bytes() != terminal.canonical_bytes()
                || record.terminal().canonical_bytes() != quiesced.canonical_bytes()
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }
}

fn named_kind(name: &[u8]) -> Result<(Kind, ComponentDigest), String> {
    for kind in [
        Kind::Original,
        Kind::Restoration,
        Kind::Finalization,
        Kind::Quiescence,
        Kind::RetirementPreparation,
    ] {
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

fn read_named_record(
    fd: &OwnedFd,
    uid: u32,
    name: &std::ffi::CStr,
) -> Result<(Kind, ComponentDigest, Vec<u8>), String> {
    let (kind, dispatch) = named_kind(name.to_bytes())?;
    let before = fs::statat(fd, name, fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|_| unavailable())?;
    record_metadata(&before, uid)?;
    let record = fs::openat(
        fd,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| unavailable())?;
    let after = fs::fstat(&record).map_err(|_| unavailable())?;
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
        return Err(unavailable());
    }
    Ok((
        kind,
        dispatch,
        check_kind_record(record, uid, &dispatch, kind)?,
    ))
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
        let retirement = if kind == Kind::RetirementPreparation {
            Some(NativeDisplayRetirementPreparation::decode(payload)?)
        } else {
            None
        };
        let terminal = if matches!(kind, Kind::Finalization | Kind::Quiescence) {
            Some(NativeDisplayFinalizationReservation::decode(payload)?)
        } else if let Some(preparation) = &retirement {
            Some(NativeDisplayFinalizationReservation::decode(
                &preparation.terminal().canonical_bytes(),
            )?)
        } else {
            None
        };
        let mut parent_seen = false;
        let mut terminal_seen = false;
        let mut quiescence_seen = false;
        let mut lineage = TerminalLineage::default();
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
            let (old_kind, _, previous) = read_named_record(fd, uid, name)?;
            lineage.observe(old_kind, &previous)?;
            if let Some(terminal) = &terminal {
                let material = terminal.decoded_material()?;
                if old_kind == Kind::Restoration {
                    let retained = NativeDisplayRestorationReservation::decode(&previous)?;
                    if retained
                        .decoded_material()?
                        .recovery_scope()
                        .map_err(|error| error.to_string())?
                        == material
                            .recovery_scope()
                            .map_err(|error| error.to_string())?
                    {
                        if parent_seen {
                            return Err(unavailable());
                        }
                        terminal.validate_restoration(&retained)?;
                        parent_seen = true;
                    }
                }
                if old_kind == Kind::Finalization {
                    let old = NativeDisplayFinalizationReservation::decode(&previous)?;
                    let old = old.decoded_material()?;
                    let new_scope = material.restoration().replacement().topology();
                    let old_scope = old.restoration().replacement().topology();
                    if matches!(kind, Kind::Quiescence | Kind::RetirementPreparation)
                        && previous == terminal.canonical_bytes()
                    {
                        if terminal_seen {
                            return Err(unavailable());
                        }
                        terminal_seen = true; // Only the same immutable LNRT parent.
                    } else if material.restoration_dispatch() == old.restoration_dispatch()
                        || (new_scope.session().boot() == old_scope.session().boot()
                            && new_scope.session().uid() == old_scope.session().uid()
                            && new_scope.seat() == old_scope.seat())
                    {
                        return Err(unavailable()); // Explicit qualified supersession only.
                    }
                }
            }
            if kind == Kind::RetirementPreparation
                && old_kind == Kind::Quiescence
                && previous == terminal.as_ref().ok_or_else(unavailable)?.canonical_bytes()
            {
                if quiescence_seen {
                    return Err(unavailable());
                }
                quiescence_seen = true;
            }
            if kind == Kind::Finalization && old_kind == Kind::Quiescence {
                let old = NativeDisplayFinalizationReservation::decode(&previous)?;
                let old = old.decoded_material()?;
                let current = terminal
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .decoded_material()?;
                let a = old.restoration().replacement().topology();
                let b = current.restoration().replacement().topology();
                if old.restoration_dispatch() == current.restoration_dispatch()
                    || (a.session().boot() == b.session().boot()
                        && a.session().uid() == b.session().uid()
                        && a.seat() == b.seat())
                {
                    return Err(unavailable()); // Orphan marker cannot be superseded.
                }
            }
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
        lineage.verify()?;
        if terminal.is_some()
            && (!parent_seen
                || matches!(kind, Kind::Quiescence | Kind::RetirementPreparation) && !terminal_seen
                || kind == Kind::RetirementPreparation && !quiescence_seen)
        {
            return Err(unavailable());
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

pub(super) fn reserve_finalization(
    record: &NativeDisplayFinalizationReservation,
) -> Result<(), String> {
    reserve_kind_at(
        &open()?,
        0,
        &record.binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::Finalization,
    )
}

/// A durable one-use quiescence marker, not Root retirement or release.
/// It requires an exact synced terminal plus restoration parent. Interrupted
/// writes leave the reservation fenced and never authorize a retry.
pub(super) fn reserve_quiescence(
    record: &NativeDisplayFinalizationReservation,
) -> Result<(), String> {
    reserve_kind_at(
        &open()?,
        0,
        &record.binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::Quiescence,
    )
}

/// Root-only durable preparation. It binds the exact immutable LNRT/LNRQ
/// parents and records the Control correlation before any physical retirement.
/// This never releases a witness, inhibitor, input fence or startup admission.
pub(super) fn reserve_retirement_preparation(
    record: &NativeDisplayRetirementPreparation,
) -> Result<(), String> {
    reserve_kind_at(
        &open()?,
        0,
        &record.terminal().binding().dispatch_digest,
        &record.canonical_bytes(),
        Kind::RetirementPreparation,
    )
}

fn read_retirement_preparation_at(
    fd: &OwnedFd,
    uid: u32,
    retained: &NativeDisplayRestorationReservation,
) -> Result<Option<NativeDisplayRetirementPreparation>, String> {
    directory(fd, uid, true)?;
    fs::flock(fd, FlockOperation::NonBlockingLockShared).map_err(|_| unavailable())?;
    let result = (|| {
        let scope = retained
            .decoded_material()?
            .recovery_scope()
            .map_err(|_| unavailable())?
            .resource_id()
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let mut lineage = TerminalLineage::default();
        let mut count = 0;
        for entry in fs::Dir::read_from(fd).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            count += 1;
            if count > MAX_RECORDS {
                return Err(unavailable());
            }
            let (kind, _, bytes) = read_named_record(fd, uid, entry.file_name())?;
            lineage.observe(kind, &bytes)?;
        }
        lineage.verify()?;
        if lineage
            .restorations
            .get(&scope)
            .is_none_or(|record| record.canonical_bytes() != retained.canonical_bytes())
        {
            return Err(unavailable());
        }
        Ok(lineage.preparations.remove(&scope))
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    match (result, unlocked) {
        (Ok(record), Ok(())) => Ok(record),
        _ => Err(unavailable()),
    }
}

/// Read-only byte-for-byte readback of the one original Root preparation.
/// Control must still prove current owner, authority and physical state.
pub(super) fn read_retirement_preparation(
    retained: &NativeDisplayRestorationReservation,
) -> Result<Option<NativeDisplayRetirementPreparation>, String> {
    read_retirement_preparation_at(&open()?, 0, retained)
}

fn read_finalization_at(
    fd: &OwnedFd,
    uid: u32,
    retained: &NativeDisplayRestorationReservation,
) -> Result<Option<NativeDisplayFinalizationReservation>, String> {
    read_finalization_state_at(fd, uid, retained).map(|(terminal, _)| terminal)
}

/// Read Root's exact immutable terminal and quiescence record under one lock.
fn read_finalization_state_at(
    fd: &OwnedFd,
    uid: u32,
    retained: &NativeDisplayRestorationReservation,
) -> Result<(Option<NativeDisplayFinalizationReservation>, bool), String> {
    directory(fd, uid, true)?;
    fs::flock(fd, FlockOperation::NonBlockingLockShared).map_err(|_| unavailable())?;
    let result = (|| {
        let scope = retained
            .decoded_material()?
            .recovery_scope()
            .map_err(|error| error.to_string())?;
        let mut found = None;
        let mut quiescence = None;
        let mut parent_seen = false;
        let mut lineage = TerminalLineage::default();
        let mut count = 0;
        for entry in fs::Dir::read_from(fd).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            count += 1;
            if count > MAX_RECORDS {
                return Err(unavailable());
            }
            let (kind, _, bytes) = read_named_record(fd, uid, entry.file_name())?;
            lineage.observe(kind, &bytes)?;
            if kind == Kind::Restoration {
                let parent = NativeDisplayRestorationReservation::decode(&bytes)?;
                if parent
                    .decoded_material()?
                    .recovery_scope()
                    .map_err(|error| error.to_string())?
                    == scope
                {
                    if parent_seen || bytes != retained.canonical_bytes() {
                        return Err(unavailable());
                    }
                    parent_seen = true;
                }
            }
            if !matches!(kind, Kind::Finalization | Kind::Quiescence) {
                continue;
            }
            let terminal = NativeDisplayFinalizationReservation::decode(&bytes)?;
            if terminal
                .decoded_material()?
                .recovery_scope()
                .map_err(|error| error.to_string())?
                == scope
            {
                terminal.validate_restoration(retained)?;
                let slot = if kind == Kind::Quiescence {
                    &mut quiescence
                } else {
                    &mut found
                };
                if slot.is_some() {
                    return Err(unavailable());
                }
                *slot = Some(terminal);
            }
        }
        lineage.verify()?;
        if !parent_seen {
            return Err(unavailable());
        }
        if let Some(ref quiesced) = quiescence
            && found
                .as_ref()
                .is_none_or(|terminal| terminal.canonical_bytes() != quiesced.canonical_bytes())
        {
            return Err(unavailable()); // Orphan or substituted quiescence marker.
        }
        let durable_quiescence = quiescence.is_some();
        Ok((found, durable_quiescence))
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    match (result, unlocked) {
        (Ok(record), Ok(())) => Ok(record),
        _ => Err(unavailable()),
    }
}

/// Reservation comparison only. The caller verifies actual original live
/// witnesses and current recovery startup before/after; no release proof exists.
pub(super) fn read_finalization(
    retained: &NativeDisplayRestorationReservation,
) -> Result<Option<NativeDisplayFinalizationReservation>, String> {
    read_finalization_at(&open()?, 0, retained)
}

/// A disk marker is historical comparison evidence, not live native proof.
pub(super) fn read_finalization_state(
    retained: &NativeDisplayRestorationReservation,
) -> Result<(Option<NativeDisplayFinalizationReservation>, bool), String> {
    read_finalization_state_at(&open()?, 0, retained)
}

fn read_restoration_at(
    fd: &OwnedFd,
    uid: u32,
    scope: &linura_core::DisplayRecoveryScope,
) -> Result<NativeDisplayRestorationReservation, String> {
    directory(fd, uid, true)?;
    fs::flock(fd, FlockOperation::NonBlockingLockShared).map_err(|_| unavailable())?;
    let result = (|| {
        let mut found = None;
        let mut lineage = TerminalLineage::default();
        let mut count = 0;
        for entry in fs::Dir::read_from(fd).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            count += 1;
            if count > MAX_RECORDS {
                return Err(unavailable());
            }
            // Validate every retained/unknown entry, including unrelated ones.
            // This query never repairs history or makes room for another write.
            let (kind, _, payload) = read_named_record(fd, uid, name)?;
            lineage.observe(kind, &payload)?;
            if kind != Kind::Restoration {
                continue;
            }
            let record = NativeDisplayRestorationReservation::decode(&payload)?;
            if record
                .decoded_material()?
                .recovery_scope()
                .map_err(|_| unavailable())?
                == *scope
            {
                if found.is_some() {
                    return Err(unavailable());
                }
                found = Some(record);
            }
        }
        lineage.verify()?;
        found.ok_or_else(unavailable)
    })();
    let unlocked = fs::flock(fd, FlockOperation::Unlock).map_err(|_| unavailable());
    match (result, unlocked) {
        (Ok(record), Ok(())) => Ok(record),
        _ => Err(unavailable()),
    }
}

/// Immutable comparison data only. The caller separately verifies the live
/// original witnesses and current recovery startup before and after this read.
pub(super) fn read_restoration(
    scope: &linura_core::DisplayRecoveryScope,
) -> Result<NativeDisplayRestorationReservation, String> {
    read_restoration_at(&open()?, 0, scope)
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
