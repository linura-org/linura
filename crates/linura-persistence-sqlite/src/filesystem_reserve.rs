use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use linura_transaction::TransactionStoreError;
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use rustix::fs::{FallocateFlags, fallocate};

// Keep one full MiB of physically allocated emergency headroom per slot even
// on 4 KiB SQLite pages. Real ext4 ENOSPC qualification showed that 256 KiB
// can be consumed by the terminal WAL plus filesystem-metadata durability path.
const MIN_RECOVERY_RESERVE_SLOT_BYTES: u64 = 1024 * 1024;
const RECOVERY_RESERVE_WAL_PAGES: u64 = 32;
const RESERVE_WRITE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct RecoveryReserve {
    database_path: PathBuf,
    path: PathBuf,
    slot_bytes: u64,
}

impl RecoveryReserve {
    fn from_connection(
        connection: &Connection,
        page_size: u64,
    ) -> Result<Self, TransactionStoreError> {
        let database = connection.path().ok_or_else(|| {
            TransactionStoreError::UnsupportedSchema(
                "durable authority storage has no filesystem path".into(),
            )
        })?;
        if database.is_empty() {
            return Err(TransactionStoreError::UnsupportedSchema(
                "durable authority storage cannot use a temporary or in-memory database".into(),
            ));
        }
        Self::from_database_path(Path::new(database), page_size)
    }

    fn from_database_path(
        database_path: &Path,
        page_size: u64,
    ) -> Result<Self, TransactionStoreError> {
        let slot_bytes = page_size
            .checked_mul(RECOVERY_RESERVE_WAL_PAGES)
            .ok_or(TransactionStoreError::CapacityExceeded)?
            .max(MIN_RECOVERY_RESERVE_SLOT_BYTES);
        Ok(Self {
            path: reserve_path_for_database(database_path),
            database_path: database_path.to_path_buf(),
            slot_bytes,
        })
    }

    #[cfg(target_os = "linux")]
    fn release_opener_headroom(&self) -> io::Result<()> {
        let file = self.open_locked()?;
        let length = file.metadata()?.len();
        self.require_aligned(length)?;
        let minimum = self.slot_bytes.checked_mul(2)
            .ok_or_else(|| io::Error::other("recovery reserve size overflow"))?;
        if length < minimum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve has no dedicated opener slot to release",
            ));
        }
        let allocated = physical_allocation_bytes(&file)?;
        let minimum_allocated = length.checked_sub(self.slot_bytes)
            .ok_or_else(|| io::Error::other("recovery reserve opener offset underflow"))?;
        if allocated < minimum_allocated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve has allocation loss beyond the opener slot",
            ));
        }
        fallocate(
            &file,
            FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
            minimum_allocated,
            self.slot_bytes,
        ).map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        file.sync_all()?;
        verify_released_opener_headroom(&file, length, self.slot_bytes)
    }

    fn restore_opener_headroom(&self, expected_len: u64) -> io::Result<()> {
        let mut file = self.open_locked()?;
        if file.metadata()?.len() != expected_len || expected_len < self.slot_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve opener restoration target is invalid",
            ));
        }
        let start = expected_len - self.slot_bytes;
        file.seek(SeekFrom::Start(start))?;
        let mut position = start;
        let mut buffer = [0_u8; RESERVE_WRITE_CHUNK_BYTES];
        while position < expected_len {
            fill_reserve_bytes(&mut buffer, position);
            let remaining = expected_len - position;
            let length = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| io::Error::other("recovery reserve write length overflow"))?;
            file.write_all(&buffer[..length])?;
            position = position.checked_add(length as u64)
                .ok_or_else(|| io::Error::other("recovery reserve size overflow"))?;
        }
        file.sync_all()?;
        verify_physical_allocation(&file, expected_len)
    }

    fn ensure_slots(&self, desired_slots: u64) -> io::Result<()> {
        let target = self.target_len(desired_slots)?;
        let mut file = self.open_locked()?;
        let original = file.metadata()?.len();
        self.require_aligned(original)?;
        if original >= target {
            verify_physical_allocation(&file, original)?;
            return Ok(());
        }

        file.seek(SeekFrom::Start(original))?;
        let mut position = original;
        let mut buffer = [0_u8; RESERVE_WRITE_CHUNK_BYTES];
        while position < target {
            fill_reserve_bytes(&mut buffer, position);
            let remaining = target - position;
            let length = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| io::Error::other("recovery reserve write length overflow"))?;
            if let Err(error) = file.write_all(&buffer[..length]) {
                rollback_growth(&file, original);
                return Err(error);
            }
            position = position
                .checked_add(length as u64)
                .ok_or_else(|| io::Error::other("recovery reserve size overflow"))?;
        }
        if let Err(error) = file.sync_all() {
            rollback_growth(&file, original);
            return Err(error);
        }
        verify_physical_allocation(&file, target)
    }

    fn release_to_slots(&self, desired_slots: u64) -> io::Result<()> {
        let target = self.target_len(desired_slots)?;
        let file = self.open_locked()?;
        let current = file.metadata()?.len();
        self.require_aligned(current)?;
        if current < target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve is smaller than the requested release target",
            ));
        }
        if current > target {
            file.set_len(target)?;
            file.sync_all()?;
        }
        verify_physical_allocation(&file, target)
    }

    fn validate_and_reconcile(
        &self,
        reservation_rows: u64,
        opener_released: bool,
    ) -> Result<(), TransactionStoreError> {
        let expected_slots = if reservation_rows == 0 {
            0
        } else {
            reservation_rows
                .checked_add(1)
                .ok_or(TransactionStoreError::CapacityExceeded)?
        };
        let expected_len = self.target_len(expected_slots).map_err(io_store)?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(TransactionStoreError::Corruption(
                        "filesystem recovery reserve path is not a regular file".into(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if reservation_rows == 0 {
                    return Ok(());
                }
                return Err(TransactionStoreError::Corruption(
                    "filesystem recovery reserve is missing for nonterminal authority state".into(),
                ));
            }
            Err(error) => return Err(io_store(error)),
        }

        let file = self.open_locked().map_err(io_store)?;
        let current = file.metadata().map_err(io_store)?.len();
        if !current.is_multiple_of(self.slot_bytes) {
            // Reserve growth is deliberately performed before the SQLite write
            // that depends on it becomes durable. A process kill can therefore
            // leave only a partial, unaligned append while SQLite rolls back the
            // corresponding reservation row. Under the database write lock the
            // authenticated reservation count is authoritative: bytes strictly
            // beyond its exact target are uncommitted crash residue and can be
            // discarded. Missing required bytes are never repaired or hidden.
            if current <= expected_len {
                return Err(TransactionStoreError::Corruption(
                    "filesystem recovery reserve is unaligned and does not contain provably excess crash residue"
                        .into(),
                ));
            }
            file.set_len(expected_len).map_err(io_store)?;
            file.sync_all().map_err(io_store)?;
            verify_physical_allocation(&file, expected_len).map_err(io_store)?;
            return Ok(());
        }
        let current_slots = current / self.slot_bytes;
        drop(file);

        if current_slots > expected_slots {
            return self.release_to_slots(expected_slots).map_err(io_store);
        }
        if current_slots == expected_slots {
            let file = self.open_locked().map_err(io_store)?;
            if opener_released {
                if reservation_rows == 0 {
                    return Err(TransactionStoreError::StateConflict);
                }
                verify_released_opener_headroom(&file, expected_len, self.slot_bytes)
                    .map_err(io_store)?;
                return Ok(());
            }
            match verify_physical_allocation(&file, expected_len) {
                Ok(()) => return Ok(()),
                Err(_) if reservation_rows > 0
                    && verify_released_opener_headroom(&file, expected_len, self.slot_bytes).is_ok() =>
                {
                    drop(file);
                    return self.restore_opener_headroom(expected_len).map_err(io_store);
                }
                Err(error) => return Err(io_store(error)),
            }
        }
        if current_slots.checked_add(1) == Some(expected_slots) {
            // A terminal transition releases exactly one filesystem slot before
            // its SQLite reservation delete and audit write are durably committed.
            // If SQLite rolls back, that one durable reservation row is restored
            // while the nontransactional sidecar truncation cannot be. Only this
            // exact one-slot deficit is therefore provable rollback residue.
            return self.ensure_slots(expected_slots).map_err(io_store);
        }
        Err(TransactionStoreError::Corruption(
            "filesystem recovery reserve deficit exceeds the single provable rollback slot".into(),
        ))
    }

    fn open_locked(&self) -> io::Result<File> {
        let path_state = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(metadata) = &path_state
            && !metadata.file_type().is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve path is not a regular file",
            ));
        }

        let (file, created) = if path_state.is_some() {
            (self.open_existing()?, false)
        } else {
            match OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&self.path)
            {
                Ok(file) => (file, true),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    (self.open_existing()?, false)
                }
                Err(error) => return Err(error),
            }
        };
        file.lock()?;
        self.verify_locked_file_identity(&file)?;
        if created {
            sync_parent(&self.path)?;
        }
        Ok(file)
    }

    fn open_existing(&self) -> io::Result<File> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve path is not a regular file",
            ));
        }
        OpenOptions::new().read(true).write(true).open(&self.path)
    }

    fn verify_locked_file_identity(&self, file: &File) -> io::Result<()> {
        let opened = file.metadata()?;
        if !opened.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve descriptor is not a regular file",
            ));
        }
        let path_metadata = fs::symlink_metadata(&self.path)?;
        if !path_metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve path changed to a non-regular file",
            ));
        }
        let database_metadata = fs::metadata(&self.database_path)?;
        if !database_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authority database path is not a regular file",
            ));
        }
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt;
            if path_metadata.dev() != opened.dev() || path_metadata.ino() != opened.ino() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "filesystem recovery reserve pathname does not identify the locked file",
                ));
            }
            if opened.dev() != database_metadata.dev() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "filesystem recovery reserve is not on the authority database filesystem",
                ));
            }
            if opened.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "filesystem recovery reserve must not have additional hard links",
                ));
            }
        }
        Ok(())
    }

    fn target_len(&self, slots: u64) -> io::Result<u64> {
        self.slot_bytes
            .checked_mul(slots)
            .ok_or_else(|| io::Error::other("recovery reserve size overflow"))
    }

    fn require_aligned(&self, length: u64) -> io::Result<()> {
        if !length.is_multiple_of(self.slot_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve length is not slot-aligned",
            ));
        }
        Ok(())
    }
}

pub(crate) fn release_preopen_recovery_headroom(
    database: &Path,
) -> Result<bool, TransactionStoreError> {
    #[cfg(target_os = "linux")]
    {
        let metadata = match fs::symlink_metadata(database) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_store(error)),
        };
        if !metadata.file_type().is_file() {
            return Err(TransactionStoreError::Corruption(
                "authority database path is not a regular file during terminal recovery open".into(),
            ));
        }
        let page_size = sqlite_page_size_from_header(database).map_err(io_store)?;
        let reserve = RecoveryReserve::from_database_path(database, page_size)?;
        match fs::symlink_metadata(&reserve.path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(TransactionStoreError::Corruption(
                "filesystem recovery reserve path is not a regular file".into(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_store(error)),
        }
        reserve.release_opener_headroom().map_err(io_store)?;
        Ok(true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = database;
        Err(TransactionStoreError::UnsupportedSchema(
            "terminal recovery open requires Linux hole-punch support".into(),
        ))
    }
}

pub(crate) fn register_filesystem_reserve_functions(
    connection: &Connection,
    page_size: u64,
) -> Result<(), TransactionStoreError> {
    let reserve = RecoveryReserve::from_connection(connection, page_size)?;
    let grow = reserve.clone();
    connection
        .create_scalar_function(
            "linura_fs_reserve_slots",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let Ok(desired) = u64::try_from(context.get::<i64>(0)?) else {
                    return Ok(-1_i64);
                };
                Ok(reserve_result(grow.ensure_slots(desired)))
            },
        )
        .map_err(sqlite_store)?;

    let shrink = reserve;
    connection
        .create_scalar_function(
            "linura_fs_release_slots",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let Ok(desired) = u64::try_from(context.get::<i64>(0)?) else {
                    return Ok(-1_i64);
                };
                Ok(reserve_result(shrink.release_to_slots(desired)))
            },
        )
        .map_err(sqlite_store)
}

pub(crate) fn validate_filesystem_reserve(
    connection: &Connection,
    page_size: u64,
    reservation_rows: u64,
    opener_released: bool,
) -> Result<(), TransactionStoreError> {
    // The complete durable reservation scan and this reconciliation must share
    // one SQLite write-serialization point. Reconciliation may shrink the
    // same-filesystem sidecar, so accepting an autocommit caller would re-open
    // the mixed-snapshot race this invariant is intended to prevent.
    if connection.is_autocommit() {
        return Err(TransactionStoreError::StateConflict);
    }
    let locked_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM audit_reservations", [], |row| row.get(0))
        .map_err(sqlite_store)?;
    let locked_rows = u64::try_from(locked_rows).map_err(|_| {
        TransactionStoreError::Corruption(
            "negative aggregate physical reservation count under reconciliation lock".into(),
        )
    })?;
    if locked_rows != reservation_rows {
        return Err(TransactionStoreError::Corruption(
            "physical reservation count changed inside serialized validation".into(),
        ));
    }
    RecoveryReserve::from_connection(connection, page_size)?
        .validate_and_reconcile(locked_rows, opener_released)
}

pub(crate) fn reserve_path_for_database(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".linura-recovery-reserve");
    PathBuf::from(path)
}

fn fill_reserve_bytes(buffer: &mut [u8], offset: u64) {
    let mut state = offset ^ 0x9e37_79b9_7f4a_7c15;
    for byte in buffer {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 24) as u8;
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

fn physical_allocation_bytes(file: &File) -> io::Result<u64> {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.blocks().saturating_mul(512))
    }
    #[cfg(not(target_family = "unix"))]
    {
        Ok(file.metadata()?.len())
    }
}

fn verify_released_opener_headroom(
    file: &File,
    expected_len: u64,
    slot_bytes: u64,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.len() != expected_len || expected_len < slot_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem recovery reserve released-opener length is invalid",
        ));
    }
    let allocated = physical_allocation_bytes(file)?;
    let minimum = expected_len - slot_bytes;
    if allocated < minimum || allocated >= expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem recovery reserve does not contain exactly bounded opener headroom",
        ));
    }
    Ok(())
}

fn sqlite_page_size_from_header(database: &Path) -> io::Result<u64> {
    let mut file = File::open(database)?;
    let mut header = [0_u8; 100];
    file.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority database does not contain a SQLite v3 header",
        ));
    }
    let encoded = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if encoded == 1 { 65_536 } else { u64::from(encoded) };
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority database header contains an invalid SQLite page size",
        ));
    }
    Ok(page_size)
}

fn verify_physical_allocation(file: &File, expected_len: u64) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem recovery reserve length changed unexpectedly",
        ));
    }
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::MetadataExt;
        let allocated = metadata.blocks().saturating_mul(512);
        if allocated < expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem recovery reserve is sparse or not physically allocated",
            ));
        }
    }
    Ok(())
}

fn rollback_growth(file: &File, original: u64) {
    let _ = file.set_len(original);
    let _ = file.sync_all();
}

fn reserve_result(result: io::Result<()>) -> i64 {
    match result {
        Ok(()) => 1,
        Err(error) if error.raw_os_error() == Some(28) => 0,
        Err(_) => -1,
    }
}

fn io_store(error: io::Error) -> TransactionStoreError {
    if error.raw_os_error() == Some(28) {
        TransactionStoreError::Storage(format!("physical storage exhausted (ENOSPC): {error}"))
    } else if error.kind() == io::ErrorKind::InvalidData {
        TransactionStoreError::Corruption(error.to_string())
    } else {
        TransactionStoreError::Storage(error.to_string())
    }
}

fn sqlite_store(error: rusqlite::Error) -> TransactionStoreError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error
        && code.code == rusqlite::ErrorCode::DiskFull
    {
        return TransactionStoreError::Storage(format!("SQLite physical storage exhausted: {error}"));
    }
    TransactionStoreError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_RESERVE: AtomicU64 = AtomicU64::new(0);

    fn temporary_database_path() -> PathBuf {
        let sequence = NEXT_RESERVE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "linura-v04-filesystem-reserve-{}-{sequence}.db",
            std::process::id()
        ))
    }

    fn direct_reserve(database: &Path) -> RecoveryReserve {
        File::create(database)
            .and_then(|file| file.sync_all())
            .unwrap_or_else(|error| unreachable!("{error}"));
        RecoveryReserve {
            database_path: database.to_path_buf(),
            path: reserve_path_for_database(database),
            slot_bytes: 64 * 1024,
        }
    }

    #[test]
    fn reserve_growth_is_physical_and_release_is_slot_aligned() {
        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let _ = fs::remove_file(&path);

        reserve
            .ensure_slots(3)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            3 * 64 * 1024
        );
        reserve
            .release_to_slots(2)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            2 * 64 * 1024
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(database);
    }

    #[test]
    fn interrupted_unaligned_growth_is_trimmed_only_when_provably_excess() {
        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let _ = fs::remove_file(&path);
        reserve
            .ensure_slots(2)
            .unwrap_or_else(|error| unreachable!("{error}"));

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap_or_else(|error| unreachable!("{error}"));
        file.write_all(&vec![0x5a; 32 * 1024])
            .unwrap_or_else(|error| unreachable!("{error}"));
        file.sync_all()
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(file);
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            2 * 64 * 1024 + 32 * 1024
        );

        reserve
            .validate_and_reconcile(1, false)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            2 * 64 * 1024
        );

        let undersized = 64 * 1024 + 32 * 1024;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(undersized))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            reserve.validate_and_reconcile(1, false),
            Err(TransactionStoreError::Corruption(reason))
                if reason.contains("does not contain provably excess crash residue")
        ));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(database);
    }

    #[test]
    fn rolled_back_release_restores_the_emergency_slot_before_acceptance() {
        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let _ = fs::remove_file(&path);
        reserve
            .ensure_slots(2)
            .unwrap_or_else(|error| unreachable!("{error}"));
        reserve
            .release_to_slots(1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            64 * 1024
        );
        reserve
            .validate_and_reconcile(1, false)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            2 * 64 * 1024
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(database);
    }

    #[test]
    fn multi_slot_reserve_deficits_fail_closed() {
        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let _ = fs::remove_file(&path);

        reserve
            .ensure_slots(3)
            .unwrap_or_else(|error| unreachable!("{error}"));
        reserve
            .release_to_slots(1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            reserve.validate_and_reconcile(2, false),
            Err(TransactionStoreError::Corruption(reason))
                if reason.contains("deficit exceeds the single provable rollback slot")
        ));

        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(0))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            reserve.validate_and_reconcile(1, false),
            Err(TransactionStoreError::Corruption(reason))
                if reason.contains("deficit exceeds the single provable rollback slot")
        ));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(database);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn symlinked_reserve_is_rejected_without_mutating_target() {
        use std::os::unix::fs::symlink;

        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let target = PathBuf::from(format!("{}.reserve-target", database.display()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&target);
        let sentinel = b"unrelated-target-must-not-change";
        let mut target_file = File::create(&target)
            .unwrap_or_else(|error| unreachable!("{error}"));
        target_file
            .write_all(sentinel)
            .unwrap_or_else(|error| unreachable!("{error}"));
        target_file
            .sync_all()
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(target_file);
        symlink(&target, &path)
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert!(reserve.ensure_slots(2).is_err());
        assert_eq!(
            fs::read(&target).unwrap_or_else(|error| unreachable!("{error}")),
            sentinel
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(target);
        let _ = fs::remove_file(database);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preopen_opener_headroom_release_is_idempotent_and_bounded() {
        let database = temporary_database_path();
        let reserve = direct_reserve(&database);
        let path = reserve.path.clone();
        let _ = fs::remove_file(&path);
        reserve.ensure_slots(2).unwrap_or_else(|error| unreachable!("{error}"));
        let logical = fs::metadata(&path).unwrap_or_else(|error| unreachable!("{error}")).len();
        reserve.release_opener_headroom().unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(fs::metadata(&path).unwrap_or_else(|error| unreachable!("{error}")).len(), logical);
        let file = reserve.open_locked().unwrap_or_else(|error| unreachable!("{error}"));
        verify_released_opener_headroom(&file, logical, reserve.slot_bytes)
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(file);
        reserve.release_opener_headroom().unwrap_or_else(|error| unreachable!("{error}"));
        reserve.release_to_slots(1).unwrap_or_else(|error| unreachable!("{error}"));
        let file = reserve.open_locked().unwrap_or_else(|error| unreachable!("{error}"));
        verify_physical_allocation(&file, reserve.slot_bytes)
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(file);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(database);
    }

    #[test]
    fn filesystem_reconciliation_requires_database_write_serialization() {
        let database = temporary_database_path();
        let path = reserve_path_for_database(&database);
        let _ = fs::remove_file(&database);
        let _ = fs::remove_file(&path);

        let connection = Connection::open(&database)
            .unwrap_or_else(|error| unreachable!("{error}"));
        connection
            .execute_batch("CREATE TABLE audit_reservations (slot INTEGER NOT NULL);")
            .unwrap_or_else(|error| unreachable!("{error}"));
        connection
            .execute("INSERT INTO audit_reservations(slot) VALUES (0), (1)", [])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let page_size = u64::try_from(page_size)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let reserve = RecoveryReserve::from_connection(&connection, page_size)
            .unwrap_or_else(|error| unreachable!("{error}"));
        reserve
            .ensure_slots(3)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let before = fs::metadata(&path)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len();

        assert!(matches!(
            validate_filesystem_reserve(&connection, page_size, 2, false),
            Err(TransactionStoreError::StateConflict)
        ));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            before
        );

        connection
            .execute_batch("BEGIN IMMEDIATE")
            .unwrap_or_else(|error| unreachable!("{error}"));
        validate_filesystem_reserve(&connection, page_size, 2, false)
            .unwrap_or_else(|error| unreachable!("{error}"));
        connection
            .execute_batch("COMMIT")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            before
        );

        drop(connection);
        let _ = fs::remove_file(database);
        let _ = fs::remove_file(path);
    }
}
