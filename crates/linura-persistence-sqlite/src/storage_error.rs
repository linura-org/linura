use std::path::Path;

use linura_transaction::TransactionStoreError;

/// Return true only when a store-open failure is attributable to physical
/// filesystem exhaustion rather than Linura's logical capacity contracts.
///
/// SQLite historically maps `SQLITE_FULL` into `CapacityExceeded` in this
/// crate, while sidecar I/O reports a `Storage` error. The caller must not treat
/// every logical capacity error as ENOSPC, so the ambiguous SQLite case is
/// accepted only when the database filesystem independently reports no blocks
/// available to the service account.
#[must_use]
pub fn is_physical_storage_exhaustion(database: &Path, error: &TransactionStoreError) -> bool {
    match error {
        TransactionStoreError::Storage(detail) => storage_detail_is_full(detail),
        TransactionStoreError::CapacityExceeded => filesystem_has_no_available_blocks(database),
        _ => false,
    }
}

fn storage_detail_is_full(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("database or disk is full")
        || detail.contains("no space left on device")
        || detail.contains("enospc")
        || detail.contains("physical storage exhausted")
}

fn filesystem_has_no_available_blocks(database: &Path) -> bool {
    #[cfg(target_family = "unix")]
    {
        let probe = database
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        rustix::fs::statvfs(probe)
            .map(|status| status.f_bavail == 0)
            .unwrap_or(false)
    }

    #[cfg(not(target_family = "unix"))]
    {
        let _ = database;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_physical_storage_failures_are_recognized() {
        let database = Path::new("/tmp/linura-authority.sqlite3");
        assert!(is_physical_storage_exhaustion(
            database,
            &TransactionStoreError::Storage("database or disk is full".into())
        ));
        assert!(is_physical_storage_exhaustion(
            database,
            &TransactionStoreError::Storage("No space left on device (os error 28)".into())
        ));
        assert!(!is_physical_storage_exhaustion(
            database,
            &TransactionStoreError::Storage("permission denied".into())
        ));
    }

    #[test]
    fn non_capacity_failures_never_enter_terminal_recovery() {
        let database = Path::new("/tmp/linura-authority.sqlite3");
        assert!(!is_physical_storage_exhaustion(
            database,
            &TransactionStoreError::Corruption("bad tag".into())
        ));
        assert!(!is_physical_storage_exhaustion(
            database,
            &TransactionStoreError::StateConflict
        ));
    }
}
