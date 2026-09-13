#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "crates/linura-migrations/src/lib.rs"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    text = PATH.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''    pub fn load_recovery_record(&self) -> Result<Option<MigrationRecoveryRecord>, MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        if metadata.len() > MAX_RECOVERY_MARKER_BYTES {
            return Err(MigrationError::CorruptRecoveryMarker(
                "migration recovery marker exceeds the supported size bound".into(),
            ));
        }
        parse_recovery_record(&fs::read(path).map_err(io_error)?).map(Some)
    }
''',
        '''    pub fn load_recovery_record(&self) -> Result<Option<MigrationRecoveryRecord>, MigrationError> {
        let path = sidecar_path(&self.path, "recovery")?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        if metadata.len() > MAX_RECOVERY_MARKER_BYTES {
            return Err(MigrationError::CorruptRecoveryMarker(
                "migration recovery marker exceeds the supported size bound".into(),
            ));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
            .map_err(io_error)?;
        let opened = file.metadata().map_err(io_error)?;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.permissions().mode() & 0o022 != 0
            || opened.nlink() != 1
            || opened.len() > MAX_RECOVERY_MARKER_BYTES
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }

        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.read_to_end(&mut bytes).map_err(io_error)?;
        if bytes.len() as u64 > MAX_RECOVERY_MARKER_BYTES {
            return Err(MigrationError::CorruptRecoveryMarker(
                "migration recovery marker exceeds the supported size bound".into(),
            ));
        }

        let after = fs::symlink_metadata(&path).map_err(io_error)?;
        if after.file_type().is_symlink()
            || !after.file_type().is_file()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || after.permissions().mode() & 0o022 != 0
            || after.nlink() != 1
        {
            return Err(MigrationError::UntrustedRecoveryPath);
        }
        parse_recovery_record(&bytes).map(Some)
    }
''',
        "harden recovery-record read identity",
    )

    text = replace_once(
        text,
        '''        if let Some(guard) = &checkpoint_guard {
            guard.assert_stable()?;
        }

        if migration.apply().is_err() {
''',
        '''        if let Some(guard) = &checkpoint_guard
            && let Err(error) = guard.assert_stable()
        {
            if let Some(store) = &store
                && let Err(cleanup_error) = store.clear_recovery_marker()
            {
                return self.handle_cleanup_failure(cleanup_error);
            }
            self.recovery_record = None;
            return Err(error);
        }

        if migration.apply().is_err() {
''',
        "clear pre-effect drift marker",
    )

    text = replace_once(
        text,
        '''            if let Some(store) = store
                && let Err(cleanup_error) = store.clear_recovery_marker()
            {
                return self.handle_cleanup_failure(cleanup_error);
            }
            Err(MigrationError::VerificationFailed {
''',
        '''            if let Some(store) = store
                && let Err(cleanup_error) = store.clear_recovery_marker()
            {
                return self.handle_cleanup_failure(cleanup_error);
            }
            self.recovery_record = None;
            Err(MigrationError::VerificationFailed {
''',
        "clear in-memory record after rollback",
    )

    anchor = '''    #[test]
    fn failed_rollback_latches_recovery_and_survives_reopen() {
'''
    tests = '''    #[test]
    fn successful_rollback_clears_durable_and_in_memory_recovery_record() {
        let dir = TestDir::new("rollback-clears-recovery-record");
        let store = MigrationLedgerStore::new(dir.path().join("migration.ledger"));
        let mut migration = TestMigration::new("0004-rollback-clears", false);
        migration.verify_ok = false;
        let mut runner =
            MigrationRunner::open(store.clone()).unwrap_or_else(|error| unreachable!("{error}"));

        assert!(matches!(
            runner.run(&migration),
            Err(MigrationError::VerificationFailed { .. })
        ));
        assert!(!runner.requires_recovery());
        assert!(runner.recovery_record().is_none());
        assert_eq!(store.load_recovery_record(), Ok(None));
    }

    #[test]
    fn hard_linked_recovery_record_fails_closed() {
        let dir = TestDir::new("recovery-record-hard-link");
        let ledger = dir.path().join("migration.ledger");
        let store = MigrationLedgerStore::new(&ledger);
        let record = MigrationRecoveryRecord::new("0004-hard-link", None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let external = dir.path().join("external-recovery-record");
        fs::write(&external, serialize_recovery_record(&record))
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let recovery = sidecar_path(&ledger, "recovery")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::hard_link(&external, &recovery).unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            store.load_recovery_record(),
            Err(MigrationError::UntrustedRecoveryPath)
        );
    }

'''
    text = replace_once(text, anchor, tests + anchor, "add recovery cleanup/path tests")

    PATH.write_text(text, encoding="utf-8")
    print("final PR #128 recovery audit transformations applied")


if __name__ == "__main__":
    main()
