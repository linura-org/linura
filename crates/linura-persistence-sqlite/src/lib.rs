#![forbid(unsafe_code)]

//! Hardened SQLite/WAL persistence for Linura durable authority transactions.
//!
//! The database is treated as untrusted persistence input. Control-signed
//! handoff/recovery/commit requests authorize semantic transitions, while a
//! separate record-integrity key authenticates durable SQLite records. The
//! filesystem recovery reserve is an independent availability invariant: it
//! keeps physically allocated same-filesystem headroom for terminal recovery
//! when SQLite/WAL reaches real ENOSPC.

#[rustfmt::skip]
mod filesystem_reserve;
#[rustfmt::skip]
mod integrity;
#[rustfmt::skip]
mod schema;
#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
mod store;
mod idle_preferences;
mod protective_lock_settings;
mod request_journal;
mod storage_error;
#[rustfmt::skip]
mod validation;
#[rustfmt::skip]
#[allow(dead_code)]
#[path = "validation_base.rs"]
mod validation_base;

pub use idle_preferences::{IdleAdvisoryPreference, SqliteIdleAdvisoryPreferenceStore};
pub use integrity::SqliteIntegrityKey;
pub use protective_lock_settings::SqliteProtectiveLockSettingStore;
pub use request_journal::SqliteApprovedRequestJournal;
pub use storage_error::is_physical_storage_exhaustion;
pub use store::{SqliteSettings, SqliteTransactionStore, StoreLimits};

#[cfg(test)]
#[rustfmt::skip]
mod tests;
