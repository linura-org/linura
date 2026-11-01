//! Bounded read-only Library catalog over the released SQLite store.
//! Each page uses one consistent read transaction. Pagination cursors are
//! navigation aids, not authority, approval, or stable database epoch tokens.

use linura_core::{IntentId, ProfileId, SetupId};
use rusqlite::params;

use crate::store::{load_intent_revision, load_profile_revision, load_setup_revision};
use crate::{LibraryError, LocalLibrary, StoredIntent, StoredProfile, StoredSetup};

pub const MAX_CATALOG_PAGE_SIZE: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogPage<T, Id> {
    pub items: Vec<T>,
    pub next_after: Option<Id>,
}

fn page_limit(size: usize) -> Result<i64, LibraryError> {
    if !(1..=MAX_CATALOG_PAGE_SIZE).contains(&size) {
        return Err(LibraryError::Validation(format!(
            "catalog page size must be between 1 and {MAX_CATALOG_PAGE_SIZE}"
        )));
    }
    i64::try_from(size + 1)
        .map_err(|_| LibraryError::Validation("catalog page size overflow".into()))
}

fn checked_long_revision(value: i64, kind: &str) -> Result<u64, LibraryError> {
    u64::try_from(value).map_err(|_| LibraryError::Corrupt(format!("{kind} revision is negative",)))
}

fn checked_short_revision(value: i64, kind: &str) -> Result<u32, LibraryError> {
    u32::try_from(checked_long_revision(value, kind)?)
        .map_err(|_| LibraryError::Corrupt(format!("{kind} revision exceeds u32")))
}

impl LocalLibrary {
    /// One consistent SQLite read page; caller must revalidate before every write.
    /// Pages fetched in separate transactions are not a global catalog snapshot.
    pub fn catalog_intents_page(
        &mut self,
        after: Option<&IntentId>,
        size: usize,
    ) -> Result<CatalogPage<StoredIntent, IntentId>, LibraryError> {
        let limit = page_limit(size)?;
        let transaction = self.connection.transaction()?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT intent_id, revision FROM intents_current \
                 WHERE (?1 IS NULL OR intent_id > ?1) \
                 ORDER BY intent_id LIMIT ?2",
            )?;
            statement
                .query_map(params![after.map(|id| id.as_str()), limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let more = rows.len() > size;
        let mut items = Vec::with_capacity(rows.len().min(size));
        for (raw_id, raw_revision) in rows.into_iter().take(size) {
            let id =
                IntentId::new(raw_id).map_err(|error| LibraryError::Corrupt(error.to_string()))?;
            items.push(load_intent_revision(
                &transaction,
                &id,
                checked_long_revision(raw_revision, "intent")?,
            )?);
        }
        transaction.commit()?;
        let next_after = if more {
            items.last().map(|item| item.intent.id.clone())
        } else {
            None
        };
        Ok(CatalogPage { items, next_after })
    }

    /// One consistent SQLite read page; caller must revalidate before every write.
    /// Pages fetched in separate transactions are not a global catalog snapshot.
    pub fn catalog_setups_page(
        &mut self,
        after: Option<&SetupId>,
        size: usize,
    ) -> Result<CatalogPage<StoredSetup, SetupId>, LibraryError> {
        let limit = page_limit(size)?;
        let transaction = self.connection.transaction()?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT setup_id, MAX(revision) FROM setup_revisions \
                 WHERE (?1 IS NULL OR setup_id > ?1) GROUP BY setup_id \
                 ORDER BY setup_id LIMIT ?2",
            )?;
            statement
                .query_map(params![after.map(|id| id.as_str()), limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let more = rows.len() > size;
        let mut items = Vec::with_capacity(rows.len().min(size));
        for (raw_id, raw_revision) in rows.into_iter().take(size) {
            let id =
                SetupId::new(raw_id).map_err(|error| LibraryError::Corrupt(error.to_string()))?;
            items.push(load_setup_revision(
                &transaction,
                &id,
                checked_short_revision(raw_revision, "setup")?,
            )?);
        }
        transaction.commit()?;
        let next_after = if more {
            items.last().map(|item| item.setup.id.clone())
        } else {
            None
        };
        Ok(CatalogPage { items, next_after })
    }

    /// One consistent SQLite read page; caller must revalidate before every write.
    /// Pages fetched in separate transactions are not a global catalog snapshot.
    pub fn catalog_profiles_page(
        &mut self,
        after: Option<&ProfileId>,
        size: usize,
    ) -> Result<CatalogPage<StoredProfile, ProfileId>, LibraryError> {
        let limit = page_limit(size)?;
        let transaction = self.connection.transaction()?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT profile_id, MAX(revision) FROM profile_revisions \
                 WHERE (?1 IS NULL OR profile_id > ?1) GROUP BY profile_id \
                 ORDER BY profile_id LIMIT ?2",
            )?;
            statement
                .query_map(params![after.map(|id| id.as_str()), limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let more = rows.len() > size;
        let mut items = Vec::with_capacity(rows.len().min(size));
        for (raw_id, raw_revision) in rows.into_iter().take(size) {
            let id =
                ProfileId::new(raw_id).map_err(|error| LibraryError::Corrupt(error.to_string()))?;
            items.push(load_profile_revision(
                &transaction,
                &id,
                checked_short_revision(raw_revision, "profile")?,
            )?);
        }
        transaction.commit()?;
        let next_after = if more {
            items.last().map(|item| item.profile.id.clone())
        } else {
            None
        };
        Ok(CatalogPage { items, next_after })
    }
}
