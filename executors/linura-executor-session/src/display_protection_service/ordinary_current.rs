//! A separate one-use ordinary current-commit permission. Root spend is not
//! physical qualification, final fence retirement or successor authority.
use super::*;
fn current(record: &NativeDisplayOrdinaryCurrentPreparation) -> zbus::fdo::Result<()> {
    let w = record.frames().window();
    let (wall, boot) = (unix_ms()?, boot_ms()?);
    if wall < w.observed_unix_ms
        || wall >= record.expires_at_unix_ms()
        || boot < w.observed_boot_ms
        || boot >= w.deadline_boot_ms
    {
        return Err(unavailable());
    }
    Ok(())
}
impl NativeProtection {
    pub(super) fn ordinary_current_record(
        &self,
        a: &Admission,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let completion = a
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let memory = a.ordinary_current_commits.get(key.as_str());
        if !completion.1.current_spent() {
            if memory.is_some_and(|v| v.spent) {
                return Err(unavailable());
            }
            return Ok(Vec::new());
        }
        let memory = memory.filter(|v| v.spent).ok_or_else(unavailable)?;
        let (record, spent) = super::super::display_checkpoint::read_ordinary_current(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let root = a
            .ordinary_root_retirements
            .get(key.as_str())
            .filter(|v| v.closed)
            .ok_or_else(unavailable)?;
        if !spent
            || memory.digest != record.record_digest()
            || root.digest != record.parent().record_digest()
            || completion.0 != record.parent().parent().parent().record_digest()
        {
            return Err(unavailable());
        }
        Ok(record.canonical_bytes())
    }
    pub(super) fn reserve_ordinary_current_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryCurrentPreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        current(&record)?;
        let scope = record.frames().scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut a = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_completion_scope(&a, record.parent().parent().parent(), true)?;
        let root = a
            .ordinary_root_retirements
            .get(key.as_str())
            .filter(|v| v.closed)
            .ok_or_else(unavailable)?;
        let completion = a
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if a.ordinary_releases.get(key.as_str()).map(|v| v.1.as_str()) != Some(sender)
            || !completion.1.power_spent()
            || completion.1.current_spent()
            || root.digest != record.parent().record_digest()
            || a.ordinary_current_commits.len() >= MAX_PENDING
            || a.ordinary_current_commits.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        a.ordinary_current_commits.insert(
            key.as_str().into(),
            CurrentCommitReservation {
                digest: record.record_digest(),
                spent: false,
            },
        );
        super::super::display_checkpoint::reserve_ordinary_current(&record, false)
            .map_err(|_| unavailable())?;
        let (stored, spent) = super::super::display_checkpoint::read_ordinary_current(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(&a, record.parent().parent().parent(), true)?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_ordinary_current_mechanism(
        &self,
        sender: &str,
        key: &str,
        parent: &NativeDisplayOrdinaryCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        self.admit_control(sender)?;
        let mut a = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_completion_scope(&a, parent, true)?;
        if a.ordinary_releases.get(key).map(|v| v.1.as_str()) != Some(sender)
            || a.ordinary_completions
                .get(key)
                .is_none_or(|v| !v.1.power_spent() || v.1.current_spent())
        {
            return Err(unavailable());
        }
        let (record, spent) =
            super::super::display_checkpoint::read_ordinary_current(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        current(&record)?;
        if spent
            || record.parent().parent().parent().canonical_bytes() != parent.canonical_bytes()
            || record.record_digest() != ComponentDigest::from_bytes(*digest)
            || a.ordinary_root_retirements
                .get(key)
                .is_none_or(|v| !v.closed || v.digest != record.parent().record_digest())
        {
            return Err(unavailable());
        }
        let memory = a
            .ordinary_current_commits
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if memory.spent || memory.digest != record.record_digest() {
            return Err(unavailable());
        }
        memory.spent = true;
        super::super::display_checkpoint::reserve_ordinary_current(&record, true)
            .map_err(|_| unavailable())?;
        let (stored, spent) =
            super::super::display_checkpoint::read_ordinary_current(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        if !spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        current(&record)?;
        self.admit_control(sender)?;
        Ok(())
    }
}
