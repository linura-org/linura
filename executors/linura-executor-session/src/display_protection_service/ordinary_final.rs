//! Purpose-separated final permission and immutable ReleasedCurrent metadata.
//! Native retirement, independent Control proof and Root completion are distinct.
use super::*;
type FinalState = (
    NativeDisplayOrdinaryFinalPreparation,
    u32,
    Option<NativeDisplayOrdinaryReleasedRecord>,
);
fn fingerprint(bytes: &[u8]) -> ComponentDigest {
    ComponentDigest::from_bytes(sha2::Sha256::digest(bytes).into())
}
fn current(record: &NativeDisplayOrdinaryFinalPreparation) -> zbus::fdo::Result<()> {
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
    // Compare files only with actual original-channel memory; never rebuild it.
    pub(super) fn ordinary_final_state(
        &self,
        a: &Admission,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<Option<FinalState>> {
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let completion = a
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let stored = super::super::display_checkpoint::read_ordinary_final(scope)
            .map_err(|_| unavailable())?;
        let memory = a.ordinary_final_retirements.get(key.as_str());
        let Some(memory) = memory else {
            if stored.is_some() || completion.1.retirement_spent() {
                return Err(unavailable());
            }
            return Ok(None);
        };
        let (record, spent) = stored.ok_or_else(unavailable)?;
        if memory.digest != fingerprint(&record.canonical_bytes())
            || memory.spent != spent
            || spent != completion.1.retirement_spent()
            || !completion.1.current_spent()
            || a.ordinary_current_commits
                .get(key.as_str())
                .is_none_or(|v| !v.spent || v.digest != record.parent().record_digest())
            || a.ordinary_root_retirements
                .get(key.as_str())
                .is_none_or(|v| !v.closed || v.digest != record.parent().parent().record_digest())
            || completion.0 != record.parent().parent().parent().parent().record_digest()
        {
            return Err(unavailable());
        }
        let completed = super::super::display_checkpoint::read_ordinary_released(scope)
            .map_err(|_| unavailable())?;
        if let Some(digest) = memory.completed {
            let retained = completed.as_ref().ok_or_else(unavailable)?;
            if !spent
                || fingerprint(&retained.canonical_bytes()) != digest
                || retained.parent().canonical_bytes() != record.canonical_bytes()
            {
                return Err(unavailable());
            }
        } else if completed
            .as_ref()
            .is_some_and(|v| !spent || v.parent().canonical_bytes() != record.canonical_bytes())
        {
            return Err(unavailable());
        }
        // A durable metadata file may predate the final witness close; phase 3
        // is asserted only after the actual witness and memory transition.
        let phase = if memory.completed.is_some() {
            3
        } else if spent {
            2
        } else {
            1
        };
        Ok(Some((
            record,
            phase,
            if phase == 3 { completed } else { None },
        )))
    }
    pub(super) fn reserve_ordinary_final_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryFinalPreparation,
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
        self.ordinary_completion_scope(&a, record.parent().parent().parent().parent(), true)?;
        if a.ordinary_releases.get(key.as_str()).map(|v| v.1.as_str()) != Some(sender)
            || a.ordinary_final_retirements.len() >= MAX_PENDING
            || a.ordinary_final_retirements.contains_key(key.as_str())
            || a.ordinary_completions
                .get(key.as_str())
                .is_none_or(|v| !v.1.current_spent() || v.1.retirement_spent())
            || self.ordinary_current_record(&a, scope)? != record.parent().canonical_bytes()
        {
            return Err(unavailable());
        }
        a.ordinary_final_retirements.insert(
            key.as_str().into(),
            FinalRetirementReservation {
                digest: fingerprint(&record.canonical_bytes()),
                spent: false,
                completed: None,
            },
        );
        super::super::display_checkpoint::reserve_ordinary_final(&record, false)
            .map_err(|_| unavailable())?;
        let (stored, spent) = super::super::display_checkpoint::read_ordinary_final(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(&a, record.parent().parent().parent().parent(), true)?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_ordinary_final_mechanism(
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
                .is_none_or(|v| !v.1.current_spent() || v.1.retirement_spent())
        {
            return Err(unavailable());
        }
        let (record, spent) =
            super::super::display_checkpoint::read_ordinary_final(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        current(&record)?;
        if spent
            || record.parent().parent().parent().parent().canonical_bytes()
                != parent.canonical_bytes()
            || fingerprint(&record.canonical_bytes()) != ComponentDigest::from_bytes(*digest)
            || self.ordinary_current_record(&a, parent.frames().scope())?
                != record.parent().canonical_bytes()
        {
            return Err(unavailable());
        }
        let memory = a
            .ordinary_final_retirements
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if memory.spent || memory.digest != ComponentDigest::from_bytes(*digest) {
            return Err(unavailable());
        }
        memory.spent = true;
        super::super::display_checkpoint::reserve_ordinary_final(&record, true)
            .map_err(|_| unavailable())?;
        let (stored, spent) =
            super::super::display_checkpoint::read_ordinary_final(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        if !spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        current(&record)?;
        self.admit_control(sender)?;
        Ok(())
    }
    pub(super) fn complete_ordinary_released_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryReleasedRecord,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        let scope = record.parent().frames().scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut a = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_completion_scope(
            &a,
            record.parent().parent().parent().parent().parent(),
            true,
        )?;
        let (parent, phase, completed) = self
            .ordinary_final_state(&a, scope)?
            .ok_or_else(unavailable)?;
        if phase < 2
            || parent.canonical_bytes() != record.parent().canonical_bytes()
            || completed
                .as_ref()
                .is_some_and(|v| v.canonical_bytes() != record.canonical_bytes())
        {
            return Err(unavailable());
        }
        let digest = fingerprint(&record.canonical_bytes());
        super::super::display_checkpoint::reserve_ordinary_released(&record)
            .map_err(|_| unavailable())?;
        let retained = super::super::display_checkpoint::read_ordinary_released(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if retained.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        let root = a
            .ordinary_root_retirements
            .get(key.as_str())
            .filter(|v| v.closed)
            .ok_or_else(unavailable)?;
        self.witnesses
            .complete_final_retirement(
                &dispatch(scope.original_dispatch())?,
                &root.digest,
                digest,
                &self.channel,
            )
            .map_err(|_| unavailable())?;
        a.ordinary_final_retirements
            .get_mut(key.as_str())
            .ok_or_else(unavailable)?
            .completed = Some(digest);
        self.ordinary_completion_scope(
            &a,
            record.parent().parent().parent().parent().parent(),
            true,
        )?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn read_ordinary_final_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)> {
        self.admit_control(sender)?;
        let a = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let (record, phase, completed) = self
            .ordinary_final_state(&a, &scope)?
            .ok_or_else(unavailable)?;
        self.ordinary_completion_scope(&a, record.parent().parent().parent().parent(), true)?;
        self.admit_control(sender)?;
        Ok((
            record.canonical_bytes(),
            phase,
            completed.map_or_else(Vec::new, |v| v.canonical_bytes()),
        ))
    }
}
