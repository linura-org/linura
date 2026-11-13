//! Final original Root permission and durable metadata. Native retirement and
//! Control's independent post-effect completion remain separate milestones.
use super::*;
fn fingerprint(bytes: &[u8]) -> ComponentDigest {
    ComponentDigest::from_bytes(sha2::Sha256::digest(bytes).into())
}
fn current(record: &NativeDisplayFinalRetirementPreparation) -> zbus::fdo::Result<()> {
    let w = record.frames().window();
    let wall = unix_ms()?;
    let boot = boot_ms()?;
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
    pub(super) fn completion_lifetime_scope_live(
        &self,
        admission: &Admission,
        original: &NativeDisplayCompletionPreparation,
        transferred: bool,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let key = original
            .frames()
            .scope()
            .resource_id()
            .map_err(|_| unavailable())?;
        let live = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if !live.channel.retirement_spent() {
            return self.completion_current_scope_live(admission, original, transferred);
        }
        let memory = admission
            .final_retirements
            .get(key.as_str())
            .filter(|entry| entry.spent)
            .ok_or_else(unavailable)?;
        let restoration =
            super::super::display_checkpoint::read_restoration(original.frames().scope())
                .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_final_retirement(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if fingerprint(&record.canonical_bytes()) != memory.digest
            || record.parent().parent().parent().parent().canonical_bytes()
                != original.canonical_bytes()
        {
            return Err(unavailable());
        }
        if let Some(digest) = memory.completed {
            let completed = super::super::display_checkpoint::read_released_current(&restoration)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if fingerprint(&completed.canonical_bytes()) != digest
                || completed.parent().canonical_bytes() != record.canonical_bytes()
            {
                return Err(unavailable());
            }
            if !transferred || !live.channel.current_spent() || !live.channel.power_spent() {
                return Err(unavailable());
            }
            let root = admission
                .root_power_retirements
                .get(key.as_str())
                .filter(|v| v.closed)
                .ok_or_else(unavailable)?;
            let root_record = record.parent().parent();
            if fingerprint(&root_record.canonical_bytes()) != root.digest {
                return Err(unavailable());
            }
            let current = admission
                .current_commits
                .get(key.as_str())
                .filter(|v| v.spent)
                .ok_or_else(unavailable)?;
            if current.digest != record.parent().record_digest() {
                return Err(unavailable());
            }
            let payload = self
                .witnesses
                .read_released_original(
                    &dispatch(original.frames().scope().original_dispatch())?,
                    &root.digest,
                    &digest,
                    &self.channel,
                )
                .map_err(|_| unavailable())?;
            self.require_scope_startups(admission, original.frames().scope(), &payload)?;
            return self.completion_scope_from_original(admission, original, true, payload);
        }
        self.completion_current_scope_live(admission, original, transferred)
    }
    pub(super) fn reserve_final_retirement_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayFinalRetirementPreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        current(&record)?;
        let scope = record.frames().scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_lifetime_scope_live(
            &admission,
            record.parent().parent().parent().parent(),
            true,
        )?;
        let channel = &admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?
            .channel;
        let parent = admission
            .current_commits
            .get(key.as_str())
            .filter(|entry| entry.spent)
            .ok_or_else(unavailable)?;
        if admission
            .retirement_owners
            .get(key.as_str())
            .map(String::as_str)
            != Some(sender)
            || !channel.current_spent()
            || channel.retirement_spent()
            || parent.digest != record.parent().record_digest()
            || admission.final_retirements.contains_key(key.as_str())
            || admission.final_retirements.len() >= MAX_STARTUPS
        {
            return Err(unavailable());
        }
        let digest = fingerprint(&record.canonical_bytes());
        admission.final_retirements.insert(
            key.as_str().into(),
            FinalRetirementReservation {
                digest,
                spent: false,
                completed: None,
            },
        );
        super::super::display_checkpoint::reserve_final_retirement(&record, false)
            .map_err(|_| unavailable())?;
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_final_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(
            &admission,
            record.parent().parent().parent().parent(),
            true,
        )?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_final_retirement_mechanism(
        &self,
        sender: &str,
        key: &str,
        original: &NativeDisplayCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        self.admit_control(sender)?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_lifetime_scope_live(&admission, original, true)?;
        if admission.retirement_owners.get(key).map(String::as_str) != Some(sender) {
            return Err(unavailable());
        }
        let restoration =
            super::super::display_checkpoint::read_restoration(original.frames().scope())
                .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_final_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let channel = &admission
            .completions
            .get(key)
            .ok_or_else(unavailable)?
            .channel;
        if !channel.current_spent()
            || channel.retirement_spent()
            || record.parent().parent().parent().parent().canonical_bytes()
                != original.canonical_bytes()
            || fingerprint(&record.canonical_bytes()) != ComponentDigest::from_bytes(*digest)
        {
            return Err(unavailable());
        }
        current(&record)?;
        let memory = admission
            .final_retirements
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if memory.spent || memory.digest != ComponentDigest::from_bytes(*digest) {
            return Err(unavailable());
        }
        memory.spent = true;
        super::super::display_checkpoint::reserve_final_retirement(&record, true)
            .map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_final_retirement(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(&admission, original, true)?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(())
    }
    pub(super) fn complete_released_current_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayReleasedCurrentRecord,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        let scope = record.parent().frames().scope();
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_lifetime_scope_live(
            &admission,
            record.parent().parent().parent().parent().parent(),
            true,
        )?;
        let channel = &admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?
            .channel;
        let memory = admission
            .final_retirements
            .get(key.as_str())
            .filter(|entry| entry.spent)
            .ok_or_else(unavailable)?;
        let digest = fingerprint(&record.canonical_bytes());
        if !channel.retirement_spent()
            || memory.digest != fingerprint(&record.parent().canonical_bytes())
            || memory.completed.is_some_and(|old| old != digest)
        {
            return Err(unavailable());
        }
        // Only immutable bookkeeping is retryable. Neither this comparison
        // window nor a replacement Control can rearm the spent native effect.
        super::super::display_checkpoint::reserve_released_current(&record)
            .map_err(|_| unavailable())?;
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_released_current(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        let root = admission
            .root_power_retirements
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
        admission
            .final_retirements
            .get_mut(key.as_str())
            .ok_or_else(unavailable)?
            .completed = Some(digest);
        self.completion_lifetime_scope_live(
            &admission,
            record.parent().parent().parent().parent().parent(),
            true,
        )?;
        self.admit_control(sender)?;
        Ok(true) // Root bookkeeping only; global future-adoption barrier remains.
    }
    pub(super) fn read_final_retirement_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = admission
            .final_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let prepared = super::super::display_checkpoint::read_final_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.completion_lifetime_scope_live(
            &admission,
            prepared.parent().parent().parent().parent(),
            true,
        )?;
        if fingerprint(&prepared.canonical_bytes()) != memory.digest {
            return Err(unavailable());
        }
        let channel = &admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?
            .channel;
        let phase = if memory.spent {
            if !channel.retirement_spent() {
                return Err(unavailable());
            }
            if memory.completed.is_some() { 3 } else { 2 }
        } else {
            if channel.retirement_spent() {
                return Err(unavailable());
            }
            1
        };
        let completed = if phase == 3 {
            super::super::display_checkpoint::read_released_current(&restoration)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?
                .canonical_bytes()
        } else {
            Vec::new()
        };
        self.admit_control(sender)?;
        Ok((prepared.canonical_bytes(), phase, completed))
    }
}
