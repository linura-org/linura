//! One durable native-power permission on the ORIGINAL transferred channel.
//! Root's independent power witness, admission and checkpoint stay held.
use super::*;

fn current(record: &NativeDisplayPowerRetirementPreparation) -> zbus::fdo::Result<()> {
    let window = record.frames().window();
    let wall = unix_ms()?;
    let boot = boot_ms()?;
    if wall < window.observed_unix_ms
        || wall >= record.expires_at_unix_ms()
        || boot < window.observed_boot_ms
        || boot >= window.deadline_boot_ms
    {
        return Err(unavailable());
    }
    Ok(())
}
impl NativeProtection {
    pub(super) fn reserve_power_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayPowerRetirementPreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        current(&record)?;
        let scope = record.parent().frames().scope();
        let key = scope
            .resource_id()
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_scope_live(&admission, record.parent(), true)?;
        let completion = admission.completions.get(&key).ok_or_else(unavailable)?;
        if admission.retirement_owners.get(&key).map(String::as_str) != Some(sender)
            || completion.scope != *scope
            || !completion.channel.transferred()
            || completion.channel.power_spent()
            || completion.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
                )
            || admission.power_retirements.len() >= MAX_STARTUPS
            || admission.power_retirements.contains_key(&key)
        {
            return Err(unavailable());
        }
        let digest =
            ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into());
        // Reserve before all fallible storage. No timeout, deletion or failed
        // readback makes this original authority reusable.
        admission.power_retirements.insert(
            key,
            PowerRetirementReservation {
                digest,
                spent: false,
            },
        );
        super::super::display_checkpoint::reserve_power_retirement(&record, false)
            .map_err(|_| unavailable())?;
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_power_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_scope_live(&admission, record.parent(), true)?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_power_mechanism(
        &self,
        sender: &str,
        key: &str,
        parent: &NativeDisplayCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        self.admit_control(sender)?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_scope_live(&admission, parent, true)?;
        if admission.retirement_owners.get(key).map(String::as_str) != Some(sender) {
            return Err(unavailable());
        }
        let restoration =
            super::super::display_checkpoint::read_restoration(parent.frames().scope())
                .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_power_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let expected = ComponentDigest::from_bytes(*digest);
        let completion = admission.completions.get(key).ok_or_else(unavailable)?;
        if !completion.channel.transferred()
            || completion.channel.power_spent()
            || completion.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(parent.canonical_bytes()).into(),
                )
            || record.parent().canonical_bytes() != parent.canonical_bytes()
            || ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into())
                != expected
        {
            return Err(unavailable());
        }
        current(&record)?;
        let reserved = admission
            .power_retirements
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if reserved.spent || reserved.digest != expected {
            return Err(unavailable());
        }
        reserved.spent = true; // Irreversible before publication, including errors.
        super::super::display_checkpoint::reserve_power_retirement(&record, true)
            .map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_power_retirement(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_scope_live(&admission, parent, true)?;
        current(&record)?;
        self.admit_control(sender)
    }
    pub(super) fn read_power_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32)> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = admission
            .power_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if completion.scope != scope || !completion.channel.transferred() {
            return Err(unavailable());
        }
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_power_retirement(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.completion_scope_live(&admission, record.parent(), true)?;
        let spent = super::super::display_checkpoint::read_power_retirement(&restoration, true)
            .map_err(|_| unavailable())?;
        if completion.digest
            != ComponentDigest::from_bytes(
                sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
            )
            || memory.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.canonical_bytes()).into(),
                )
            || memory.spent != completion.channel.power_spent()
            || memory.spent != spent.is_some()
            || spent
                .as_ref()
                .is_some_and(|old| old.canonical_bytes() != record.canonical_bytes())
        {
            return Err(unavailable());
        }
        self.admit_control(sender)?;
        // Spent acknowledges only a grant, never the physical power effect.
        Ok((record.canonical_bytes(), if memory.spent { 2 } else { 1 }))
    }
}
