//! A separate one-use native-power permission on the genuine ordinary
//! completion lifetime. Root's own independent power/startup fences stay held.
use super::*;

fn current(record: &NativeDisplayOrdinaryPowerPreparation) -> zbus::fdo::Result<()> {
    let window = record.frames().window();
    let (wall, boot) = (unix_ms()?, boot_ms()?);
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
    fn ordinary_power_parent(
        &self,
        admission: &Admission,
        parent: &NativeDisplayOrdinaryCompletionPreparation,
    ) -> zbus::fdo::Result<()> {
        self.ordinary_completion_scope(admission, parent, true)?;
        let key = parent
            .frames()
            .scope()
            .resource_id()
            .map_err(|_| unavailable())?;
        let held = admission
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if held.0 != parent.record_digest() || !held.1.transferred() {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(super) fn reserve_ordinary_power_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryPowerPreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        current(&record)?;
        let scope = record.frames().scope();
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
        self.ordinary_power_parent(&admission, record.parent())?;
        if admission
            .ordinary_releases
            .get(&key)
            .map(|entry| entry.1.as_str())
            != Some(sender)
            || admission
                .ordinary_completions
                .get(&key)
                .ok_or_else(unavailable)?
                .1
                .power_spent()
            || admission.ordinary_power_retirements.len() >= MAX_PENDING
            || admission.ordinary_power_retirements.contains_key(&key)
        {
            return Err(unavailable());
        }
        let digest =
            ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into());
        // Irreversible reservation before every fallible publication/readback.
        admission.ordinary_power_retirements.insert(
            key,
            PowerRetirementReservation {
                digest,
                spent: false,
            },
        );
        super::super::display_checkpoint::reserve_ordinary_power(&record, false)
            .map_err(|_| unavailable())?;
        let (stored, spent) = super::super::display_checkpoint::read_ordinary_power(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_power_parent(&admission, record.parent())?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_ordinary_power_mechanism(
        &self,
        sender: &str,
        key: &str,
        parent: &NativeDisplayOrdinaryCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        self.admit_control(sender)?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_power_parent(&admission, parent)?;
        if admission
            .ordinary_releases
            .get(key)
            .map(|entry| entry.1.as_str())
            != Some(sender)
            || admission
                .ordinary_completions
                .get(key)
                .ok_or_else(unavailable)?
                .1
                .power_spent()
        {
            return Err(unavailable());
        }
        let (record, spent) =
            super::super::display_checkpoint::read_ordinary_power(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        let expected = ComponentDigest::from_bytes(*digest);
        if spent
            || record.parent().canonical_bytes() != parent.canonical_bytes()
            || ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into())
                != expected
        {
            return Err(unavailable());
        }
        current(&record)?;
        let held = admission
            .ordinary_power_retirements
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if held.spent || held.digest != expected {
            return Err(unavailable());
        }
        held.spent = true;
        super::super::display_checkpoint::reserve_ordinary_power(&record, true)
            .map_err(|_| unavailable())?;
        let (stored, spent) =
            super::super::display_checkpoint::read_ordinary_power(parent.frames().scope())
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        if !spent || stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_power_parent(&admission, parent)?;
        current(&record)?;
        self.admit_control(sender)
    }
    pub(super) fn read_ordinary_power_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32)> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let held = admission
            .ordinary_power_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let (record, spent) = super::super::display_checkpoint::read_ordinary_power(&scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.ordinary_power_parent(&admission, record.parent())?;
        let channel = &admission
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?
            .1;
        if held.digest
            != ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into())
            || held.spent != spent
            || channel.power_spent() != spent
        {
            return Err(unavailable());
        }
        self.admit_control(sender)?;
        Ok((record.canonical_bytes(), if spent { 2 } else { 1 }))
    }
}
