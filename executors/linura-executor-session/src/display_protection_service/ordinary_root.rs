//! Separately prepared ordinary Root-power close. Kernel, startup, native
//! completion and provenance remain retained. Closing is never completion.
use super::*;

fn current(record: &NativeDisplayOrdinaryRootPreparation) -> zbus::fdo::Result<()> {
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
    /// Only the actual in-memory close and its exact full parent permit this
    /// phase. Historical preparation files can never manufacture continuity.
    pub(super) fn ordinary_completion_original(
        &self,
        admission: &Admission,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let Some(retired) = admission
            .ordinary_root_retirements
            .get(key.as_str())
            .filter(|v| v.closed)
        else {
            return self.ordinary_original_for_scope(admission, scope);
        };
        let record = super::super::display_checkpoint::read_ordinary_root(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let completion = admission
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let power = admission
            .ordinary_power_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if record.record_digest() != retired.digest
            || !completion.1.power_spent()
            || !power.spent
            || power.digest != record.parent().record_digest()
            || completion.0 != record.parent().parent().record_digest()
        {
            return Err(unavailable());
        }
        let payload = self
            .witnesses
            .read_retired_original(
                &dispatch(scope.original_dispatch())?,
                &retired.digest,
                &self.channel,
            )
            .map_err(|_| unavailable())?;
        record
            .parent()
            .parent()
            .validate_original(&payload)
            .map_err(|_| unavailable())?;
        self.ordinary_current_record(admission, scope)?;
        self.ordinary_startup_for_original(admission, scope, &payload)?;
        Ok(payload)
    }
    pub(super) fn retire_ordinary_root_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryRootPreparation,
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
        // Require actual HELD power for initial admission, never retired history.
        self.ordinary_original_for_scope(&a, scope)?;
        self.ordinary_completion_scope(&a, record.parent().parent(), true)?;
        let completion = a
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let power = a
            .ordinary_power_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if a.ordinary_releases.get(key.as_str()).map(|v| v.1.as_str()) != Some(sender)
            || !completion.1.power_spent()
            || !power.spent
            || power.digest != record.parent().record_digest()
            || a.ordinary_root_retirements.len() >= MAX_PENDING
            || a.ordinary_root_retirements.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        let (parent, spent) = super::super::display_checkpoint::read_ordinary_power(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if !spent || parent.canonical_bytes() != record.parent().canonical_bytes() {
            return Err(unavailable());
        }
        let digest = record.record_digest();
        // Irreversible before any fallible storage/close, with no retry on loss.
        a.ordinary_root_retirements.insert(
            key.as_str().into(),
            RootPowerRetirementReservation {
                digest,
                closed: false,
            },
        );
        super::super::display_checkpoint::reserve_ordinary_root(&record)
            .map_err(|_| unavailable())?;
        let retained = super::super::display_checkpoint::read_ordinary_root(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if retained.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_original_for_scope(&a, scope)?;
        self.ordinary_completion_scope(&a, record.parent().parent(), true)?;
        self.admit_control(sender)?;
        self.witnesses
            .retire_power(
                &dispatch(scope.original_dispatch())?,
                digest,
                &self.channel,
                || {
                    current(&record)
                        .map_err(|_| "ordinary Root power preparation expired before effect".into())
                },
            )
            .map_err(|_| unavailable())?;
        // Serialized with every continuity read; publish immediately after close.
        a.ordinary_root_retirements
            .get_mut(key.as_str())
            .ok_or_else(unavailable)?
            .closed = true;
        self.admit_control(sender)?;
        Ok(true) // Close ACK only. Independent power absence must still be read.
    }
    pub(super) fn read_ordinary_root_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<OrdinaryRootPowerRead> {
        self.admit_control(sender)?;
        let a = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = a
            .ordinary_root_retirements
            .get(key.as_str())
            .filter(|v| v.closed)
            .ok_or_else(unavailable)?;
        let record = super::super::display_checkpoint::read_ordinary_root(&scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let payload = self.ordinary_completion_original(&a, &scope)?;
        self.ordinary_completion_scope(&a, record.parent().parent(), true)?;
        if record.record_digest() != memory.digest {
            return Err(unavailable());
        }
        // The power service must independently report this exact original fence
        // absent. A close ACK or remembered boolean cannot replace this check.
        self.witnesses
            .verify_retired_power_absent(
                &dispatch(scope.original_dispatch())?,
                &memory.digest,
                &self.channel,
            )
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        let current = self.ordinary_current_record(&a, &scope)?;
        Ok((record.canonical_bytes(), payload, current, true))
    }
}
