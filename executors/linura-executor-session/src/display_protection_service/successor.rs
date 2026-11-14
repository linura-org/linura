//! Move the global exclusion to an exact fresh protected operation. Preparing
//! or spending a record never admits an unfenced startup or discards ancestry.
use super::*;

fn clocks(
    record: &NativeDisplaySuccessorPreparation,
    last: &mut (u64, u64),
) -> zbus::fdo::Result<()> {
    let w = record.window();
    let now = (unix_ms()?, boot_ms()?);
    if now.0 < last.0
        || now.1 < last.1
        || now.0 < w.observed_unix_ms
        || now.1 < w.observed_boot_ms
        || now.0 >= w.deadline_unix_ms
        || now.1 >= w.deadline_boot_ms
    {
        return Err(unavailable());
    }
    *last = now;
    Ok(())
}

impl NativeProtection {
    pub(super) fn startup_admits_original(
        &self,
        admission: &Admission,
        startup: &StartupLease,
        payload: &[u8],
        dispatch: &ComponentDigest,
    ) -> zbus::fdo::Result<bool> {
        if startup.ordinary {
            return Ok(true);
        }
        for (key, memory) in &admission.successors {
            if !memory.spent || memory.dispatch != *dispatch {
                continue;
            }
            let scope = linura_core::DisplayRecoveryScope::from_resource(
                &linura_core::ResourceId::new(key).map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
            let restoration = super::super::display_checkpoint::read_restoration(&scope)
                .map_err(|_| unavailable())?;
            let record = super::super::display_checkpoint::read_successor(&restoration, true)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if record.record_digest() != memory.record
                || record.binding().dispatch_digest != *dispatch
            {
                return Err(unavailable());
            }
            record
                .validate_checkpoint(payload)
                .map_err(|_| unavailable())?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn read_successor_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<(Vec<u8>, bool)> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = admission
            .successors
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_successor(&restoration, memory.spent)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if record.record_digest() != memory.record
            || record.binding().dispatch_digest != memory.dispatch
        {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(
            &admission,
            record.parent().parent().parent().parent().parent().parent(),
            true,
        )?;
        self.witnesses
            .verify(&memory.dispatch, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        Ok((record.canonical_bytes(), memory.spent))
    }
    pub(super) fn reserve_successor_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
        payload: &[u8],
    ) -> zbus::fdo::Result<Vec<u8>> {
        self.admit(sender)?;
        let dispatch =
            NativeDisplayRecoveryCheckpoint::stored_dispatch(payload).map_err(|_| unavailable())?;
        NativeDisplayRecoveryCheckpoint::validate_stored(payload, &dispatch)
            .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let subscription = consume(&mut admission.pending, sender, &dispatch, Instant::now())?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let parent = super::super::display_checkpoint::read_released_current(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.completion_lifetime_scope_live(
            &admission,
            parent.parent().parent().parent().parent().parent(),
            true,
        )?;
        if admission.successors.contains_key(key.as_str())
            || admission.successors.len() >= MAX_PENDING
        {
            return Err(unavailable());
        }
        let (topology, integration) =
            NativeDisplayRecoveryCheckpoint::original_startup_scope(payload, &dispatch)
                .map_err(|_| unavailable())?;
        if &topology != scope.replacement() {
            return Err(unavailable());
        }
        let startup = admission
            .startups
            .iter()
            .find(|v| v.peer.matches_preimage(&topology, &integration))
            .ok_or_else(unavailable)?;
        if startup.ordinary {
            return Err(unavailable());
        }
        startup.live().map_err(|_| unavailable())?;
        let record = NativeDisplaySuccessorPreparation::from_checkpoint(
            &parent,
            payload,
            unix_ms()?,
            boot_ms()?,
        )
        .map_err(|_| unavailable())?;
        let mut last = (
            record.window().observed_unix_ms,
            record.window().observed_boot_ms,
        );
        clocks(&record, &mut last)?;
        self.admit(sender)?;
        // Consume memory ownership before either durable write. A partial
        // checkpoint/preparation cannot be replaced under a fresh dispatch ID.
        admission.successors.insert(
            key.as_str().into(),
            SuccessorReservation {
                record: record.record_digest(),
                dispatch,
                spent: false,
            },
        );
        self.witnesses
            .reserve_stored(&dispatch, payload, subscription, &self.channel)
            .map_err(|_| unavailable())?;
        clocks(&record, &mut last)?;
        super::super::display_checkpoint::reserve_successor(&record, false)
            .map_err(|_| unavailable())?;
        let retained = super::super::display_checkpoint::read_successor(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if retained.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(
            &admission,
            parent.parent().parent().parent().parent().parent(),
            true,
        )?;
        self.witnesses
            .verify(&dispatch, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        clocks(&record, &mut last)?;
        Ok(record.canonical_bytes())
    }

    pub(super) fn spend_successor_mechanism(
        &self,
        key: &str,
        original: &NativeDisplayCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.completion_lifetime_scope_live(&admission, original, true)?;
        let restoration =
            super::super::display_checkpoint::read_restoration(original.frames().scope())
                .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_successor(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let memory = admission.successors.get(key).ok_or_else(unavailable)?;
        if memory.spent
            || memory.record != record.record_digest()
            || memory.record != ComponentDigest::from_bytes(*digest)
            || memory.dispatch != record.binding().dispatch_digest
            || record
                .parent()
                .parent()
                .parent()
                .parent()
                .parent()
                .parent()
                .canonical_bytes()
                != original.canonical_bytes()
        {
            return Err(unavailable());
        }
        let mut last = (
            record.window().observed_unix_ms,
            record.window().observed_boot_ms,
        );
        clocks(&record, &mut last)?;
        self.witnesses
            .verify(&memory.dispatch, &self.channel)
            .map_err(|_| unavailable())?;
        admission
            .successors
            .get_mut(key)
            .ok_or_else(unavailable)?
            .spent = true;
        super::super::display_checkpoint::reserve_successor(&record, true)
            .map_err(|_| unavailable())?;
        let after = super::super::display_checkpoint::read_successor(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if after.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(&admission, original, true)?;
        self.witnesses
            .verify(&record.binding().dispatch_digest, &self.channel)
            .map_err(|_| unavailable())?;
        clocks(&record, &mut last)?;
        Ok(())
    }
}
