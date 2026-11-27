//! Purpose-separated ordinary successor transfer to a fresh protected Apply. Preparing
//! or spending a record never admits an unfenced startup or discards ancestry.
use super::*;

fn clocks(
    record: &NativeDisplayOrdinarySuccessorPreparation,
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
    pub(super) fn ordinary_startup_admits_successor(
        &self,
        admission: &Admission,
        payload: &[u8],
        dispatch: &ComponentDigest,
    ) -> zbus::fdo::Result<bool> {
        for (key, memory) in &admission.ordinary_successors {
            if !memory.spent || memory.dispatch != *dispatch {
                continue;
            }
            let scope = linura_core::DisplayOrdinaryReleaseScope::from_resource(
                &linura_core::ResourceId::new(key).map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
            let record = super::super::display_checkpoint::read_ordinary_successor(&scope, true)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if record.record_digest() != memory.record
                || record.binding().dispatch_digest != *dispatch
                || !matches!(
                    self.ordinary_final_state(admission, &scope)?,
                    Some((_, 3, Some(_)))
                )
            {
                return Err(unavailable());
            }
            record
                .validate_checkpoint(payload)
                .map_err(|_| unavailable())?;
            self.ordinary_completion_scope(
                admission,
                record.parent().parent().parent().parent().parent().parent(),
                true,
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn read_ordinary_successor_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<(Vec<u8>, bool)> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = admission
            .ordinary_successors
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let record =
            super::super::display_checkpoint::read_ordinary_successor(&scope, memory.spent)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
        if record.record_digest() != memory.record
            || record.binding().dispatch_digest != memory.dispatch
        {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(
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
    pub(super) fn reserve_ordinary_successor_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayOrdinaryReleaseScope,
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
        let parent = super::super::display_checkpoint::read_ordinary_released(&scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.ordinary_completion_scope(
            &admission,
            parent.parent().parent().parent().parent().parent(),
            true,
        )?;
        if !matches!(
            self.ordinary_final_state(&admission, &scope)?,
            Some((_, 3, Some(_)))
        ) {
            return Err(unavailable());
        }
        if admission.ordinary_successors.contains_key(key.as_str())
            || admission.ordinary_successors.len() >= MAX_PENDING
        {
            return Err(unavailable());
        }
        let (topology, integration) =
            NativeDisplayRecoveryCheckpoint::original_startup_scope(payload, &dispatch)
                .map_err(|_| unavailable())?;
        if &topology != scope.topology() {
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
        let record = NativeDisplayOrdinarySuccessorPreparation::from_checkpoint(
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
        admission.ordinary_successors.insert(
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
        super::super::display_checkpoint::reserve_ordinary_successor(&record, false)
            .map_err(|_| unavailable())?;
        let retained = super::super::display_checkpoint::read_ordinary_successor(&scope, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if retained.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(
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

    pub(super) fn spend_ordinary_successor_mechanism(
        &self,
        key: &str,
        original: &NativeDisplayOrdinaryCompletionPreparation,
        digest: &[u8; 32],
    ) -> zbus::fdo::Result<()> {
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_completion_scope(&admission, original, true)?;
        let record = super::super::display_checkpoint::read_ordinary_successor(
            original.frames().scope(),
            false,
        )
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
        let memory = admission
            .ordinary_successors
            .get(key)
            .ok_or_else(unavailable)?;
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
            .ordinary_successors
            .get_mut(key)
            .ok_or_else(unavailable)?
            .spent = true;
        super::super::display_checkpoint::reserve_ordinary_successor(&record, true)
            .map_err(|_| unavailable())?;
        let after = super::super::display_checkpoint::read_ordinary_successor(
            original.frames().scope(),
            true,
        )
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
        if after.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(&admission, original, true)?;
        self.witnesses
            .verify(&record.binding().dispatch_digest, &self.channel)
            .map_err(|_| unavailable())?;
        clocks(&record, &mut last)?;
        Ok(())
    }
}
