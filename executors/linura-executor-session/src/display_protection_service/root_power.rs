//! One separately prepared original Root power close. Kernel/checkpoint, native
//! lifetime, S17 and startup admission stay retained. No completion is inferred.
use super::*;

fn current(record: &NativeDisplayRootRetirementPreparation) -> zbus::fdo::Result<()> {
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
    pub(super) fn completion_root_power_scope_live(
        &self,
        admission: &Admission,
        record: &NativeDisplayCompletionPreparation,
        transferred: bool,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let key = record
            .frames()
            .scope()
            .resource_id()
            .map_err(|_| unavailable())?;
        let Some(retired) = admission
            .root_power_retirements
            .get(key.as_str())
            .filter(|entry| entry.closed)
        else {
            return self.completion_scope_live(admission, record, transferred);
        };
        if !transferred {
            return Err(unavailable());
        }
        let restoration =
            super::super::display_checkpoint::read_restoration(record.frames().scope())
                .map_err(|_| unavailable())?;
        let prepared = super::super::display_checkpoint::read_root_power_retirement(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if prepared.parent().parent().canonical_bytes() != record.canonical_bytes()
            || ComponentDigest::from_bytes(sha2::Sha256::digest(prepared.canonical_bytes()).into())
                != retired.digest
        {
            return Err(unavailable());
        }
        let payload =
            self.retired_original_for_scope(admission, record.frames().scope(), &retired.digest)?;
        self.completion_scope_from_original(admission, record, true, payload)
    }
    pub(super) fn retire_root_power_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayRootRetirementPreparation,
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
        self.completion_scope_live(&admission, record.parent().parent(), true)?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let native = admission
            .power_retirements
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if admission
            .retirement_owners
            .get(key.as_str())
            .map(String::as_str)
            != Some(sender)
            || completion.scope != *scope
            || !completion.channel.power_spent()
            || !native.spent
            || native.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
                )
            || admission.root_power_retirements.len() >= MAX_STARTUPS
            || admission.root_power_retirements.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let spent = super::super::display_checkpoint::read_power_retirement(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent.canonical_bytes() != record.parent().canonical_bytes() {
            return Err(unavailable());
        }
        let digest =
            ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into());
        admission.root_power_retirements.insert(
            key.as_str().into(),
            RootPowerRetirementReservation {
                digest,
                closed: false,
            },
        );
        super::super::display_checkpoint::reserve_root_power_retirement(&record)
            .map_err(|_| unavailable())?;
        let retained = super::super::display_checkpoint::read_root_power_retirement(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if retained.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_scope_live(&admission, record.parent().parent(), true)?;
        self.admit_control(sender)?;
        self.witnesses
            .retire_power(
                &dispatch(scope.original_dispatch())?,
                digest,
                &self.channel,
                || {
                    current(&record)
                        .map_err(|_| "root power preparation expired before effect".into())
                },
            )
            .map_err(|_| unavailable())?;
        // No fallible operation intervenes between close and phase publication.
        admission
            .root_power_retirements
            .get_mut(key.as_str())
            .ok_or_else(unavailable)?
            .closed = true;
        self.admit_control(sender)?;
        Ok(true) // Close ACK only; independent logind processing remains required.
    }
    pub(super) fn read_root_power_mechanism(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<OriginalRootPowerRead> {
        self.admit_control(sender)?;
        let admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let memory = admission
            .root_power_retirements
            .get(key.as_str())
            .filter(|entry| entry.closed)
            .ok_or_else(unavailable)?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_root_power_retirement(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let payload =
            self.completion_lifetime_scope_live(&admission, record.parent().parent(), true)?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if completion.scope != scope
            || !completion.channel.power_spent()
            || memory.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.canonical_bytes()).into(),
                )
        {
            return Err(unavailable());
        }
        self.witnesses
            .verify_retired_power_absent(
                &dispatch(scope.original_dispatch())?,
                &memory.digest,
                &self.channel,
            )
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        let current_commit = self.current_commit_record(&admission, &scope)?;
        Ok((record.canonical_bytes(), payload, current_commit, true))
    }
}
