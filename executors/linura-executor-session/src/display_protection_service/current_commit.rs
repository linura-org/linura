//! Original channel's separately prepared committed-current permission. Its
//! durable spend precedes the ACK and never proves native permanent admission.
use super::*;
fn current(record: &NativeDisplayCurrentCommitPreparation) -> zbus::fdo::Result<()> {
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
        let payload = self.completion_root_power_scope_live(admission, original, transferred)?;
        let key = original
            .frames()
            .scope()
            .resource_id()
            .map_err(|_| unavailable())?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if !completion.channel.current_spent() {
            return Ok(payload);
        }
        let memory = admission
            .current_commits
            .get(key.as_str())
            .filter(|entry| entry.spent)
            .ok_or_else(unavailable)?;
        let restoration =
            super::super::display_checkpoint::read_restoration(original.frames().scope())
                .map_err(|_| unavailable())?;
        let prepared = super::super::display_checkpoint::read_current_commit(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let spent = super::super::display_checkpoint::read_current_commit(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if prepared.parent().parent().parent().canonical_bytes() != original.canonical_bytes()
            || spent.canonical_bytes() != prepared.canonical_bytes()
            || memory.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(prepared.canonical_bytes()).into(),
                )
        {
            return Err(unavailable());
        }
        Ok(payload)
    }
    pub(super) fn current_commit_record(
        &self,
        admission: &Admission,
        scope: &linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let current = admission.current_commits.get(key.as_str());
        if !completion.channel.current_spent() {
            if current.is_some_and(|entry| entry.spent) {
                return Err(unavailable());
            }
            return Ok(Vec::new());
        }
        let memory = current
            .filter(|entry| entry.spent)
            .ok_or_else(unavailable)?;
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let record = super::super::display_checkpoint::read_current_commit(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let bytes = record.canonical_bytes();
        if memory.digest != ComponentDigest::from_bytes(sha2::Sha256::digest(&bytes).into()) {
            return Err(unavailable());
        }
        Ok(bytes)
    }

    pub(super) fn reserve_current_commit_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayCurrentCommitPreparation,
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
        self.completion_lifetime_scope_live(&admission, record.parent().parent().parent(), true)?;
        let root = admission
            .root_power_retirements
            .get(key.as_str())
            .filter(|entry| entry.closed)
            .ok_or_else(unavailable)?;
        let completion = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if admission
            .retirement_owners
            .get(key.as_str())
            .map(String::as_str)
            != Some(sender)
            || completion.scope != *scope
            || !completion.channel.power_spent()
            || completion.channel.current_spent()
            || root.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(record.parent().canonical_bytes()).into(),
                )
            || admission.current_commits.len() >= MAX_STARTUPS
            || admission.current_commits.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        let digest =
            ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into());
        admission.current_commits.insert(
            key.as_str().into(),
            CurrentCommitReservation {
                digest,
                spent: false,
            },
        );
        super::super::display_checkpoint::reserve_current_commit(&record, false)
            .map_err(|_| unavailable())?;
        let restoration =
            super::super::display_checkpoint::read_restoration(scope).map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_current_commit(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(&admission, record.parent().parent().parent(), true)?;
        current(&record)?;
        self.admit_control(sender)?;
        Ok(true)
    }
    pub(super) fn spend_current_commit_mechanism(
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
        let record = super::super::display_checkpoint::read_current_commit(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let completion = admission.completions.get(key).ok_or_else(unavailable)?;
        let expected = ComponentDigest::from_bytes(*digest);
        if !completion.channel.power_spent()
            || completion.channel.current_spent()
            || record.parent().parent().parent().canonical_bytes() != original.canonical_bytes()
            || ComponentDigest::from_bytes(sha2::Sha256::digest(record.canonical_bytes()).into())
                != expected
        {
            return Err(unavailable());
        }
        current(&record)?;
        let memory = admission
            .current_commits
            .get_mut(key)
            .ok_or_else(unavailable)?;
        if memory.spent || memory.digest != expected {
            return Err(unavailable());
        }
        memory.spent = true;
        super::super::display_checkpoint::reserve_current_commit(&record, true)
            .map_err(|_| unavailable())?;
        let stored = super::super::display_checkpoint::read_current_commit(&restoration, true)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.completion_lifetime_scope_live(&admission, original, true)?;
        current(&record)?;
        self.admit_control(sender)
    }
}
