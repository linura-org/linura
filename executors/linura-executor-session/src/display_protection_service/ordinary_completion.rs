//! Original-invocation ordinary lifetime transfer. Every other fence remains
//! held. Historical files and replacement Control/Root cannot recreate it.
use super::*;

fn current(record: &NativeDisplayOrdinaryCompletionPreparation) -> zbus::fdo::Result<()> {
    let window = record.frames().window();
    let (wall, boot) = (unix_ms()?, boot_ms()?);
    if wall < window.observed_unix_ms
        || wall >= record.expiry()
        || wall >= window.deadline_unix_ms
        || boot < window.observed_boot_ms
        || boot >= window.deadline_boot_ms
    {
        return Err(unavailable());
    }
    Ok(())
}
impl NativeProtection {
    fn ordinary_completion_scope(
        &self,
        admission: &Admission,
        record: &NativeDisplayOrdinaryCompletionPreparation,
        transferred: bool,
    ) -> zbus::fdo::Result<()> {
        let material = record
            .parent()
            .decoded_material()
            .map_err(|_| unavailable())?;
        let scope = material.release_scope().map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let original = self.ordinary_original_for_scope(admission, &scope)?;
        record
            .validate_original(&original)
            .map_err(|_| unavailable())?;
        let (parent, spent) = self.ordinary_release_state(admission, &scope)?;
        let grant = admission
            .ordinary_grants
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if !spent
            || parent.canonical_bytes() != record.parent().canonical_bytes()
            || if transferred {
                !grant.transferred()
            } else {
                !grant.held()
            }
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(super) fn reserve_ordinary_completion_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryCompletionPreparation,
    ) -> zbus::fdo::Result<OwnedFd> {
        let slot = StartupSlot::enter(&self.transfer_pending)?;
        let grant_slot = GrantSlot::enter(&self.live_grants)?;
        self.admit_control(sender)?;
        current(&record)?;
        let scope = record
            .parent()
            .decoded_material()
            .map_err(|_| unavailable())?
            .release_scope()
            .map_err(|_| unavailable())?;
        let key = scope
            .resource_id()
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let encoded = record.canonical_bytes();
        let digest: [u8; 32] = sha2::Sha256::digest(&encoded).into();
        let fingerprint = ComponentDigest::from_bytes(digest);
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        self.ordinary_completion_scope(&admission, &record, false)?;
        if admission.ordinary_releases.get(&key).map(|v| v.1.as_str()) != Some(sender)
            || admission.ordinary_completions.len() >= MAX_PENDING
            || admission.ordinary_completions.contains_key(&key)
        {
            return Err(unavailable());
        }
        let payload = self.ordinary_original_for_scope(&admission, &scope)?;
        let (_, integration) = NativeDisplayRecoveryCheckpoint::original_startup_scope(
            &payload,
            &dispatch(scope.original_dispatch())?,
        )
        .map_err(|_| unavailable())?;
        let state = super::super::display_completion_grant::ChannelState::reserved();
        let lifetime = super::super::display_completion_grant::Lifetime::new(state.clone());
        // Claim before storage/socket/worker failure. No retry may recreate it.
        admission
            .ordinary_completions
            .insert(key.clone(), (fingerprint, state.clone()));
        super::super::display_checkpoint::reserve_ordinary_completion(&record)
            .map_err(|_| unavailable())?;
        let (before, spent) = super::super::display_checkpoint::read_ordinary_completion(&scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent || before.canonical_bytes() != encoded {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(&admission, &record, false)?;
        current(&record)?;
        self.admit_control(sender)?;
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        rustix::net::sockopt::set_socket_passcred(&writer, true).map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let mut grant = b"LOCG:1\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        let service = self.clone();
        let owner = sender.to_owned();
        let persisted = AtomicBool::new(false);
        let mut last = (unix_ms()?, boot_ms()?);
        drop(admission);
        std::thread::Builder::new()
            .name("display-ordinary-current".into())
            .spawn(move || {
                let _grant_slot = grant_slot;
                let mut verify = |initial: bool| {
                    if initial {
                        current(&record)?;
                        service.admit_control(&owner)?;
                    }
                    // After transfer, continuity belongs to the actual Root/native
                    // lifetime. A restarted Control can inspect, never inherit
                    // the original owner's effect preparation or grant.

                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.ordinary_completion_scope(&admission, &record, !initial)?;
                    let live = admission
                        .ordinary_completions
                        .get(&key)
                        .ok_or_else(unavailable)?;
                    if live.0 != fingerprint
                        || !Arc::ptr_eq(&live.1, &state)
                        || admission.ordinary_releases.get(&key).map(|v| v.1.as_str())
                            != Some(owner.as_str())
                        || (initial && !state.pending())
                        || (!initial && !state.transferred())
                    {
                        return Err(unavailable());
                    }
                    let (actual, spent) =
                        super::super::display_checkpoint::read_ordinary_completion(&scope)
                            .map_err(|_| unavailable())?
                            .ok_or_else(unavailable)?;
                    if actual.canonical_bytes() != encoded
                        || spent != persisted.load(Ordering::Acquire)
                    {
                        return Err(unavailable());
                    }
                    let now = (unix_ms()?, boot_ms()?);
                    if now.0 < last.0 || now.1 < last.1 {
                        return Err(unavailable());
                    }
                    last = now;
                    Ok(())
                };
                let published = write_grant_with_marker(
                    &mut writer,
                    &grant,
                    b"LOCG-END:1\n",
                    ORIGINAL_PROBE,
                    &mut || verify(true),
                );
                drop(slot);
                if published.is_err() {
                    return;
                }
                let authenticate = |credentials: &rustix::net::UCred| {
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.ordinary_original_for_scope(&admission, &scope)?;
                    let startup = admission
                        .startups
                        .iter()
                        .find(|v| v.peer.matches_preimage(scope.topology(), &integration))
                        .ok_or_else(unavailable)?;
                    startup.live().map_err(|_| unavailable())?;
                    startup
                        .peer
                        .require_message_sender(credentials)
                        .map_err(|_| unavailable())
                };
                let transfer = || {
                    service.admit_control(&owner)?;
                    current(&record)?;
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.ordinary_completion_scope(&admission, &record, false)?;
                    if !state.pending() {
                        return Err(unavailable());
                    }
                    super::super::display_checkpoint::spend_ordinary_completion(&record)
                        .map_err(|_| unavailable())?;
                    let (actual, spent) =
                        super::super::display_checkpoint::read_ordinary_completion(&scope)
                            .map_err(|_| unavailable())?
                            .ok_or_else(unavailable)?;
                    if !spent || actual.canonical_bytes() != encoded {
                        return Err(unavailable());
                    }
                    current(&record)?;
                    service.admit_control(&owner)?;
                    let anchor = admission
                        .ordinary_grants
                        .get(&key)
                        .ok_or_else(unavailable)?
                        .transfer()?;
                    persisted.store(true, Ordering::Release);
                    Ok(anchor)
                };
                let _result = super::super::display_completion_grant::serve_ordinary(
                    &mut writer,
                    &digest,
                    lifetime,
                    authenticate,
                    &mut verify,
                    transfer,
                );
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }
    pub(super) fn read_ordinary_completion_mechanism(
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
        let live = admission
            .ordinary_completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let (record, spent) = super::super::display_checkpoint::read_ordinary_completion(&scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if live.0 != record.record_digest() {
            return Err(unavailable());
        }
        let phase = if live.1.pending() {
            1
        } else if live.1.transferred() {
            2
        } else {
            return Err(unavailable());
        };
        if spent != (phase == 2) {
            return Err(unavailable());
        }
        self.ordinary_completion_scope(&admission, &record, phase == 2)?;
        self.admit_control(sender)?;
        Ok((record.canonical_bytes(), phase)) // Never ReleasedCurrent.
    }
}
