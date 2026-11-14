//! Same-invocation ordinary preparation and authenticated one-use native spend.
//! Every acknowledgment retains the original protective fences.
use super::*;

fn check_clocks(
    last: &mut (u64, u64),
    deadline: (u64, u64),
    now: (u64, u64),
) -> zbus::fdo::Result<()> {
    if now.0 < last.0 || now.1 < last.1 || now.0 >= deadline.0 || now.1 >= deadline.1 {
        return Err(unavailable());
    }
    *last = now;
    Ok(())
}

impl NativeProtection {
    fn ordinary_release_state(
        &self,
        admission: &Admission,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
    ) -> zbus::fdo::Result<(NativeDisplayOrdinaryReleasePreparation, bool)> {
        let original = self.ordinary_original_for_scope(admission, scope)?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let (record, spent) = super::super::display_checkpoint::read_ordinary_release_state(scope)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let memory = admission
            .ordinary_releases
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        record
            .validate_original(&original)
            .map_err(|_| unavailable())?;
        if record.record_digest() != memory.0
            || (spent && !admission.ordinary_grants.contains_key(key.as_str()))
            || self.ordinary_original_for_scope(admission, scope)? != original
        {
            return Err(unavailable());
        }
        Ok((record, spent))
    }

    pub(super) fn read_ordinary_release_mechanism(
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
        let (record, spent) = self.ordinary_release_state(&admission, &scope)?;
        self.admit_control(sender)?;
        Ok((record.canonical_bytes(), spent))
    }

    pub(super) fn reserve_ordinary_release_grant_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryReleasePreparation,
    ) -> zbus::fdo::Result<OwnedFd> {
        let slot = StartupSlot::enter(&self.transfer_pending)?;
        let grant_slot = GrantSlot::enter(&self.live_grants)?;
        self.admit_control(sender)?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.release_scope().map_err(|_| unavailable())?;
        let key = scope
            .resource_id()
            .map_err(|_| unavailable())?
            .as_str()
            .to_owned();
        let window = record.window();
        let mut last_clock = (window.observed_unix_ms, window.observed_boot_ms);
        check_clocks(
            &mut last_clock,
            (window.deadline_unix_ms, window.deadline_boot_ms),
            (unix_ms()?, boot_ms()?),
        )?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let (actual, spent) = self.ordinary_release_state(&admission, &scope)?;
        if spent
            || actual.canonical_bytes() != record.canonical_bytes()
            || admission.ordinary_releases.get(&key).map(|v| v.1.as_str()) != Some(sender)
            || admission.ordinary_grants.contains_key(&key)
            || admission.ordinary_grants.len() >= MAX_PENDING
        {
            return Err(unavailable());
        }
        let original = self.ordinary_original_for_scope(&admission, &scope)?;
        let (_, integration) = NativeDisplayRecoveryCheckpoint::original_startup_scope(
            &original,
            &dispatch(scope.original_dispatch())?,
        )
        .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        check_clocks(
            &mut last_clock,
            (window.deadline_unix_ms, window.deadline_boot_ms),
            (unix_ms()?, boot_ms()?),
        )?;
        // Claim the actual invocation before socket/worker/transfer failures.
        // No disk receipt or restarted Control reconstructs this endpoint.
        let state = super::super::display_native_release_grant::ChannelState::reserved();
        admission.ordinary_grants.insert(key.clone(), state.clone());
        let lifetime = super::super::display_native_release_grant::Lifetime::new(state.clone());
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        rustix::net::sockopt::set_socket_passcred(&writer, true).map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let encoded = record.canonical_bytes();
        let digest: [u8; 32] = sha2::Sha256::digest(&encoded).into();
        let mut grant = b"LNOG:1\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        let owner = sender.to_owned();
        let service = self.clone();
        let persisted = Arc::new(AtomicBool::new(false));
        drop(admission);
        std::thread::Builder::new()
            .name("display-ordinary-grant".into())
            .spawn(move || {
                let _grant_slot = grant_slot;
                let mut verify = || {
                    service.admit_control(&owner)?;
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    let (actual, spent) = service.ordinary_release_state(&admission, &scope)?;
                    if !state.pending()
                        || actual.canonical_bytes() != encoded
                        || spent != persisted.load(Ordering::Acquire)
                        || admission.ordinary_releases.get(&key).map(|v| v.1.as_str())
                            != Some(owner.as_str())
                        || admission
                            .ordinary_grants
                            .get(&key)
                            .is_none_or(|live| !Arc::ptr_eq(live, &state))
                    {
                        return Err(unavailable());
                    }
                    check_clocks(
                        &mut last_clock,
                        (window.deadline_unix_ms, window.deadline_boot_ms),
                        (unix_ms()?, boot_ms()?),
                    )?;
                    service.admit_control(&owner)
                };
                let sent = write_grant_with_marker(
                    &mut writer,
                    &grant,
                    b"LNOG-END:1\n",
                    ORIGINAL_PROBE,
                    &mut verify,
                );
                drop(slot);
                if sent.is_err() {
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
                let persist = || {
                    service.admit_control(&owner)?;
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    let (actual, spent) = service.ordinary_release_state(&admission, &scope)?;
                    if spent
                        || !state.pending()
                        || actual.canonical_bytes() != encoded
                        || admission.ordinary_releases.get(&key).map(|v| v.1.as_str())
                            != Some(owner.as_str())
                    {
                        return Err(unavailable());
                    }
                    super::super::display_checkpoint::spend_ordinary_release(&record)
                        .map_err(|_| unavailable())?;
                    let (after, spent) = service.ordinary_release_state(&admission, &scope)?;
                    if !spent || after.canonical_bytes() != encoded {
                        return Err(unavailable());
                    }
                    let mut clock = (window.observed_unix_ms, window.observed_boot_ms);
                    check_clocks(
                        &mut clock,
                        (window.deadline_unix_ms, window.deadline_boot_ms),
                        (unix_ms()?, boot_ms()?),
                    )?;
                    service.admit_control(&owner)?;
                    persisted.store(true, Ordering::Release);
                    Ok(())
                };
                let _result = super::super::display_native_release_grant::serve_ordinary(
                    &mut writer,
                    &digest,
                    lifetime,
                    authenticate,
                    &mut verify,
                    persist,
                );
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }

    pub(super) fn reserve_ordinary_release_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryReleasePreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        let window = record.window();
        let mut last_clock = (window.observed_unix_ms, window.observed_boot_ms);
        let mut check_clock = || {
            check_clocks(
                &mut last_clock,
                (window.deadline_unix_ms, window.deadline_boot_ms),
                (unix_ms()?, boot_ms()?),
            )
        };
        check_clock()?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.release_scope().map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let payload = self.ordinary_original_for_scope(&admission, &scope)?;
        record
            .validate_original(&payload)
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        check_clock()?;
        if admission.ordinary_releases.len() >= MAX_PENDING
            || admission.ordinary_releases.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        // Irreversibly claim this live invocation before any fallible durable
        // write. Missing files, readback loss or a replacement Control do not
        // recreate the original preparation or physical release authority.
        admission
            .ordinary_releases
            .insert(key.as_str().into(), (record.record_digest(), sender.into()));
        super::super::display_checkpoint::reserve_ordinary_release(&record)
            .map_err(|_| unavailable())?;
        if super::super::display_checkpoint::read_ordinary_release(&record)
            .map_err(|_| unavailable())?
            != record.canonical_bytes()
            || self.ordinary_original_for_scope(&admission, &scope)? != payload
        {
            return Err(unavailable());
        }
        self.admit_control(sender)?;
        check_clock()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_clocks_cannot_expire_or_rewind_after_an_intermediate_check() {
        let mut last = (1000, 100);
        assert!(check_clocks(&mut last, (3000, 2100), (2500, 1600)).is_ok());
        for now in [(2499, 1600), (2500, 1599), (3000, 1600), (2500, 2100)] {
            let mut previous = last;
            assert!(check_clocks(&mut previous, (3000, 2100), now).is_err());
            assert_eq!(previous, last);
        }
        assert!(check_clocks(&mut last, (3000, 2100), (2999, 2099)).is_ok());
        assert!(check_clocks(&mut last, (3000, 2100), (3000, 2100)).is_err());
    }
}
