//! Original Root's one-use current-lifetime transfer. No Control policy,
//! recovery orchestration, power retirement or ReleasedCurrent inference.
use super::*;

fn frame_current(record: &NativeDisplayCompletionPreparation) -> zbus::fdo::Result<()> {
    let window = record.frames().window();
    let wall = unix_ms()?;
    let boot = boot_ms()?;
    if wall < window.observed_unix_ms
        || wall >= window.deadline_unix_ms
        || wall >= record.expires_at_unix_ms()
        || boot < window.observed_boot_ms
        || boot >= window.deadline_boot_ms
    {
        return Err(unavailable());
    }
    Ok(())
}

impl NativeProtection {
    pub(super) fn completion_scope_live(
        &self,
        admission: &Admission,
        record: &NativeDisplayCompletionPreparation,
        transferred: bool,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let payload = self.original_for_scope(admission, record.frames().scope())?;
        self.completion_scope_from_original(admission, record, transferred, payload)
    }
    pub(super) fn completion_scope_from_original(
        &self,
        admission: &Admission,
        record: &NativeDisplayCompletionPreparation,
        transferred: bool,
        payload: Vec<u8>,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let parent = record.parent();
        let terminal = parent.terminal();
        let scope = terminal
            .decoded_material()
            .map_err(|_| unavailable())?
            .recovery_scope()
            .map_err(|_| unavailable())?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        record
            .validate_restoration(&restoration)
            .map_err(|_| unavailable())?;
        let spent = super::super::display_checkpoint::read_native_release_spent(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if spent.canonical_bytes() != parent.canonical_bytes() {
            return Err(unavailable());
        }
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let fingerprint =
            ComponentDigest::from_bytes(sha2::Sha256::digest(parent.canonical_bytes()).into());
        if admission.retirements.get(key.as_str()) != Some(&fingerprint)
            || admission.root_retirements.get(key.as_str()) != Some(&fingerprint)
            || admission.native_release_reservations.get(key.as_str()) != Some(&fingerprint)
            || admission
                .native_release_grants
                .get(key.as_str())
                .is_none_or(|grant| grant.pending())
        {
            return Err(unavailable());
        }
        let original = admission
            .finalizations
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        if original.scope != scope
            || original.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(terminal.canonical_bytes()).into(),
                )
            || if transferred {
                !original.channel.transferred()
            } else {
                original.channel.phase()? != 2
            }
        {
            return Err(unavailable());
        }
        let retained = super::super::display_checkpoint::read_finalization_state(&restoration)
            .map_err(|_| unavailable())?;
        if !retained.1
            || retained
                .0
                .as_ref()
                .is_none_or(|old| old.canonical_bytes() != terminal.canonical_bytes())
        {
            return Err(unavailable());
        }
        Ok(payload)
    }

    pub(super) fn reserve_completion_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayCompletionPreparation,
    ) -> zbus::fdo::Result<OwnedFd> {
        let transfer_slot = StartupSlot::enter(&self.transfer_pending)?;
        let grant_slot = GrantSlot::enter(&self.live_grants)?;
        self.admit_control(sender)?;
        frame_current(&record)?;
        let scope = record
            .parent()
            .terminal()
            .decoded_material()
            .map_err(|_| unavailable())?
            .recovery_scope()
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
        let payload = self.completion_scope_live(&admission, &record, false)?;
        if admission.retirement_owners.get(&key).map(String::as_str) != Some(sender) {
            return Err(unavailable());
        }
        if admission.completions.len() >= MAX_STARTUPS || admission.completions.contains_key(&key) {
            return Err(unavailable());
        }
        let (_, integration) = NativeDisplayRecoveryCheckpoint::original_startup_scope(
            &payload,
            &dispatch(scope.original_dispatch())?,
        )
        .map_err(|_| unavailable())?;
        let state = super::super::display_completion_grant::ChannelState::reserved();
        let lifetime = super::super::display_completion_grant::Lifetime::new(state.clone());
        // Irreversible memory reservation precedes storage, sockets and replies.
        admission.completions.insert(
            key.clone(),
            CompletionReservation {
                scope: scope.clone(),
                digest: fingerprint,
                channel: state.clone(),
            },
        );
        super::super::display_checkpoint::reserve_completion(&record).map_err(|_| unavailable())?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let before = super::super::display_checkpoint::read_completion(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if before.canonical_bytes() != encoded {
            return Err(unavailable());
        }
        frame_current(&record)?;
        self.completion_scope_live(&admission, &record, false)?;
        self.admit_control(sender)?;
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        rustix::net::sockopt::set_socket_passcred(&writer, true).map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let mut grant = b"LNCG:1\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        let service = self.clone();
        let control = sender.to_owned();
        let persisted = AtomicBool::new(false);
        let mut last = (unix_ms()?, boot_ms()?);
        drop(admission);
        std::thread::Builder::new()
            .name("display-current-lifetime".into())
            .spawn(move || {
                let _grant_slot = grant_slot;
                let mut verify = |initial: bool| {
                    if initial {
                        service.admit_control(&control)?;
                        frame_current(&record)?;
                    }
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.completion_lifetime_scope_live(&admission, &record, !initial)?;
                    let live = admission.completions.get(&key).ok_or_else(unavailable)?;
                    if live.scope != scope
                        || live.digest != fingerprint
                        || !Arc::ptr_eq(&live.channel, &state)
                        || initial && !state.pending()
                        || !initial && !state.transferred()
                    {
                        return Err(unavailable());
                    }
                    let prepared =
                        super::super::display_checkpoint::read_completion(&restoration, false)
                            .map_err(|_| unavailable())?
                            .ok_or_else(unavailable)?;
                    let spent =
                        super::super::display_checkpoint::read_completion(&restoration, true)
                            .map_err(|_| unavailable())?;
                    if prepared.canonical_bytes() != encoded
                        || match spent {
                            Some(spent) => {
                                !persisted.load(Ordering::Acquire)
                                    || spent.canonical_bytes() != encoded
                            }
                            None => persisted.load(Ordering::Acquire),
                        }
                    {
                        return Err(unavailable());
                    }
                    let clock = (unix_ms()?, boot_ms()?);
                    if clock.0 < last.0 || clock.1 < last.1 {
                        return Err(unavailable());
                    }
                    last = clock;
                    Ok(())
                };
                let published = write_grant_with_marker(
                    &mut writer,
                    &grant,
                    b"LNCG-END:1\n",
                    ORIGINAL_PROBE,
                    &mut || verify(true),
                );
                drop(transfer_slot);
                if published.is_err() {
                    return;
                }
                let authenticate = |sender: &rustix::net::UCred| {
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    let startup = admission
                        .startups
                        .iter()
                        .find(|startup| {
                            startup
                                .peer
                                .matches_preimage(scope.replacement(), &integration)
                        })
                        .ok_or_else(unavailable)?;
                    startup.live().map_err(|_| unavailable())?;
                    startup
                        .peer
                        .require_message_sender(sender)
                        .map_err(|_| unavailable())
                };
                let transfer = || {
                    service.admit_control(&control)?;
                    frame_current(&record)?;
                    let admission = super::super::protection_lock::acquire(
                        &service.admission,
                        super::super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.completion_scope_live(&admission, &record, false)?;
                    if !state.pending() {
                        return Err(unavailable());
                    }
                    super::super::display_checkpoint::spend_completion(&record)
                        .map_err(|_| unavailable())?;
                    let spent =
                        super::super::display_checkpoint::read_completion(&restoration, true)
                            .map_err(|_| unavailable())?
                            .ok_or_else(unavailable)?;
                    if spent.canonical_bytes() != encoded {
                        return Err(unavailable());
                    }
                    frame_current(&record)?;
                    service.admit_control(&control)?;
                    let anchor = admission
                        .finalizations
                        .get(&key)
                        .ok_or_else(unavailable)?
                        .channel
                        .transfer()?;
                    persisted.store(true, Ordering::Release);
                    Ok(anchor)
                };
                let _result = super::super::display_completion_grant::serve(
                    &mut writer,
                    &digest,
                    lifetime,
                    authenticate,
                    &mut verify,
                    transfer,
                    |digest| service.spend_power_mechanism(&control, &key, &record, digest),
                    |digest| {
                        service.spend_current_commit_mechanism(&control, &key, &record, digest)
                    },
                    |digest| {
                        service.spend_final_retirement_mechanism(&control, &key, &record, digest)
                    },
                    |digest| service.spend_successor_mechanism(&key, &record, digest),
                );
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }

    pub(super) fn read_completion_mechanism(
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
        let live = admission
            .completions
            .get(key.as_str())
            .ok_or_else(unavailable)?;
        let restoration = super::super::display_checkpoint::read_restoration(&scope)
            .map_err(|_| unavailable())?;
        let prepared = super::super::display_checkpoint::read_completion(&restoration, false)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if live.scope != scope
            || live.digest
                != ComponentDigest::from_bytes(
                    sha2::Sha256::digest(prepared.canonical_bytes()).into(),
                )
        {
            return Err(unavailable());
        }
        let phase = if live.channel.pending() {
            1
        } else if live.channel.transferred() {
            2
        } else {
            return Err(unavailable());
        };
        self.completion_scope_live(&admission, &prepared, phase == 2)?;
        let spent = super::super::display_checkpoint::read_completion(&restoration, true)
            .map_err(|_| unavailable())?;
        if (phase == 2) != spent.is_some()
            || spent
                .as_ref()
                .is_some_and(|old| old.canonical_bytes() != prepared.canonical_bytes())
        {
            return Err(unavailable());
        }
        self.admit_control(sender)?;
        Ok((prepared.canonical_bytes(), phase)) // Never ReleasedCurrent.
    }
}
