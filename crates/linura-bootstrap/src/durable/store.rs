#[cfg(feature = "qualification-harness")]
fn qualification_crash_after(point: &str) {
    if std::env::var("LINURA_BOOTSTRAP_QUALIFICATION_CRASH_AFTER")
        .ok()
        .as_deref()
        == Some(point)
    {
        eprintln!("qualification_crash_after={point}");
        std::process::abort();
    }
}

#[cfg(not(feature = "qualification-harness"))]
fn qualification_crash_after(_point: &str) {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapStateStore {
    path: PathBuf,
}

impl BootstrapStateStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<DurableBootstrapState>, DurableBootstrapError> {
        validate_state_parent(&self.path)?;
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(DurableBootstrapError::Io(error)),
        };
        validate_state_metadata(&metadata)?;
        if metadata.len() > MAX_BOOTSTRAP_STATE_BYTES {
            return Err(DurableBootstrapError::StateSizeExceeded);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&self.path)
            .map_err(DurableBootstrapError::Io)?;
        let opened = file.metadata().map_err(DurableBootstrapError::Io)?;
        validate_state_metadata(&opened)?;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.len() != metadata.len()
        {
            return Err(DurableBootstrapError::UntrustedStatePath);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(DurableBootstrapError::Io)?;
        if bytes.len() as u64 > MAX_BOOTSTRAP_STATE_BYTES {
            return Err(DurableBootstrapError::StateSizeExceeded);
        }
        let after = fs::symlink_metadata(&self.path).map_err(DurableBootstrapError::Io)?;
        validate_state_metadata(&after)?;
        if after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || after.len() != opened.len()
        {
            return Err(DurableBootstrapError::UntrustedStatePath);
        }
        parse_state(&bytes).map(Some)
    }

    fn generation(
        &self,
        state: &DurableBootstrapState,
    ) -> Result<StoreGeneration, DurableBootstrapError> {
        validate_state_parent(&self.path)?;
        let metadata = fs::symlink_metadata(&self.path).map_err(DurableBootstrapError::Io)?;
        validate_state_metadata(&metadata)?;
        Ok(StoreGeneration {
            state_generation: state.generation,
            device: metadata.dev(),
            inode: metadata.ino(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            len: metadata.len(),
        })
    }

    fn persist(&self, state: &DurableBootstrapState) -> Result<(), DurableBootstrapError> {
        atomic_write(&self.path, &serialize_state(state))
    }

    fn acquire_exclusive(&self) -> Result<File, DurableBootstrapError> {
        let lock_path = sidecar_path(&self.path, "lock")?;
        let parent = lock_path.parent().ok_or_else(|| {
            DurableBootstrapError::Io(std::io::Error::other(
                "bootstrap lock path has no parent directory",
            ))
        })?;
        fs::create_dir_all(parent).map_err(DurableBootstrapError::Io)?;
        validate_state_parent(&self.path)?;
        reject_untrusted_existing_control_file(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&lock_path)
            .map_err(DurableBootstrapError::Io)?;
        validate_control_identity(&lock_path, &file)?;
        file.lock().map_err(DurableBootstrapError::Io)?;
        validate_control_identity(&lock_path, &file)?;
        Ok(file)
    }
}

#[derive(Debug)]
pub struct DurableBootstrapCoordinator {
    store: BootstrapStateStore,
    state: DurableBootstrapState,
    store_generation: StoreGeneration,
    durability_uncertain: Option<String>,
}

impl DurableBootstrapCoordinator {
    pub fn open(
        store: BootstrapStateStore,
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
    ) -> Result<Self, DurableBootstrapError> {
        let session_id = normalize_identifier("bootstrap session id", &session_id.into())?;
        let machine_id = normalize_identifier("machine id", &machine_id.into())?;
        let _lock = store.acquire_exclusive()?;
        let state = match store.load()? {
            Some(state) => {
                if state.session_id != session_id || state.machine_id != machine_id {
                    return Err(DurableBootstrapError::StateBindingMismatch);
                }
                store.reconcile_generation_anchor(&state)?;
                state
            }
            None => {
                let state = DurableBootstrapState::new(session_id, machine_id)?;
                store.persist(&state)?;
                // Generation zero is initialization, not a historical transition.
                // Reconciliation creates the machine-scoped committed anchor and
                // makes a crash after the state rename recoverable on reopen.
                store.reconcile_generation_anchor(&state)?;
                state
            }
        };
        state.validate()?;
        let store_generation = store.generation(&state)?;
        Ok(Self {
            store,
            state,
            store_generation,
            durability_uncertain: None,
        })
    }

    #[must_use]
    pub fn state(&self) -> &DurableBootstrapState {
        &self.state
    }

    #[must_use]
    pub fn requires_recovery(&self) -> bool {
        self.durability_uncertain.is_some()
    }

    #[must_use]
    pub fn resume_decision(&self) -> BootstrapResumeDecision<'_> {
        if self.durability_uncertain.is_some() {
            return BootstrapResumeDecision::RecoveryRequired;
        }
        match self.state.active.as_ref() {
            Some(active) if active.effect_state == BootstrapEffectState::Prepared => {
                BootstrapResumeDecision::ExecutePrepared {
                    stage: active.stage,
                    operation_id: &active.operation_id,
                }
            }
            Some(active) => BootstrapResumeDecision::ReobserveBeforeContinuing {
                stage: active.stage,
                operation_id: &active.operation_id,
            },
            None => match self.state.next_stage() {
                Some(stage) => BootstrapResumeDecision::ContinueAt(stage),
                None => BootstrapResumeDecision::Complete,
            },
        }
    }

    pub fn prepare_stage(
        &mut self,
        stage: BootstrapStage,
        operation_id: impl Into<String>,
    ) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.prepare_stage(stage, operation_id.into())?;
        self.commit(candidate)
    }

    pub fn mark_effect_started(
        &mut self,
        operation_id: &str,
    ) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.mark_effect_started(operation_id)?;
        self.commit(candidate)
    }

    /// Complete a stage that has no external-effect boundary. Effectful stages
    /// must use an authoritative verifier method from `part3e`.
    pub fn complete_verified(
        &mut self,
        operation_id: &str,
    ) -> Result<(), DurableBootstrapError> {
        if let Some(active) = self.state.active()
            && stage_requires_effect_boundary(active.stage())
        {
            return Err(DurableBootstrapError::VerificationEvidenceRequired(
                active.stage(),
            ));
        }
        let mut candidate = self.state.clone();
        candidate.complete_verified(operation_id)?;
        self.commit(candidate)
    }

    pub fn select_provisioning(
        &mut self,
        mode: ProvisioningMode,
        manifest: Option<&ProvisioningManifest>,
    ) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.select_provisioning(mode, manifest)?;
        self.commit(candidate)
    }

    pub fn enter_owner_enrollment_pending(
        &mut self,
        revocation: &TrustedPreparerAuthorityRevocationReceipt,
    ) -> Result<(), DurableBootstrapError> {
        revocation.validate_binding(&self.state)?;
        let mut candidate = self.state.clone();
        candidate.enter_owner_enrollment_pending(revocation)?;
        self.commit(candidate)
    }

    fn ensure_usable(&self) -> Result<(), DurableBootstrapError> {
        if let Some(reason) = &self.durability_uncertain {
            return Err(DurableBootstrapError::RecoveryRequired(reason.clone()));
        }
        Ok(())
    }

    fn commit(&mut self, mut candidate: DurableBootstrapState) -> Result<(), DurableBootstrapError> {
        self.ensure_usable()?;
        candidate.validate()?;
        let _lock = self.store.acquire_exclusive()?;
        let durable = self.store.load()?.ok_or_else(|| {
            DurableBootstrapError::CorruptState("durable bootstrap state disappeared".into())
        })?;
        self.store.reconcile_generation_anchor(&durable)?;
        let durable_generation = self.store.generation(&durable)?;
        if durable != self.state || durable_generation != self.store_generation {
            let reason = "durable bootstrap state/generation changed through another coordinator; reopen and reconcile before continuing".to_owned();
            self.durability_uncertain = Some(reason);
            return Err(DurableBootstrapError::StaleCoordinator);
        }
        candidate.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(DurableBootstrapError::GenerationOverflow)?;
        candidate.validate()?;

        // Two-phase durability: first fsync an external machine-scoped anchor
        // containing the exact next generation and candidate digest. Only then
        // publish the atomic ledger rename, and finally promote the pending
        // anchor. Reopen can distinguish both crash windows without guessing.
        self.store
            .stage_generation_anchor(&self.state, &candidate)?;
        qualification_crash_after("anchor-stage");
        match self.store.persist(&candidate) {
            Ok(()) => {
                qualification_crash_after("ledger-persist");
                if let Err(error) = self.store.finalize_generation_anchor(&candidate) {
                    let reason = format!(
                        "bootstrap state generation {} committed but external generation anchor could not be finalized: {error}",
                        candidate.generation
                    );
                    self.durability_uncertain = Some(reason.clone());
                    return Err(DurableBootstrapError::DurabilityUncertain(reason));
                }
                qualification_crash_after("anchor-finalize");
                if let Err(error) = self.store.reconcile_generation_anchor(&candidate) {
                    let reason = format!(
                        "bootstrap state/anchor commit could not be re-observed consistently: {error}"
                    );
                    self.durability_uncertain = Some(reason.clone());
                    return Err(DurableBootstrapError::DurabilityUncertain(reason));
                }
                let generation = match self.store.generation(&candidate) {
                    Ok(generation) => generation,
                    Err(error) => {
                        let reason = format!(
                            "bootstrap state commit succeeded but durable generation could not be re-observed: {error}"
                        );
                        self.durability_uncertain = Some(reason.clone());
                        return Err(DurableBootstrapError::DurabilityUncertain(reason));
                    }
                };
                self.state = candidate;
                self.store_generation = generation;
                Ok(())
            }
            Err(DurableBootstrapError::DurabilityUncertain(reason)) => {
                self.durability_uncertain = Some(reason.clone());
                Err(DurableBootstrapError::DurabilityUncertain(reason))
            }
            Err(error) => Err(error),
        }
    }
}
