const OWNER_ENROLLMENT_RECEIPT_SCHEMA: &str = "linura-owner-enrollment-receipt-v1";
const OWNER_ENROLLMENT_PRODUCER: &str = "linura-control-owner-enrollment-v1";
const MAX_OWNER_ENROLLMENT_RECEIPT_BYTES: u64 = 4096;
const OWNER_ENROLLMENT_RECEIPT_MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// Authenticated-owner evidence crossing from the Control-owned enrollment
/// boundary into durable bootstrap state. Callers cannot construct this type
/// from owner/enrollment strings; it must be loaded from a protected receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedOwnerEnrollmentReceipt {
    session_id: String,
    machine_id: String,
    owner_id: String,
    enrollment_id: String,
    issued_unix_ms: u64,
    receipt_sha256: String,
}

impl TrustedOwnerEnrollmentReceipt {
    pub fn load(
        path: &Path,
        expected_session_id: &str,
        expected_machine_id: &str,
    ) -> Result<Self, DurableBootstrapError> {
        validate_state_parent(path)?;
        let metadata = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != current_effective_uid()?
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_OWNER_ENROLLMENT_RECEIPT_BYTES
        {
            return Err(DurableBootstrapError::UntrustedControlPath);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(DurableBootstrapError::Io)?;
        validate_control_identity(path, &file)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(DurableBootstrapError::Io)?;
        validate_control_identity(path, &file)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            DurableBootstrapError::CorruptState("owner enrollment receipt is not UTF-8".into())
        })?;
        let integrity_index = text
            .rfind("\nintegrity=")
            .map(|index| index + 1)
            .ok_or_else(|| {
                DurableBootstrapError::CorruptState(
                    "owner enrollment receipt integrity record is missing".into(),
                )
            })?;
        let (payload, integrity_line) = text.split_at(integrity_index);
        let expected_digest = integrity_line
            .strip_prefix("integrity=")
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or_else(|| {
                DurableBootstrapError::CorruptState(
                    "owner enrollment receipt integrity record is malformed".into(),
                )
            })?;
        validate_anchor_sha256(expected_digest)?;
        let actual_digest = sha256(payload.as_bytes());
        if !constant_time_ascii_eq(actual_digest.as_bytes(), expected_digest.as_bytes()) {
            return Err(DurableBootstrapError::StateIntegrityMismatch);
        }

        let mut lines = payload.lines();
        if lines.next() != Some(OWNER_ENROLLMENT_RECEIPT_SCHEMA) {
            return Err(DurableBootstrapError::CorruptState(
                "unsupported owner enrollment receipt schema".into(),
            ));
        }
        if lines
            .next()
            .and_then(|line| line.strip_prefix("producer="))
            != Some(OWNER_ENROLLMENT_PRODUCER)
        {
            return Err(DurableBootstrapError::CorruptState(
                "owner enrollment receipt is not Control-produced".into(),
            ));
        }
        let session_id = normalize_identifier(
            "owner enrollment receipt session id",
            lines
                .next()
                .and_then(|line| line.strip_prefix("session_id="))
                .ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "owner enrollment receipt lacks session id".into(),
                    )
                })?,
        )?;
        let machine_id = normalize_identifier(
            "owner enrollment receipt machine id",
            lines
                .next()
                .and_then(|line| line.strip_prefix("machine_id="))
                .ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "owner enrollment receipt lacks machine id".into(),
                    )
                })?,
        )?;
        let owner_id = normalize_identifier(
            "owner id",
            lines
                .next()
                .and_then(|line| line.strip_prefix("owner_id="))
                .ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "owner enrollment receipt lacks owner id".into(),
                    )
                })?,
        )?;
        let enrollment_id = normalize_identifier(
            "owner enrollment id",
            lines
                .next()
                .and_then(|line| line.strip_prefix("enrollment_id="))
                .ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "owner enrollment receipt lacks enrollment id".into(),
                    )
                })?,
        )?;
        let issued_unix_ms = lines
            .next()
            .and_then(|line| line.strip_prefix("issued_unix_ms="))
            .ok_or_else(|| {
                DurableBootstrapError::CorruptState(
                    "owner enrollment receipt lacks issue timestamp".into(),
                )
            })?
            .parse::<u64>()
            .map_err(|_| {
                DurableBootstrapError::CorruptState(
                    "owner enrollment receipt timestamp is invalid".into(),
                )
            })?;
        if lines.next().is_some() {
            return Err(DurableBootstrapError::CorruptState(
                "owner enrollment receipt contains unexpected fields".into(),
            ));
        }
        if session_id != expected_session_id || machine_id != expected_machine_id {
            return Err(DurableBootstrapError::StateBindingMismatch);
        }
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableBootstrapError::Io(std::io::Error::other(error.to_string()))
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                DurableBootstrapError::Io(std::io::Error::other(
                    "owner enrollment timestamp exceeds u64",
                ))
            })?;
        if issued_unix_ms > now.saturating_add(BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS)
            || now.saturating_sub(issued_unix_ms) > OWNER_ENROLLMENT_RECEIPT_MAX_AGE_MS
        {
            return Err(DurableBootstrapError::VerificationEvidenceStale);
        }
        Ok(Self {
            session_id,
            machine_id,
            owner_id,
            enrollment_id,
            issued_unix_ms,
            receipt_sha256: actual_digest,
        })
    }

    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }

    #[must_use]
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }

    #[must_use]
    pub const fn issued_unix_ms(&self) -> u64 {
        self.issued_unix_ms
    }

    fn validate_binding(&self, state: &DurableBootstrapState) -> Result<(), DurableBootstrapError> {
        if self.session_id != state.session_id || self.machine_id != state.machine_id {
            return Err(DurableBootstrapError::StateBindingMismatch);
        }
        Ok(())
    }
}

impl DurableBootstrapState {
    fn stage_is_completed(&self, stage: BootstrapStage) -> bool {
        self.completed.contains(&stage)
    }

    fn enroll_pending_owner_fresh(
        &mut self,
        owner_id: String,
        enrollment_id: String,
    ) -> Result<(), DurableBootstrapError> {
        if self.active.is_some()
            || !self.stage_is_completed(BootstrapStage::OwnerEnrollmentResolution)
            || !matches!(
                self.provisioning.mode,
                Some(ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal)
            )
            || self.provisioning.owner_enrollment != OwnerEnrollmentState::Pending
        {
            return Err(DurableBootstrapError::FreshOwnerEnrollmentRequired);
        }
        if !self.provisioning.preparer_authority_retired {
            return Err(DurableBootstrapError::PreparerAuthorityStillActive);
        }

        let generation = self
            .provisioning
            .authority_generation
            .checked_add(1)
            .ok_or(DurableBootstrapError::GenerationOverflow)?;
        self.provisioning.owner_authority = Some(OwnerAuthorityRecord {
            owner_id: normalize_identifier("owner id", &owner_id)?,
            enrollment_id: normalize_identifier("owner enrollment id", &enrollment_id)?,
            generation,
        });
        self.provisioning.authority_generation = generation;
        self.provisioning.owner_enrollment = OwnerEnrollmentState::Enrolled;
        self.provisioning.validate()?;
        self.validate()
    }
}

impl DurableBootstrapCoordinator {
    /// Consume a Control-produced owner enrollment receipt after a deferred
    /// handoff. Raw owner/enrollment strings are never accepted by production
    /// APIs, so durable authority cannot be minted by an arbitrary coordinator
    /// caller.
    pub fn enroll_pending_owner_from_receipt(
        &mut self,
        receipt: &TrustedOwnerEnrollmentReceipt,
    ) -> Result<(), DurableBootstrapError> {
        receipt.validate_binding(&self.state)?;
        let mut candidate = self.state.clone();
        candidate.enroll_pending_owner_fresh(
            receipt.owner_id.clone(),
            receipt.enrollment_id.clone(),
        )?;
        self.commit(candidate)
    }

    pub fn enroll_interactive_owner_from_receipt(
        &mut self,
        receipt: &TrustedOwnerEnrollmentReceipt,
    ) -> Result<(), DurableBootstrapError> {
        if self.state.provisioning.mode != Some(ProvisioningMode::InteractiveOwner) {
            return Err(DurableBootstrapError::FreshOwnerEnrollmentRequired);
        }
        receipt.validate_binding(&self.state)?;
        let mut candidate = self.state.clone();
        candidate.enroll_owner_fresh(receipt.owner_id.clone(), receipt.enrollment_id.clone())?;
        self.commit(candidate)
    }
}
