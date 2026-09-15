const OWNER_ENROLLMENT_RECEIPT_SCHEMA: &str = "linura-owner-enrollment-receipt-v2";
const PREPARER_REVOCATION_RECEIPT_SCHEMA: &str = "linura-preparer-revocation-receipt-v1";
const OWNER_ENROLLMENT_PRODUCER: &str = "linura-control-owner-enrollment-v2";
const PREPARER_REVOCATION_SCOPE: &str = "preparer-os-authority-v1";
const MAX_OWNER_ENROLLMENT_RECEIPT_BYTES: u64 = 4096;
const OWNER_ENROLLMENT_RECEIPT_MAX_AGE_MS: u64 = 5 * 60 * 1000;
const OWNER_ENROLLMENT_AUTH_KEY_BYTES: usize = 32;
const HMAC_BLOCK_BYTES: usize = 64;

pub struct OwnerEnrollmentAuthorityVerifier {
    key: [u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES],
    fingerprint: String,
}

impl std::fmt::Debug for OwnerEnrollmentAuthorityVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerEnrollmentAuthorityVerifier")
            .field("fingerprint", &self.fingerprint)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OwnerEnrollmentAuthorityVerifier {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl OwnerEnrollmentAuthorityVerifier {
    pub fn open(path: &Path) -> Result<Self, DurableBootstrapError> {
        let key = read_owner_enrollment_auth_key(path)?;
        let fingerprint = sha256(&key);
        Ok(Self { key, fingerprint })
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn verify(&self, payload: &[u8], authentication: &str) -> Result<(), DurableBootstrapError> {
        validate_authentication_hex(authentication)?;
        let observed = hmac_sha256(&self.key, payload);
        if !constant_time_ascii_eq(observed.as_bytes(), authentication.as_bytes()) {
            return Err(DurableBootstrapError::StateIntegrityMismatch);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "qualification-harness"))]
pub struct OwnerEnrollmentAuthoritySigner {
    key: [u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES],
}

#[cfg(any(test, feature = "qualification-harness"))]
impl std::fmt::Debug for OwnerEnrollmentAuthoritySigner {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerEnrollmentAuthoritySigner")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(any(test, feature = "qualification-harness"))]
impl Drop for OwnerEnrollmentAuthoritySigner {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

#[cfg(any(test, feature = "qualification-harness"))]
impl OwnerEnrollmentAuthoritySigner {
    pub fn open(path: &Path) -> Result<Self, DurableBootstrapError> {
        Ok(Self {
            key: read_owner_enrollment_auth_key(path)?,
        })
    }

    pub fn owner_enrollment_receipt_bytes(
        &self,
        session_id: &str,
        machine_id: &str,
        owner_id: &str,
        enrollment_id: &str,
    ) -> Result<Vec<u8>, DurableBootstrapError> {
        let session_id = normalize_identifier("owner enrollment receipt session id", session_id)?;
        let machine_id = normalize_identifier("owner enrollment receipt machine id", machine_id)?;
        let owner_id = normalize_identifier("owner id", owner_id)?;
        let enrollment_id = normalize_identifier("owner enrollment id", enrollment_id)?;
        let issued_unix_ms = owner_receipt_now_ms()?;
        let payload = format!(
            "{OWNER_ENROLLMENT_RECEIPT_SCHEMA}\nproducer={OWNER_ENROLLMENT_PRODUCER}\nsession_id={session_id}\nmachine_id={machine_id}\nowner_id={owner_id}\nenrollment_id={enrollment_id}\nissued_unix_ms={issued_unix_ms}\n"
        );
        Ok(authenticated_receipt_bytes(&self.key, payload))
    }

    pub fn preparer_revocation_receipt_bytes(
        &self,
        state: &DurableBootstrapState,
        postcondition_sha256: &str,
    ) -> Result<Vec<u8>, DurableBootstrapError> {
        validate_anchor_sha256(postcondition_sha256)?;
        let active = state
            .active()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.stage() != BootstrapStage::OwnerEnrollmentResolution
            || active.effect_state() != BootstrapEffectState::EffectStarted
        {
            return Err(DurableBootstrapError::StageContextRequired(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }
        let issued_unix_ms = owner_receipt_now_ms()?;
        let payload = format!(
            "{PREPARER_REVOCATION_RECEIPT_SCHEMA}\nproducer={OWNER_ENROLLMENT_PRODUCER}\nsession_id={}\nmachine_id={}\noperation_id={}\nstage=owner-enrollment-resolution\neffect_state=effect-started\nscope={PREPARER_REVOCATION_SCOPE}\npostcondition_sha256={postcondition_sha256}\nissued_unix_ms={issued_unix_ms}\n",
            state.session_id(),
            state.machine_id(),
            active.operation_id(),
        );
        Ok(authenticated_receipt_bytes(&self.key, payload))
    }
}

fn read_owner_enrollment_auth_key(
    path: &Path,
) -> Result<[u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES], DurableBootstrapError> {
    validate_state_parent(path)?;
    let before = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != current_effective_uid()?
        || before.permissions().mode() & 0o077 != 0
        || before.len() != OWNER_ENROLLMENT_AUTH_KEY_BYTES as u64
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(DurableBootstrapError::Io)?;
    validate_control_identity(path, &file)?;
    let mut key = [0_u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES];
    file.read_exact(&mut key).map_err(DurableBootstrapError::Io)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(DurableBootstrapError::Io)? != 0
        || key.iter().all(|byte| *byte == 0)
    {
        key.fill(0);
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    validate_control_identity(path, &file)?;
    Ok(key)
}

fn hmac_sha256(key: &[u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES], payload: &[u8]) -> String {
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= *byte;
        outer_pad[index] ^= *byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(payload);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

#[cfg(any(test, feature = "qualification-harness"))]
fn authenticated_receipt_bytes(
    key: &[u8; OWNER_ENROLLMENT_AUTH_KEY_BYTES],
    payload: String,
) -> Vec<u8> {
    let authentication = hmac_sha256(key, payload.as_bytes());
    format!("{payload}authentication={authentication}\n").into_bytes()
}

fn validate_authentication_hex(value: &str) -> Result<(), DurableBootstrapError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableBootstrapError::CorruptState(
            "Control receipt authentication is not HMAC-SHA-256".into(),
        ));
    }
    Ok(())
}

fn split_authenticated_receipt<'a>(
    bytes: &'a [u8],
    label: &str,
) -> Result<(&'a str, &'a str), DurableBootstrapError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        DurableBootstrapError::CorruptState(format!("{label} is not UTF-8"))
    })?;
    let authentication_index = text
        .rfind("\nauthentication=")
        .map(|index| index + 1)
        .ok_or_else(|| {
            DurableBootstrapError::CorruptState(format!(
                "{label} authentication record is missing"
            ))
        })?;
    let (payload, authentication_line) = text.split_at(authentication_index);
    let authentication = authentication_line
        .strip_prefix("authentication=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptState(format!(
                "{label} authentication record is malformed"
            ))
        })?;
    validate_authentication_hex(authentication)?;
    Ok((payload, authentication))
}

fn owner_receipt_now_ms() -> Result<u64, DurableBootstrapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DurableBootstrapError::Io(std::io::Error::other(error.to_string())))?
        .as_millis()
        .try_into()
        .map_err(|_| {
            DurableBootstrapError::Io(std::io::Error::other(
                "owner enrollment timestamp exceeds u64",
            ))
        })
}

fn validate_owner_receipt_freshness(issued_unix_ms: u64) -> Result<(), DurableBootstrapError> {
    let now = owner_receipt_now_ms()?;
    if issued_unix_ms > now.saturating_add(BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS)
        || now.saturating_sub(issued_unix_ms) > OWNER_ENROLLMENT_RECEIPT_MAX_AGE_MS
    {
        return Err(DurableBootstrapError::VerificationEvidenceStale);
    }
    Ok(())
}

/// Authenticated-owner evidence crossing from the Control-owned enrollment
/// boundary into durable bootstrap state. Production exposes verification only;
/// signing is compiled solely for tests and the qualification harness.
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
        verifier: &OwnerEnrollmentAuthorityVerifier,
    ) -> Result<Self, DurableBootstrapError> {
        let bytes = protected_control_receipt_bytes(path)?;
        let (payload, authentication) = split_authenticated_receipt(
            &bytes,
            "owner enrollment receipt",
        )?;
        verifier.verify(payload.as_bytes(), authentication)?;
        let mut lines = payload.lines();
        if lines.next() != Some(OWNER_ENROLLMENT_RECEIPT_SCHEMA)
            || lines
                .next()
                .and_then(|line| line.strip_prefix("producer="))
                != Some(OWNER_ENROLLMENT_PRODUCER)
        {
            return Err(DurableBootstrapError::CorruptState(
                "owner enrollment receipt is not authenticated Control v2 evidence".into(),
            ));
        }
        let session_id = receipt_identifier(&mut lines, "session_id", "owner enrollment receipt session id")?;
        let machine_id = receipt_identifier(&mut lines, "machine_id", "owner enrollment receipt machine id")?;
        let owner_id = receipt_identifier(&mut lines, "owner_id", "owner id")?;
        let enrollment_id = receipt_identifier(&mut lines, "enrollment_id", "owner enrollment id")?;
        let issued_unix_ms = receipt_timestamp(&mut lines)?;
        if lines.next().is_some() {
            return Err(DurableBootstrapError::CorruptState(
                "owner enrollment receipt contains unexpected fields".into(),
            ));
        }
        if session_id != expected_session_id || machine_id != expected_machine_id {
            return Err(DurableBootstrapError::StateBindingMismatch);
        }
        validate_owner_receipt_freshness(issued_unix_ms)?;
        Ok(Self {
            session_id,
            machine_id,
            owner_id,
            enrollment_id,
            issued_unix_ms,
            receipt_sha256: sha256(&bytes),
        })
    }

    #[must_use]
    pub fn owner_id(&self) -> &str { &self.owner_id }
    #[must_use]
    pub fn enrollment_id(&self) -> &str { &self.enrollment_id }
    #[must_use]
    pub fn receipt_sha256(&self) -> &str { &self.receipt_sha256 }
    #[must_use]
    pub const fn issued_unix_ms(&self) -> u64 { self.issued_unix_ms }

    fn validate_binding(&self, state: &DurableBootstrapState) -> Result<(), DurableBootstrapError> {
        if self.session_id != state.session_id || self.machine_id != state.machine_id {
            return Err(DurableBootstrapError::StateBindingMismatch);
        }
        validate_owner_receipt_freshness(self.issued_unix_ms)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPreparerAuthorityRevocationReceipt {
    session_id: String,
    machine_id: String,
    operation_id: String,
    postcondition_sha256: String,
    issued_unix_ms: u64,
    receipt_sha256: String,
}

impl TrustedPreparerAuthorityRevocationReceipt {
    pub fn load(
        path: &Path,
        state: &DurableBootstrapState,
        verifier: &OwnerEnrollmentAuthorityVerifier,
    ) -> Result<Self, DurableBootstrapError> {
        let bytes = protected_control_receipt_bytes(path)?;
        let (payload, authentication) = split_authenticated_receipt(
            &bytes,
            "preparer revocation receipt",
        )?;
        verifier.verify(payload.as_bytes(), authentication)?;
        let mut lines = payload.lines();
        if lines.next() != Some(PREPARER_REVOCATION_RECEIPT_SCHEMA)
            || lines
                .next()
                .and_then(|line| line.strip_prefix("producer="))
                != Some(OWNER_ENROLLMENT_PRODUCER)
        {
            return Err(DurableBootstrapError::CorruptState(
                "preparer revocation receipt is not authenticated Control evidence".into(),
            ));
        }
        let session_id = receipt_identifier(&mut lines, "session_id", "preparer revocation session id")?;
        let machine_id = receipt_identifier(&mut lines, "machine_id", "preparer revocation machine id")?;
        let operation_id = receipt_identifier(&mut lines, "operation_id", "preparer revocation operation id")?;
        if lines.next() != Some("stage=owner-enrollment-resolution")
            || lines.next() != Some("effect_state=effect-started")
            || lines
        .next()
        .and_then(|line| line.strip_prefix("scope="))
        != Some(PREPARER_REVOCATION_SCOPE)
        {
            return Err(DurableBootstrapError::CorruptState(
                "preparer revocation receipt has an invalid stage/effect/scope binding".into(),
            ));
        }
        let postcondition_sha256 = lines
            .next()
            .and_then(|line| line.strip_prefix("postcondition_sha256="))
            .ok_or_else(|| DurableBootstrapError::CorruptState("preparer revocation receipt lacks postcondition digest".into()))?
            .to_owned();
        validate_anchor_sha256(&postcondition_sha256)?;
        let issued_unix_ms = receipt_timestamp(&mut lines)?;
        if lines.next().is_some() {
            return Err(DurableBootstrapError::CorruptState(
                "preparer revocation receipt contains unexpected fields".into(),
            ));
        }
        let receipt = Self {
            session_id,
            machine_id,
            operation_id,
            postcondition_sha256,
            issued_unix_ms,
            receipt_sha256: sha256(&bytes),
        };
        receipt.validate_binding(state)?;
        Ok(receipt)
    }

    #[cfg(any(test, feature = "qualification-harness"))]
    pub fn qualification_observation(
        state: &DurableBootstrapState,
        canonical_postcondition: &[u8],
    ) -> Result<Self, DurableBootstrapError> {
        let active = state.active().ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.stage() != BootstrapStage::OwnerEnrollmentResolution
            || active.effect_state() != BootstrapEffectState::EffectStarted
        {
            return Err(DurableBootstrapError::StageContextRequired(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }
        Ok(Self {
            session_id: state.session_id().to_owned(),
            machine_id: state.machine_id().to_owned(),
            operation_id: active.operation_id().to_owned(),
            postcondition_sha256: sha256(canonical_postcondition),
            issued_unix_ms: owner_receipt_now_ms()?,
            receipt_sha256: sha256(canonical_postcondition),
        })
    }

    #[must_use]
    pub fn postcondition_sha256(&self) -> &str { &self.postcondition_sha256 }
    #[must_use]
    pub fn receipt_sha256(&self) -> &str { &self.receipt_sha256 }

    fn validate_binding(&self, state: &DurableBootstrapState) -> Result<(), DurableBootstrapError> {
        let active = state.active().ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.stage() != BootstrapStage::OwnerEnrollmentResolution
            || active.effect_state() != BootstrapEffectState::EffectStarted
            || self.session_id != state.session_id()
            || self.machine_id != state.machine_id()
            || self.operation_id != active.operation_id()
        {
            return Err(DurableBootstrapError::StateBindingMismatch);
        }
        validate_owner_receipt_freshness(self.issued_unix_ms)
    }
}

fn protected_control_receipt_bytes(path: &Path) -> Result<Vec<u8>, DurableBootstrapError> {
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
    file.read_to_end(&mut bytes).map_err(DurableBootstrapError::Io)?;
    validate_control_identity(path, &file)?;
    Ok(bytes)
}

fn receipt_identifier(
    lines: &mut std::str::Lines<'_>,
    field: &str,
    label: &'static str,
) -> Result<String, DurableBootstrapError> {
    normalize_identifier(
        label,
        lines
            .next()
            .and_then(|line| line.strip_prefix(&format!("{field}=")))
            .ok_or_else(|| {
                DurableBootstrapError::CorruptState(format!(
                    "Control receipt lacks {field}"
                ))
            })?,
    )
}

fn receipt_timestamp(lines: &mut std::str::Lines<'_>) -> Result<u64, DurableBootstrapError> {
    lines
        .next()
        .and_then(|line| line.strip_prefix("issued_unix_ms="))
        .ok_or_else(|| DurableBootstrapError::CorruptState("Control receipt lacks issue timestamp".into()))?
        .parse::<u64>()
        .map_err(|_| DurableBootstrapError::CorruptState("Control receipt timestamp is invalid".into()))
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

#[cfg(test)]
mod owner_receipt_consumption_tests {
    use super::*;

    #[test]
    fn receipt_freshness_is_rechecked_at_consumption() {
        let state = DurableBootstrapState::new("session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let receipt = TrustedOwnerEnrollmentReceipt {
            session_id: "session-1".into(),
            machine_id: "machine-1".into(),
            owner_id: "owner-1".into(),
            enrollment_id: "enrollment-1".into(),
            issued_unix_ms: 1,
            receipt_sha256: "0".repeat(64),
        };
        assert!(matches!(
            receipt.validate_binding(&state),
            Err(DurableBootstrapError::VerificationEvidenceStale)
        ));
    }
}
