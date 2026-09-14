const MAX_BOOTSTRAP_POSTCONDITION_BYTES: usize = 16 * 1024;
const BOOTSTRAP_VERIFICATION_MAX_AGE_MS: u64 = 5 * 60 * 1000;
const BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS: u64 = 30 * 1000;
const SYSTEM_BOOTSTRAP_VERIFIER_ID: &str = "linura-bootstrap-system-verifier-v2";
const MANAGED_FIRSTBOOT_PATH: &str = "/opt/linura/bin/linura-firstboot";

/// Exact, fresh postcondition evidence required before an effectful bootstrap
/// stage may be recorded complete.
///
/// Fields are intentionally private and normal production builds expose no
/// caller-authored constructor. Evidence is issued by the stage-specific
/// authoritative probes on `DurableBootstrapCoordinator`. Qualification builds
/// have an explicit synthetic constructor so the state machine can be tested
/// without confusing fixture evidence with production authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapVerificationEvidence {
    stage: BootstrapStage,
    operation_id: String,
    session_id: String,
    machine_id: String,
    verifier_id: String,
    observation_id: String,
    postcondition_sha256: String,
    observed_unix_ms: u64,
}

impl BootstrapVerificationEvidence {
    fn issue(
        stage: BootstrapStage,
        operation_id: impl Into<String>,
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
        verifier_id: impl Into<String>,
        observation_id: impl Into<String>,
        canonical_postcondition: &[u8],
    ) -> Result<Self, DurableBootstrapError> {
        if !stage_requires_effect_boundary(stage) {
            return Err(DurableBootstrapError::VerificationEvidenceUnexpected(stage));
        }
        if canonical_postcondition.is_empty()
            || canonical_postcondition.len() > MAX_BOOTSTRAP_POSTCONDITION_BYTES
        {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "canonical postcondition is empty or exceeds the supported bound",
            ));
        }
        let observed_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableBootstrapError::Io(std::io::Error::other(error.to_string()))
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                DurableBootstrapError::Io(std::io::Error::other(
                    "bootstrap verification timestamp exceeds u64",
                ))
            })?;
        Ok(Self {
            stage,
            operation_id: normalize_identifier(
                "bootstrap verification operation id",
                &operation_id.into(),
            )?,
            session_id: normalize_identifier(
                "bootstrap verification session id",
                &session_id.into(),
            )?,
            machine_id: normalize_identifier(
                "bootstrap verification machine id",
                &machine_id.into(),
            )?,
            verifier_id: normalize_identifier(
                "bootstrap verification producer id",
                &verifier_id.into(),
            )?,
            observation_id: normalize_identifier(
                "bootstrap verification observation id",
                &observation_id.into(),
            )?,
            postcondition_sha256: sha256(canonical_postcondition),
            observed_unix_ms,
        })
    }

    /// Qualification-only state-machine evidence. This constructor is excluded
    /// from normal/release builds so product integrations cannot self-attest.
    #[cfg(feature = "qualification-harness")]
    pub fn qualification_observation(
        stage: BootstrapStage,
        operation_id: impl Into<String>,
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
        observation_id: impl Into<String>,
        canonical_postcondition: &[u8],
    ) -> Result<Self, DurableBootstrapError> {
        Self::issue(
            stage,
            operation_id,
            session_id,
            machine_id,
            "linura-bootstrap-qualification-fixture-v1",
            observation_id,
            canonical_postcondition,
        )
    }

    #[must_use]
    pub const fn stage(&self) -> BootstrapStage {
        self.stage
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    #[must_use]
    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    #[must_use]
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    #[must_use]
    pub fn postcondition_sha256(&self) -> &str {
        &self.postcondition_sha256
    }

    #[must_use]
    pub const fn observed_unix_ms(&self) -> u64 {
        self.observed_unix_ms
    }

    fn validate_binding(
        &self,
        active: &ActiveBootstrapStage,
        expected_session_id: &str,
        expected_machine_id: &str,
    ) -> Result<(), DurableBootstrapError> {
        if self.stage != active.stage
            || self.operation_id != active.operation_id
            || self.session_id != expected_session_id
            || self.machine_id != expected_machine_id
        {
            return Err(DurableBootstrapError::VerificationEvidenceBindingMismatch);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableBootstrapError::Io(std::io::Error::other(error.to_string()))
            })?
            .as_millis();
        let now: u64 = now.try_into().map_err(|_| {
            DurableBootstrapError::Io(std::io::Error::other(
                "bootstrap verification timestamp exceeds u64",
            ))
        })?;
        if self.observed_unix_ms > now.saturating_add(BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS)
            || now.saturating_sub(self.observed_unix_ms) > BOOTSTRAP_VERIFICATION_MAX_AGE_MS
        {
            return Err(DurableBootstrapError::VerificationEvidenceStale);
        }
        if self.postcondition_sha256.len() != 64
            || !self
                .postcondition_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "postcondition digest is not SHA-256",
            ));
        }
        Ok(())
    }
}

impl From<&BootstrapVerificationEvidence> for CompletedEffectVerification {
    fn from(evidence: &BootstrapVerificationEvidence) -> Self {
        Self {
            stage: evidence.stage,
            operation_id: evidence.operation_id.clone(),
            verifier_id: evidence.verifier_id.clone(),
            observation_id: evidence.observation_id.clone(),
            postcondition_sha256: evidence.postcondition_sha256.clone(),
            observed_unix_ms: evidence.observed_unix_ms,
        }
    }
}

impl DurableBootstrapState {
    fn complete_effect_verified(
        &mut self,
        evidence: &BootstrapVerificationEvidence,
    ) -> Result<(), DurableBootstrapError> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if !stage_requires_effect_boundary(active.stage) {
            return Err(DurableBootstrapError::VerificationEvidenceUnexpected(
                active.stage,
            ));
        }
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(active.stage));
        }
        evidence.validate_binding(active, &self.session_id, &self.machine_id)?;
        self.effect_verifications
            .push(CompletedEffectVerification::from(evidence));
        self.completed.push(active.stage);
        self.active = None;
        self.validate()
    }

    fn enter_recovery_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        let active = self.active_stage_for(BootstrapStage::OwnerEnrollmentResolution)?;
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }
        if self.provisioning.mode != Some(ProvisioningMode::Recovery) {
            return Err(DurableBootstrapError::RecoveryOwnerResolutionNotAllowed);
        }
        if self.provisioning.owner_enrollment != OwnerEnrollmentState::Unresolved {
            return Err(DurableBootstrapError::OwnerStateAlreadyResolved);
        }
        self.provisioning.owner_authority = None;
        self.provisioning.authority_generation = 0;
        self.provisioning.preparer_authority_retired = false;
        self.provisioning.owner_enrollment = OwnerEnrollmentState::RecoveryResolved;
        self.provisioning.validate()?;
        self.validate()
    }
}

fn protected_regular_file_sha256(path: &Path) -> Result<String, DurableBootstrapError> {
    let before = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(DurableBootstrapError::Io)?;
    let opened = file.metadata().map_err(DurableBootstrapError::Io)?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != 0
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o022 != 0
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(DurableBootstrapError::Io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn command_output(program: &str, args: &[&str]) -> Result<std::process::Output, DurableBootstrapError> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(DurableBootstrapError::Io)
}

fn ssh_enabled() -> Result<bool, DurableBootstrapError> {
    for unit in ["ssh.service", "sshd.service", "ssh.socket", "sshd.socket"] {
        let output = command_output("systemctl", &["is-enabled", unit])?;
        if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "enabled" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn firewall_default_deny() -> Result<bool, DurableBootstrapError> {
    let output = command_output("nft", &["list", "ruleset"])?;
    if !output.status.success() {
        return Ok(false);
    }
    let rules = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    Ok(rules.contains("hook input")
        && (rules.contains("policy drop") || rules.contains("policy reject")))
}

fn apt_sources_fail_closed() -> Result<bool, DurableBootstrapError> {
    fn check_file(path: &Path) -> Result<bool, DurableBootstrapError> {
        let text = fs::read_to_string(path).map_err(DurableBootstrapError::Io)?;
        let lower = text.to_ascii_lowercase();
        Ok(!lower.contains("trusted=yes")
            && !lower.contains("allow-insecure=yes")
            && !lower.contains("allow-weak=yes")
            && !lower.contains("allow_downgrade_to_insecure_repositories"))
    }

    let primary = Path::new("/etc/apt/sources.list");
    if primary.exists() && !check_file(primary)? {
        return Ok(false);
    }
    let directory = Path::new("/etc/apt/sources.list.d");
    if directory.exists() {
        for entry in fs::read_dir(directory).map_err(DurableBootstrapError::Io)? {
            let path = entry.map_err(DurableBootstrapError::Io)?.path();
            if path.is_file() && !check_file(&path)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl DurableBootstrapCoordinator {
    fn active_effect_context(
        &self,
        required: BootstrapStage,
    ) -> Result<(&str, &str, &str), DurableBootstrapError> {
        let active = self
            .state
            .active()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.stage() != required {
            return Err(DurableBootstrapError::StageContextRequired(required));
        }
        if active.effect_state() != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(required));
        }
        Ok((
            active.operation_id(),
            self.state.session_id(),
            self.state.machine_id(),
        ))
    }

    fn issue_system_evidence(
        &self,
        stage: BootstrapStage,
        observation_id: &str,
        canonical_postcondition: &[u8],
    ) -> Result<BootstrapVerificationEvidence, DurableBootstrapError> {
        let (operation_id, session_id, machine_id) = self.active_effect_context(stage)?;
        BootstrapVerificationEvidence::issue(
            stage,
            operation_id,
            session_id,
            machine_id,
            SYSTEM_BOOTSTRAP_VERIFIER_ID,
            observation_id,
            canonical_postcondition,
        )
    }

    /// Low-level completion remains public for verifier integrations that
    /// receive an opaque evidence value, but production builds expose no public
    /// constructor for that value.
    pub fn complete_effect_verified(
        &mut self,
        evidence: &BootstrapVerificationEvidence,
    ) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.complete_effect_verified(evidence)?;
        self.commit(candidate)
    }

    /// Verify the exact managed Linura First Boot installation from protected
    /// filesystem state. The caller supplies only the expected source digest;
    /// verifier identity, operation/session/machine bindings and observation
    /// bytes are produced inside this crate.
    pub fn verify_linura_installation(
        &mut self,
        expected_sha256: &str,
    ) -> Result<(), DurableBootstrapError> {
        validate_anchor_sha256(expected_sha256)?;
        let observed = protected_regular_file_sha256(Path::new(MANAGED_FIRSTBOOT_PATH))?;
        if !constant_time_ascii_eq(observed.as_bytes(), expected_sha256.as_bytes()) {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "managed First Boot installation digest does not match exact source",
            ));
        }
        let postcondition = format!(
            "managed_path={MANAGED_FIRSTBOOT_PATH};sha256={observed};root_owned=true;protected=true"
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::LinuraInstallation,
            "managed-installation-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_persistent_state_root(
        &mut self,
        root: &Path,
    ) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::PersistentStateInitialization)?;
        let metadata = fs::symlink_metadata(root).map_err(DurableBootstrapError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.uid() != current_effective_uid()?
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(DurableBootstrapError::UntrustedStatePath);
        }
        let postcondition = format!(
            "root={};uid={};mode={:o};dev={};ino={}",
            root.display(),
            metadata.uid(),
            metadata.permissions().mode() & 0o7777,
            metadata.dev(),
            metadata.ino(),
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::PersistentStateInitialization,
            "protected-state-root-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_security_baseline(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::SecurityBaseline)?;
        if ssh_enabled()? || !firewall_default_deny()? || !apt_sources_fail_closed()? {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "Q8 security baseline is not fail-closed",
            ));
        }
        let postcondition = b"disk-encryption-claim=absent;inbound-firewall=default-deny;ssh-enabled=false;untrusted-package-sources=false";
        let evidence = self.issue_system_evidence(
            BootstrapStage::SecurityBaseline,
            "q8-system-security-observation",
            postcondition,
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_connectivity_observation(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::BootstrapConnectivityResolution)?;
        let mut interfaces = fs::read_dir("/sys/class/net")
            .map_err(DurableBootstrapError::Io)?
            .map(|entry| {
                entry
                    .map_err(DurableBootstrapError::Io)?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        DurableBootstrapError::InvalidVerificationEvidence(
                            "network interface name is not UTF-8",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        interfaces.sort();
        if interfaces.is_empty() {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "no network interface was authoritatively observed",
            ));
        }
        let postcondition = format!("interfaces={}", interfaces.join(","));
        let evidence = self.issue_system_evidence(
            BootstrapStage::BootstrapConnectivityResolution,
            "kernel-network-interface-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_recovery_checkpoint_manifest(
        &mut self,
        manifest: &Path,
    ) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::RecoveryCheckpoint)?;
        let digest = protected_regular_file_sha256(manifest)?;
        let postcondition = format!(
            "checkpoint_manifest={};sha256={digest};protected=true",
            manifest.display()
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::RecoveryCheckpoint,
            "recovery-checkpoint-bundle-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::OwnerEnrollmentResolution)?;
        if self.state.provisioning().owner_enrollment() == OwnerEnrollmentState::Unresolved {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "owner enrollment remains unresolved",
            ));
        }
        let postcondition = format!(
            "owner-state={};authority-generation={};preparer-retired={}",
            self.state.provisioning().owner_enrollment().as_str(),
            self.state.provisioning().authority_generation(),
            self.state.provisioning().preparer_authority_retired(),
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::OwnerEnrollmentResolution,
            "durable-owner-resolution-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    /// Resolve the owner stage for Recovery without creating, inheriting or
    /// deferring final-owner authority.
    pub fn enter_recovery_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.enter_recovery_owner_resolution()?;
        self.commit(candidate)
    }
}
