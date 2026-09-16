#[derive(Debug)]
pub enum DurableBootstrapError {
    Io(std::io::Error),
    InvalidIdentifier(&'static str),
    InvalidManifest(&'static str),
    UnsupportedManifestVersion,
    ManifestSizeExceeded,
    ManifestIntegrityMismatch,
    ManifestBindingMismatch,
    ManifestRequired,
    StateSizeExceeded,
    UnsupportedStateVersion,
    StateIntegrityMismatch,
    CorruptState(String),
    UntrustedStatePath,
    UntrustedControlPath,
    StateBindingMismatch,
    UnexpectedStage {
        expected: BootstrapStage,
        actual: BootstrapStage,
    },
    StageAlreadyActive,
    StageContextRequired(BootstrapStage),
    NoActiveStage,
    OperationBindingMismatch,
    EffectAlreadyStarted,
    EffectNotStarted(BootstrapStage),
    VerificationEvidenceRequired(BootstrapStage),
    VerificationEvidenceUnexpected(BootstrapStage),
    InvalidVerificationEvidence(&'static str),
    VerificationEvidenceBindingMismatch,
    VerificationEvidenceStale,
    AlreadyComplete,
    ProvisioningModeAlreadySelected,
    ProvisioningModeRequired,
    OwnerPendingNotAllowed,
    OwnerStateAlreadyResolved,
    RecoveryOwnerResolutionNotAllowed,
    PreparerAuthorityStillActive,
    FreshOwnerEnrollmentRequired,
    GenerationOverflow,
    GenerationAnchorMissing,
    UnsupportedGenerationAnchorVersion,
    GenerationAnchorIntegrityMismatch,
    CorruptGenerationAnchor(String),
    GenerationRollbackDetected {
        state_generation: u64,
        anchor_generation: u64,
    },
    StaleCoordinator,
    DurabilityUncertain(String),
    RecoveryRequired(String),
}

impl Display for DurableBootstrapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "durable bootstrap I/O failed: {error}"),
            Self::InvalidIdentifier(label) => write!(f, "invalid {label}"),
            Self::InvalidManifest(reason) => write!(f, "invalid Provisioning Manifest: {reason}"),
            Self::UnsupportedManifestVersion => {
                f.write_str("unsupported Provisioning Manifest version")
            }
            Self::ManifestSizeExceeded => {
                f.write_str("Provisioning Manifest exceeds the supported byte bound")
            }
            Self::ManifestIntegrityMismatch => f.write_str(
                "Provisioning Manifest integrity binding does not match its canonical payload",
            ),
            Self::ManifestBindingMismatch => f.write_str(
                "Provisioning Manifest is not bound to this bootstrap session, machine, and provisioning mode",
            ),
            Self::ManifestRequired => f.write_str(
                "unattended-local provisioning requires a validated Provisioning Manifest",
            ),
            Self::StateSizeExceeded => {
                f.write_str("durable bootstrap state exceeds the supported byte bound")
            }
            Self::UnsupportedStateVersion => {
                f.write_str("unsupported durable bootstrap state version")
            }
            Self::StateIntegrityMismatch => f.write_str(
                "durable bootstrap state integrity binding does not match its canonical payload",
            ),
            Self::CorruptState(reason) => write!(f, "corrupt durable bootstrap state: {reason}"),
            Self::UntrustedStatePath => f.write_str(
                "durable bootstrap state path must resolve through trusted directories to a protected single-link regular file owned by the bootstrap process identity",
            ),
            Self::UntrustedControlPath => f.write_str(
                "durable bootstrap lock/control file must be a protected single-link regular file owned by the bootstrap process identity",
            ),
            Self::StateBindingMismatch => f.write_str(
                "durable bootstrap state is bound to another bootstrap session or machine",
            ),
            Self::UnexpectedStage { expected, actual } => write!(
                f,
                "bootstrap stage must advance monotonically: expected {expected:?}, got {actual:?}"
            ),
            Self::StageAlreadyActive => f.write_str(
                "a bootstrap stage is already active and must be reconciled before another starts",
            ),
            Self::StageContextRequired(stage) => write!(
                f,
                "bootstrap operation is valid only while the canonical {stage:?} stage is active"
            ),
            Self::NoActiveStage => f.write_str("no bootstrap stage is active"),
            Self::OperationBindingMismatch => f.write_str(
                "bootstrap operation id does not match the durable active-stage binding",
            ),
            Self::EffectAlreadyStarted => {
                f.write_str("bootstrap external effect has already crossed the started boundary")
            }
            Self::EffectNotStarted(stage) => write!(
                f,
                "bootstrap stage {stage:?} cannot be verified complete before its external-effect start boundary is durable"
            ),
            Self::VerificationEvidenceRequired(stage) => write!(
                f,
                "bootstrap stage {stage:?} crossed an external-effect boundary and requires fresh exact-bound postcondition evidence before completion"
            ),
            Self::VerificationEvidenceUnexpected(stage) => write!(
                f,
                "bootstrap verification evidence is not valid for non-effectful stage {stage:?}"
            ),
            Self::InvalidVerificationEvidence(reason) => {
                write!(f, "invalid bootstrap verification evidence: {reason}")
            }
            Self::VerificationEvidenceBindingMismatch => f.write_str(
                "bootstrap verification evidence is not bound to the exact machine, stage, and durable operation instance",
            ),
            Self::VerificationEvidenceStale => f.write_str(
                "bootstrap verification evidence is stale or implausibly future-dated and must be freshly re-observed",
            ),
            Self::AlreadyComplete => f.write_str("durable bootstrap state is already complete"),
            Self::ProvisioningModeAlreadySelected => {
                f.write_str("provisioning mode is already durably selected")
            }
            Self::ProvisioningModeRequired => {
                f.write_str("provisioning mode must be selected before owner enrollment")
            }
            Self::OwnerPendingNotAllowed => f.write_str(
                "owner-enrollment-pending is valid only for prepare-for-another-owner or unattended-local provisioning",
            ),
            Self::OwnerStateAlreadyResolved => {
                f.write_str("owner-enrollment state is already pending, enrolled, or recovery-resolved")
            }
            Self::RecoveryOwnerResolutionNotAllowed => f.write_str(
                "recovery owner resolution is valid only for Recovery provisioning mode",
            ),
            Self::PreparerAuthorityStillActive => f.write_str(
                "preparer authority must be retired before final-owner enrollment",
            ),
            Self::FreshOwnerEnrollmentRequired => f.write_str(
                "final-owner authority requires a fresh enrollment transition and cannot be inherited from preparer state",
            ),
            Self::GenerationOverflow => f.write_str("durable bootstrap generation overflow"),
            Self::GenerationAnchorMissing => f.write_str(
                "durable bootstrap generation anchor is missing; historical rollback cannot be excluded",
            ),
            Self::UnsupportedGenerationAnchorVersion => {
                f.write_str("unsupported durable bootstrap generation-anchor version")
            }
            Self::GenerationAnchorIntegrityMismatch => f.write_str(
                "durable bootstrap generation-anchor integrity binding does not match its canonical payload",
            ),
            Self::CorruptGenerationAnchor(reason) => {
                write!(f, "corrupt durable bootstrap generation anchor: {reason}")
            }
            Self::GenerationRollbackDetected {
                state_generation,
                anchor_generation,
            } => write!(
                f,
                "durable bootstrap history moved backwards or became inconsistent: state generation {state_generation}, protected anchor generation {anchor_generation}"
            ),
            Self::StaleCoordinator => f.write_str(
                "bootstrap coordinator observed stale durable state/generation and must be reopened",
            ),
            Self::DurabilityUncertain(reason) => {
                write!(f, "bootstrap durable commit is uncertain: {reason}")
            }
            Self::RecoveryRequired(reason) => write!(
                f,
                "bootstrap coordinator requires reopen/recovery before continuing: {reason}"
            ),
        }
    }
}

impl std::error::Error for DurableBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

fn normalize_identifier(
    label: &'static str,
    value: &str,
) -> Result<String, DurableBootstrapError> {
    if value != value.trim()
        || value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
    {
        return Err(DurableBootstrapError::InvalidIdentifier(label));
    }
    Ok(value.to_owned())
}

fn parse_exact_field<'a>(
    line: Option<&'a str>,
    name: &'static str,
) -> Result<&'a str, DurableBootstrapError> {
    let line = line.ok_or(DurableBootstrapError::InvalidManifest(
        "manifest field is missing",
    ))?;
    line.strip_prefix(&format!("{name}="))
        .ok_or(DurableBootstrapError::InvalidManifest(
            "manifest field order/name is invalid",
        ))
}

fn parse_identifier_field(
    line: Option<&str>,
    name: &'static str,
) -> Result<String, DurableBootstrapError> {
    normalize_identifier(name, parse_exact_field(line, name)?)
}

fn parse_optional_reference(
    line: Option<&str>,
    name: &'static str,
) -> Result<Option<String>, DurableBootstrapError> {
    let value = parse_exact_field(line, name)?;
    if value == "-" {
        Ok(None)
    } else {
        normalize_identifier(name, value).map(Some)
    }
}

fn parse_mode(value: &str) -> Result<ProvisioningMode, DurableBootstrapError> {
    match value {
        "interactive-owner" => Ok(ProvisioningMode::InteractiveOwner),
        "prepare-for-another-owner" => Ok(ProvisioningMode::PrepareForAnotherOwner),
        "unattended-local" => Ok(ProvisioningMode::UnattendedLocal),
        "recovery" => Ok(ProvisioningMode::Recovery),
        _ => Err(DurableBootstrapError::InvalidManifest(
            "unknown provisioning mode",
        )),
    }
}

fn mode_str(mode: ProvisioningMode) -> &'static str {
    match mode {
        ProvisioningMode::InteractiveOwner => "interactive-owner",
        ProvisioningMode::PrepareForAnotherOwner => "prepare-for-another-owner",
        ProvisioningMode::UnattendedLocal => "unattended-local",
        ProvisioningMode::Recovery => "recovery",
    }
}

fn connectivity_str(value: BootstrapConnectivity) -> &'static str {
    match value {
        BootstrapConnectivity::Offline => "offline",
        BootstrapConnectivity::BoundedNetwork => "bounded-network",
    }
}

fn parse_connectivity(value: &str) -> Result<BootstrapConnectivity, DurableBootstrapError> {
    match value {
        "offline" => Ok(BootstrapConnectivity::Offline),
        "bounded-network" => Ok(BootstrapConnectivity::BoundedNetwork),
        _ => Err(DurableBootstrapError::InvalidManifest(
            "unknown bootstrap connectivity mode",
        )),
    }
}

fn stage_str(stage: BootstrapStage) -> &'static str {
    match stage {
        BootstrapStage::BaseEnvironmentVerification => "base-environment-verification",
        BootstrapStage::LinuraInstallation => "linura-installation",
        BootstrapStage::PersistentStateInitialization => "persistent-state-initialization",
        BootstrapStage::SecurityBaseline => "security-baseline",
        BootstrapStage::ProvisioningModeSelection => "provisioning-mode-selection",
        BootstrapStage::BootstrapConnectivityResolution => "bootstrap-connectivity-resolution",
        BootstrapStage::HardwareDiscovery => "hardware-discovery",
        BootstrapStage::SourceSelection => "source-selection",
        BootstrapStage::TargetObservation => "target-observation",
        BootstrapStage::FirstBootPlanning => "firstboot-planning",
        BootstrapStage::RecoveryCheckpoint => "recovery-checkpoint",
        BootstrapStage::OwnerEnrollmentResolution => "owner-enrollment-resolution",
        BootstrapStage::FirstBootReady => "firstboot-ready",
    }
}

fn parse_stage(value: &str) -> Result<BootstrapStage, DurableBootstrapError> {
    BootstrapStage::ORDERED
        .into_iter()
        .find(|stage| stage_str(*stage) == value)
        .ok_or_else(|| DurableBootstrapError::CorruptState("unknown bootstrap stage".into()))
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_sha256(value: &str) -> Result<(), DurableBootstrapError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableBootstrapError::InvalidManifest(
            "integrity must be a 64-character SHA-256 hex digest",
        ));
    }
    Ok(())
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn optional(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn serialize_state(state: &DurableBootstrapState) -> Vec<u8> {
    let completed = if state.completed.is_empty() {
        "-".to_owned()
    } else {
        state
            .completed
            .iter()
            .map(|stage| stage_str(*stage))
            .collect::<Vec<_>>()
            .join(",")
    };
    let effect_verifications = if state.effect_verifications.is_empty() {
        "-".to_owned()
    } else {
        state
            .effect_verifications
            .iter()
            .map(|verification| {
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    stage_str(verification.stage),
                    verification.operation_id,
                    verification.verifier_id,
                    verification.observation_id,
                    verification.postcondition_sha256,
                    verification.observed_unix_ms,
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let (active_stage, active_operation, active_effect) = match &state.active {
        Some(active) => (
            stage_str(active.stage),
            active.operation_id.as_str(),
            active.effect_state.as_str(),
        ),
        None => ("-", "-", "-"),
    };
    let mode = state.provisioning.mode.map(mode_str).unwrap_or("-");
    let manifest_connectivity = state.provisioning.manifest_connectivity.map(connectivity_str).unwrap_or("-");
    let manifest_defer_owner = state.provisioning.manifest_defer_owner_enrollment.map(|value| if value { "true" } else { "false" }).unwrap_or("-");
    let (owner_id, enrollment_id, owner_generation) = match &state.provisioning.owner_authority {
        Some(authority) => (
            authority.owner_id.as_str(),
            authority.enrollment_id.as_str(),
            authority.generation.to_string(),
        ),
        None => ("-", "-", "0".to_owned()),
    };
    let mut payload = format!(
        "{BOOTSTRAP_STATE_SCHEMA}\ngeneration={}\nsession_id={}\nmachine_id={}\ncompleted={}\neffect_verifications={}\nactive_stage={}\nactive_operation={}\nactive_effect={}\nprovisioning_mode={}\nmanifest_identity={}\nmanifest_id={}\nmanifest_connectivity={}\nmanifest_defer_owner_enrollment={}\nmanifest_source_ref={}\nmanifest_setup_ref={}\nmanifest_machine_profile_ref={}\nmanifest_host_identity={}\nowner_enrollment={}\nowner_id={}\nowner_enrollment_id={}\nauthority_generation={}\nowner_authority_generation={}\npreparer_authority_retired={}\n",
        state.generation,
        state.session_id,
        state.machine_id,
        completed,
        effect_verifications,
        active_stage,
        active_operation,
        active_effect,
        mode,
        optional(state.provisioning.manifest_identity.as_deref()),
        optional(state.provisioning.manifest_id.as_deref()),
        manifest_connectivity,
        manifest_defer_owner,
        optional(state.provisioning.manifest_source_ref.as_deref()),
        optional(state.provisioning.manifest_setup_ref.as_deref()),
        optional(state.provisioning.manifest_machine_profile_ref.as_deref()),
        optional(state.provisioning.manifest_host_identity.as_deref()),
        state.provisioning.owner_enrollment.as_str(),
        owner_id,
        enrollment_id,
        state.provisioning.authority_generation,
        owner_generation,
        state.provisioning.preparer_authority_retired,
    );
    let digest = sha256(payload.as_bytes());
    payload.push_str(&format!("integrity={digest}\n"));
    payload.into_bytes()
}

fn state_field<'a>(
    line: Option<&'a str>,
    name: &'static str,
) -> Result<&'a str, DurableBootstrapError> {
    let line = line.ok_or_else(|| {
        DurableBootstrapError::CorruptState(format!("missing {name} field"))
    })?;
    line.strip_prefix(&format!("{name}="))
        .ok_or_else(|| DurableBootstrapError::CorruptState(format!("invalid {name} field")))
}
