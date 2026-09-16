// Durable v0.9 bootstrap/provisioning state.
//
// This module deliberately keeps persistence and manifest data non-authorizing:
// it records exact durable facts and recovery state, never executor, approval,
// policy, shell, model, credential, or replay authority.

use crate::{BootstrapConnectivity, BootstrapStage, ProvisioningMode};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROVISIONING_MANIFEST_SCHEMA: &str = "linura-provisioning-manifest-v1";
pub const BOOTSTRAP_STATE_SCHEMA: &str = "linura-bootstrap-state-v1";
pub const MAX_PROVISIONING_MANIFEST_BYTES: usize = 16 * 1024;
pub const MAX_BOOTSTRAP_STATE_BYTES: u64 = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const O_NOFOLLOW: i32 = 0o400000;

fn stage_requires_effect_boundary(stage: BootstrapStage) -> bool {
    matches!(
        stage,
        BootstrapStage::LinuraInstallation
            | BootstrapStage::PersistentStateInitialization
            | BootstrapStage::SecurityBaseline
            | BootstrapStage::BootstrapConnectivityResolution
            | BootstrapStage::RecoveryCheckpoint
            | BootstrapStage::OwnerEnrollmentResolution
    )
}

fn canonical_stage_index(stage: BootstrapStage) -> Result<usize, DurableBootstrapError> {
    BootstrapStage::ORDERED
        .iter()
        .position(|candidate| *candidate == stage)
        .ok_or_else(|| {
            DurableBootstrapError::CorruptState(format!(
                "canonical bootstrap order does not contain {stage:?}"
            ))
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerEnrollmentState {
    Unresolved,
    Pending,
    Enrolled,
    /// Recovery deliberately does not mint, inherit, or defer an eventual-owner
    /// authority. This terminal state records only that owner enrollment is not
    /// part of the bounded recovery session.
    RecoveryResolved,
}

impl OwnerEnrollmentState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Pending => "owner-enrollment-pending",
            Self::Enrolled => "enrolled",
            Self::RecoveryResolved => "recovery-resolved",
        }
    }

    fn parse(value: &str) -> Result<Self, DurableBootstrapError> {
        match value {
            "unresolved" => Ok(Self::Unresolved),
            "owner-enrollment-pending" => Ok(Self::Pending),
            "enrolled" => Ok(Self::Enrolled),
            "recovery-resolved" => Ok(Self::RecoveryResolved),
            _ => Err(DurableBootstrapError::CorruptState(
                "unknown owner-enrollment state".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapEffectState {
    Prepared,
    EffectStarted,
}

impl BootstrapEffectState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::EffectStarted => "effect-started",
        }
    }

    fn parse(value: &str) -> Result<Self, DurableBootstrapError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "effect-started" => Ok(Self::EffectStarted),
            _ => Err(DurableBootstrapError::CorruptState(
                "unknown bootstrap effect state".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveBootstrapStage {
    stage: BootstrapStage,
    operation_id: String,
    effect_state: BootstrapEffectState,
}

impl ActiveBootstrapStage {
    #[must_use]
    pub const fn stage(&self) -> BootstrapStage {
        self.stage
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub const fn effect_state(&self) -> BootstrapEffectState {
        self.effect_state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedEffectVerification {
    stage: BootstrapStage,
    operation_id: String,
    verifier_id: String,
    observation_id: String,
    postcondition_sha256: String,
    observed_unix_ms: u64,
}

impl CompletedEffectVerification {
    #[must_use]
    pub const fn stage(&self) -> BootstrapStage {
        self.stage
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
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

    fn validate(&self) -> Result<(), DurableBootstrapError> {
        if !stage_requires_effect_boundary(self.stage) {
            return Err(DurableBootstrapError::CorruptState(
                "completed effect verification names a non-effectful stage".into(),
            ));
        }
        normalize_identifier("verified bootstrap operation id", &self.operation_id)?;
        normalize_identifier("bootstrap verifier id", &self.verifier_id)?;
        normalize_identifier("bootstrap observation id", &self.observation_id)?;
        if self.postcondition_sha256.len() != 64
            || !self
                .postcondition_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.observed_unix_ms == 0
        {
            return Err(DurableBootstrapError::CorruptState(
                "completed effect verification contains invalid digest or timestamp".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerAuthorityRecord {
    owner_id: String,
    enrollment_id: String,
    generation: u64,
}

impl OwnerAuthorityRecord {
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningState {
    mode: Option<ProvisioningMode>,
    manifest_identity: Option<String>,
    manifest_id: Option<String>,
    manifest_connectivity: Option<BootstrapConnectivity>,
    manifest_defer_owner_enrollment: Option<bool>,
    manifest_source_ref: Option<String>,
    manifest_setup_ref: Option<String>,
    manifest_machine_profile_ref: Option<String>,
    manifest_host_identity: Option<String>,
    first_boot_plan_sha256: Option<String>,
    first_boot_plan_count: u32,
    owner_enrollment: OwnerEnrollmentState,
    owner_authority: Option<OwnerAuthorityRecord>,
    authority_generation: u64,
    preparer_authority_retired: bool,
}

impl Default for ProvisioningState {
    fn default() -> Self {
        Self {
            mode: None,
            manifest_identity: None,
            manifest_id: None,
            manifest_connectivity: None,
            manifest_defer_owner_enrollment: None,
            manifest_source_ref: None,
            manifest_setup_ref: None,
            manifest_machine_profile_ref: None,
            manifest_host_identity: None,
            first_boot_plan_sha256: None,
            first_boot_plan_count: 0,
            owner_enrollment: OwnerEnrollmentState::Unresolved,
            owner_authority: None,
            authority_generation: 0,
            preparer_authority_retired: false,
        }
    }
}

impl ProvisioningState {
    #[must_use]
    pub const fn mode(&self) -> Option<ProvisioningMode> {
        self.mode
    }

    #[must_use]
    pub fn manifest_identity(&self) -> Option<&str> {
        self.manifest_identity.as_deref()
    }

    #[must_use]
    pub fn manifest_id(&self) -> Option<&str> {
        self.manifest_id.as_deref()
    }

    #[must_use]
    pub const fn manifest_connectivity(&self) -> Option<BootstrapConnectivity> {
        self.manifest_connectivity
    }

    #[must_use]
    pub const fn manifest_defer_owner_enrollment(&self) -> Option<bool> {
        self.manifest_defer_owner_enrollment
    }

    #[must_use]
    pub fn manifest_source_ref(&self) -> Option<&str> {
        self.manifest_source_ref.as_deref()
    }

    #[must_use]
    pub fn manifest_setup_ref(&self) -> Option<&str> {
        self.manifest_setup_ref.as_deref()
    }

    #[must_use]
    pub fn manifest_machine_profile_ref(&self) -> Option<&str> {
        self.manifest_machine_profile_ref.as_deref()
    }

    #[must_use]
    pub fn manifest_host_identity(&self) -> Option<&str> {
        self.manifest_host_identity.as_deref()
    }

    #[must_use]
    pub fn first_boot_plan_sha256(&self) -> Option<&str> {
        self.first_boot_plan_sha256.as_deref()
    }

    #[must_use]
    pub const fn first_boot_plan_count(&self) -> u32 {
        self.first_boot_plan_count
    }

    #[must_use]
    pub const fn owner_enrollment(&self) -> OwnerEnrollmentState {
        self.owner_enrollment
    }

    #[must_use]
    pub fn owner_authority(&self) -> Option<&OwnerAuthorityRecord> {
        self.owner_authority.as_ref()
    }

    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    #[must_use]
    pub const fn preparer_authority_retired(&self) -> bool {
        self.preparer_authority_retired
    }

    fn validate(&self) -> Result<(), DurableBootstrapError> {
        if self.mode == Some(ProvisioningMode::UnattendedLocal) && self.manifest_identity.is_none() {
            return Err(DurableBootstrapError::CorruptState(
                "unattended-local provisioning lacks manifest identity".into(),
            ));
        }
        if self.manifest_identity.is_some() && self.mode.is_none() {
            return Err(DurableBootstrapError::CorruptState(
                "manifest identity exists before provisioning mode selection".into(),
            ));
        }
        let typed_manifest_present = self.manifest_id.is_some()
            && self.manifest_connectivity.is_some()
            && self.manifest_defer_owner_enrollment.is_some();
        if self.manifest_identity.is_some() != typed_manifest_present {
            return Err(DurableBootstrapError::CorruptState(
                "manifest identity and typed selections must be persisted together".into(),
            ));
        }
        if self.manifest_identity.is_none()
            && (self.manifest_source_ref.is_some()
                || self.manifest_setup_ref.is_some()
                || self.manifest_machine_profile_ref.is_some()
                || self.manifest_host_identity.is_some())
        {
            return Err(DurableBootstrapError::CorruptState(
                "manifest references exist without a validated manifest identity".into(),
            ));
        }
        match self.first_boot_plan_sha256.as_deref() {
            Some(digest)
                if digest.len() != 64
                    || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                return Err(DurableBootstrapError::CorruptState(
                    "First Boot plan binding is not a SHA-256 digest".into(),
                ));
            }
            None if self.first_boot_plan_count != 0 => {
                return Err(DurableBootstrapError::CorruptState(
                    "First Boot plan count exists without a durable plan binding".into(),
                ));
            }
            _ => {}
        }
        if (self.manifest_setup_ref.is_some()
            || self.manifest_machine_profile_ref.is_some())
            && self.first_boot_plan_sha256.is_some()
            && self.first_boot_plan_count == 0
        {
            return Err(DurableBootstrapError::CorruptState(
                "Library-backed First Boot planning completed without canonical plans".into(),
            ));
        }

        if let (Some(mode), Some(defer)) =
            (self.mode, self.manifest_defer_owner_enrollment)
        {
            if matches!(
                mode,
                ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal
            ) && !defer
            {
                return Err(DurableBootstrapError::CorruptState(
                    "deferred-owner provisioning lost its manifest handoff selection".into(),
                ));
            }
            if mode == ProvisioningMode::InteractiveOwner && defer {
                return Err(DurableBootstrapError::CorruptState(
                    "interactive-owner state cannot persist deferred owner enrollment".into(),
                ));
            }
            if mode == ProvisioningMode::Recovery {
                return Err(DurableBootstrapError::CorruptState(
                    "Recovery mode cannot carry Provisioning Manifest selections".into(),
                ));
            }
        }

        match self.owner_enrollment {
            OwnerEnrollmentState::Unresolved => {
                if self.owner_authority.is_some() || self.authority_generation != 0 {
                    return Err(DurableBootstrapError::CorruptState(
                        "unresolved owner state retained owner authority".into(),
                    ));
                }
            }
            OwnerEnrollmentState::Pending => {
                if !matches!(
                    self.mode,
                    Some(
                        ProvisioningMode::PrepareForAnotherOwner
                            | ProvisioningMode::UnattendedLocal
                    )
                ) || !self.preparer_authority_retired
                    || self.owner_authority.is_some()
                    || self.authority_generation != 0
                {
                    return Err(DurableBootstrapError::CorruptState(
                        "owner-enrollment-pending violates handoff authority separation".into(),
                    ));
                }
            }
            OwnerEnrollmentState::Enrolled => {
                let authority = self.owner_authority.as_ref().ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "enrolled owner state lacks authority record".into(),
                    )
                })?;
                if !self.preparer_authority_retired
                    || self.authority_generation == 0
                    || authority.generation != self.authority_generation
                {
                    return Err(DurableBootstrapError::CorruptState(
                        "owner authority generation is not fresh and separated".into(),
                    ));
                }
            }
            OwnerEnrollmentState::RecoveryResolved => {
                if self.mode != Some(ProvisioningMode::Recovery)
                    || self.preparer_authority_retired
                    || self.owner_authority.is_some()
                    || self.authority_generation != 0
                {
                    return Err(DurableBootstrapError::CorruptState(
                        "recovery owner resolution must not mint, inherit, retire, or defer owner authority"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableBootstrapState {
    generation: u64,
    session_id: String,
    machine_id: String,
    completed: Vec<BootstrapStage>,
    effect_verifications: Vec<CompletedEffectVerification>,
    active: Option<ActiveBootstrapStage>,
    provisioning: ProvisioningState,
}

impl DurableBootstrapState {
    pub fn new(
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
    ) -> Result<Self, DurableBootstrapError> {
        let state = Self {
            generation: 0,
            session_id: normalize_identifier("bootstrap session id", &session_id.into())?,
            machine_id: normalize_identifier("machine id", &machine_id.into())?,
            completed: Vec::new(),
            effect_verifications: Vec::new(),
            active: None,
            provisioning: ProvisioningState::default(),
        };
        state.validate()?;
        Ok(state)
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
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
    pub fn completed(&self) -> &[BootstrapStage] {
        &self.completed
    }

    #[must_use]
    pub fn effect_verifications(&self) -> &[CompletedEffectVerification] {
        &self.effect_verifications
    }

    #[must_use]
    pub fn active(&self) -> Option<&ActiveBootstrapStage> {
        self.active.as_ref()
    }

    #[must_use]
    pub fn provisioning(&self) -> &ProvisioningState {
        &self.provisioning
    }

    #[must_use]
    pub fn next_stage(&self) -> Option<BootstrapStage> {
        BootstrapStage::ORDERED.get(self.completed.len()).copied()
    }

    fn validate(&self) -> Result<(), DurableBootstrapError> {
        if self.completed.len() > BootstrapStage::ORDERED.len() {
            return Err(DurableBootstrapError::CorruptState(
                "bootstrap completed prefix is longer than canonical stage order".into(),
            ));
        }
        for (index, stage) in self.completed.iter().copied().enumerate() {
            if BootstrapStage::ORDERED[index] != stage {
                return Err(DurableBootstrapError::CorruptState(
                    "bootstrap completed stages are not a canonical ordered prefix".into(),
                ));
            }
        }
        let mut verifications = self.effect_verifications.iter();
        for stage in self
            .completed
            .iter()
            .copied()
            .filter(|stage| stage_requires_effect_boundary(*stage))
        {
            let verification = verifications.next().ok_or_else(|| {
                DurableBootstrapError::CorruptState(
                    "completed effectful stage lacks durable verification lineage".into(),
                )
            })?;
            if verification.stage != stage {
                return Err(DurableBootstrapError::CorruptState(
                    "durable verification lineage does not match completed effect order".into(),
                ));
            }
            verification.validate()?;
        }
        if verifications.next().is_some() {
            return Err(DurableBootstrapError::CorruptState(
                "durable verification lineage contains an uncompleted effect".into(),
            ));
        }
        if let Some(active) = &self.active {
            if self.next_stage() != Some(active.stage) {
                return Err(DurableBootstrapError::CorruptState(
                    "active bootstrap stage does not equal first incomplete stage".into(),
                ));
            }
            normalize_identifier("bootstrap operation id", &active.operation_id)?;
        }

        let provisioning_index =
            canonical_stage_index(BootstrapStage::ProvisioningModeSelection)?;
        let provisioning_stage_active = self
            .active
            .as_ref()
            .is_some_and(|active| active.stage == BootstrapStage::ProvisioningModeSelection);
        let provisioning_stage_complete = self.completed.len() > provisioning_index;
        if self.provisioning.mode.is_some()
            && !provisioning_stage_active
            && !provisioning_stage_complete
        {
            return Err(DurableBootstrapError::CorruptState(
                "provisioning state exists before provisioning-mode-selection stage".into(),
            ));
        }
        if provisioning_stage_complete && self.provisioning.mode.is_none() {
            return Err(DurableBootstrapError::CorruptState(
                "provisioning-mode-selection completed without a provisioning mode".into(),
            ));
        }

        let planning_index = canonical_stage_index(BootstrapStage::FirstBootPlanning)?;
        let planning_stage_active = self
            .active
            .as_ref()
            .is_some_and(|active| active.stage == BootstrapStage::FirstBootPlanning);
        let planning_stage_complete = self.completed.len() > planning_index;
        let planning_bound = self.provisioning.first_boot_plan_sha256.is_some();
        if planning_bound && !planning_stage_active && !planning_stage_complete {
            return Err(DurableBootstrapError::CorruptState(
                "First Boot plan binding exists before the planning stage".into(),
            ));
        }
        if planning_stage_complete && !planning_bound {
            return Err(DurableBootstrapError::CorruptState(
                "First Boot planning completed without a durable canonical plan binding".into(),
            ));
        }

        let owner_index = canonical_stage_index(BootstrapStage::OwnerEnrollmentResolution)?;
        let owner_stage_active = self
            .active
            .as_ref()
            .is_some_and(|active| active.stage == BootstrapStage::OwnerEnrollmentResolution);
        let owner_stage_complete = self.completed.len() > owner_index;
        let owner_resolved = self.provisioning.owner_enrollment != OwnerEnrollmentState::Unresolved;
        if owner_resolved && !owner_stage_active && !owner_stage_complete {
            return Err(DurableBootstrapError::CorruptState(
                "owner-enrollment state exists before owner-enrollment-resolution stage".into(),
            ));
        }
        if owner_stage_complete && !owner_resolved {
            return Err(DurableBootstrapError::CorruptState(
                "owner-enrollment-resolution completed without a resolved owner state".into(),
            ));
        }

        normalize_identifier("bootstrap session id", &self.session_id)?;
        normalize_identifier("machine id", &self.machine_id)?;
        self.provisioning.validate()?;
        Ok(())
    }

    fn active_stage_for(
        &self,
        required: BootstrapStage,
    ) -> Result<&ActiveBootstrapStage, DurableBootstrapError> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableBootstrapError::StageContextRequired(required))?;
        if active.stage != required {
            return Err(DurableBootstrapError::StageContextRequired(required));
        }
        Ok(active)
    }

    fn prepare_stage(
        &mut self,
        stage: BootstrapStage,
        operation_id: String,
    ) -> Result<(), DurableBootstrapError> {
        if self.active.is_some() {
            return Err(DurableBootstrapError::StageAlreadyActive);
        }
        let expected = self.next_stage().ok_or(DurableBootstrapError::AlreadyComplete)?;
        if expected != stage {
            return Err(DurableBootstrapError::UnexpectedStage {
                expected,
                actual: stage,
            });
        }
        self.active = Some(ActiveBootstrapStage {
            stage,
            operation_id: normalize_identifier("bootstrap operation id", &operation_id)?,
            effect_state: BootstrapEffectState::Prepared,
        });
        self.validate()
    }

    fn mark_effect_started(&mut self, operation_id: &str) -> Result<(), DurableBootstrapError> {
        let active = self
            .active
            .as_mut()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.operation_id != operation_id {
            return Err(DurableBootstrapError::OperationBindingMismatch);
        }
        if active.effect_state != BootstrapEffectState::Prepared {
            return Err(DurableBootstrapError::EffectAlreadyStarted);
        }
        active.effect_state = BootstrapEffectState::EffectStarted;
        self.validate()
    }

    fn complete_verified(&mut self, operation_id: &str) -> Result<(), DurableBootstrapError> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.operation_id != operation_id {
            return Err(DurableBootstrapError::OperationBindingMismatch);
        }
        if stage_requires_effect_boundary(active.stage)
            && active.effect_state != BootstrapEffectState::EffectStarted
        {
            return Err(DurableBootstrapError::EffectNotStarted(active.stage));
        }
        self.completed.push(active.stage);
        self.active = None;
        self.validate()
    }

    fn select_provisioning(
        &mut self,
        mode: ProvisioningMode,
        manifest: Option<&ProvisioningManifest>,
    ) -> Result<(), DurableBootstrapError> {
        self.active_stage_for(BootstrapStage::ProvisioningModeSelection)?;
        if self.provisioning.mode.is_some() {
            return Err(DurableBootstrapError::ProvisioningModeAlreadySelected);
        }
        if mode == ProvisioningMode::UnattendedLocal && manifest.is_none() {
            return Err(DurableBootstrapError::ManifestRequired);
        }
        if let Some(manifest) = manifest {
            manifest.validate_binding(&self.session_id, &self.machine_id, mode)?;
            self.provisioning.manifest_identity = Some(manifest.identity.clone());
            self.provisioning.manifest_id = Some(manifest.manifest_id.clone());
            self.provisioning.manifest_connectivity = Some(manifest.connectivity);
            self.provisioning.manifest_defer_owner_enrollment = Some(manifest.defer_owner_enrollment);
            self.provisioning.manifest_source_ref = manifest.source_ref.clone();
            self.provisioning.manifest_setup_ref = manifest.setup_ref.clone();
            self.provisioning.manifest_machine_profile_ref = manifest.machine_profile_ref.clone();
            self.provisioning.manifest_host_identity = manifest.host_identity.clone();
        }
        self.provisioning.mode = Some(mode);
        self.provisioning.validate()?;
        self.validate()
    }

    fn bind_first_boot_plan(
        &mut self,
        plan_sha256: String,
        plan_count: u32,
    ) -> Result<(), DurableBootstrapError> {
        let active = self.active_stage_for(BootstrapStage::FirstBootPlanning)?;
        if active.effect_state != BootstrapEffectState::Prepared {
            return Err(DurableBootstrapError::CorruptState(
                "First Boot plan binding requires the prepared planning stage".into(),
            ));
        }
        if plan_sha256.len() != 64
            || !plan_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DurableBootstrapError::CorruptState(
                "First Boot plan binding is not a SHA-256 digest".into(),
            ));
        }
        if (self.provisioning.manifest_setup_ref.is_some()
            || self.provisioning.manifest_machine_profile_ref.is_some())
            && plan_count == 0
        {
            return Err(DurableBootstrapError::CorruptState(
                "Library-backed First Boot planning produced no canonical plans".into(),
            ));
        }
        if let Some(existing) = self.provisioning.first_boot_plan_sha256.as_deref() {
            if existing == plan_sha256 && self.provisioning.first_boot_plan_count == plan_count {
                return Ok(());
            }
            return Err(DurableBootstrapError::CorruptState(
                "prepared First Boot planning attempted to substitute its durable plan binding".into(),
            ));
        }
        self.provisioning.first_boot_plan_sha256 = Some(plan_sha256);
        self.provisioning.first_boot_plan_count = plan_count;
        self.validate()
    }

    fn enter_owner_enrollment_pending(
        &mut self,
        revocation: &TrustedPreparerAuthorityRevocationReceipt,
    ) -> Result<(), DurableBootstrapError> {
        revocation.validate_binding(self)?;
        let active = self.active_stage_for(BootstrapStage::OwnerEnrollmentResolution)?;
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }
        if !matches!(
            self.provisioning.mode,
            Some(
                ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal
            )
        ) {
            return Err(DurableBootstrapError::OwnerPendingNotAllowed);
        }
        if self.provisioning.owner_enrollment != OwnerEnrollmentState::Unresolved {
            return Err(DurableBootstrapError::OwnerStateAlreadyResolved);
        }
        self.provisioning.preparer_authority_retired = true;
        self.provisioning.owner_authority = None;
        self.provisioning.authority_generation = 0;
        self.provisioning.owner_enrollment = OwnerEnrollmentState::Pending;
        self.provisioning.validate()?;
        self.validate()
    }

    fn enroll_owner_fresh(
        &mut self,
        owner_id: String,
        enrollment_id: String,
    ) -> Result<(), DurableBootstrapError> {
        if self.provisioning.mode != Some(ProvisioningMode::InteractiveOwner)
            || self.provisioning.owner_enrollment != OwnerEnrollmentState::Unresolved
        {
            return Err(DurableBootstrapError::FreshOwnerEnrollmentRequired);
        }
        let active = self.active_stage_for(BootstrapStage::OwnerEnrollmentResolution)?;
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }

        let generation = self
            .provisioning
            .authority_generation
            .checked_add(1)
            .ok_or(DurableBootstrapError::GenerationOverflow)?;
        self.provisioning.preparer_authority_retired = true;
        self.provisioning.authority_generation = generation;
        self.provisioning.owner_authority = Some(OwnerAuthorityRecord {
            owner_id: normalize_identifier("owner id", &owner_id)?,
            enrollment_id: normalize_identifier("owner enrollment id", &enrollment_id)?,
            generation,
        });
        self.provisioning.owner_enrollment = OwnerEnrollmentState::Enrolled;
        self.provisioning.validate()?;
        self.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapResumeDecision<'a> {
    ContinueAt(BootstrapStage),
    ExecutePrepared {
        stage: BootstrapStage,
        operation_id: &'a str,
    },
    ReobserveBeforeContinuing {
        stage: BootstrapStage,
        operation_id: &'a str,
    },
    Complete,
    RecoveryRequired,
}
