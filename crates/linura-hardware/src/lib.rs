#![forbid(unsafe_code)]

pub const V09_QUALIFICATION_ENVIRONMENT_ID: &str =
    "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless";
pub const V09_BASE_IMAGE_URL: &str = "https://cloud-images.ubuntu.com/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img";
pub const V09_BASE_IMAGE_SHA256: &str =
    "d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac";
pub const LINURA_REPOSITORY: &str = "linura-org/linura";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceTier {
    Unknown,
    FixtureOnly,
    VirtualMachine,
    CommunityHardware,
    MaintainerHardware,
    ReleaseQualified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineClass {
    Workstation,
    Server,
    Edge,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionMode {
    Headless,
    Interactive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualizationKind {
    BareMetal,
    QemuTcg,
    QemuKvm,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationEnvironment {
    pub id: &'static str,
    pub milestone: &'static str,
    pub machine_class_context: MachineClass,
    pub distribution_id: &'static str,
    pub distribution_version: &'static str,
    pub architecture: &'static str,
    pub interaction: InteractionMode,
    pub virtualization: VirtualizationKind,
    pub init_system: &'static str,
    pub base_image_url: &'static str,
    pub base_image_sha256: &'static str,
    pub minimum_evidence: EvidenceTier,
}

impl QualificationEnvironment {
    #[must_use]
    pub const fn v09_candidate() -> Self {
        Self {
            id: V09_QUALIFICATION_ENVIRONMENT_ID,
            milestone: "v0.9.0",
            machine_class_context: MachineClass::Server,
            distribution_id: "ubuntu",
            distribution_version: "24.04",
            architecture: "x86_64",
            interaction: InteractionMode::Headless,
            virtualization: VirtualizationKind::QemuTcg,
            init_system: "systemd",
            base_image_url: V09_BASE_IMAGE_URL,
            base_image_sha256: V09_BASE_IMAGE_SHA256,
            minimum_evidence: EvidenceTier::VirtualMachine,
        }
    }

    pub fn validate_contract(&self) -> Result<(), HardwareContractError> {
        if self != &Self::v09_candidate() {
            return Err(HardwareContractError::InvalidQualificationEnvironment);
        }
        validate_sha256(
            self.base_image_sha256,
            HardwareContractError::InvalidBaseImageDigest,
        )?;
        if !self
            .base_image_url
            .starts_with("https://cloud-images.ubuntu.com/")
        {
            return Err(HardwareContractError::UntrustedBaseImageOrigin);
        }
        Ok(())
    }

    #[must_use]
    pub fn assess(&self, observed: &ObservedEnvironment) -> Vec<EnvironmentMismatch> {
        let mut mismatches = Vec::new();
        compare(
            &mut mismatches,
            "machine_class_context",
            format!("{:?}", self.machine_class_context),
            format!("{:?}", observed.machine_class),
        );
        compare(
            &mut mismatches,
            "distribution_id",
            self.distribution_id.to_owned(),
            observed.distribution_id.clone(),
        );
        compare(
            &mut mismatches,
            "distribution_version",
            self.distribution_version.to_owned(),
            observed.distribution_version.clone(),
        );
        compare(
            &mut mismatches,
            "architecture",
            self.architecture.to_owned(),
            observed.architecture.clone(),
        );
        compare(
            &mut mismatches,
            "interaction",
            format!("{:?}", self.interaction),
            format!("{:?}", observed.interaction),
        );
        compare(
            &mut mismatches,
            "virtualization",
            format!("{:?}", self.virtualization),
            format!("{:?}", observed.virtualization),
        );
        compare(
            &mut mismatches,
            "init_system",
            self.init_system.to_owned(),
            observed.init_system.clone(),
        );
        mismatches
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEnvironment {
    pub machine_class: MachineClass,
    pub distribution_id: String,
    pub distribution_version: String,
    pub architecture: String,
    pub interaction: InteractionMode,
    pub virtualization: VirtualizationKind,
    pub init_system: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentMismatch {
    pub field: &'static str,
    pub expected: String,
    pub observed: String,
}

fn compare(
    mismatches: &mut Vec<EnvironmentMismatch>,
    field: &'static str,
    expected: String,
    observed: String,
) {
    if expected != observed {
        mismatches.push(EnvironmentMismatch {
            field,
            expected,
            observed,
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationEvidenceReference {
    repository: &'static str,
    qualification_environment_id: &'static str,
    source_sha: String,
    base_image_sha256: &'static str,
    virtualization: VirtualizationKind,
    scenario_sha256: String,
    workflow_run_id: u64,
    workflow_run_attempt: u32,
    artifact_name: String,
    artifact_sha256: String,
}

impl QualificationEvidenceReference {
    pub fn v09_vm(
        source_sha: impl Into<String>,
        scenario_sha256: impl Into<String>,
        workflow_run_id: u64,
        workflow_run_attempt: u32,
        artifact_name: impl Into<String>,
        artifact_sha256: impl Into<String>,
    ) -> Result<Self, HardwareContractError> {
        let source_sha = source_sha.into();
        validate_git_oid(&source_sha)?;
        let scenario_sha256 = scenario_sha256.into();
        validate_sha256(
            &scenario_sha256,
            HardwareContractError::InvalidScenarioDigest,
        )?;
        if workflow_run_id == 0 || workflow_run_attempt == 0 {
            return Err(HardwareContractError::InvalidWorkflowIdentity);
        }
        let artifact_name = validate_text("artifact name", artifact_name.into())?;
        let artifact_sha256 = artifact_sha256.into();
        validate_sha256(
            &artifact_sha256,
            HardwareContractError::InvalidArtifactDigest,
        )?;
        Ok(Self {
            repository: LINURA_REPOSITORY,
            qualification_environment_id: V09_QUALIFICATION_ENVIRONMENT_ID,
            source_sha,
            base_image_sha256: V09_BASE_IMAGE_SHA256,
            virtualization: VirtualizationKind::QemuTcg,
            scenario_sha256,
            workflow_run_id,
            workflow_run_attempt,
            artifact_name,
            artifact_sha256,
        })
    }

    pub fn validate_for_environment(
        &self,
        environment: QualificationEnvironment,
    ) -> Result<(), HardwareContractError> {
        environment.validate_contract()?;
        if self.repository != LINURA_REPOSITORY
            || self.qualification_environment_id != environment.id
            || self.base_image_sha256 != environment.base_image_sha256
            || self.virtualization != environment.virtualization
            || self.workflow_run_id == 0
            || self.workflow_run_attempt == 0
        {
            return Err(HardwareContractError::EvidenceEnvironmentMismatch);
        }
        validate_git_oid(&self.source_sha)?;
        validate_sha256(
            &self.scenario_sha256,
            HardwareContractError::InvalidScenarioDigest,
        )?;
        validate_sha256(
            &self.artifact_sha256,
            HardwareContractError::InvalidArtifactDigest,
        )?;
        validate_text("artifact name", self.artifact_name.clone())?;
        Ok(())
    }

    #[must_use]
    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }
    #[must_use]
    pub fn scenario_sha256(&self) -> &str {
        &self.scenario_sha256
    }
    #[must_use]
    pub const fn workflow_run_id(&self) -> u64 {
        self.workflow_run_id
    }
    #[must_use]
    pub const fn workflow_run_attempt(&self) -> u32 {
        self.workflow_run_attempt
    }
    #[must_use]
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }
    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }
    fn identity_tuple(&self) -> (&str, &str, u64, u32, &str, &str) {
        (
            &self.source_sha,
            &self.scenario_sha256,
            self.workflow_run_id,
            self.workflow_run_attempt,
            &self.artifact_name,
            &self.artifact_sha256,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareEvidence {
    component: String,
    vendor: String,
    model: String,
    scope: &'static str,
    tier: EvidenceTier,
    evidence_reference: QualificationEvidenceReference,
}

impl HardwareEvidence {
    pub fn v09_vm_candidate(
        component: impl Into<String>,
        vendor: impl Into<String>,
        model: impl Into<String>,
        evidence_reference: QualificationEvidenceReference,
    ) -> Result<Self, HardwareContractError> {
        evidence_reference.validate_for_environment(QualificationEnvironment::v09_candidate())?;
        Ok(Self {
            component: validate_text("component", component.into())?,
            vendor: validate_text("vendor", vendor.into())?,
            model: validate_text("model", model.into())?,
            scope: V09_QUALIFICATION_ENVIRONMENT_ID,
            tier: EvidenceTier::VirtualMachine,
            evidence_reference,
        })
    }
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
    #[must_use]
    pub const fn scope(&self) -> &'static str {
        self.scope
    }
    #[must_use]
    pub const fn tier(&self) -> EvidenceTier {
        self.tier
    }
    #[must_use]
    pub const fn evidence_reference(&self) -> &QualificationEvidenceReference {
        &self.evidence_reference
    }
    #[must_use]
    pub const fn release_qualified(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HardwareSnapshot {
    pub components: Vec<HardwareEvidence>,
}

impl HardwareSnapshot {
    #[must_use]
    pub fn weakest_tier(&self) -> EvidenceTier {
        self.components
            .iter()
            .map(HardwareEvidence::tier)
            .min()
            .unwrap_or(EvidenceTier::Unknown)
    }

    /// Validates exact candidate evidence bindings only. Protected release closure
    /// owns the separate support-promotion transition.
    pub fn validate_candidate_for_environment(
        &self,
        environment: QualificationEnvironment,
    ) -> Result<(), HardwareContractError> {
        environment.validate_contract()?;
        let Some(first) = self.components.first() else {
            return Err(HardwareContractError::MissingHardwareEvidence);
        };
        let expected_identity = first.evidence_reference.identity_tuple();
        for item in &self.components {
            if item.scope != environment.id || item.tier < environment.minimum_evidence {
                return Err(HardwareContractError::InsufficientEvidence);
            }
            item.evidence_reference
                .validate_for_environment(environment)?;
            if item.evidence_reference.identity_tuple() != expected_identity {
                return Err(HardwareContractError::MixedEvidenceIdentity);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareContractError {
    InvalidQualificationEnvironment,
    InvalidBaseImageDigest,
    UntrustedBaseImageOrigin,
    InvalidSourceSha,
    InvalidScenarioDigest,
    InvalidArtifactDigest,
    InvalidWorkflowIdentity,
    InvalidEvidenceField(&'static str),
    EvidenceEnvironmentMismatch,
    MissingHardwareEvidence,
    InsufficientEvidence,
    MixedEvidenceIdentity,
}

fn validate_git_oid(value: &str) -> Result<(), HardwareContractError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HardwareContractError::InvalidSourceSha);
    }
    Ok(())
}
fn validate_sha256(value: &str, error: HardwareContractError) -> Result<(), HardwareContractError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error);
    }
    Ok(())
}
fn validate_text(label: &'static str, value: String) -> Result<String, HardwareContractError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(HardwareContractError::InvalidEvidenceField(label));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SCENARIO_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ARTIFACT_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn evidence_reference() -> QualificationEvidenceReference {
        QualificationEvidenceReference::v09_vm(
            SOURCE_SHA,
            SCENARIO_SHA,
            42,
            1,
            "linura-vm-acceptance-firstboot-offline",
            ARTIFACT_SHA,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn evidence() -> HardwareEvidence {
        HardwareEvidence::v09_vm_candidate(
            "virtual-machine",
            "qemu",
            "tcg-x86_64",
            evidence_reference(),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    #[test]
    fn empty_snapshot_is_unknown() {
        assert_eq!(
            HardwareSnapshot::default().weakest_tier(),
            EvidenceTier::Unknown
        );
    }
    #[test]
    fn v09_qualification_environment_is_exact_and_valid() {
        let environment = QualificationEnvironment::v09_candidate();
        assert_eq!(environment.validate_contract(), Ok(()));
        assert_eq!(environment.machine_class_context, MachineClass::Server);
        assert_eq!(environment.minimum_evidence, EvidenceTier::VirtualMachine);
        assert!(environment.id.starts_with("qualification/"));
    }
    #[test]
    fn qualification_assessment_reports_platform_drift() {
        let environment = QualificationEnvironment::v09_candidate();
        let observed = ObservedEnvironment {
            machine_class: MachineClass::Server,
            distribution_id: "ubuntu".to_owned(),
            distribution_version: "24.04".to_owned(),
            architecture: "aarch64".to_owned(),
            interaction: InteractionMode::Headless,
            virtualization: VirtualizationKind::QemuTcg,
            init_system: "systemd".to_owned(),
        };
        let mismatches = environment.assess(&observed);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].field, "architecture");
    }
    #[test]
    fn candidate_evidence_requires_exact_immutable_bindings() {
        let environment = QualificationEnvironment::v09_candidate();
        let snapshot = HardwareSnapshot {
            components: vec![evidence()],
        };
        assert_eq!(
            snapshot.validate_candidate_for_environment(environment),
            Ok(())
        );
        assert!(!snapshot.components[0].release_qualified());
        assert_eq!(
            QualificationEvidenceReference::v09_vm(
                "short",
                SCENARIO_SHA,
                42,
                1,
                "artifact",
                ARTIFACT_SHA
            ),
            Err(HardwareContractError::InvalidSourceSha)
        );
        assert_eq!(
            QualificationEvidenceReference::v09_vm(
                SOURCE_SHA,
                SCENARIO_SHA,
                0,
                1,
                "artifact",
                ARTIFACT_SHA
            ),
            Err(HardwareContractError::InvalidWorkflowIdentity)
        );
        assert_eq!(
            QualificationEvidenceReference::v09_vm(
                SOURCE_SHA,
                SCENARIO_SHA,
                42,
                1,
                "artifact",
                "bad"
            ),
            Err(HardwareContractError::InvalidArtifactDigest)
        );
    }
    #[test]
    fn candidate_snapshot_rejects_mixed_run_or_artifact_identity() {
        let first = evidence();
        let second_reference = QualificationEvidenceReference::v09_vm(
            SOURCE_SHA,
            SCENARIO_SHA,
            43,
            1,
            "linura-vm-acceptance-firstboot-offline",
            ARTIFACT_SHA,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let second =
            HardwareEvidence::v09_vm_candidate("systemd", "ubuntu", "24.04", second_reference)
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        let snapshot = HardwareSnapshot {
            components: vec![first, second],
        };
        assert_eq!(
            snapshot.validate_candidate_for_environment(QualificationEnvironment::v09_candidate()),
            Err(HardwareContractError::MixedEvidenceIdentity)
        );
    }
}
