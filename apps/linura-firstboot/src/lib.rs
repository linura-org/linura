#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_bootstrap::{ProvisioningMode, RecoveryCheckpointEvidence};
use linura_core::{Actor, ActorKind, RequestId};
use linura_hardware::{
    EnvironmentMismatch, ObservedEnvironment, QualificationEnvironment,
    V09_QUALIFICATION_ENVIRONMENT_ID,
};
use linura_library::{ProfileIdentity, SetupRevisionRef};
use linura_linux_observation::{NetworkManagerObserver, SystemdObserver};
use linura_observation::{ObservationAuthority, ObservationEnvelope};
use linura_observation_control::ObservationCoordinator;
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
    ReconciliationPlan,
};
use linura_protocol::ObservationRequest;
use sha2::{Digest, Sha256};

pub const FIRST_BOOT_CONTRACT_VERSION: u16 = 1;
pub const CANDIDATE_BASE_IMAGE_URL: &str = "https://cloud-images.ubuntu.com/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img";
pub const CANDIDATE_BASE_IMAGE_SHA256: &str =
    "d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    FreshIntent,
    DefaultProfile,
    LibrarySetup,
    LibraryProfile,
    PortableSetup,
    PortableProfile,
    Recovery,
}

impl SourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FreshIntent => "fresh-intent",
            Self::DefaultProfile => "default-profile",
            Self::LibrarySetup => "library-setup",
            Self::LibraryProfile => "library-profile",
            Self::PortableSetup => "portable-setup",
            Self::PortableProfile => "portable-profile",
            Self::Recovery => "recovery",
        }
    }
}

/// Declarative source selected for First Boot.
///
/// Fields are private so callers cannot bypass exact Library-revision or
/// portable-content validation by constructing the value directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSelection {
    kind: SourceKind,
    reference: String,
    library_revision: Option<u32>,
    source_sha256: Option<String>,
}

impl SourceSelection {
    pub fn fresh_intent(goal: impl Into<String>) -> Result<Self, FirstBootError> {
        Self::new(SourceKind::FreshIntent, goal, None, None)
    }

    pub fn default_profile(profile: impl Into<String>) -> Result<Self, FirstBootError> {
        Self::new(SourceKind::DefaultProfile, profile, None, None)
    }

    pub fn library_setup(revision: SetupRevisionRef) -> Result<Self, FirstBootError> {
        if revision.revision == 0 {
            return Err(FirstBootError::InvalidLibraryRevision);
        }
        Self::new(
            SourceKind::LibrarySetup,
            revision.id.as_str(),
            Some(revision.revision),
            None,
        )
    }

    pub fn library_profile(identity: ProfileIdentity) -> Result<Self, FirstBootError> {
        if identity.revision == 0 {
            return Err(FirstBootError::InvalidLibraryRevision);
        }
        Self::new(
            SourceKind::LibraryProfile,
            identity.id.as_str(),
            Some(identity.revision),
            None,
        )
    }

    pub fn portable_setup(
        label: impl Into<String>,
        source_sha256: impl Into<String>,
    ) -> Result<Self, FirstBootError> {
        Self::new(
            SourceKind::PortableSetup,
            label,
            None,
            Some(source_sha256.into()),
        )
    }

    pub fn portable_profile(
        label: impl Into<String>,
        source_sha256: impl Into<String>,
    ) -> Result<Self, FirstBootError> {
        Self::new(
            SourceKind::PortableProfile,
            label,
            None,
            Some(source_sha256.into()),
        )
    }

    pub fn recovery(checkpoint: impl Into<String>) -> Result<Self, FirstBootError> {
        Self::new(SourceKind::Recovery, checkpoint, None, None)
    }

    fn new(
        kind: SourceKind,
        reference: impl Into<String>,
        library_revision: Option<u32>,
        source_sha256: Option<String>,
    ) -> Result<Self, FirstBootError> {
        let reference = normalize_required("source reference", reference.into())?;
        match kind {
            SourceKind::PortableSetup | SourceKind::PortableProfile => {
                if library_revision.is_some() {
                    return Err(FirstBootError::UnexpectedLibraryRevision);
                }
                let digest = source_sha256
                    .as_deref()
                    .ok_or(FirstBootError::MissingDigest)?;
                validate_sha256("portable source digest", digest)?;
            }
            SourceKind::LibrarySetup | SourceKind::LibraryProfile => {
                if source_sha256.is_some() {
                    return Err(FirstBootError::UnexpectedDigest);
                }
                if library_revision.is_none() {
                    return Err(FirstBootError::InvalidLibraryRevision);
                }
            }
            _ => {
                if source_sha256.is_some() {
                    return Err(FirstBootError::UnexpectedDigest);
                }
                if library_revision.is_some() {
                    return Err(FirstBootError::UnexpectedLibraryRevision);
                }
            }
        }
        Ok(Self {
            kind,
            reference,
            library_revision,
            source_sha256,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SourceKind {
        self.kind
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub const fn library_revision(&self) -> Option<u32> {
        self.library_revision
    }

    #[must_use]
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    /// Domain-separated identity of the exact declarative source revision.
    /// This is lineage/provenance, never approval or execution authority.
    #[must_use]
    pub fn binding_sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "linura-firstboot-source-v1");
        hash_field(&mut hasher, self.kind.as_str());
        hash_field(&mut hasher, &self.reference);
        hash_field(
            &mut hasher,
            &self
                .library_revision
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        hash_field(&mut hasher, self.source_sha256.as_deref().unwrap_or(""));
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstBootStage {
    AwaitingSource,
    AwaitingDiscovery,
    AwaitingFreshObservation,
    AwaitingPlan,
    AwaitingRecoveryCheckpoint,
    ReadyForControlSubmission,
}

/// Exact lineage connecting selected declarative source material to the
/// canonical non-executable plan submitted to Control.
///
/// Fields are private so callers cannot substitute a different source binding
/// or canonical request identity after planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstBootPlanLineage {
    upstream_request_id: RequestId,
    canonical_request_id: RequestId,
    source_binding_sha256: String,
    observation_evidence_id: String,
}

impl FirstBootPlanLineage {
    #[must_use]
    pub const fn upstream_request_id(&self) -> &RequestId {
        &self.upstream_request_id
    }

    #[must_use]
    pub const fn canonical_request_id(&self) -> &RequestId {
        &self.canonical_request_id
    }

    #[must_use]
    pub fn source_binding_sha256(&self) -> &str {
        &self.source_binding_sha256
    }

    #[must_use]
    pub fn observation_evidence_id(&self) -> &str {
        &self.observation_evidence_id
    }
}

/// Opaque pre-authority submission from First Boot to Linura Control.
///
/// There is deliberately no review result, approval, executor permit or
/// writable authorization field. Construction is private to `FirstBootSession`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlSubmission {
    contract_version: u16,
    qualification_environment_id: &'static str,
    session_id: String,
    provisioning_mode: ProvisioningMode,
    source: SourceSelection,
    observed_environment: ObservedEnvironment,
    observation: ObservationEnvelope,
    plan: ReconciliationPlan,
    plan_lineage: FirstBootPlanLineage,
    recovery: RecoveryCheckpointEvidence,
}

impl ControlSubmission {
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }

    #[must_use]
    pub const fn qualification_environment_id(&self) -> &'static str {
        self.qualification_environment_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn provisioning_mode(&self) -> ProvisioningMode {
        self.provisioning_mode
    }

    #[must_use]
    pub const fn source(&self) -> &SourceSelection {
        &self.source
    }

    #[must_use]
    pub const fn observed_environment(&self) -> &ObservedEnvironment {
        &self.observed_environment
    }

    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }

    #[must_use]
    pub const fn plan(&self) -> &ReconciliationPlan {
        &self.plan
    }

    #[must_use]
    pub const fn plan_lineage(&self) -> &FirstBootPlanLineage {
        &self.plan_lineage
    }

    #[must_use]
    pub const fn recovery(&self) -> &RecoveryCheckpointEvidence {
        &self.recovery
    }

    #[must_use]
    pub const fn execution_authorized(&self) -> bool {
        false
    }
}

/// Trusted v0.9 observation source for First Boot.
///
/// The coordinator and observer registry are private: external callers can
/// choose a typed observation request, but cannot inject a caller-authored
/// `ObservationEnvelope` or register a synthetic observer as authoritative.
#[derive(Debug)]
pub struct FirstBootObservationSource {
    coordinator: ObservationCoordinator,
}

impl FirstBootObservationSource {
    pub fn connect_reference_environment() -> Result<Self, FirstBootError> {
        let mut coordinator = ObservationCoordinator::new();
        let systemd = SystemdObserver::connect()
            .map_err(|error| FirstBootError::ObservationSource(error.to_string()))?;
        coordinator
            .register_observer(Box::new(systemd))
            .map_err(|error| FirstBootError::ObservationSource(error.to_string()))?;
        let network_manager = NetworkManagerObserver::connect()
            .map_err(|error| FirstBootError::ObservationSource(error.to_string()))?;
        coordinator
            .register_observer(Box::new(network_manager))
            .map_err(|error| FirstBootError::ObservationSource(error.to_string()))?;
        Ok(Self { coordinator })
    }

    fn observe(
        &mut self,
        request: &ObservationRequest,
    ) -> Result<ObservationEnvelope, FirstBootError> {
        self.coordinator
            .observe(request)
            .map(|response| response.observation)
            .map_err(|error| FirstBootError::ObservationSource(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstBootSession {
    session_id: String,
    provisioning_mode: ProvisioningMode,
    stage: FirstBootStage,
    source: Option<SourceSelection>,
    observed_environment: Option<ObservedEnvironment>,
    observation: Option<ObservationEnvelope>,
    plan: Option<ReconciliationPlan>,
    plan_lineage: Option<FirstBootPlanLineage>,
    recovery: Option<RecoveryCheckpointEvidence>,
}

impl FirstBootSession {
    pub fn new(
        session_id: impl Into<String>,
        provisioning_mode: ProvisioningMode,
    ) -> Result<Self, FirstBootError> {
        Ok(Self {
            session_id: normalize_required("First Boot session id", session_id.into())?,
            provisioning_mode,
            stage: FirstBootStage::AwaitingSource,
            source: None,
            observed_environment: None,
            observation: None,
            plan: None,
            plan_lineage: None,
            recovery: None,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn provisioning_mode(&self) -> ProvisioningMode {
        self.provisioning_mode
    }

    #[must_use]
    pub const fn stage(&self) -> FirstBootStage {
        self.stage
    }

    #[must_use]
    pub fn current_plan_id(&self) -> Option<&str> {
        self.plan.as_ref().map(|plan| plan.id.as_str())
    }

    pub fn select_source(&mut self, source: SourceSelection) -> Result<(), FirstBootError> {
        match (self.provisioning_mode, source.kind()) {
            (ProvisioningMode::Recovery, SourceKind::Recovery) => {}
            (ProvisioningMode::Recovery, _) => return Err(FirstBootError::ModeSourceMismatch),
            (_, SourceKind::Recovery) => return Err(FirstBootError::ModeSourceMismatch),
            _ => {}
        }

        self.source = Some(source);
        self.observed_environment = None;
        self.observation = None;
        self.plan = None;
        self.plan_lineage = None;
        self.recovery = None;
        self.stage = FirstBootStage::AwaitingDiscovery;
        Ok(())
    }

    pub fn record_discovery(
        &mut self,
        observed: ObservedEnvironment,
    ) -> Result<(), FirstBootError> {
        self.require_stage(FirstBootStage::AwaitingDiscovery)?;
        let environment = QualificationEnvironment::v09_candidate();
        environment
            .validate_contract()
            .map_err(|error| FirstBootError::QualificationContract(format!("{error:?}")))?;
        let mismatches = environment.assess(&observed);
        if !mismatches.is_empty() {
            return Err(FirstBootError::UnsupportedQualificationEnvironment(
                mismatches,
            ));
        }
        self.observed_environment = Some(observed);
        self.stage = FirstBootStage::AwaitingFreshObservation;
        Ok(())
    }

    /// Obtain current target evidence through the repository-owned observation
    /// boundary. The caller selects only a typed request and cannot manufacture
    /// the resulting authoritative envelope or its freshness window.
    pub fn observe_target(
        &mut self,
        source: &mut FirstBootObservationSource,
        request: &ObservationRequest,
    ) -> Result<(), FirstBootError> {
        self.require_stage(FirstBootStage::AwaitingFreshObservation)?;
        let observation = source.observe(request)?;
        self.bind_observation_at(observation, current_unix_ms()?)
    }

    fn bind_observation_at(
        &mut self,
        observation: ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<(), FirstBootError> {
        self.require_stage(FirstBootStage::AwaitingFreshObservation)?;
        observation
            .validate(
                &observation.provider,
                &observation.resource,
                &observation.capability,
            )
            .map_err(|error| FirstBootError::InvalidObservation(error.to_string()))?;
        observation
            .require_current(now_unix_ms)
            .map_err(|error| FirstBootError::InvalidObservation(error.to_string()))?;
        if observation.authority == ObservationAuthority::SyntheticTest {
            return Err(FirstBootError::UntrustedObservationAuthority);
        }
        self.observation = Some(observation);
        self.plan = None;
        self.plan_lineage = None;
        self.recovery = None;
        self.stage = FirstBootStage::AwaitingPlan;
        Ok(())
    }

    /// Build the canonical non-executable plan from the exact retained
    /// authoritative observation and exact declarative source revision.
    /// Callers cannot substitute a pre-built plan and a source change changes
    /// the canonical request/plan identity even when desired state is identical.
    pub fn plan_resource(
        &mut self,
        upstream_request_id: RequestId,
        actor: Actor,
        desired: DesiredResource,
    ) -> Result<(), FirstBootError> {
        self.require_stage(FirstBootStage::AwaitingPlan)?;
        let source = self
            .source
            .as_ref()
            .ok_or(FirstBootError::MissingBinding("declarative source"))?;
        let observation = self
            .observation
            .as_ref()
            .ok_or(FirstBootError::MissingBinding("authoritative observation"))?;
        let source_binding_sha256 = source.binding_sha256();
        let observation_evidence_id = observation.evidence_id();
        let canonical_request_id = canonical_plan_request_id(
            &self.session_id,
            self.provisioning_mode,
            &source_binding_sha256,
            &upstream_request_id,
            &actor,
            &desired,
            &observation_evidence_id,
        )?;
        let planning_observation = PlanningObservation {
            provider: observation.provider.clone(),
            resource: observation.resource.clone(),
            observation_capability: observation.capability.clone(),
            authority: observation.authority.as_str().to_owned(),
            evidence_id: observation_evidence_id.clone(),
            freshness: PlanningFreshness::Current,
            attributes: observation
                .attributes
                .iter()
                .map(|(key, value)| (key.clone(), value.to_string()))
                .collect::<BTreeMap<_, _>>(),
        };

        let plan = DeterministicPlanner
            .plan_resource(
                canonical_request_id.clone(),
                actor,
                desired,
                &planning_observation,
            )
            .map_err(|error| FirstBootError::Planning(error.to_string()))?;
        if plan.execution_authorized() {
            return Err(FirstBootError::UnexpectedPlanAuthority);
        }
        if plan.has_blockers() {
            return Err(FirstBootError::PlanBlocked);
        }
        self.plan_lineage = Some(FirstBootPlanLineage {
            upstream_request_id,
            canonical_request_id,
            source_binding_sha256,
            observation_evidence_id,
        });
        self.plan = Some(plan);
        self.recovery = None;
        self.stage = FirstBootStage::AwaitingRecoveryCheckpoint;
        Ok(())
    }

    /// Consume verifier-produced recovery evidence exact-bound to this session
    /// and canonical plan. No caller-authored booleans are accepted here.
    pub fn record_recovery_checkpoint(
        &mut self,
        evidence: RecoveryCheckpointEvidence,
    ) -> Result<(), FirstBootError> {
        self.require_stage(FirstBootStage::AwaitingRecoveryCheckpoint)?;
        let plan = self
            .plan
            .as_ref()
            .ok_or(FirstBootError::MissingBinding("canonical plan"))?;
        evidence
            .validate_binding(&self.session_id, plan.id.as_str())
            .map_err(|error| FirstBootError::RecoveryNotReady(error.to_string()))?;
        self.recovery = Some(evidence);
        self.stage = FirstBootStage::ReadyForControlSubmission;
        Ok(())
    }

    /// Seal a non-authorizing Control submission using a process-owned clock.
    /// This is preflight only; Control independently revalidates current evidence
    /// with its own trusted clock/state before any authority decision.
    pub fn control_submission(&self) -> Result<ControlSubmission, FirstBootError> {
        self.control_submission_at(current_unix_ms()?)
    }

    fn control_submission_at(&self, now_unix_ms: u64) -> Result<ControlSubmission, FirstBootError> {
        self.require_stage(FirstBootStage::ReadyForControlSubmission)?;
        let source = self
            .source
            .clone()
            .ok_or(FirstBootError::MissingBinding("source"))?;
        let observed_environment = self
            .observed_environment
            .clone()
            .ok_or(FirstBootError::MissingBinding("QualificationEnvironment"))?;
        let observation = self
            .observation
            .clone()
            .ok_or(FirstBootError::MissingBinding("authoritative observation"))?;
        observation
            .require_current(now_unix_ms)
            .map_err(|error| FirstBootError::InvalidObservation(error.to_string()))?;
        let plan = self
            .plan
            .clone()
            .ok_or(FirstBootError::MissingBinding("canonical plan"))?;
        if plan.observed_evidence_id != observation.evidence_id()
            || plan.provider != observation.provider
            || plan.resource != observation.resource
            || plan.observation_capability != observation.capability
        {
            return Err(FirstBootError::BindingMismatch(
                "canonical plan no longer matches retained authoritative observation",
            ));
        }
        let plan_lineage = self
            .plan_lineage
            .clone()
            .ok_or(FirstBootError::MissingBinding(
                "canonical source/plan lineage",
            ))?;
        if source.binding_sha256() != plan_lineage.source_binding_sha256
            || observation.evidence_id() != plan_lineage.observation_evidence_id
            || plan.request_id.as_str() != plan_lineage.canonical_request_id.as_str()
            || plan.id.as_str() != plan_lineage.canonical_request_id.as_str()
        {
            return Err(FirstBootError::BindingMismatch(
                "source/observation lineage no longer matches the canonical plan",
            ));
        }
        let recovery = self.recovery.clone().ok_or(FirstBootError::MissingBinding(
            "verified recovery checkpoint",
        ))?;
        recovery
            .validate_binding(&self.session_id, plan.id.as_str())
            .map_err(|error| FirstBootError::RecoveryNotReady(error.to_string()))?;

        Ok(ControlSubmission {
            contract_version: FIRST_BOOT_CONTRACT_VERSION,
            qualification_environment_id: V09_QUALIFICATION_ENVIRONMENT_ID,
            session_id: self.session_id.clone(),
            provisioning_mode: self.provisioning_mode,
            source,
            observed_environment,
            observation,
            plan,
            plan_lineage,
            recovery,
        })
    }

    fn require_stage(&self, expected: FirstBootStage) -> Result<(), FirstBootError> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(FirstBootError::InvalidStage {
                expected,
                actual: self.stage,
            })
        }
    }
}

fn current_unix_ms() -> Result<u64, FirstBootError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| FirstBootError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| FirstBootError::Clock("system clock exceeds supported range".into()))
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn provisioning_mode_name(mode: ProvisioningMode) -> &'static str {
    match mode {
        ProvisioningMode::InteractiveOwner => "interactive-owner",
        ProvisioningMode::PrepareForAnotherOwner => "prepare-for-another-owner",
        ProvisioningMode::UnattendedLocal => "unattended-local",
        ProvisioningMode::Recovery => "recovery",
    }
}

fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn canonical_plan_request_id(
    session_id: &str,
    provisioning_mode: ProvisioningMode,
    source_binding_sha256: &str,
    upstream_request_id: &RequestId,
    actor: &Actor,
    desired: &DesiredResource,
    observation_evidence_id: &str,
) -> Result<RequestId, FirstBootError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "linura-firstboot-canonical-plan-v1");
    hash_field(&mut hasher, session_id);
    hash_field(&mut hasher, provisioning_mode_name(provisioning_mode));
    hash_field(&mut hasher, source_binding_sha256);
    hash_field(&mut hasher, upstream_request_id.as_str());
    hash_field(&mut hasher, observation_evidence_id);
    hash_field(&mut hasher, actor.id.as_str());
    hash_field(&mut hasher, actor_kind_name(actor.kind));
    hash_field(
        &mut hasher,
        if actor.interactive {
            "interactive"
        } else {
            "non-interactive"
        },
    );
    hash_field(&mut hasher, desired.provider.as_str());
    hash_field(&mut hasher, desired.resource.as_str());
    hash_field(&mut hasher, desired.observation_capability.as_str());
    for (key, value) in &desired.state {
        hash_field(&mut hasher, key);
        hash_field(&mut hasher, value);
    }
    hash_field(&mut hasher, &desired.reason.summary);
    for value in &desired.reason.intent_ids {
        hash_field(&mut hasher, value.as_str());
    }
    for value in &desired.reason.requirement_ids {
        hash_field(&mut hasher, value.as_str());
    }
    for value in &desired.reason.capability_ids {
        hash_field(&mut hasher, value.as_str());
    }
    let digest = format!("{:x}", hasher.finalize());
    RequestId::new(format!("firstboot-plan:{digest}"))
        .map_err(|error| FirstBootError::CanonicalLineage(error.to_string()))
}

fn normalize_required(label: &'static str, value: String) -> Result<String, FirstBootError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.chars().any(char::is_control) {
        return Err(FirstBootError::InvalidField(label));
    }
    Ok(trimmed.to_owned())
}

fn validate_sha256(label: &'static str, value: &str) -> Result<(), FirstBootError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FirstBootError::InvalidDigest(label));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirstBootError {
    InvalidField(&'static str),
    InvalidDigest(&'static str),
    MissingDigest,
    UnexpectedDigest,
    InvalidLibraryRevision,
    UnexpectedLibraryRevision,
    ModeSourceMismatch,
    InvalidStage {
        expected: FirstBootStage,
        actual: FirstBootStage,
    },
    QualificationContract(String),
    UnsupportedQualificationEnvironment(Vec<EnvironmentMismatch>),
    InvalidObservation(String),
    UntrustedObservationAuthority,
    ObservationSource(String),
    Clock(String),
    Planning(String),
    PlanBlocked,
    UnexpectedPlanAuthority,
    MissingBinding(&'static str),
    BindingMismatch(&'static str),
    RecoveryNotReady(String),
    CanonicalLineage(String),
}

impl Display for FirstBootError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField(label) => write!(f, "invalid or empty {label}"),
            Self::InvalidDigest(label) => {
                write!(f, "{label} must be a 64-character SHA-256 hex digest")
            }
            Self::MissingDigest => f.write_str("portable source requires a SHA-256 digest"),
            Self::UnexpectedDigest => {
                f.write_str("source kind must not carry this portable-source digest")
            }
            Self::InvalidLibraryRevision => {
                f.write_str("Library source requires an exact nonzero stored revision")
            }
            Self::UnexpectedLibraryRevision => {
                f.write_str("non-Library source must not carry a Library revision")
            }
            Self::ModeSourceMismatch => {
                f.write_str("recovery sources are valid only in recovery provisioning mode")
            }
            Self::InvalidStage { expected, actual } => write!(
                f,
                "invalid First Boot transition: expected {expected:?}, found {actual:?}"
            ),
            Self::QualificationContract(reason) => {
                write!(
                    f,
                    "invalid v0.9 QualificationEnvironment contract: {reason}"
                )
            }
            Self::UnsupportedQualificationEnvironment(mismatches) => write!(
                f,
                "target does not match the v0.9 QualificationEnvironment: {} mismatch(es)",
                mismatches.len()
            ),
            Self::InvalidObservation(reason) => {
                write!(
                    f,
                    "authoritative observation is not current/valid: {reason}"
                )
            }
            Self::UntrustedObservationAuthority => f.write_str(
                "synthetic-test observation cannot satisfy First Boot production evidence",
            ),
            Self::ObservationSource(reason) => {
                write!(f, "trusted First Boot observation failed: {reason}")
            }
            Self::Clock(reason) => write!(f, "First Boot clock failed: {reason}"),
            Self::Planning(reason) => write!(f, "canonical planning failed: {reason}"),
            Self::PlanBlocked => f.write_str("canonical plan contains blocking findings"),
            Self::UnexpectedPlanAuthority => {
                f.write_str("First Boot received a plan carrying execution authority")
            }
            Self::MissingBinding(binding) => write!(f, "missing First Boot binding: {binding}"),
            Self::BindingMismatch(reason) => write!(f, "First Boot binding mismatch: {reason}"),
            Self::RecoveryNotReady(reason) => write!(f, "recovery is not ready: {reason}"),
            Self::CanonicalLineage(reason) => {
                write!(f, "canonical First Boot lineage is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for FirstBootError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_bootstrap::RecoveryCheckpointVerifier;
    use linura_core::{
        ActorId, ActorKind, CapabilityId, IntentId, ProfileId, ProviderId, ResourceId,
        SemanticReason, SetupId, ValidationError,
    };
    use linura_observation::ObservedValue;
    use std::fs;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RECOVERY_DIGEST: &str =
        "2d19f6ef0dd2620cb4563e52cc3d9101310f4d00b761471639c66b98ad38c80c";

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn environment() -> ObservedEnvironment {
        ObservedEnvironment {
            machine_class: linura_hardware::MachineClass::Server,
            distribution_id: "ubuntu".into(),
            distribution_version: "24.04".into(),
            architecture: "x86_64".into(),
            interaction: linura_hardware::InteractionMode::Headless,
            virtualization: linura_hardware::VirtualizationKind::QemuTcg,
            init_system: "systemd".into(),
        }
    }

    fn observation() -> ObservationEnvelope {
        ObservationEnvelope {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new("systemd:unit:ssh.service")),
            capability: id(CapabilityId::new("systemd.unit.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1_000,
            valid_for_ms: 1_000,
            sequence: 1,
            attributes: BTreeMap::from([(
                "active_state".into(),
                ObservedValue::Text("inactive".into()),
            )]),
        }
    }

    fn desired() -> DesiredResource {
        DesiredResource {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new("systemd:unit:ssh.service")),
            observation_capability: id(CapabilityId::new("systemd.unit.observe")),
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "explicitly request SSH active".into(),
                intent_ids: vec![id(IntentId::new("intent:ssh"))],
                requirement_ids: vec![],
                capability_ids: vec![id(CapabilityId::new("remote.ssh"))],
            },
        }
    }

    fn actor() -> Actor {
        Actor {
            id: id(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        }
    }

    fn verified_recovery(session: &FirstBootSession) -> RecoveryCheckpointEvidence {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint = dir.path().join("checkpoint.bin");
        let restored = dir.path().join("restored.bin");
        fs::write(&checkpoint, b"linura-v09-recovery-checkpoint")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::copy(&checkpoint, &restored).unwrap_or_else(|error| unreachable!("{error}"));
        RecoveryCheckpointVerifier::verify_v09(
            session.session_id(),
            session
                .current_plan_id()
                .unwrap_or_else(|| unreachable!("plan required")),
            "snapshot:test:1",
            &checkpoint,
            &restored,
            RECOVERY_DIGEST,
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn ready_session() -> FirstBootSession {
        let mut session =
            FirstBootSession::new("firstboot:test:1", ProvisioningMode::InteractiveOwner)
                .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .select_source(
                SourceSelection::fresh_intent("enable SSH intentionally")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .record_discovery(environment())
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .bind_observation_at(observation(), 1_500)
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .plan_resource(
                id(RequestId::new("request:firstboot:ssh")),
                actor(),
                desired(),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let recovery = verified_recovery(&session);
        session
            .record_recovery_checkpoint(recovery)
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
    }

    #[test]
    fn portable_sources_require_valid_digest() {
        let source = SourceSelection::portable_profile("portable:test", DIGEST)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(source.kind(), SourceKind::PortableProfile);
        assert_eq!(source.source_sha256(), Some(DIGEST));
        assert!(SourceSelection::portable_profile("portable:test", "bad").is_err());
    }

    #[test]
    fn library_sources_require_exact_typed_revision_identity() {
        let setup = SourceSelection::library_setup(SetupRevisionRef {
            id: id(SetupId::new("setup:rust")),
            revision: 7,
        })
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(setup.reference(), "setup:rust");
        assert_eq!(setup.library_revision(), Some(7));

        let profile = SourceSelection::library_profile(ProfileIdentity {
            id: id(ProfileId::new("profile:workstation")),
            revision: 3,
        })
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(profile.reference(), "profile:workstation");
        assert_eq!(profile.library_revision(), Some(3));

        assert_eq!(
            SourceSelection::library_setup(SetupRevisionRef {
                id: id(SetupId::new("setup:invalid")),
                revision: 0,
            }),
            Err(FirstBootError::InvalidLibraryRevision)
        );
    }

    #[test]
    fn recovery_source_requires_recovery_mode() {
        let mut session =
            FirstBootSession::new("firstboot:test:mode", ProvisioningMode::InteractiveOwner)
                .unwrap_or_else(|error| unreachable!("{error}"));
        let recovery = SourceSelection::recovery("snapshot:test")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            session.select_source(recovery),
            Err(FirstBootError::ModeSourceMismatch)
        );
    }

    #[test]
    fn unsupported_environment_fails_closed() {
        let mut session = FirstBootSession::new(
            "firstboot:test:environment",
            ProvisioningMode::InteractiveOwner,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .select_source(
                SourceSelection::fresh_intent("test")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut wrong = environment();
        wrong.architecture = "aarch64".into();
        assert!(matches!(
            session.record_discovery(wrong),
            Err(FirstBootError::UnsupportedQualificationEnvironment(_))
        ));
    }

    #[test]
    fn synthetic_or_stale_observation_cannot_advance() {
        let mut session = FirstBootSession::new(
            "firstboot:test:observation",
            ProvisioningMode::InteractiveOwner,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .select_source(
                SourceSelection::fresh_intent("test")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .record_discovery(environment())
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut synthetic = observation();
        synthetic.authority = ObservationAuthority::SyntheticTest;
        assert_eq!(
            session.bind_observation_at(synthetic, 1_500),
            Err(FirstBootError::UntrustedObservationAuthority)
        );

        let mut session =
            FirstBootSession::new("firstboot:test:stale", ProvisioningMode::InteractiveOwner)
                .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .select_source(
                SourceSelection::fresh_intent("test")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        session
            .record_discovery(environment())
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            session.bind_observation_at(observation(), 2_001),
            Err(FirstBootError::InvalidObservation(_))
        ));
    }

    #[test]
    fn canonical_plan_is_built_from_retained_observation_and_never_authorizes() {
        let session = ready_session();
        let submission = session
            .control_submission_at(1_600)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            submission.qualification_environment_id(),
            V09_QUALIFICATION_ENVIRONMENT_ID
        );
        assert_eq!(submission.contract_version(), FIRST_BOOT_CONTRACT_VERSION);
        assert_eq!(
            submission.plan().observed_evidence_id,
            submission.observation().evidence_id()
        );
        assert_eq!(
            submission.recovery().plan_id(),
            submission.plan().id.as_str()
        );
        assert_eq!(submission.recovery().session_id(), submission.session_id());
        assert_eq!(
            submission.plan_lineage().source_binding_sha256(),
            submission.source().binding_sha256()
        );
        assert_eq!(
            submission.plan_lineage().canonical_request_id().as_str(),
            submission.plan().id.as_str()
        );
        assert!(!submission.plan().execution_authorized());
        assert!(!submission.execution_authorized());
    }

    #[test]
    fn submission_rechecks_freshness_before_control_handoff() {
        let session = ready_session();
        assert!(matches!(
            session.control_submission_at(2_001),
            Err(FirstBootError::InvalidObservation(_))
        ));
    }

    #[test]
    fn exact_source_revision_changes_canonical_plan_identity() {
        fn planned_with_revision(revision: u32) -> FirstBootSession {
            let mut session = FirstBootSession::new(
                "firstboot:test:source-lineage",
                ProvisioningMode::InteractiveOwner,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
            session
                .select_source(
                    SourceSelection::library_setup(SetupRevisionRef {
                        id: id(SetupId::new("setup:source-lineage")),
                        revision,
                    })
                    .unwrap_or_else(|error| unreachable!("{error}")),
                )
                .unwrap_or_else(|error| unreachable!("{error}"));
            session
                .record_discovery(environment())
                .unwrap_or_else(|error| unreachable!("{error}"));
            session
                .bind_observation_at(observation(), 1_500)
                .unwrap_or_else(|error| unreachable!("{error}"));
            session
                .plan_resource(
                    id(RequestId::new("request:firstboot:source-lineage")),
                    actor(),
                    desired(),
                )
                .unwrap_or_else(|error| unreachable!("{error}"));
            session
        }

        let first = planned_with_revision(1);
        let second = planned_with_revision(2);
        assert_ne!(first.current_plan_id(), second.current_plan_id());
        assert_ne!(
            first.source.as_ref().map(SourceSelection::binding_sha256),
            second.source.as_ref().map(SourceSelection::binding_sha256)
        );
    }

    #[test]
    fn first_boot_contains_no_caller_manufactured_review_stage() {
        let mut session =
            FirstBootSession::new("firstboot:test:stage", ProvisioningMode::InteractiveOwner)
                .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(session.stage(), FirstBootStage::AwaitingSource);
        session
            .select_source(
                SourceSelection::fresh_intent("test")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(session.stage(), FirstBootStage::AwaitingDiscovery);
    }
}
