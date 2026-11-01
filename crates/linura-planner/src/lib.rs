#![forbid(unsafe_code)]

// Non-executable, bounded S23 package impact advisory.
pub mod package_impact;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};

use linura_capability_sdk::{CapabilityCatalog, Resolution};
use linura_core::{
    Actor, CapabilityId, IntentId, PlanId, ProviderId, RequestId, ResourceId, RiskClass,
    SemanticReason,
};
use linura_intent::Intent;

pub const DEFAULT_PLAN_STORE_CAPACITY: usize = 256;

type DesiredResourceKey = (ProviderId, ResourceId, CapabilityId);
type DesiredResourceContributions = BTreeMap<DesiredResourceKey, DesiredResourceContribution>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DesiredResourceContribution {
    state: BTreeMap<String, String>,
    capabilities: BTreeSet<CapabilityId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredResource {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub state: BTreeMap<String, String>,
    pub reason: SemanticReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DesiredState {
    pub resources: Vec<DesiredResource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredStateValidationError {
    EmptyDesiredState,
    DuplicateResource(ResourceId),
    EmptyResourceState(ResourceId),
    InvalidAttributeKey {
        resource: ResourceId,
        key: String,
    },
    InvalidAttributeValue {
        resource: ResourceId,
        key: String,
    },
    InvalidSemanticReason {
        resource: ResourceId,
        reason: String,
    },
}

impl Display for DesiredStateValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDesiredState => {
                f.write_str("desired state must contain at least one resource")
            }
            Self::DuplicateResource(resource) => write!(
                f,
                "desired state contains duplicate resource {}",
                resource.as_str()
            ),
            Self::EmptyResourceState(resource) => write!(
                f,
                "desired resource {} must contain at least one state attribute",
                resource.as_str()
            ),
            Self::InvalidAttributeKey { resource, key } => write!(
                f,
                "desired resource {} contains invalid attribute key {key:?}",
                resource.as_str()
            ),
            Self::InvalidAttributeValue { resource, key } => write!(
                f,
                "desired resource {} contains an invalid value for attribute {key:?}",
                resource.as_str()
            ),
            Self::InvalidSemanticReason { resource, reason } => write!(
                f,
                "desired resource {} has invalid semantic provenance: {reason}",
                resource.as_str()
            ),
        }
    }
}

impl std::error::Error for DesiredStateValidationError {}

impl DesiredState {
    pub fn validate(&self) -> Result<(), DesiredStateValidationError> {
        if self.resources.is_empty() {
            return Err(DesiredStateValidationError::EmptyDesiredState);
        }

        let mut resources = BTreeSet::new();
        for desired in &self.resources {
            if !resources.insert(desired.resource.clone()) {
                return Err(DesiredStateValidationError::DuplicateResource(
                    desired.resource.clone(),
                ));
            }
            validate_desired_resource(desired)?;
        }
        Ok(())
    }
}

fn validate_desired_resource(desired: &DesiredResource) -> Result<(), DesiredStateValidationError> {
    if desired.state.is_empty() {
        return Err(DesiredStateValidationError::EmptyResourceState(
            desired.resource.clone(),
        ));
    }
    for (key, value) in &desired.state {
        if key.trim().is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
            return Err(DesiredStateValidationError::InvalidAttributeKey {
                resource: desired.resource.clone(),
                key: key.clone(),
            });
        }
        if value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(DesiredStateValidationError::InvalidAttributeValue {
                resource: desired.resource.clone(),
                key: key.clone(),
            });
        }
    }
    desired
        .reason
        .validate()
        .map_err(|error| DesiredStateValidationError::InvalidSemanticReason {
            resource: desired.resource.clone(),
            reason: error.to_string(),
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentPlan {
    pub intent_id: IntentId,
    pub capability_resolution: Resolution,
    pub desired_state: DesiredState,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanningFreshness {
    Current,
    Stale,
    Future,
}

impl PlanningFreshness {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Future => "future",
        }
    }
}

/// Minimal authoritative observation projection consumed by the pure planner.
///
/// Transport/provider layers are responsible for authenticating and validating
/// the source observation before constructing this projection. Keeping this type
/// in the planner prevents the deterministic domain layer from depending on a
/// D-Bus or protocol representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanningObservation {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub authority: String,
    pub evidence_id: String,
    pub freshness: PlanningFreshness,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanStatus {
    NoChange,
    ChangeProposed,
    Blocked,
}

impl PlanStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no-change",
            Self::ChangeProposed => "change-proposed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanFindingLevel {
    Pass,
    Warning,
    Blocker,
}

impl PlanFindingLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warning => "warning",
            Self::Blocker => "blocker",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanFinding {
    pub code: String,
    pub level: PlanFindingLevel,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateChange {
    pub key: String,
    pub current: Option<String>,
    pub desired: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionAuthority {
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationPlan {
    pub id: PlanId,
    pub request_id: RequestId,
    pub actor: Actor,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub reason: SemanticReason,
    pub observed_evidence_id: String,
    pub prospective_risk: RiskClass,
    pub status: PlanStatus,
    execution_authority: ExecutionAuthority,
    pub changes: Vec<StateChange>,
    pub findings: Vec<PlanFinding>,
}

impl ReconciliationPlan {
    #[must_use]
    pub fn has_blockers(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.level == PlanFindingLevel::Blocker)
    }

    /// Planning previews never carry execution authority. The private enum makes
    /// an authorized preview unrepresentable outside this module.
    #[must_use]
    pub const fn execution_authorized(&self) -> bool {
        match self.execution_authority {
            ExecutionAuthority::Disabled => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanningError {
    RetiredIntent,
    MissingCapability(CapabilityId),
    Conflict(CapabilityId, CapabilityId),
    EmptyIntentStatement,
    DesiredStateConflict {
        resource: ResourceId,
        key: String,
        first: String,
        second: String,
    },
    InvalidDesiredState(String),
    InvalidObservation(String),
    ObservationIdentityMismatch(String),
    ObservationNotCurrent(PlanningFreshness),
    InvalidPlanId(String),
}

impl Display for PlanningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RetiredIntent => f.write_str("intent is not in a managed state"),
            Self::MissingCapability(capability) => {
                write!(f, "missing capability {}", capability.as_str())
            }
            Self::Conflict(left, right) => write!(
                f,
                "capability conflict between {} and {}",
                left.as_str(),
                right.as_str()
            ),
            Self::EmptyIntentStatement => f.write_str("intent statement cannot be empty"),
            Self::DesiredStateConflict {
                resource,
                key,
                first,
                second,
            } => write!(
                f,
                "desired-state conflict for {} attribute {key:?}: {first:?} != {second:?}",
                resource.as_str()
            ),
            Self::InvalidDesiredState(reason) => write!(f, "invalid desired state: {reason}"),
            Self::InvalidObservation(reason) => write!(f, "invalid planning observation: {reason}"),
            Self::ObservationIdentityMismatch(reason) => {
                write!(f, "authoritative observation identity mismatch: {reason}")
            }
            Self::ObservationNotCurrent(freshness) => write!(
                f,
                "planning requires current authoritative observation, got {}",
                freshness.as_str()
            ),
            Self::InvalidPlanId(reason) => write!(f, "invalid deterministic plan id: {reason}"),
        }
    }
}

impl std::error::Error for PlanningError {}

#[derive(Clone, Debug, Default)]
pub struct DeterministicPlanner;

impl DeterministicPlanner {
    pub fn resolve_capabilities(
        &self,
        intent: &Intent,
        catalog: &CapabilityCatalog,
        requested: &[CapabilityId],
    ) -> Result<Resolution, PlanningError> {
        if !intent.is_managed() {
            return Err(PlanningError::RetiredIntent);
        }
        let resolution = catalog.resolve(requested);
        if let Some(missing) = resolution.missing.iter().next() {
            return Err(PlanningError::MissingCapability(missing.clone()));
        }
        if let Some((left, right)) = resolution.conflicts.first() {
            return Err(PlanningError::Conflict(left.clone(), right.clone()));
        }
        Ok(resolution)
    }

    /// Compile a hand-authored intent and capability selection into deterministic
    /// declarative desired state. No model provider, shell command, executor or
    /// machine mutation participates in this transformation.
    pub fn compile_intent(
        &self,
        intent: &Intent,
        catalog: &CapabilityCatalog,
        requested: &[CapabilityId],
    ) -> Result<IntentPlan, PlanningError> {
        if intent.statement.trim().is_empty() {
            return Err(PlanningError::EmptyIntentStatement);
        }
        let resolution = self.resolve_capabilities(intent, catalog, requested)?;
        let mut contributions = DesiredResourceContributions::new();
        let mut warnings = Vec::new();

        for capability in &resolution.selected {
            let Some(blueprint) = catalog.blueprint(capability) else {
                return Err(PlanningError::MissingCapability(capability.clone()));
            };
            if blueprint.desired_resources.is_empty() {
                warnings.push(format!(
                    "capability {} contributes no desired resources",
                    capability.as_str()
                ));
            }
            for template in &blueprint.desired_resources {
                let key = (
                    template.provider.clone(),
                    template.resource.clone(),
                    template.observation_capability.clone(),
                );
                let entry = contributions.entry(key).or_default();
                for (attribute, value) in &template.state {
                    match entry.state.get(attribute) {
                        Some(existing) if existing != value => {
                            return Err(PlanningError::DesiredStateConflict {
                                resource: template.resource.clone(),
                                key: attribute.clone(),
                                first: existing.clone(),
                                second: value.clone(),
                            });
                        }
                        _ => {
                            entry.state.insert(attribute.clone(), value.clone());
                        }
                    }
                }
                entry.capabilities.insert(capability.clone());
            }
        }

        let mut resources = Vec::with_capacity(contributions.len());
        for ((provider, resource, observation_capability), contribution) in contributions {
            resources.push(DesiredResource {
                provider,
                resource,
                observation_capability,
                state: contribution.state,
                reason: SemanticReason {
                    summary: intent.statement.clone(),
                    intent_ids: vec![intent.id.clone()],
                    // Requirement IDs are intentionally omitted until the input
                    // model carries an explicit requirement-to-capability edge.
                    // Attaching every requirement here would create false causal
                    // provenance for unrelated desired resources.
                    requirement_ids: vec![],
                    capability_ids: contribution.capabilities.into_iter().collect(),
                },
            });
        }
        let desired_state = DesiredState { resources };
        desired_state
            .validate()
            .map_err(|error| PlanningError::InvalidDesiredState(error.to_string()))?;
        warnings.sort();

        Ok(IntentPlan {
            intent_id: intent.id.clone(),
            capability_resolution: resolution,
            desired_state,
            warnings,
        })
    }

    /// Compare one normalized desired resource with a current authoritative
    /// observation and produce a deterministic, explicitly non-executable plan.
    pub fn plan_resource(
        &self,
        request_id: RequestId,
        actor: Actor,
        desired: DesiredResource,
        observation: &PlanningObservation,
    ) -> Result<ReconciliationPlan, PlanningError> {
        validate_desired_resource(&desired)
            .map_err(|error| PlanningError::InvalidDesiredState(error.to_string()))?;
        validate_planning_observation(observation)?;
        if observation.freshness != PlanningFreshness::Current {
            return Err(PlanningError::ObservationNotCurrent(observation.freshness));
        }
        if observation.provider != desired.provider {
            return Err(PlanningError::ObservationIdentityMismatch(
                "provider differs from desired-state observation route".into(),
            ));
        }
        if observation.resource != desired.resource {
            return Err(PlanningError::ObservationIdentityMismatch(
                "resource differs from desired-state resource".into(),
            ));
        }
        if observation.observation_capability != desired.observation_capability {
            return Err(PlanningError::ObservationIdentityMismatch(
                "capability differs from desired-state observation route".into(),
            ));
        }

        let mut changes = Vec::new();
        let mut findings = vec![
            PlanFinding {
                code: "semantic-origin".into(),
                level: PlanFindingLevel::Pass,
                message: "desired state retains semantic provenance".into(),
            },
            PlanFinding {
                code: "authoritative-observation".into(),
                level: PlanFindingLevel::Pass,
                message: format!(
                    "planning is bound to current {} evidence {}",
                    observation.authority, observation.evidence_id
                ),
            },
            PlanFinding {
                code: "execution-disabled".into(),
                level: PlanFindingLevel::Pass,
                message:
                    "v0.2 planning produces no executable effects and grants no mutation authority"
                        .into(),
            },
        ];

        for (key, desired_value) in &desired.state {
            match observation.attributes.get(key) {
                Some(current) if current != desired_value => changes.push(StateChange {
                    key: key.clone(),
                    current: Some(current.clone()),
                    desired: desired_value.clone(),
                }),
                Some(_) => {}
                None => {
                    changes.push(StateChange {
                        key: key.clone(),
                        current: None,
                        desired: desired_value.clone(),
                    });
                    findings.push(PlanFinding {
                        code: "attribute-not-observed".into(),
                        level: PlanFindingLevel::Blocker,
                        message: format!(
                            "authoritative observation does not expose desired attribute {key:?}; planning fails closed"
                        ),
                    });
                }
            }
        }

        let blocked = findings
            .iter()
            .any(|finding| finding.level == PlanFindingLevel::Blocker);
        let status = if blocked {
            PlanStatus::Blocked
        } else if changes.is_empty() {
            PlanStatus::NoChange
        } else {
            PlanStatus::ChangeProposed
        };
        let prospective_risk = if changes.is_empty() {
            RiskClass::ReadOnly
        } else {
            RiskClass::SystemMutation
        };
        let id = PlanId::new(request_id.as_str().to_string())
            .map_err(|error| PlanningError::InvalidPlanId(error.to_string()))?;

        Ok(ReconciliationPlan {
            id,
            request_id,
            actor,
            provider: desired.provider,
            resource: desired.resource,
            observation_capability: desired.observation_capability,
            reason: desired.reason,
            observed_evidence_id: observation.evidence_id.clone(),
            prospective_risk,
            status,
            execution_authority: ExecutionAuthority::Disabled,
            changes,
            findings,
        })
    }
}

fn validate_planning_observation(observation: &PlanningObservation) -> Result<(), PlanningError> {
    if observation.authority.trim().is_empty() {
        return Err(PlanningError::InvalidObservation(
            "authority cannot be empty".into(),
        ));
    }
    if observation.evidence_id.trim().is_empty() {
        return Err(PlanningError::InvalidObservation(
            "evidence id cannot be empty".into(),
        ));
    }
    if observation.attributes.is_empty() {
        return Err(PlanningError::InvalidObservation(
            "authoritative attributes cannot be empty".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanStoreError {
    InvalidCapacity,
    IdempotencyConflict { plan_id: PlanId },
}

impl Display for PlanStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCapacity => f.write_str("plan store capacity must be greater than zero"),
            Self::IdempotencyConflict { plan_id } => write!(
                f,
                "request/plan id {} already identifies a different plan",
                plan_id.as_str()
            ),
        }
    }
}

impl std::error::Error for PlanStoreError {}

#[derive(Clone, Debug)]
pub struct PlanStore {
    capacity: usize,
    plans: BTreeMap<PlanId, ReconciliationPlan>,
    order: VecDeque<PlanId>,
}

impl Default for PlanStore {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_PLAN_STORE_CAPACITY,
            plans: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl PlanStore {
    pub fn with_capacity(capacity: usize) -> Result<Self, PlanStoreError> {
        if capacity == 0 {
            return Err(PlanStoreError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            plans: BTreeMap::new(),
            order: VecDeque::new(),
        })
    }

    pub fn insert(&mut self, plan: ReconciliationPlan) -> Result<(), PlanStoreError> {
        if let Some(existing) = self.plans.get(&plan.id) {
            if existing == &plan {
                return Ok(());
            }
            return Err(PlanStoreError::IdempotencyConflict {
                plan_id: plan.id.clone(),
            });
        }

        while self.plans.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.plans.remove(&oldest);
        }
        self.order.push_back(plan.id.clone());
        self.plans.insert(plan.id.clone(), plan);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, plan_id: &PlanId) -> Option<&ReconciliationPlan> {
        self.plans.get(plan_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.plans.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_capability_sdk::{CapabilityBlueprint, DesiredResourceBlueprint};
    use linura_core::{ActorId, ActorKind, RequirementId, ValidationError};
    use linura_intent::{IntentStatus, Requirement, RequirementKind};

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn actor() -> Actor {
        Actor {
            id: id(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        }
    }

    fn intent() -> Intent {
        Intent {
            id: id(IntentId::new("intent:ssh")),
            actor: actor(),
            statement: "keep the SSH service active".into(),
            status: IntentStatus::Active,
            requirements: vec![Requirement {
                id: id(RequirementId::new("requirement:ssh-active")),
                kind: RequirementKind::Goal,
                statement: "SSH service is active".into(),
            }],
            supersedes: vec![],
        }
    }

    fn systemd_blueprint(capability: &str, desired_active_state: &str) -> CapabilityBlueprint {
        CapabilityBlueprint {
            id: id(CapabilityId::new(capability)),
            title: capability.into(),
            relations: vec![],
            desired_resources: vec![DesiredResourceBlueprint {
                provider: id(ProviderId::new("systemd")),
                resource: id(ResourceId::new("systemd:unit:ssh.service")),
                observation_capability: id(CapabilityId::new("systemd.unit.observe")),
                state: BTreeMap::from([("active_state".into(), desired_active_state.into())]),
            }],
        }
    }

    fn observation(active_state: &str) -> PlanningObservation {
        PlanningObservation {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new("systemd:unit:ssh.service")),
            observation_capability: id(CapabilityId::new("systemd.unit.observe")),
            authority: "synthetic-test".into(),
            evidence_id: "observation:test:ssh:1".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("active_state".into(), active_state.into())]),
        }
    }

    fn desired(active_state: &str) -> DesiredResource {
        DesiredResource {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new("systemd:unit:ssh.service")),
            observation_capability: id(CapabilityId::new("systemd.unit.observe")),
            state: BTreeMap::from([("active_state".into(), active_state.into())]),
            reason: SemanticReason {
                summary: "keep SSH active".into(),
                intent_ids: vec![id(IntentId::new("intent:ssh"))],
                requirement_ids: vec![],
                capability_ids: vec![id(CapabilityId::new("remote.ssh"))],
            },
        }
    }

    #[test]
    fn intent_compilation_is_deterministic_and_preserves_causal_origins() {
        let capability = id(CapabilityId::new("remote.ssh"));
        let mut catalog = CapabilityCatalog::default();
        catalog.register(systemd_blueprint("remote.ssh", "active"));
        let planner = DeterministicPlanner;

        let first = planner
            .compile_intent(&intent(), &catalog, std::slice::from_ref(&capability))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second = planner
            .compile_intent(&intent(), &catalog, std::slice::from_ref(&capability))
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(first, second);
        assert_eq!(first.desired_state.resources.len(), 1);
        let resource = &first.desired_state.resources[0];
        assert_eq!(
            resource.state.get("active_state").map(String::as_str),
            Some("active")
        );
        assert_eq!(
            resource.reason.intent_ids,
            vec![id(IntentId::new("intent:ssh"))]
        );
        assert!(resource.reason.requirement_ids.is_empty());
        assert_eq!(resource.reason.capability_ids, vec![capability]);
    }

    #[test]
    fn conflicting_capability_desired_state_fails_closed() {
        let mut catalog = CapabilityCatalog::default();
        catalog.register(systemd_blueprint("remote.ssh.active", "active"));
        catalog.register(systemd_blueprint("remote.ssh.inactive", "inactive"));
        let requested = vec![
            id(CapabilityId::new("remote.ssh.active")),
            id(CapabilityId::new("remote.ssh.inactive")),
        ];

        let result = DeterministicPlanner.compile_intent(&intent(), &catalog, &requested);
        assert!(matches!(
            result,
            Err(PlanningError::DesiredStateConflict { .. })
        ));
    }

    #[test]
    fn authoritative_diff_proposes_change_without_authorizing_execution() {
        let plan = DeterministicPlanner
            .plan_resource(
                id(RequestId::new("request:ssh-active")),
                actor(),
                desired("active"),
                &observation("inactive"),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(plan.status, PlanStatus::ChangeProposed);
        assert_eq!(plan.prospective_risk, RiskClass::SystemMutation);
        assert!(!plan.execution_authorized());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].current.as_deref(), Some("inactive"));
        assert_eq!(plan.changes[0].desired, "active");
    }

    #[test]
    fn unobserved_desired_attribute_blocks_plan() {
        let mut desired = desired("active");
        desired
            .state
            .insert("unit_file_state".into(), "enabled".into());
        let plan = DeterministicPlanner
            .plan_resource(
                id(RequestId::new("request:ssh-enabled")),
                actor(),
                desired,
                &observation("inactive"),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(plan.status, PlanStatus::Blocked);
        assert!(plan.has_blockers());
        assert!(
            plan.findings
                .iter()
                .any(|finding| finding.code == "attribute-not-observed")
        );
        assert!(!plan.execution_authorized());
    }

    #[test]
    fn already_satisfied_state_is_a_no_change_plan() {
        let plan = DeterministicPlanner
            .plan_resource(
                id(RequestId::new("request:ssh-no-change")),
                actor(),
                desired("active"),
                &observation("active"),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(plan.status, PlanStatus::NoChange);
        assert_eq!(plan.prospective_risk, RiskClass::ReadOnly);
        assert!(plan.changes.is_empty());
        assert!(!plan.execution_authorized());
    }

    #[test]
    fn stale_observation_cannot_be_planned() {
        let mut stale = observation("inactive");
        stale.freshness = PlanningFreshness::Stale;
        let result = DeterministicPlanner.plan_resource(
            id(RequestId::new("request:stale")),
            actor(),
            desired("active"),
            &stale,
        );
        assert!(matches!(
            result,
            Err(PlanningError::ObservationNotCurrent(
                PlanningFreshness::Stale
            ))
        ));
    }

    #[test]
    fn plan_store_rejects_idempotency_key_reuse_for_different_plan() {
        let request_id = id(RequestId::new("request:idempotent"));
        let first = DeterministicPlanner
            .plan_resource(
                request_id.clone(),
                actor(),
                desired("active"),
                &observation("inactive"),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second = DeterministicPlanner
            .plan_resource(
                request_id,
                actor(),
                desired("inactive"),
                &observation("inactive"),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut store = PlanStore::default();
        store
            .insert(first.clone())
            .unwrap_or_else(|error| unreachable!("{error}"));
        store
            .insert(first)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let result = store.insert(second);
        assert!(matches!(
            result,
            Err(PlanStoreError::IdempotencyConflict { .. })
        ));
    }
}
