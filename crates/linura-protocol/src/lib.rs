#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use linura_core::{
    Actor, Capability, CapabilityId, IntentId, PlanId, PolicyId, PolicyRevisionId, PrincipalId,
    ProviderId, RequestId, ResourceId, RiskClass, SemanticReason, SetupId,
};
use linura_graph::{RemovalImpact, SystemGraph};
use linura_intent::{Intent, IntentProposal, MachineProfile, Setup};
use linura_observation::{FreshnessState, ObservationEnvelope, ProviderHealth};
use linura_provenance::WhyChain;

pub const PROTOCOL_MAJOR: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub product_version: &'static str,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            product_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySnapshot {
    pub profile_id: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSnapshot {
    pub providers: Vec<ProviderHealth>,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRequest {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationResponse {
    pub observation: ObservationEnvelope,
    pub freshness: FreshnessState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSystemSnapshot {
    pub graph: SystemGraph,
    pub providers: ProviderSnapshot,
}

/// Authenticated desired-state request for one non-executable reconciliation preview.
///
/// Actor identity is deliberately absent. Local transports derive the actor and
/// authorization principal from authenticated transport credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDesiredStateRequest {
    pub request_id: RequestId,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub reason: SemanticReason,
    pub desired_state: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanPreviewStatus {
    NoChange,
    ChangeProposed,
    Blocked,
}

impl PlanPreviewStatus {
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
pub enum PlanPreviewFindingLevel {
    Pass,
    Warning,
    Blocker,
}

impl PlanPreviewFindingLevel {
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
pub struct PlanPreviewChange {
    pub key: String,
    pub current: Option<String>,
    pub desired: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPreviewFinding {
    pub code: String,
    pub level: PlanPreviewFindingLevel,
    pub message: String,
}

/// Public, transport-neutral projection of a deterministic reconciliation plan.
///
/// `execution_authorized` is present so wire/schema consumers can assert the
/// authority boundary explicitly. Conforming Linura transports reject a value of
/// `true`; the current public plan lineage has no conversion into an executable effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPreview {
    pub plan_id: PlanId,
    pub request_id: RequestId,
    pub actor: Actor,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub reason: SemanticReason,
    pub observed_evidence_id: String,
    pub prospective_risk: RiskClass,
    pub status: PlanPreviewStatus,
    pub execution_authorized: bool,
    pub changes: Vec<PlanPreviewChange>,
    pub findings: Vec<PlanPreviewFinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanReviewApprovalClass {
    InteractiveUser,
    Administrator,
    DestructiveAction,
}

impl PlanReviewApprovalClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveUser => "interactive-user",
            Self::Administrator => "administrator",
            Self::DestructiveAction => "destructive-action",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanReviewDecision {
    Allow,
    Deny,
    RequireApproval,
    Blocked,
}

impl PlanReviewDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require-approval",
            Self::Blocked => "blocked",
        }
    }
}

/// Public, transport-neutral projection of Control's trusted review of one
/// retained canonical plan. This is explanation/authorization evidence only;
/// it deliberately contains no executor handle, grant, prepare record, or
/// conversion into an external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanReview {
    pub plan_id: PlanId,
    pub request_id: RequestId,
    pub principal: PrincipalId,
    pub actor: Actor,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub reason: SemanticReason,
    pub observed_evidence_id: String,
    pub planner_risk_floor: RiskClass,
    pub reviewed_risk: RiskClass,
    pub status: PlanPreviewStatus,
    pub policy_id: PolicyId,
    pub policy_revision_id: PolicyRevisionId,
    pub decision: PlanReviewDecision,
    pub approval_class: Option<PlanReviewApprovalClass>,
    pub decision_reason: String,
    pub execution_authorized: bool,
    pub changes: Vec<PlanPreviewChange>,
    pub findings: Vec<PlanPreviewFinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentCommand {
    Propose(Box<IntentProposal>),
    Activate(IntentId),
    Suspend(IntentId),
    Retire(IntentId),
    Supersede { old: IntentId, new: Intent },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplainTarget {
    Intent(IntentId),
    Setup(SetupId),
    Resource(ResourceId),
    Capability(CapabilityId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainResponse {
    pub target: ExplainTarget,
    pub why: WhyChain,
    pub removal_impact: Option<RemovalImpact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationExplanation {
    pub resource: ResourceId,
    pub provider: ProviderId,
    pub capability: CapabilityId,
    pub freshness: FreshnessState,
    pub evidence_id: String,
    pub authority: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemSnapshot {
    pub graph: SystemGraph,
    pub active_intents: Vec<Intent>,
}

/// Self-contained portable setup bundle. It carries the reusable setup graph and
/// the intent definitions needed to adopt it on the same or another machine.
/// Secret values are never embedded; setup definitions carry only secret refs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableSetupExport {
    pub root_setup_id: SetupId,
    pub setups: Vec<Setup>,
    pub intents: Vec<Intent>,
    pub format_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupAdoptionRequest {
    pub actor: Actor,
    pub bundle: PortableSetupExport,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupAdoptionResponse {
    pub imported_setup_ids: Vec<SetupId>,
    pub imported_intent_ids: Vec<IntentId>,
    pub missing_secret_refs: Vec<String>,
    pub warnings: Vec<String>,
    pub requires_plan: bool,
}

/// A portable machine profile export is self-contained: the profile references
/// setup/intent IDs while this bundle carries those definitions for replay. The
/// profile's canonical machine class is retained in the typed profile itself so
/// adoption can detect and review cross-class replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableProfileExport {
    pub profile: MachineProfile,
    pub setups: Vec<Setup>,
    pub intents: Vec<Intent>,
    pub format_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileAdoptionRequest {
    pub actor: Actor,
    pub bundle: PortableProfileExport,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileAdoptionResponse {
    pub imported_setup_ids: Vec<SetupId>,
    pub imported_intent_ids: Vec<IntentId>,
    pub missing_secret_refs: Vec<String>,
    pub warnings: Vec<String>,
    pub requires_plan: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::ProfileId;
    use linura_intent::MachineClass;

    #[test]
    fn preview_contract_names_are_explicitly_non_executable() {
        assert_eq!(PlanPreviewStatus::NoChange.as_str(), "no-change");
        assert_eq!(
            PlanPreviewStatus::ChangeProposed.as_str(),
            "change-proposed"
        );
        assert_eq!(PlanPreviewStatus::Blocked.as_str(), "blocked");
        assert_eq!(PlanPreviewFindingLevel::Blocker.as_str(), "blocker");
        assert_eq!(
            PlanReviewDecision::RequireApproval.as_str(),
            "require-approval"
        );
        assert_eq!(
            PlanReviewApprovalClass::Administrator.as_str(),
            "administrator"
        );
    }

    #[test]
    fn public_request_has_no_actor_field_constructor_requirement() {
        let request = PlanDesiredStateRequest {
            request_id: RequestId::new("request:test")
                .unwrap_or_else(|error| unreachable!("{error}")),
            provider: ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new("systemd:unit:test.service")
                .unwrap_or_else(|error| unreachable!("{error}")),
            observation_capability: CapabilityId::new("systemd.unit.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            reason: SemanticReason {
                summary: "keep test active".into(),
                intent_ids: vec![
                    IntentId::new("intent:test").unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            desired_state: BTreeMap::from([("active_state".into(), "active".into())]),
        };
        assert_eq!(request.request_id.as_str(), "request:test");
    }

    #[test]
    fn portable_profile_export_retains_machine_class() {
        let bundle = PortableProfileExport {
            profile: MachineProfile {
                id: ProfileId::new("profile:edge-gateway")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                name: "Edge gateway".into(),
                machine_class: MachineClass::Edge,
                setup_ids: vec![],
                intent_ids: vec![],
                portable_constraints: vec!["intermittent-connectivity".into()],
                hardware_hints: vec![],
            },
            setups: vec![],
            intents: vec![],
            format_version: 1,
        };

        assert_eq!(bundle.profile.machine_class, MachineClass::Edge);
        assert_eq!(bundle.profile.machine_class.as_str(), "edge");
    }
}
