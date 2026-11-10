//! S18-3: Control-owned, non-authorizing NetworkManager operation semantics.
//!
//! No candidate in this module is registered for execution. The typed table
//! refines review and denial only: it cannot create an approval, durable
//! prepare, native grant, executor payload, or recovery replay. The inherited
//! managed lifecycle is the *only* future durable-authority route.

use linura_core::{
    ActorKind, NetworkActiveConnectionId, NetworkDeviceId, NetworkManagerEpoch,
    NetworkObservationId, NetworkProfileRevision, OperationClass, RiskClass,
};
use linura_planner::{PlanStatus, ReconciliationPlan};
use linura_transaction::TransactionState;

use crate::AuthenticatedPrincipal;

pub const NETWORK_PROVIDER: &str = "networkmanager";
const MAX_EVIDENCE_BYTES: usize = 1024;
const MAX_OBSERVATION_AGE_US: u64 = 5_000_000;
const MAX_IMPACT_ENTRIES: u32 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkOperation {
    WifiScan,
    NetworkingEnabled,
    WifiEnabled,
    ConnectionActivate,
    ConnectionDeactivate,
    WifiJoin,
    ProfileCreate,
    ProfileUpdate,
    ProfileDelete,
}

impl NetworkOperation {
    pub const ALL: [Self; 9] = [
        Self::WifiScan,
        Self::NetworkingEnabled,
        Self::WifiEnabled,
        Self::ConnectionActivate,
        Self::ConnectionDeactivate,
        Self::WifiJoin,
        Self::ProfileCreate,
        Self::ProfileUpdate,
        Self::ProfileDelete,
    ];

    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::WifiScan => "operation:network.wifi.scan",
            Self::NetworkingEnabled => "operation:network.networking.set-enabled",
            Self::WifiEnabled => "operation:network.wifi.set-enabled",
            Self::ConnectionActivate => "operation:network.connection.activate",
            Self::ConnectionDeactivate => "operation:network.connection.deactivate",
            Self::WifiJoin => "operation:network.wifi.join",
            Self::ProfileCreate => "operation:network.profile.create",
            Self::ProfileUpdate => "operation:network.profile.update",
            Self::ProfileDelete => "operation:network.profile.delete",
        }
    }

    pub const fn class(self) -> OperationClass {
        OperationClass::ManagedExternalEffect
    }

    pub const fn floor(self) -> RiskClass {
        match self {
            Self::WifiScan => RiskClass::UserState,
            Self::ProfileDelete => RiskClass::Destructive,
            _ => RiskClass::SecuritySensitive,
        }
    }

    pub const fn observation_capability(self) -> &'static str {
        match self {
            Self::WifiScan => "networkmanager.wifi.observe",
            Self::NetworkingEnabled | Self::WifiEnabled => "networkmanager.manager.observe",
            _ => "networkmanager.connections.observe",
        }
    }

    pub const fn change_key(self) -> &'static str {
        match self {
            Self::WifiScan => "scan_requested",
            Self::NetworkingEnabled => "networking_enabled",
            Self::WifiEnabled => "wireless_enabled",
            Self::ConnectionActivate | Self::ConnectionDeactivate | Self::WifiJoin => "active",
            Self::ProfileCreate | Self::ProfileUpdate => "typed_profile",
            Self::ProfileDelete => "removed",
        }
    }

    pub const fn impacts_connectivity(self) -> bool {
        !matches!(self, Self::WifiScan)
    }

    pub const fn always_requires_local_recovery(self) -> bool {
        matches!(
            self,
            Self::NetworkingEnabled
                | Self::WifiEnabled
                | Self::ConnectionDeactivate
                | Self::ProfileDelete
        )
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.operation_id() == id)
    }
}

/// An exact typed native target is correlation only, *never* effect authority.
/// It must match the same provider epoch as the fresh observation.
#[derive(Clone, Copy, Debug)]
pub enum NetworkTarget<'a> {
    Manager(&'a NetworkManagerEpoch),
    WifiDevice(&'a NetworkDeviceId),
    Profile {
        device: Option<&'a NetworkDeviceId>,
        profile: &'a NetworkProfileRevision,
    },
    Activation(&'a NetworkActiveConnectionId),
    Settings(&'a NetworkManagerEpoch),
}

impl NetworkTarget<'_> {
    fn epoch(&self) -> &NetworkManagerEpoch {
        match self {
            Self::Manager(epoch) | Self::Settings(epoch) => epoch,
            Self::WifiDevice(device) => device.epoch(),
            Self::Profile { profile, .. } => profile.epoch(),
            Self::Activation(activation) => activation.device().epoch(),
        }
    }
}

/// A bounded preview of possible network disruption. These values are *not*
/// independently authenticated native facts. They can reject a review, but
/// never grant permission, prove local fallback, or authorize a dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct NetworkImpact {
    pub ipv4_default_routes_at_risk: u32,
    pub ipv6_default_routes_at_risk: u32,
    pub dns_servers_at_risk: u32,
    pub remote_control_path_at_risk: bool,
    pub offline_local_recovery_reviewed: bool,
    pub native_impact_complete: bool,
}

impl NetworkImpact {
    fn significant(self) -> bool {
        self.ipv4_default_routes_at_risk > 0
            || self.ipv6_default_routes_at_risk > 0
            || self.dns_servers_at_risk > 0
    }

    fn require_safe_preview(self, operation: NetworkOperation) -> Result<(), NetworkReviewError> {
        if self.ipv4_default_routes_at_risk > MAX_IMPACT_ENTRIES
            || self.ipv6_default_routes_at_risk > MAX_IMPACT_ENTRIES
            || self.dns_servers_at_risk > MAX_IMPACT_ENTRIES
        {
            return Err(NetworkReviewError::ImpactTooLarge);
        }
        if operation.impacts_connectivity() && !self.native_impact_complete {
            return Err(NetworkReviewError::UnknownNativeImpact);
        }
        if operation.impacts_connectivity() && self.remote_control_path_at_risk {
            return Err(NetworkReviewError::RemoteControlPathAtRisk);
        }
        if (operation.always_requires_local_recovery() || self.significant())
            && !self.offline_local_recovery_reviewed
        {
            return Err(NetworkReviewError::OfflineLocalRecoveryUnproven);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkReviewError {
    UnauthenticatedPrincipal,
    NonInteractiveActor,
    NoncanonicalPlan,
    PlanBlocked,
    NoChange,
    InvalidEvidence,
    InvalidObservation,
    IdentityEpochChanged,
    TargetMismatch,
    UnexpectedProvider,
    UnexpectedCapability,
    UnexpectedResource,
    UnexpectedPostcondition,
    RiskDowngrade,
    ImpactTooLarge,
    UnknownNativeImpact,
    RemoteControlPathAtRisk,
    OfflineLocalRecoveryUnproven,
    ProtectedProfilePayloadUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkReviewDisposition {
    /// All nine operations remain unregistered and impossible to dispatch.
    AwaitingSeparateNativeQualification,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkAuthorityAssessment {
    operation: NetworkOperation,
    risk: RiskClass,
    disposition: NetworkReviewDisposition,
}

impl NetworkAuthorityAssessment {
    pub const fn risk(&self) -> RiskClass {
        self.risk
    }

    pub const fn disposition(&self) -> NetworkReviewDisposition {
        self.disposition
    }

    pub const fn operation(&self) -> NetworkOperation {
        self.operation
    }
}

/// A recovery decision does not issue a dispatch permit. It is only a
/// description of the existing durable TransactionStore state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRecoveryRule {
    NeverDispatch,
    ObserveOnly,
    AwaitOriginalDurableCommit,
    TerminalNoReplay,
}

pub const fn recovery_rule(state: TransactionState) -> NetworkRecoveryRule {
    match state {
        TransactionState::Prepared => NetworkRecoveryRule::NeverDispatch,
        TransactionState::Indeterminate | TransactionState::RecoveryBlocked => {
            NetworkRecoveryRule::ObserveOnly
        }
        TransactionState::Verified => NetworkRecoveryRule::AwaitOriginalDurableCommit,
        TransactionState::Committed | TransactionState::Aborted => {
            NetworkRecoveryRule::TerminalNoReplay
        }
    }
}

fn expected_resource(
    operation: NetworkOperation,
    target: NetworkTarget<'_>,
) -> Result<String, NetworkReviewError> {
    match (operation, target) {
        (NetworkOperation::WifiScan, NetworkTarget::WifiDevice(device)) => Ok(format!(
            "networkmanager:wifi:{}",
            device.interface().as_str()
        )),
        (
            NetworkOperation::NetworkingEnabled | NetworkOperation::WifiEnabled,
            NetworkTarget::Manager(_),
        ) => Ok("networkmanager:manager".into()),
        (
            NetworkOperation::ConnectionActivate | NetworkOperation::WifiJoin,
            NetworkTarget::Profile {
                device: Some(_),
                profile,
            },
        )
        | (
            NetworkOperation::ProfileUpdate | NetworkOperation::ProfileDelete,
            NetworkTarget::Profile { profile, .. },
        ) => Ok(format!(
            "networkmanager:profile:{}",
            profile.object().sequence()
        )),
        (NetworkOperation::ConnectionDeactivate, NetworkTarget::Activation(activation)) => Ok(
            format!("networkmanager:active:{}", activation.object().sequence()),
        ),
        (NetworkOperation::ProfileCreate, NetworkTarget::Settings(_)) => {
            Ok("networkmanager:connections".into())
        }
        _ => Err(NetworkReviewError::TargetMismatch),
    }
}

/// Read-only, non-granting Control review. These facts are correlation; future
/// executors must independently re-attest exact native identity *and* source
/// before a durable prepare or native dispatch can ever be added by S18-4+.
#[allow(clippy::too_many_arguments)]
pub fn assess_network_candidate(
    principal: &AuthenticatedPrincipal,
    plan: &ReconciliationPlan,
    operation: NetworkOperation,
    target: NetworkTarget<'_>,
    observation: &NetworkObservationId,
    current_epoch: &NetworkManagerEpoch,
    now_monotonic_us: u64,
    impact: NetworkImpact,
) -> Result<NetworkAuthorityAssessment, NetworkReviewError> {
    let uid = principal
        .as_str()
        .strip_prefix("unix:uid:")
        .ok_or(NetworkReviewError::UnauthenticatedPrincipal)?;
    if uid.is_empty()
        || (uid.len() > 1 && uid.starts_with('0'))
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || uid.parse::<u32>().is_err()
    {
        return Err(NetworkReviewError::UnauthenticatedPrincipal);
    }
    if plan.actor.kind != ActorKind::Human || !plan.actor.interactive {
        return Err(NetworkReviewError::NonInteractiveActor);
    }
    if plan.execution_authorized() {
        return Err(NetworkReviewError::NoncanonicalPlan);
    }
    if plan.status == PlanStatus::NoChange {
        return Err(NetworkReviewError::NoChange);
    }
    if plan.status != PlanStatus::ChangeProposed || plan.has_blockers() {
        return Err(NetworkReviewError::PlanBlocked);
    }
    if plan.observed_evidence_id.is_empty()
        || plan.observed_evidence_id.len() > MAX_EVIDENCE_BYTES
        || plan.observed_evidence_id.chars().any(char::is_control)
    {
        return Err(NetworkReviewError::InvalidEvidence);
    }
    observation
        .require_fresh(current_epoch, now_monotonic_us, MAX_OBSERVATION_AGE_US)
        .map_err(|_| NetworkReviewError::InvalidObservation)?;
    current_epoch
        .require_same(target.epoch())
        .map_err(|_| NetworkReviewError::IdentityEpochChanged)?;
    if let NetworkTarget::Profile {
        device: Some(device),
        profile,
    } = target
    {
        current_epoch
            .require_same(device.epoch())
            .map_err(|_| NetworkReviewError::IdentityEpochChanged)?;
        current_epoch
            .require_same(profile.epoch())
            .map_err(|_| NetworkReviewError::IdentityEpochChanged)?;
    }
    if plan.provider.as_str() != NETWORK_PROVIDER {
        return Err(NetworkReviewError::UnexpectedProvider);
    }
    if plan.observation_capability.as_str() != operation.observation_capability() {
        return Err(NetworkReviewError::UnexpectedCapability);
    }
    if plan.resource.as_str() != expected_resource(operation, target)? {
        return Err(NetworkReviewError::UnexpectedResource);
    }
    if plan.changes.len() != 1 || plan.changes[0].key != operation.change_key() {
        return Err(NetworkReviewError::UnexpectedPostcondition);
    }
    let desired = plan.changes[0].desired.as_str();
    match operation {
        NetworkOperation::WifiScan
        | NetworkOperation::ConnectionActivate
        | NetworkOperation::WifiJoin
        | NetworkOperation::ProfileDelete
            if desired != "true" =>
        {
            return Err(NetworkReviewError::UnexpectedPostcondition);
        }
        NetworkOperation::ConnectionDeactivate if desired != "false" => {
            return Err(NetworkReviewError::UnexpectedPostcondition);
        }
        NetworkOperation::NetworkingEnabled | NetworkOperation::WifiEnabled
            if !matches!(desired, "true" | "false") =>
        {
            return Err(NetworkReviewError::UnexpectedPostcondition);
        }
        // Typed profile requests in S18-8 must never be collapsed into an
        // opaque string, JSON, arbitrary settings map, or credential-bearing
        // canonical PlanDesiredStateRequest. Classify, then reject here.
        NetworkOperation::ProfileCreate | NetworkOperation::ProfileUpdate => {
            return Err(NetworkReviewError::ProtectedProfilePayloadUnavailable);
        }
        _ => {}
    }
    // The canonical planner classifies changed resources as SystemMutation.
    // The trusted S18 operation table *raises* that baseline to the fixed
    // reviewed floor. A forged plan reporting a lesser-than-mutation risk
    // for an actual change is denied; never accept a client-provided low
    // risk as an override, and never turn this assessment into a permit.
    if plan.prospective_risk < RiskClass::SystemMutation {
        return Err(NetworkReviewError::RiskDowngrade);
    }
    impact.require_safe_preview(operation)?;
    Ok(NetworkAuthorityAssessment {
        operation,
        risk: plan.prospective_risk.max(operation.floor()),
        disposition: NetworkReviewDisposition::AwaitingSeparateNativeQualification,
    })
}

/// No speculative source, client, observation, or policy receipt can promote
/// one of the candidate network operations to the managed execution route.
pub(crate) fn require_network_effect_inactive(provider: &str) -> Result<(), &'static str> {
    if provider == NETWORK_PROVIDER {
        return Err("S18 network mutations are not natively qualified or registered");
    }
    Ok(())
}

// Transient registrations are untrusted for S18: passive discovery is a
// query, while RequestScan emits radio traffic and is a managed candidate.
// An arbitrary provider label cannot launder an operation:network.* request
// into the audio/transient executor, and neither may a network provider
// borrow a different operation ID to bypass source classification.
pub(crate) fn require_network_transient_inactive(
    provider: &str,
    operation_id: &str,
) -> Result<(), &'static str> {
    if provider == NETWORK_PROVIDER || operation_id.starts_with("operation:network.") {
        return Err("S18 network mutations cannot enter the transient executor");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_core::{
        Actor, ActorId, BootId, CapabilityId, IntentId, NetworkInterfaceName, NetworkManagerOwner,
        NetworkObjectId, NetworkObjectKind, OperationId, ProviderId, RequestId, ResourceId,
        SemanticReason, SystemBusInstanceId,
    };
    use linura_planner::{
        DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
    };

    use super::*;

    fn checked<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("known test fixture: {error:?}"))
    }

    fn epoch() -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(":1.48")),
        )
    }

    fn device() -> NetworkDeviceId {
        checked(NetworkDeviceId::new(
            epoch(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            4_026_531_840,
            7,
            checked(NetworkInterfaceName::new("wlan0")),
            8,
        ))
    }

    fn profile() -> NetworkProfileRevision {
        checked(NetworkProfileRevision::new(
            epoch(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                "/org/freedesktop/NetworkManager/Settings/9",
            )),
            "10203040-5060-7080-90ab-cdef12345678",
            10,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        ))
    }

    fn observation() -> NetworkObservationId {
        checked(NetworkObservationId::new(epoch(), 4, 10_000))
    }

    fn principal() -> AuthenticatedPrincipal {
        checked(AuthenticatedPrincipal::new("unix:uid:1000"))
    }

    fn plan(operation: NetworkOperation, resource: &str, desired: &str) -> ReconciliationPlan {
        let provider = checked(ProviderId::new(NETWORK_PROVIDER));
        let resource = checked(ResourceId::new(resource));
        let capability = checked(CapabilityId::new(operation.observation_capability()));
        let key = operation.change_key().to_owned();
        let desired_resource = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([(key.clone(), desired.into())]),
            reason: SemanticReason {
                summary: "review native network state".into(),
                intent_ids: vec![checked(IntentId::new("intent:s18-review"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        };
        let observation = PlanningObservation {
            provider,
            resource,
            observation_capability: capability,
            authority: "authoritative".into(),
            evidence_id: "evidence:s18-network".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([(key, "false".into())]),
        };
        checked(DeterministicPlanner.plan_resource(
            checked(RequestId::new("request:s18-review")),
            Actor {
                id: checked(ActorId::new("actor:authenticated-human")),
                kind: ActorKind::Human,
                interactive: true,
            },
            desired_resource,
            &observation,
        ))
    }

    fn safe_impact() -> NetworkImpact {
        NetworkImpact {
            native_impact_complete: true,
            offline_local_recovery_reviewed: true,
            ..NetworkImpact::default()
        }
    }

    #[test]
    fn all_nine_effects_are_fixed_managed_and_unregistered() {
        let registry = crate::operation_registry::trusted_builtin_operation_registry()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let design = include_str!("../../../contracts/v010-s18-design.toml");
        for operation in NetworkOperation::ALL {
            assert_eq!(operation.class(), OperationClass::ManagedExternalEffect);
            let operation_id = checked(OperationId::new(operation.operation_id()));
            assert!(registry.descriptor(&operation_id).is_none());
            let marker = format!("id = \"{}\"", operation.operation_id());
            let matching = design
                .split("[[candidate_operation]]")
                .filter(|block| block.contains(&marker))
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1);
            let floor = match operation.floor() {
                RiskClass::UserState => "user-state",
                RiskClass::SecuritySensitive => "security-sensitive",
                RiskClass::Destructive => "destructive",
                other => unreachable!("unexpected candidate floor: {other:?}"),
            };
            assert!(matching[0].contains(&format!("risk_floor = \"{floor}\"")));
            assert!(matching[0].contains("enabled = false"));
            assert_eq!(
                NetworkOperation::from_id(operation.operation_id()),
                Some(operation),
            );
        }
        assert_eq!(
            NetworkOperation::from_id("operation:network.vpn.enable"),
            None
        );
        assert_eq!(
            NetworkOperation::from_id("operation:systemd.unit.set-active-state"),
            None
        );
    }

    #[test]
    fn networking_and_wifi_radio_requests_use_disjoint_observed_manager_keys() {
        let networking = NetworkOperation::NetworkingEnabled;
        let wireless = NetworkOperation::WifiEnabled;
        assert_eq!(networking.change_key(), "networking_enabled");
        assert_eq!(wireless.change_key(), "wireless_enabled");
        assert_ne!(networking.change_key(), wireless.change_key());
        assert_eq!(
            networking.observation_capability(),
            "networkmanager.manager.observe"
        );
        assert_eq!(
            wireless.observation_capability(),
            "networkmanager.manager.observe"
        );
        let design = include_str!("../../../contracts/v010-s18-design.toml");
        for (op, key) in [
            (networking, "networking_enabled"),
            (wireless, "wireless_enabled"),
        ] {
            let marker = format!("id = \"{}\"", op.operation_id());
            let blocks = design
                .split("[[candidate_operation]]")
                .filter(|block| block.contains(&marker))
                .collect::<Vec<_>>();
            assert_eq!(blocks.len(), 1);
            assert!(blocks[0].contains(&format!("requested_keys = [\"{key}\"]")));
            assert!(blocks[0].contains("enabled = false"));
        }
    }

    #[test]
    fn exact_identity_principal_epoch_and_plan_required() {
        let source = device();
        let mut p = plan(
            NetworkOperation::WifiScan,
            "networkmanager:wifi:wlan0",
            "true",
        );
        let review = |p: &ReconciliationPlan| {
            assess_network_candidate(
                &principal(),
                p,
                NetworkOperation::WifiScan,
                NetworkTarget::WifiDevice(&source),
                &observation(),
                &epoch(),
                12_000,
                safe_impact(),
            )
        };
        let accepted = review(&p).unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(accepted.risk(), RiskClass::SystemMutation);
        assert_eq!(accepted.operation(), NetworkOperation::WifiScan);
        assert_eq!(
            accepted.disposition(),
            NetworkReviewDisposition::AwaitingSeparateNativeQualification,
        );
        p.resource = checked(ResourceId::new("networkmanager:wifi:wlan1"));
        assert_eq!(review(&p), Err(NetworkReviewError::UnexpectedResource));
        p = plan(
            NetworkOperation::WifiScan,
            "networkmanager:wifi:wlan0",
            "true",
        );
        p.provider = checked(ProviderId::new("systemd"));
        assert_eq!(review(&p), Err(NetworkReviewError::UnexpectedProvider));
        p = plan(
            NetworkOperation::WifiScan,
            "networkmanager:wifi:wlan0",
            "true",
        );
        p.observation_capability = checked(CapabilityId::new("networkmanager.manager.observe"));
        assert_eq!(review(&p), Err(NetworkReviewError::UnexpectedCapability));
        p = plan(
            NetworkOperation::WifiScan,
            "networkmanager:wifi:wlan0",
            "true",
        );
        p.actor.interactive = false;
        assert_eq!(review(&p), Err(NetworkReviewError::NonInteractiveActor));
        p = plan(
            NetworkOperation::WifiScan,
            "networkmanager:wifi:wlan0",
            "true",
        );
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &p,
                NetworkOperation::WifiScan,
                NetworkTarget::WifiDevice(&source),
                &observation(),
                &epoch(),
                5_010_001,
                safe_impact(),
            ),
            Err(NetworkReviewError::InvalidObservation),
        );
        let swapped = NetworkManagerEpoch::new(
            epoch().boot().clone(),
            epoch().bus().clone(),
            checked(NetworkManagerOwner::new(":1.49")),
        );
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &p,
                NetworkOperation::WifiScan,
                NetworkTarget::WifiDevice(&source),
                &observation(),
                &swapped,
                12_000,
                safe_impact(),
            ),
            Err(NetworkReviewError::InvalidObservation),
        );
    }

    #[test]
    fn route_and_dns_risk_cannot_hide_last_link_or_remote_lockout() {
        let current = epoch();
        let target = NetworkTarget::Manager(&current);
        let mut p = plan(
            NetworkOperation::NetworkingEnabled,
            "networkmanager:manager",
            "true",
        );
        p.prospective_risk = RiskClass::ReadOnly;
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &p,
                NetworkOperation::NetworkingEnabled,
                target,
                &observation(),
                &epoch(),
                12_000,
                NetworkImpact::default(),
            ),
            Err(NetworkReviewError::RiskDowngrade),
        );
        let mut elevated = p;
        elevated.prospective_risk = RiskClass::SystemMutation;
        let review = |impact| {
            assess_network_candidate(
                &principal(),
                &elevated,
                NetworkOperation::NetworkingEnabled,
                target,
                &observation(),
                &epoch(),
                12_000,
                impact,
            )
        };
        assert_eq!(
            review(NetworkImpact::default()),
            Err(NetworkReviewError::UnknownNativeImpact)
        );
        assert_eq!(
            review(NetworkImpact {
                native_impact_complete: true,
                ..NetworkImpact::default()
            }),
            Err(NetworkReviewError::OfflineLocalRecoveryUnproven),
        );
        assert_eq!(
            review(NetworkImpact {
                remote_control_path_at_risk: true,
                ..safe_impact()
            }),
            Err(NetworkReviewError::RemoteControlPathAtRisk),
        );
        assert_eq!(
            review(NetworkImpact {
                ipv4_default_routes_at_risk: MAX_IMPACT_ENTRIES + 1,
                ..safe_impact()
            }),
            Err(NetworkReviewError::ImpactTooLarge),
        );
        let accepted = review(safe_impact())
            .unwrap_or_else(|error| unreachable!("canonical risk elevation: {error:?}"));
        assert_eq!(accepted.risk(), RiskClass::SecuritySensitive);
        assert_eq!(
            accepted.disposition(),
            NetworkReviewDisposition::AwaitingSeparateNativeQualification,
        );
    }

    #[test]
    fn profile_alias_opaque_payload_and_unknown_epoch_are_denied() {
        let source = device();
        let revision = profile();
        let mut p = plan(
            NetworkOperation::ConnectionActivate,
            "networkmanager:profile:9",
            "true",
        );
        p.prospective_risk = RiskClass::ReadOnly;
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &p,
                NetworkOperation::ConnectionActivate,
                NetworkTarget::Profile {
                    device: Some(&source),
                    profile: &revision
                },
                &observation(),
                &epoch(),
                12_000,
                safe_impact(),
            ),
            Err(NetworkReviewError::RiskDowngrade),
        );
        let update = plan(
            NetworkOperation::ProfileUpdate,
            "networkmanager:profile:9",
            "secret-material",
        );
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &update,
                NetworkOperation::ProfileUpdate,
                NetworkTarget::Profile {
                    device: None,
                    profile: &revision
                },
                &observation(),
                &epoch(),
                12_000,
                safe_impact(),
            ),
            Err(NetworkReviewError::ProtectedProfilePayloadUnavailable),
        );
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &p,
                NetworkOperation::ConnectionActivate,
                NetworkTarget::Manager(&epoch()),
                &observation(),
                &epoch(),
                12_000,
                safe_impact(),
            ),
            Err(NetworkReviewError::TargetMismatch),
        );
    }

    #[test]
    fn canonical_plan_risk_is_elevated_to_destructive_profile_floor() {
        let revision = profile();
        let plan = plan(
            NetworkOperation::ProfileDelete,
            "networkmanager:profile:9",
            "true",
        );
        // Planner's generic mutation classification is not caller-selected
        // approval and must be raised to the independently trusted S18 floor.
        assert_eq!(plan.prospective_risk, RiskClass::SystemMutation);
        let approved_for_review = assess_network_candidate(
            &principal(),
            &plan,
            NetworkOperation::ProfileDelete,
            NetworkTarget::Profile {
                device: None,
                profile: &revision,
            },
            &observation(),
            &epoch(),
            12_000,
            safe_impact(),
        )
        .unwrap_or_else(|error| unreachable!("trusted floor: {error:?}"));
        assert_eq!(approved_for_review.risk(), RiskClass::Destructive);
        assert_eq!(
            approved_for_review.disposition(),
            NetworkReviewDisposition::AwaitingSeparateNativeQualification,
        );
        let mut forged = plan;
        forged.prospective_risk = RiskClass::UserState;
        assert_eq!(
            assess_network_candidate(
                &principal(),
                &forged,
                NetworkOperation::ProfileDelete,
                NetworkTarget::Profile {
                    device: None,
                    profile: &revision,
                },
                &observation(),
                &epoch(),
                12_000,
                safe_impact(),
            ),
            Err(NetworkReviewError::RiskDowngrade),
        );
    }

    #[test]
    fn indeterminate_attempts_and_terminal_states_cannot_replay() {
        for state in [
            TransactionState::Indeterminate,
            TransactionState::RecoveryBlocked,
        ] {
            assert_eq!(recovery_rule(state), NetworkRecoveryRule::ObserveOnly);
        }
        assert_eq!(
            recovery_rule(TransactionState::Prepared),
            NetworkRecoveryRule::NeverDispatch
        );
        assert_eq!(
            recovery_rule(TransactionState::Verified),
            NetworkRecoveryRule::AwaitOriginalDurableCommit,
        );
        for state in [TransactionState::Committed, TransactionState::Aborted] {
            assert_eq!(recovery_rule(state), NetworkRecoveryRule::TerminalNoReplay);
        }
        assert!(require_network_effect_inactive("networkmanager").is_err());
        assert!(require_network_effect_inactive("systemd").is_ok());
        assert!(
            require_network_transient_inactive(
                "networkmanager",
                "operation:audio.output.set-session-volume"
            )
            .is_err()
        );
        assert!(
            require_network_transient_inactive("pipewire", "operation:network.wifi.scan").is_err()
        );
        assert!(
            require_network_transient_inactive("pipewire", "operation:network.vpn.unknown")
                .is_err()
        );
        assert!(
            require_network_transient_inactive(
                "pipewire",
                "operation:audio.output.set-session-volume"
            )
            .is_ok()
        );
    }
}
