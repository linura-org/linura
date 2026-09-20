use linura_capability_sdk::{OperationDescriptor, OperationRegistry};
use linura_core::{OperationClass, OperationId, RiskClass};
use linura_planner::ReconciliationPlan;

use crate::risk_classification::{RiskClassification, classify_plan_risk};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedExternalOperationSemantics {
    operation_id: OperationId,
    class: OperationClass,
    risk: RiskClass,
}

impl TrustedExternalOperationSemantics {
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn class(&self) -> OperationClass {
        self.class
    }

    #[must_use]
    pub const fn risk(&self) -> RiskClass {
        self.risk
    }

    #[must_use]
    pub const fn requires_plan_bound_authorization(&self) -> bool {
        self.class.requires_plan_bound_external_authorization()
    }

    #[must_use]
    pub const fn permits_privileged_executor(&self) -> bool {
        self.class.permits_privileged_executor()
    }

    #[must_use]
    pub const fn requires_durable_managed_lifecycle(&self) -> bool {
        self.class.requires_canonical_managed_lifecycle()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSemanticsError {
    UnknownOperation(OperationId),
    NotPlanBoundExternalEffect {
        operation_id: OperationId,
        class: OperationClass,
    },
    UnclassifiedRisk(OperationId),
    RiskDowngradeRejected(OperationId),
    TransientRiskExceedsBoundary {
        operation_id: OperationId,
        risk: RiskClass,
    },
}

#[derive(Clone, Debug)]
pub struct OperationSemanticsControl {
    registry: OperationRegistry,
}

impl OperationSemanticsControl {
    #[must_use]
    pub fn new(registry: OperationRegistry) -> Self {
        Self { registry }
    }

    #[must_use]
    pub fn descriptor(&self, operation_id: &OperationId) -> Option<&OperationDescriptor> {
        self.registry.descriptor(operation_id)
    }

    pub fn resolve_external(
        &self,
        operation_id: &OperationId,
        plan: &ReconciliationPlan,
    ) -> Result<TrustedExternalOperationSemantics, OperationSemanticsError> {
        let descriptor = self
            .registry
            .descriptor(operation_id)
            .ok_or_else(|| OperationSemanticsError::UnknownOperation(operation_id.clone()))?;

        let class = descriptor.class();
        if !class.requires_plan_bound_external_authorization() {
            return Err(OperationSemanticsError::NotPlanBoundExternalEffect {
                operation_id: operation_id.clone(),
                class,
            });
        }

        let trusted_risk = match classify_plan_risk(plan) {
            RiskClassification::NotApplicable { risk }
            | RiskClassification::Classified { risk, .. } => risk,
            RiskClassification::Unclassified { .. } => {
                return Err(OperationSemanticsError::UnclassifiedRisk(
                    operation_id.clone(),
                ));
            }
            RiskClassification::DowngradeRejected { .. } => {
                return Err(OperationSemanticsError::RiskDowngradeRejected(
                    operation_id.clone(),
                ));
            }
        };

        let risk = descriptor
            .risk_floor()
            .map_or(trusted_risk, |floor| std::cmp::max(floor, trusted_risk));

        if class == OperationClass::TransientExternalEffect && risk > RiskClass::UserState {
            return Err(OperationSemanticsError::TransientRiskExceedsBoundary {
                operation_id: operation_id.clone(),
                risk,
            });
        }

        Ok(TrustedExternalOperationSemantics {
            operation_id: operation_id.clone(),
            class,
            risk,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_capability_sdk::OperationDescriptor;
    use linura_core::{
        Actor, ActorId, ActorKind, CapabilityId, IntentId, ProviderId, RequestId, ResourceId,
        SemanticReason,
    };
    use linura_planner::{
        DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
    };

    use super::*;

    fn operation_id(value: &str) -> OperationId {
        OperationId::new(value).unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn registry_with(descriptors: Vec<OperationDescriptor>) -> OperationRegistry {
        let mut registry = OperationRegistry::default();
        for descriptor in descriptors {
            registry
                .register(descriptor)
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        }
        registry
    }

    fn canonical_systemd_plan(resource: &str) -> ReconciliationPlan {
        let provider = ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new(resource).unwrap_or_else(|error| unreachable!("{error}"));
        let capability = CapabilityId::new("systemd.unit.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "manage test unit".into(),
                intent_ids: vec![
                    IntentId::new("intent:operation-semantics")
                        .unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        };
        let observation = PlanningObservation {
            provider,
            resource,
            observation_capability: capability,
            authority: "authoritative".into(),
            evidence_id: "evidence:operation-semantics".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("active_state".into(), "inactive".into())]),
        };
        DeterministicPlanner
            .plan_resource(
                RequestId::new("request:operation-semantics")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                Actor {
                    id: ActorId::new("actor:human")
                        .unwrap_or_else(|error| unreachable!("{error}")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                desired,
                &observation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn unknown_operation_fails_closed() {
        let control = OperationSemanticsControl::new(OperationRegistry::default());
        let id = operation_id("operation:missing");
        assert_eq!(
            control.resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service")),
            Err(OperationSemanticsError::UnknownOperation(id))
        );
    }

    #[test]
    fn non_external_operation_cannot_enter_external_authority_path() {
        let id = operation_id("operation:network.inspect");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::AuthoritativeQuery,
            Some(RiskClass::ReadOnly),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = OperationSemanticsControl::new(registry_with(vec![descriptor]));

        assert_eq!(
            control.resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service")),
            Err(OperationSemanticsError::NotPlanBoundExternalEffect {
                operation_id: id,
                class: OperationClass::AuthoritativeQuery,
            })
        );
    }

    #[test]
    fn transient_operation_rejects_plan_risk_above_user_state() {
        let id = operation_id("operation:service.start-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = OperationSemanticsControl::new(registry_with(vec![descriptor]));

        assert_eq!(
            control.resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service")),
            Err(OperationSemanticsError::TransientRiskExceedsBoundary {
                operation_id: id,
                risk: RiskClass::SecuritySensitive,
            })
        );
    }

    #[test]
    fn managed_operation_uses_trusted_plan_risk_and_registered_floor() {
        let id = operation_id("operation:service.manage");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::ManagedExternalEffect,
            Some(RiskClass::Destructive),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = OperationSemanticsControl::new(registry_with(vec![descriptor]));

        let resolved = control
            .resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service"))
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(resolved.operation_id(), &id);
        assert_eq!(resolved.class(), OperationClass::ManagedExternalEffect);
        assert_eq!(resolved.risk(), RiskClass::Destructive);
        assert!(resolved.requires_plan_bound_authorization());
        assert!(resolved.permits_privileged_executor());
        assert!(resolved.requires_durable_managed_lifecycle());
    }
}
