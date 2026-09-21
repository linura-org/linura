use std::collections::BTreeMap;

use linura_capability_sdk::{OperationDescriptor, OperationRegistry};
use linura_core::{OperationClass, OperationId, RiskClass};
use linura_planner::ReconciliationPlan;

use crate::risk_classification::{
    RiskClassification, classify_exact_registered_transient_risk, classify_plan_risk,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedExternalOperationSemantics {
    operation_id: OperationId,
    class: OperationClass,
    risk: RiskClass,
    risk_classification: RiskClassification,
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

    pub(crate) fn risk_classification(&self) -> &RiskClassification {
        &self.risk_classification
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
pub enum OperationPlanBindingMismatch {
    Provider,
    ObservationCapability,
    Resource,
    ChangeKey(String),
    RequestedStateKey(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSemanticsError {
    UnknownOperation(OperationId),
    NotPlanBoundExternalEffect {
        operation_id: OperationId,
        class: OperationClass,
    },
    MissingEffectBinding(OperationId),
    PlanBindingMismatch {
        operation_id: OperationId,
        mismatch: OperationPlanBindingMismatch,
    },
    UnclassifiedRisk(OperationId),
    RiskDowngradeRejected(OperationId),
    TransientRequestedStateRequired(OperationId),
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
    pub(crate) fn from_trusted_registry(registry: OperationRegistry) -> Self {
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
        self.resolve_external_internal(operation_id, plan, None)
    }

    pub(crate) fn resolve_external_with_requested_state(
        &self,
        operation_id: &OperationId,
        plan: &ReconciliationPlan,
        requested_state: &BTreeMap<String, String>,
    ) -> Result<TrustedExternalOperationSemantics, OperationSemanticsError> {
        self.resolve_external_internal(operation_id, plan, Some(requested_state))
    }

    fn resolve_external_internal(
        &self,
        operation_id: &OperationId,
        plan: &ReconciliationPlan,
        requested_state: Option<&BTreeMap<String, String>>,
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

        let binding = descriptor
            .effect_binding()
            .ok_or_else(|| OperationSemanticsError::MissingEffectBinding(operation_id.clone()))?;

        if binding.provider() != &plan.provider {
            return Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: operation_id.clone(),
                mismatch: OperationPlanBindingMismatch::Provider,
            });
        }
        if binding.observation_capability() != &plan.observation_capability {
            return Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: operation_id.clone(),
                mismatch: OperationPlanBindingMismatch::ObservationCapability,
            });
        }
        if !binding.matches_resource(plan.resource.as_str()) {
            return Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: operation_id.clone(),
                mismatch: OperationPlanBindingMismatch::Resource,
            });
        }
        if let Some(change) = plan
            .changes
            .iter()
            .find(|change| !binding.change_keys().contains(&change.key))
        {
            return Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: operation_id.clone(),
                mismatch: OperationPlanBindingMismatch::ChangeKey(change.key.clone()),
            });
        }

        if let Some(requested_state) = requested_state
            && let Some(key) = requested_state
                .keys()
                .find(|key| !binding.change_keys().contains(*key))
        {
            return Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: operation_id.clone(),
                mismatch: OperationPlanBindingMismatch::RequestedStateKey(key.clone()),
            });
        }

        let risk_classification = if class == OperationClass::TransientExternalEffect {
            let requested_state = requested_state.ok_or_else(|| {
                OperationSemanticsError::TransientRequestedStateRequired(operation_id.clone())
            })?;
            classify_exact_registered_transient_risk(plan, requested_state)
        } else {
            classify_plan_risk(plan)
        };
        let trusted_risk = match &risk_classification {
            RiskClassification::NotApplicable { risk }
            | RiskClassification::Classified { risk, .. } => *risk,
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
            risk_classification,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_capability_sdk::{OperationDescriptor, OperationEffectBinding};
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

    fn effect_binding(
        provider: &str,
        capability: &str,
        resource_prefix: &str,
        change_keys: &[&str],
    ) -> OperationEffectBinding {
        OperationEffectBinding::try_new(
            ProviderId::new(provider).unwrap_or_else(|error| unreachable!("{error}")),
            CapabilityId::new(capability).unwrap_or_else(|error| unreachable!("{error}")),
            resource_prefix,
            change_keys.iter().map(|value| (*value).into()).collect(),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"))
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

    fn control_with(descriptors: Vec<OperationDescriptor>) -> OperationSemanticsControl {
        OperationSemanticsControl {
            registry: registry_with(descriptors),
        }
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
                    id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
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
        let control = OperationSemanticsControl {
            registry: OperationRegistry::default(),
        };
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
            None,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        assert_eq!(
            control.resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service")),
            Err(OperationSemanticsError::NotPlanBoundExternalEffect {
                operation_id: id,
                class: OperationClass::AuthoritativeQuery,
            })
        );
    }

    #[test]
    fn operation_id_cannot_be_bound_to_an_unrelated_plan() {
        let id = operation_id("operation:audio.volume.set-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(effect_binding(
                "pipewire",
                "audio.session.observe",
                "audio:session:",
                &["volume_percent"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        assert_eq!(
            control.resolve_external(&id, &canonical_systemd_plan("systemd:unit:test.service")),
            Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: id,
                mismatch: OperationPlanBindingMismatch::Provider,
            })
        );
    }

    #[test]
    fn exact_registered_audio_transient_refines_to_user_state() {
        let id = operation_id("operation:audio.volume.set-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(effect_binding(
                "pipewire",
                "audio.session.observe",
                "audio:session:",
                &["volume_percent"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        let provider = ProviderId::new("pipewire").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new("audio:session:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let capability = CapabilityId::new("audio.session.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([("volume_percent".into(), "40".into())]),
            reason: SemanticReason {
                summary: "set current session volume".into(),
                intent_ids: vec![
                    IntentId::new("intent:audio").unwrap_or_else(|error| unreachable!("{error}")),
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
            evidence_id: "evidence:audio".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("volume_percent".into(), "20".into())]),
        };
        let plan = DeterministicPlanner
            .plan_resource(
                RequestId::new("request:audio").unwrap_or_else(|error| unreachable!("{error}")),
                Actor {
                    id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                desired,
                &observation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            control.resolve_external(&id, &plan),
            Err(OperationSemanticsError::TransientRequestedStateRequired(
                id.clone()
            ))
        );
        let requested_state = BTreeMap::from([("volume_percent".to_owned(), "40".to_owned())]);
        let resolved = control
            .resolve_external_with_requested_state(&id, &plan, &requested_state)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(resolved.class(), OperationClass::TransientExternalEffect);
        assert_eq!(resolved.risk(), RiskClass::UserState);
        assert!(!resolved.permits_privileged_executor());
        assert!(!resolved.requires_durable_managed_lifecycle());
    }

    #[test]
    fn transient_registration_validates_complete_requested_postcondition() {
        let id = operation_id("operation:audio.volume.set-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(effect_binding(
                "pipewire",
                "audio.session.observe",
                "audio:session:",
                &["volume_percent"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        let provider = ProviderId::new("pipewire").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new("audio:session:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let capability = CapabilityId::new("audio.session.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([
                ("muted".into(), "false".into()),
                ("volume_percent".into(), "40".into()),
            ]),
            reason: SemanticReason {
                summary: "set current session volume".into(),
                intent_ids: vec![
                    IntentId::new("intent:audio-complete-postcondition")
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
            evidence_id: "evidence:audio-complete-postcondition".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([
                ("muted".into(), "false".into()),
                ("volume_percent".into(), "20".into()),
            ]),
        };
        let plan = DeterministicPlanner
            .plan_resource(
                RequestId::new("request:audio-complete-postcondition")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                Actor {
                    id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                desired,
                &observation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            plan.changes
                .iter()
                .map(|change| change.key.as_str())
                .collect::<Vec<_>>(),
            vec!["volume_percent"]
        );

        let requested_state = BTreeMap::from([
            ("muted".into(), "false".into()),
            ("volume_percent".into(), "40".into()),
        ]);
        assert_eq!(
            control.resolve_external_with_requested_state(&id, &plan, &requested_state),
            Err(OperationSemanticsError::PlanBindingMismatch {
                operation_id: id,
                mismatch: OperationPlanBindingMismatch::RequestedStateKey("muted".into()),
            })
        );
    }

    #[test]
    fn transient_risk_refinement_covers_complete_requested_postcondition() {
        let id = operation_id("operation:audio.volume.set-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(effect_binding(
                "pipewire",
                "audio.session.observe",
                "audio:session:",
                &["privileged_toggle", "volume_percent"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        let provider = ProviderId::new("pipewire").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new("audio:session:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let capability = CapabilityId::new("audio.session.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([
                ("privileged_toggle".into(), "false".into()),
                ("volume_percent".into(), "40".into()),
            ]),
            reason: SemanticReason {
                summary: "set current session volume with complete requested state".into(),
                intent_ids: vec![
                    IntentId::new("intent:audio-risk-complete-postcondition")
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
            evidence_id: "evidence:audio-risk-complete-postcondition".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([
                ("privileged_toggle".into(), "false".into()),
                ("volume_percent".into(), "20".into()),
            ]),
        };
        let plan = DeterministicPlanner
            .plan_resource(
                RequestId::new("request:audio-risk-complete-postcondition")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                Actor {
                    id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
                    kind: ActorKind::Human,
                    interactive: true,
                },
                desired,
                &observation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            plan.changes
                .iter()
                .map(|change| change.key.as_str())
                .collect::<Vec<_>>(),
            vec!["volume_percent"]
        );

        let requested_state = BTreeMap::from([
            ("privileged_toggle".into(), "false".into()),
            ("volume_percent".into(), "40".into()),
        ]);
        assert_eq!(
            control.resolve_external_with_requested_state(&id, &plan, &requested_state),
            Err(OperationSemanticsError::UnclassifiedRisk(id))
        );
    }

    #[test]
    fn transient_operation_rejects_plan_risk_above_user_state() {
        let id = operation_id("operation:service.start-session");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(effect_binding(
                "systemd",
                "systemd.unit.observe",
                "systemd:unit:",
                &["active_state"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

        let plan = canonical_systemd_plan("systemd:unit:test.service");
        let requested_state = BTreeMap::from([("active_state".to_owned(), "active".to_owned())]);
        assert_eq!(
            control.resolve_external_with_requested_state(&id, &plan, &requested_state),
            Err(OperationSemanticsError::TransientRiskExceedsBoundary {
                operation_id: id,
                risk: RiskClass::SecuritySensitive,
            })
        );
    }

    #[test]
    fn unclassified_plan_risk_fails_closed() {
        let id = operation_id("operation:service.manage-unclassified");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::ManagedExternalEffect,
            Some(RiskClass::SystemMutation),
            Some(effect_binding(
                "systemd",
                "systemd.unit.observe",
                "systemd:unit:",
                &["active_state", "unknown_mutation_shape"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);
        let mut plan = canonical_systemd_plan("systemd:unit:test.service");
        plan.changes[0].key = "unknown_mutation_shape".into();

        assert_eq!(
            control.resolve_external(&id, &plan),
            Err(OperationSemanticsError::UnclassifiedRisk(id))
        );
    }

    #[test]
    fn managed_operation_uses_trusted_plan_risk_and_registered_floor() {
        let id = operation_id("operation:service.manage");
        let descriptor = OperationDescriptor::try_new(
            id.clone(),
            OperationClass::ManagedExternalEffect,
            Some(RiskClass::Destructive),
            Some(effect_binding(
                "systemd",
                "systemd.unit.observe",
                "systemd:unit:",
                &["active_state"],
            )),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let control = control_with(vec![descriptor]);

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
